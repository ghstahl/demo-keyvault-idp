using System;
using System.Collections.Generic;
using System.Linq;
using System.Security.Cryptography.X509Certificates;
using System.Threading.Tasks;
using CorrelationId;
using IdentityServer4.Services;
using IdentityServer4.Validation;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Hosting;
using Microsoft.AspNetCore.HttpsPolicy;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Hosting;
using Microsoft.Extensions.Logging;
using Serilog;
using Serilog.Enrichers.Correlation;

namespace DemoKeyVaultIDP
{
    public class Startup
    {
        public Startup(IConfiguration configuration, IWebHostEnvironment env)
        {
            Configuration = configuration;
            _currentEnvironment = env;
        }

        public IConfiguration Configuration { get; }

        private IWebHostEnvironment _currentEnvironment;

        // This method gets called by the runtime. Use this method to add services to the container.
        public void ConfigureServices(IServiceCollection services)
        {
            services.AddCorrelationId();
            services.AddCorrelationEnricher();
            services.AddOptions();
            services.AddControllersWithViews();
            services.AddRazorPages();
            var identityServerBuilder =services.AddIdentityServer(options =>
            {
                options.Events.RaiseErrorEvents = true;
                options.Events.RaiseFailureEvents = true;
                options.Events.RaiseInformationEvents = true;
                options.Events.RaiseSuccessEvents = true;
            });

            identityServerBuilder.AddInMemoryApiResources(Config.GetApis());
            identityServerBuilder.AddInMemoryIdentityResources(Config.GetIdentityResources());
            identityServerBuilder.AddInMemoryClients(Config.GetClients());
            identityServerBuilder.AddTestUsers(TestUsers.Users);
            var useKeyVaultS = Configuration["Identity:UseKeyVault"];
             
            bool useKeyVault = false;

            if (!_currentEnvironment.IsDevelopment() || (bool.TryParse(useKeyVaultS, out useKeyVault) && useKeyVault))
            {
                var key = Configuration["P7IdentityServer4SelfSigned"];
                var pfxBytes = Convert.FromBase64String(key);
                var cert = new X509Certificate2(pfxBytes, (string)null, X509KeyStorageFlags.MachineKeySet);
                identityServerBuilder.AddSigningCredential(cert);
            }
            else
            {
                identityServerBuilder.AddDeveloperSigningCredential();
            }
         


            identityServerBuilder.AddDeveloperSigningCredential(persistKey: false);

            // preserve OIDC state in cache (solves problems with AAD and URL lenghts)
            services.AddOidcStateDataFormatterCache("aad");

            // add CORS policy for non-IdentityServer endpoints
            services.AddCors(options =>
            {
                options.AddPolicy("api", policy =>
                {
                    policy.AllowAnyOrigin().AllowAnyHeader().AllowAnyMethod();
                });
            });

            // demo versions (never use in production)
            services.AddTransient<IRedirectUriValidator, DemoRedirectValidator>();
            services.AddTransient<ICorsPolicyService, DemoCorsPolicy>();
        }

        // This method gets called by the runtime. Use this method to configure the HTTP request pipeline.
        public void Configure(IApplicationBuilder app, IWebHostEnvironment env, IServiceProvider provider)
        {
            app.UseCorrelationId(new CorrelationIdOptions
            {
                Header = "X-Correlation-ID",
                UseGuidForCorrelationId = true,
                UpdateTraceIdentifier = false
            });
            Log.Logger = new LoggerConfiguration()
                .ReadFrom.Configuration(Configuration)
                .Enrich.WithCorrelationHttpContext(provider)
                .CreateLogger();
            var loggerFactory = app.ApplicationServices.GetService(typeof(ILoggerFactory)) as ILoggerFactory;
            if (loggerFactory == null) throw new ArgumentNullException(nameof(loggerFactory));

            var logger = loggerFactory.CreateLogger("DemoKeyVaultIDP.Startup");
            logger.LogInformation("Configuring App");

            app.UseSerilogRequestLogging();
            app.UseDeveloperExceptionPage();

            app.UseCors("api");
            if (env.IsDevelopment())
            {
                app.UseDeveloperExceptionPage();
            }
            else
            {
                app.UseExceptionHandler("/Error");
                // The default HSTS value is 30 days. You may want to change this for production scenarios, see https://aka.ms/aspnetcore-hsts.
                app.UseHsts();
            }

            app.UseHttpsRedirection();
            app.UseStaticFiles();

            app.UseRouting();
            app.UseIdentityServer();
            app.UseAuthorization();

            app.UseEndpoints(endpoints =>
            {
                endpoints.MapDefaultControllerRoute();
                endpoints.MapRazorPages();
            });
        }
    }
}

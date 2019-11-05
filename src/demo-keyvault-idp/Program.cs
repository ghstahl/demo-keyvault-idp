using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading.Tasks;
using Microsoft.AspNetCore.Hosting;
using Microsoft.Azure.KeyVault;
using Microsoft.Azure.Services.AppAuthentication;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.Configuration.AzureKeyVault;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Hosting;
using Microsoft.Extensions.Logging;
using Serilog;
using Serilog.Events;

namespace DemoKeyVaultIDP
{
    public class Program
    {
        public static void Main(string[] args)
        {
            // This switch must be set before creating the GrpcChannel/HttpClient.
            AppContext.SetSwitch("System.Net.Http.SocketsHttpHandler.Http2UnencryptedSupport", true);

            Console.Title = "Demo KeyVault IDP";
            var host = CreateHostBuilder(args).Build();
            var logger = host.Services.GetRequiredService<ILogger<Program>>();
            logger.LogInformation("About to run......");
            host.Run();
        }

        public static IHostBuilder CreateHostBuilder(string[] args) =>
            Host.CreateDefaultBuilder(args)
                .UseSerilog((ctx, config) =>
                {
                    config.MinimumLevel.Debug()
                        .MinimumLevel.Debug()
                        .MinimumLevel.Override("Microsoft", LogEventLevel.Warning)
                        .MinimumLevel.Override("System", LogEventLevel.Warning)
                        .MinimumLevel.Override("Microsoft.AspNetCore.Authentication", LogEventLevel.Information)
                        .Enrich.FromLogContext();

                    if (ctx.HostingEnvironment.IsDevelopment())
                    {
                        config.WriteTo.Console(outputTemplate: "[{Timestamp:HH:mm:ss} {Level}] {SourceContext}{NewLine}{Message:lj}{NewLine}{Exception}{NewLine}");
                    }

                })
                .ConfigureAppConfiguration((ctx, builder) =>
                {
                    var environmentName = ctx.HostingEnvironment.EnvironmentName;
                    LoadConfigurations(builder, environmentName);
                    builder.AddUserSecrets<Startup>();
                    builder.AddEnvironmentVariables();


                    var config = builder.Build();

                    var tokenProvider = new AzureServiceTokenProvider();
                    var kvClient = new KeyVaultClient((authority, resource, scope) => tokenProvider.KeyVaultTokenCallback(authority, resource, scope));

                    var clientId = config["Identity:AzureAd:ClientId"];
                    var clientSecret = config["Identity:AzureAd:ClientSecret"];

                    builder.AddAzureKeyVault(
                       $"https://{config["Identity:KeyVault"]}.vault.azure.net/",
                       clientId,
                       clientSecret);

                    // builder.AddAzureKeyVault(config["KeyVault:BaseUrl"], kvClient, new DefaultKeyVaultSecretManager());
                })
                .ConfigureWebHostDefaults(webBuilder =>
                {
                    webBuilder.UseStartup<Startup>().UseSerilog();
                });

        public static void LoadConfigurations(IConfigurationBuilder builder, string environmentName)
        {
            // NOTE:
            // {root}/appsettings.json and {root}/appsettings.{environmentName}.json are already loaded.
            builder.AddJsonFile($"ExternalConfigs/{environmentName}/appsettings.json", optional: true, reloadOnChange: true);
        }
    }
}

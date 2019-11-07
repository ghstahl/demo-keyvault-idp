using Microsoft.Extensions.Caching.Memory;
using Microsoft.Extensions.Hosting;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;
using Newtonsoft.Json;
using System;
using System.IO;
using System.Threading;
using System.Threading.Tasks;

namespace KeyVaultBackground
{

    public class FileSystemConfigFetchOptions
    {
        public string ConfigPath { get; set; }
    }
    public class FileSystemConfigFetchHostedService : IHostedService, IDisposable
    {
        private int executionCount = 0;
        private readonly IOptionsMonitor<FileSystemConfigFetchOptions> _optionsAccessor;
        private readonly ILogger<FileSystemConfigFetchHostedService> _logger;
        private Timer _timer;
        private readonly IMemoryCache _cache;

        public FileSystemConfigFetchHostedService(
            IMemoryCache cache,
            IOptionsMonitor<FileSystemConfigFetchOptions> optionsAccessor, 
            ILogger<FileSystemConfigFetchHostedService> logger)
        {
            _cache = cache;
            _optionsAccessor = optionsAccessor;
            _logger = logger;
        }

        public Task StartAsync(CancellationToken stoppingToken)
        {
            _logger.LogInformation("Timed Hosted Service running.");

            _timer = new Timer(DoWork, null, TimeSpan.Zero,
                TimeSpan.FromSeconds(5));

            return Task.CompletedTask;
        }

        private void DoWork(object state)
        {
            executionCount++;
            _logger.LogInformation(
            "Timed Hosted Service is working. Count: {Count}, ConfigPath: {ConfigPath}", executionCount, _optionsAccessor.CurrentValue.ConfigPath);

            try
            {
                var json = File.ReadAllText(_optionsAccessor.CurrentValue.ConfigPath);
                var got = JsonConvert.DeserializeObject<EDCSAConfigSet>(json);
                _cache.Set("4be948db-3255-4fa1-a802-da66621d180c", got);
                _logger.LogInformation(json);



            }
            catch(Exception e)
            {
                _logger.LogCritical(e.Message);
            }
           
        }

        public Task StopAsync(CancellationToken stoppingToken)
        {
            _logger.LogInformation("Timed Hosted Service is stopping.");

            _timer?.Change(Timeout.Infinite, 0);

            return Task.CompletedTask;
        }

        public void Dispose()
        {
            _timer?.Dispose();
        }
    }
}

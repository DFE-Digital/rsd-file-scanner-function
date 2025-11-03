using GovUK.Dfe.CoreLibs.Messaging.Contracts.Entities.Topics;
using GovUK.Dfe.CoreLibs.Messaging.Contracts.Messages.Events;
using GovUK.Dfe.CoreLibs.Messaging.MassTransit.Extensions;
using Microsoft.Azure.Functions.Worker;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Hosting;

var host = new HostBuilder()
    .ConfigureFunctionsWebApplication()
    .ConfigureAppConfiguration((context, config) =>
    {
        config
            .SetBasePath(context.HostingEnvironment.ContentRootPath)
            .AddEnvironmentVariables();
    })
    .ConfigureServices((context, services) =>
    {
        services.AddApplicationInsightsTelemetryWorkerService();
        services.ConfigureFunctionsApplicationInsights();

        var config = context.Configuration;
        
        // Add HttpClient factory for file downloads
        services.AddHttpClient();
        
        services.AddDfEMassTransit(
            config,
            configureConsumers: x =>
            {
                // No consumers - Azure Function trigger handles message consumption
            },
            configureBus: (context, cfg) =>
            {
                // Configure message routing for publishing
                cfg.Message<ScanResultEvent>(m => m.SetEntityName(TopicNames.ScanResult));
            });

        services.AddRedisCaching(config);

    })
    .Build();

host.Run();

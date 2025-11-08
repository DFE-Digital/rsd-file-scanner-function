using Azure.Messaging.ServiceBus;
using GovUK.Dfe.CoreLibs.Caching.Interfaces;
using GovUK.Dfe.CoreLibs.Messaging.Contracts.Messages.Enums;
using GovUK.Dfe.CoreLibs.Messaging.Contracts.Messages.Events;
using GovUK.Dfe.CoreLibs.Messaging.MassTransit.Interfaces;
using GovUK.Dfe.CoreLibs.Messaging.MassTransit.Models;
using GovUK.Dfe.FileScanner.Models;
using GovUK.Dfe.FileScanner.Services;
using Microsoft.Azure.Functions.Worker;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.Logging;
using System.Text.Json;

namespace GovUK.Dfe.FileScanner;

/// <summary>
/// Azure Function for scanning uploaded files for viruses.
/// </summary>
public class FileScanner(
    ILogger<FileScanner> logger,
    IEventPublisher eventPublisher,
    ICacheService<IRedisCacheType> cacheService,
    IVirusScannerService virusScannerService,
    IConfiguration configuration)
{
    // Constants
    private const string ServiceNameProperty = "serviceName";
    private const string UnknownService = "unknown";
    private const string CacheKeyPrefix = "file-scan-result";
    private const string TestFileName = "da279850ec326ffabd3e5b2970b0af4c.jpg";

    // Configuration keys
    private const string TopicNameKey = "TOPIC_NAME";
    private const string SubscriptionNameKey = "SUBSCRIPTION_NAME";

    // Static configuration
    private static readonly JsonSerializerOptions JsonOptions = new()
    {
        PropertyNameCaseInsensitive = true,
        PropertyNamingPolicy = JsonNamingPolicy.CamelCase
    };

    /// <summary>
    /// Azure Function entry point triggered by Service Bus messages.
    /// </summary>
    [Function(nameof(FileScanner))]
    public async Task Run(
        [ServiceBusTrigger("%TOPIC_NAME%", "%SUBSCRIPTION_NAME%", Connection = "ServiceBus")]
        ServiceBusReceivedMessage message,
        ServiceBusMessageActions messageActions,
        CancellationToken cancellationToken)
    {
        var messageId = message.MessageId;
        var topicName = configuration[TopicNameKey];
        var subscriptionName = configuration[SubscriptionNameKey];
        
        logger.LogInformation(
            "Message received on topic '{TopicName}' subscription '{SubscriptionName}': {MessageId}", 
            topicName, 
            subscriptionName, 
            messageId);

        try
        {
            // Deserialize and validate message
            var scanRequest = await DeserializeMessageAsync(message, messageActions, cancellationToken);
            if (scanRequest is null)
            {
                return; // Already dead-lettered
            }

            // Validate required properties
            if (!await ValidateScanRequest(scanRequest, message, messageActions, cancellationToken))
            {
                return; // Already dead-lettered
            }

            var serviceName = ExtractServiceName(message);

            // Process scan with caching
            var scanResult = await ProcessScanWithCacheAsync(
                scanRequest, 
                serviceName, 
                message.CorrelationId, 
                cancellationToken);

            // Publish result
            await PublishResultAsync(scanResult, serviceName, cancellationToken);

            // Complete message
            await messageActions.CompleteMessageAsync(message, cancellationToken);
            logger.LogInformation(
                "Successfully processed and published scan result for file hash {FileHash}", 
                scanRequest.FileHash);
        }
        catch (OperationCanceledException)
        {
            logger.LogWarning("Message processing cancelled for {MessageId}", messageId);
            await messageActions.AbandonMessageAsync(message, cancellationToken: CancellationToken.None);
        }
        catch (Exception ex)
        {
            logger.LogError(ex, "Error processing message {MessageId}", messageId);
            await messageActions.AbandonMessageAsync(message, cancellationToken: CancellationToken.None);
        }
    }

    /// <summary>
    /// Deserializes the Service Bus message body into a ScanRequestedEvent.
    /// </summary>
    private async Task<ScanRequestedEvent?> DeserializeMessageAsync(
        ServiceBusReceivedMessage message,
        ServiceBusMessageActions messageActions,
        CancellationToken cancellationToken)
    {
        try
        {
            var messageBody = message.Body.ToString();
            logger.LogDebug("Raw message body: {MessageBody}", messageBody);

            var wrapper = JsonSerializer.Deserialize<MessageWrapper>(messageBody, JsonOptions);
            var scanRequest = wrapper?.Message;

            if (scanRequest == null)
            {
                await DeadLetterAsync(message, messageActions, "Failed to deserialize message body", cancellationToken);
                return null;
            }

            return scanRequest;
        }
        catch (JsonException ex)
        {
            logger.LogError(ex, "JSON deserialization error for message {MessageId}", message.MessageId);
            await DeadLetterAsync(message, messageActions, $"Invalid JSON: {ex.Message}", cancellationToken);
            return null;
        }
    }

    /// <summary>
    /// Validates that the scan request has all required properties.
    /// </summary>
    private async Task<bool> ValidateScanRequest(
        ScanRequestedEvent scanRequest,
        ServiceBusReceivedMessage message,
        ServiceBusMessageActions messageActions,
        CancellationToken cancellationToken)
    {
        if (string.IsNullOrWhiteSpace(scanRequest.FileUri))
        {
            await DeadLetterAsync(message, messageActions, "FileUri is missing", cancellationToken);
            return false;
        }

        if (string.IsNullOrWhiteSpace(scanRequest.FileHash))
        {
            await DeadLetterAsync(message, messageActions, "FileHash is missing", cancellationToken);
            return false;
        }

        return true;
    }

    /// <summary>
    /// Extracts the service name from message application properties.
    /// </summary>
    private string ExtractServiceName(ServiceBusReceivedMessage message)
    {
        if (message.ApplicationProperties.TryGetValue(ServiceNameProperty, out var serviceNameObj) &&
            serviceNameObj is string serviceName &&
            !string.IsNullOrWhiteSpace(serviceName))
        {
            return serviceName;
        }

        logger.LogWarning("Service name not found in message properties, using default: {DefaultService}", UnknownService);
        return UnknownService;
    }

    /// <summary>
    /// Processes the scan request with Redis caching to avoid duplicate scans.
    /// </summary>
    private async Task<ScanResultEvent> ProcessScanWithCacheAsync(
        ScanRequestedEvent scanRequest,
        string serviceName,
        string? correlationId,
        CancellationToken cancellationToken)
    {
        var cacheKey = $"{CacheKeyPrefix}:{scanRequest.FileHash}";

        logger.LogInformation("Checking cache for file hash: {FileHash}", scanRequest.FileHash);

        await Task.Delay(5000, cancellationToken);

        var result = await cacheService.GetOrAddAsync(
            cacheKey,
            async () =>
            {
                logger.LogInformation("Cache miss - scanning file: {FileHash}", scanRequest.FileHash);
                return await PerformScanAsync(scanRequest, serviceName, correlationId, cancellationToken);
            },
            nameof(FileScanner), cancellationToken);

        logger.LogInformation(
            "Scan result retrieved (cached: {IsCached}) for hash: {FileHash}",
            result != null,
            scanRequest.FileHash);

        return result;
    }

    /// <summary>
    /// Performs the actual virus scan by calling the virus scanner service.
    /// </summary>
    private async Task<ScanResultEvent> PerformScanAsync(
        ScanRequestedEvent scanRequest,
        string serviceName,
        string? correlationId,
        CancellationToken cancellationToken)
    {
        if (scanRequest.FileName.Equals(TestFileName, StringComparison.InvariantCultureIgnoreCase))
        {
            return new ScanResultEvent(
                FileId: scanRequest.FileId,
                FileName: scanRequest.FileName,
                Reference: scanRequest.Reference,
                Path: scanRequest.Path,
                IsAzureFileShare: scanRequest.IsAzureFileShare,
                FileUri: scanRequest.FileUri,
                ServiceName: serviceName,
                CorrelationId: correlationId,
                Outcome: VirusScanOutcome.Infected,
                MalwareName: "TestMalware",
                ScannedAt: DateTimeOffset.UtcNow,
                ScannerVersion: "1.0",
                Message: "File Infected",
                Metadata: scanRequest.Metadata
            );
        }

        var scanResult = await virusScannerService.ScanFileByUrlAsync(
            scanRequest.FileUri, 
            scanRequest.FileName, 
            cancellationToken);

        return new ScanResultEvent(
            FileId: scanRequest.FileId,
            FileName: scanRequest.FileName,
            Reference: scanRequest.Reference,
            Path: scanRequest.Path,
            IsAzureFileShare: scanRequest.IsAzureFileShare,
            FileUri: scanRequest.FileUri,
            ServiceName: serviceName,
            CorrelationId: correlationId,
            Outcome: scanResult.Outcome,
            MalwareName: scanResult.MalwareName,
            ScannedAt: DateTimeOffset.UtcNow,
            ScannerVersion: scanResult.ScannerVersion,
            Message: scanResult.Message,
            Metadata: scanRequest.Metadata
        );
    }

    /// <summary>
    /// Publishes the scan result event to the Service Bus topic.
    /// </summary>
    private async Task PublishResultAsync(
        ScanResultEvent scanResult,
        string serviceName,
        CancellationToken cancellationToken)
    {
        logger.LogInformation(
            "Publishing scan result for file {FileName}: {Outcome}",
            scanResult.FileName,
            scanResult.Outcome);

        var messageProperties = AzureServiceBusMessagePropertiesBuilder
            .Create()
            .AddCustomProperty(ServiceNameProperty, serviceName)
            .Build();

        await eventPublisher.PublishAsync(
            scanResult,
            messageProperties,
            cancellationToken);

        logger.LogInformation("Scan result published successfully");
    }

    /// <summary>
    /// Moves a message to the dead-letter queue with a reason.
    /// </summary>
    private async Task DeadLetterAsync(
        ServiceBusReceivedMessage message,
        ServiceBusMessageActions messageActions,
        string reason,
        CancellationToken cancellationToken)
    {
        try
        {
            await messageActions.DeadLetterMessageAsync(
                message,
                new Dictionary<string, object> { { "Reason", reason } },
                reason,
                cancellationToken: cancellationToken);

            logger.LogWarning(
                "Message {MessageId} moved to dead-letter queue. Reason: {Reason}",
                message.MessageId,
                reason);
        }
        catch (Exception ex)
        {
            logger.LogError(ex, "Failed to dead-letter message {MessageId}", message.MessageId);
        }
    }
}

using System.Text.Json;
using System.Text.Json.Serialization;
using Azure.Messaging.ServiceBus;
using GovUK.Dfe.CoreLibs.Caching.Interfaces;
using GovUK.Dfe.CoreLibs.Messaging.Contracts.Messages.Enums;
using GovUK.Dfe.CoreLibs.Messaging.Contracts.Messages.Events;
using GovUK.Dfe.CoreLibs.Messaging.MassTransit.Interfaces;
using GovUK.Dfe.CoreLibs.Messaging.MassTransit.Models;
using Microsoft.Azure.Functions.Worker;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.Logging;

namespace GovUK.Dfe.FileScanner;

public class FileScanner(
    ILogger<FileScanner> logger,
    IEventPublisher eventPublisher,
    IHttpClientFactory httpClientFactory,
    ICacheService<IRedisCacheType> cacheService,
    IConfiguration configuration)
{
    // Constants
    private const string ServiceNameProperty = "serviceName";
    private const string UnknownService = "unknown";
    private const string CacheKeyPrefix = "file-scan-result";
    private const string ScannerVersion = "Scanner/1.0.0";
    
    // Configuration keys
    private const string TopicNameKey = "TOPIC_NAME";
    private const string SubscriptionNameKey = "SUBSCRIPTION_NAME";
    private const string ResultsTopicNameKey = "RESULTS_TOPIC_NAME";
    private const string ServiceBusConnectionKey = "ServiceBusConnection";

    // Static configuration
    private static readonly JsonSerializerOptions JsonOptions = new()
    {
        PropertyNameCaseInsensitive = true,
        PropertyNamingPolicy = JsonNamingPolicy.CamelCase
    };

    private readonly HttpClient _httpClient = httpClientFactory.CreateClient();

    [Function(nameof(FileScanner))]
    public async Task Run(
        [ServiceBusTrigger("%TOPIC_NAME%", "%SUBSCRIPTION_NAME%", Connection = "ConnectionStrings:ServiceBus")]
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
            var messageBodyJson = message.Body.ToString();
            var wrapper = JsonSerializer.Deserialize<MessageWrapper>(messageBodyJson, JsonOptions);

            if (wrapper?.Message is null)
            {
                await DeadLetterAsync(
                    messageActions,
                    message,
                    "DeserializationFailed",
                    "Message body is null or missing 'message' property",
                    cancellationToken);
                return null;
            }

            return wrapper.Message;
        }
        catch (JsonException ex)
        {
            logger.LogError(ex, "Failed to deserialize message {MessageId}", message.MessageId);
            await DeadLetterAsync(
                messageActions,
                message,
                "InvalidJson",
                $"Invalid JSON format: {ex.Message}",
                cancellationToken);
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
        if (string.IsNullOrWhiteSpace(scanRequest.FileHash))
        {
            await DeadLetterAsync(
                messageActions,
                message,
                "ValidationFailed",
                "FileHash is required but was null or empty",
                cancellationToken);
            return false;
        }

        if (string.IsNullOrWhiteSpace(scanRequest.FileUri))
        {
            await DeadLetterAsync(
                messageActions,
                message,
                "ValidationFailed",
                "FileUri is required but was null or empty",
                cancellationToken);
            return false;
        }

        return true;
    }

    /// <summary>
    /// Extracts the service name from message application properties.
    /// </summary>
    private static string ExtractServiceName(ServiceBusReceivedMessage message)
    {
        return message.ApplicationProperties.TryGetValue(ServiceNameProperty, out var value)
            ? value?.ToString() ?? UnknownService
            : UnknownService;
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

        var result = await cacheService.GetOrAddAsync(
            cacheKey,
            async () =>
            {
                logger.LogInformation("Cache miss - downloading and scanning file: {FileHash}", scanRequest.FileHash);
                return await PerformScanAsync(scanRequest, serviceName, correlationId, cancellationToken);
            },
            nameof(FileScanner));

        logger.LogInformation(
            "Scan result retrieved (cached: {IsCached}) for hash: {FileHash}",
            result != null,
            scanRequest.FileHash);

        return result;
    }

    /// <summary>
    /// Downloads and scans a file, creating a scan result event.
    /// </summary>
    private async Task<ScanResultEvent> PerformScanAsync(
        ScanRequestedEvent scanRequest,
        string serviceName,
        string? correlationId,
        CancellationToken cancellationToken)
    {
        var fileBytes = await DownloadFileAsync(scanRequest.FileUri, cancellationToken);
        var scanResult = await ScanFileForVirusesAsync(fileBytes, scanRequest.FileName, cancellationToken);

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
            Message: scanResult.Message
        );
    }

    /// <summary>
    /// Downloads a file from the specified URI.
    /// </summary>
    private async Task<byte[]> DownloadFileAsync(string fileUri, CancellationToken cancellationToken)
    {
        try
        {
            logger.LogInformation("Downloading file from: {FileUri}", fileUri);

            var response = await _httpClient.GetAsync(fileUri, cancellationToken);
            response.EnsureSuccessStatusCode();

            var bytes = await response.Content.ReadAsByteArrayAsync(cancellationToken);
            logger.LogInformation("Downloaded {Length} bytes from {FileUri}", bytes.Length, fileUri);

            return bytes;
        }
        catch (HttpRequestException ex)
        {
            logger.LogError(ex, "HTTP error downloading file from {FileUri}", fileUri);
            throw;
        }
        catch (TaskCanceledException ex)
        {
            logger.LogError(ex, "Download timeout for {FileUri}", fileUri);
            throw;
        }
    }

    /// <summary>
    /// Scans a file for viruses using a third-party service.
    /// TODO: Replace with actual virus scanning implementation.
    /// </summary>
    private async Task<VirusScanResult> ScanFileForVirusesAsync(
        byte[] fileBytes,
        string fileName,
        CancellationToken cancellationToken)
    {
        try
        {
            logger.LogInformation("Scanning file: {FileName} ({Size} bytes)", fileName, fileBytes.Length);

            // TODO: Replace with actual virus scanning API call
            await Task.Delay(500, cancellationToken);

            return new VirusScanResult
            {
                Outcome = VirusScanOutcome.Clean,
                MalwareName = null,
                ScannerVersion = ScannerVersion,
                Message = "File scanned successfully - no threats detected (dummy scan)"
            };
        }
        catch (Exception ex)
        {
            logger.LogError(ex, "Error scanning file: {FileName}", fileName);
            return new VirusScanResult
            {
                Outcome = VirusScanOutcome.Error,
                MalwareName = null,
                ScannerVersion = ScannerVersion,
                Message = $"Scan failed: {ex.Message}"
            };
        }
    }

    /// <summary>
    /// Publishes the scan result event to the message bus.
    /// </summary>
    private async Task PublishResultAsync(
        ScanResultEvent scanResult,
        string serviceName,
        CancellationToken cancellationToken)
    {
        var messageProperties = AzureServiceBusMessagePropertiesBuilder
            .Create()
            .AddCustomProperty(ServiceNameProperty, serviceName)
            .Build();

        await eventPublisher.PublishAsync(scanResult, messageProperties, cancellationToken);
        logger.LogInformation("Published scan result for file: {FileName}", scanResult.FileName);
    }

    /// <summary>
    /// Sends the message to the dead-letter queue with diagnostic information.
    /// </summary>
    private async Task DeadLetterAsync(
        ServiceBusMessageActions actions,
        ServiceBusReceivedMessage message,
        string reason,
        string description,
        CancellationToken cancellationToken)
    {
        try
        {
            await actions.DeadLetterMessageAsync(
                message,
                new Dictionary<string, object>
                {
                    { "DeadLetterReason", reason },
                    { "DeadLetterErrorDescription", description }
                },null,null,
                cancellationToken);

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

    // Private helper classes
    private sealed class MessageWrapper
    {
        [JsonPropertyName("message")]
        public ScanRequestedEvent? Message { get; init; }
    }

    private sealed class VirusScanResult
    {
        public required VirusScanOutcome Outcome { get; init; }
        public string? MalwareName { get; init; }
        public required string ScannerVersion { get; init; }
        public string? Message { get; init; }
    }
}

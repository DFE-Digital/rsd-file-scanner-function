using Azure.Messaging.ServiceBus;
using GovUK.Dfe.CoreLibs.Caching.Interfaces;
using GovUK.Dfe.CoreLibs.Messaging.Contracts.Messages.Enums;
using GovUK.Dfe.CoreLibs.Messaging.Contracts.Messages.Events;
using GovUK.Dfe.CoreLibs.Messaging.MassTransit.Interfaces;
using GovUK.Dfe.CoreLibs.Messaging.MassTransit.Models;
using Microsoft.Azure.Functions.Worker;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.Logging;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using System.Text.Json.Serialization;

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
    private const string TestFileName = "da279850ec326ffabd3e5b2970b0af4c.jpg"; //test__virus__file__rsd.jpg

    // Configuration keys
    private const string TopicNameKey = "TOPIC_NAME";
    private const string SubscriptionNameKey = "SUBSCRIPTION_NAME";
    private const string VirusScannerApiBaseUrlKey = "VirusScannerApi:BaseUrl";
    private const string VirusScannerApiAsyncScanEndpointKey = "VirusScannerApi:AsyncScanEndpoint";
    private const string VirusScannerApiVersionEndpointKey = "VirusScannerApi:VersionEndpoint";
    private const string VirusScannerApiPollingIntervalSecondsKey = "VirusScannerApi:PollingIntervalSeconds";
    private const string VirusScannerApiMaxPollingTimeoutSecondsKey = "VirusScannerApi:MaxPollingTimeoutSeconds";
    
    // Default values for async scanning
    private const int DefaultPollingIntervalSeconds = 5;
    private const int DefaultMaxPollingTimeoutSeconds = 300; // 5 minutes

    // Static configuration
    private static readonly JsonSerializerOptions JsonOptions = new()
    {
        PropertyNameCaseInsensitive = true,
        PropertyNamingPolicy = JsonNamingPolicy.CamelCase
    };

    private readonly HttpClient _httpClient = httpClientFactory.CreateClient();

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

        await Task.Delay(5000, cancellationToken);

        var result = await cacheService.GetOrAddAsync(
            cacheKey,
            async () =>
            {
                logger.LogInformation("Cache miss - downloading and scanning file: {FileHash}", scanRequest.FileHash);
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
    /// Downloads and scans a file, creating a scan result event.
    /// </summary>
    private async Task<ScanResultEvent> PerformScanAsync(
        ScanRequestedEvent scanRequest,
        string serviceName,
        string? correlationId,
        CancellationToken cancellationToken)
    {
        var fileBytes = await DownloadFileAsync(scanRequest.FileUri, cancellationToken);

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
            Message: scanResult.Message,
            Metadata: scanRequest.Metadata
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

            var fUri = new Uri(fileUri);


            byte[] fileBytes;

            if (fUri.Scheme.Equals("file", StringComparison.OrdinalIgnoreCase))
            {
                // Local mode: read directly from disk
                var localPath = fUri.LocalPath;
                fileBytes = await File.ReadAllBytesAsync(localPath, cancellationToken);
                Console.WriteLine($"[LOCAL] Loaded file from {localPath}");
            }
            else
            {
                // Azure mode: download via SAS (HTTPS)
                var response = await _httpClient.GetAsync(fUri, cancellationToken);
                response.EnsureSuccessStatusCode();

                fileBytes = await response.Content.ReadAsByteArrayAsync(cancellationToken);
                Console.WriteLine($"[AZURE] Downloaded file from {fUri}");
            }


            logger.LogInformation("Downloaded {Length} bytes from {FileUri}", fileBytes.Length, fUri);

            return fileBytes;
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
    /// Scans a file for viruses using the virus scanner API with async scanning and polling.
    /// </summary>
    private async Task<VirusScanResult> ScanFileForVirusesAsync(
        byte[] fileBytes,
        string fileName,
        CancellationToken cancellationToken)
    {
        try
        {
            var baseUrl = configuration[VirusScannerApiBaseUrlKey];
            var asyncScanEndpoint = configuration[VirusScannerApiAsyncScanEndpointKey] ?? "/scan/async";
            var versionEndpoint = configuration[VirusScannerApiVersionEndpointKey] ?? "/version";
            
            if (string.IsNullOrWhiteSpace(baseUrl))
            {
                logger.LogError("Virus scanner API base URL is not configured");
                return new VirusScanResult
                {
                    Outcome = VirusScanOutcome.Error,
                    MalwareName = null,
                    ScannerVersion = "Unknown",
                    Message = "Virus scanner API not configured"
                };
            }

            logger.LogInformation("Submitting file for async scan: {FileName} ({Size} bytes) using API: {BaseUrl}", 
                fileName, fileBytes.Length, baseUrl);

            // Get scanner version
            var scannerVersion = await GetScannerVersionAsync(baseUrl, versionEndpoint, cancellationToken);

            // Submit the file for async scanning
            var scanUrl = $"{baseUrl.TrimEnd('/')}{asyncScanEndpoint}";
            using var content = new MultipartFormDataContent();
            using var fileContent = new ByteArrayContent(fileBytes);
            fileContent.Headers.ContentType = new System.Net.Http.Headers.MediaTypeHeaderValue("application/octet-stream");
            content.Add(fileContent, "file", fileName);

            var submitResponse = await _httpClient.PostAsync(scanUrl, content, cancellationToken);
            submitResponse.EnsureSuccessStatusCode();

            var submitResponseBody = await submitResponse.Content.ReadAsStringAsync(cancellationToken);
            var asyncSubmitResponse = JsonSerializer.Deserialize<AsyncScanSubmitResponse>(submitResponseBody, JsonOptions);

            if (asyncSubmitResponse == null || string.IsNullOrWhiteSpace(asyncSubmitResponse.StatusUrl))
            {
                logger.LogError("Failed to parse async scan submission response or missing statusUrl");
                return new VirusScanResult
                {
                    Outcome = VirusScanOutcome.Error,
                    MalwareName = null,
                    ScannerVersion = scannerVersion,
                    Message = "Failed to submit file for async scanning"
                };
            }

            logger.LogInformation(
                "Scan job submitted successfully. JobId: {JobId}, Status: {Status}, StatusUrl: {StatusUrl}",
                asyncSubmitResponse.JobId,
                asyncSubmitResponse.Status,
                asyncSubmitResponse.StatusUrl);

            // Poll the status URL until scan is complete
            var scanStatusResponse = await PollScanStatusAsync(baseUrl, asyncSubmitResponse.StatusUrl, cancellationToken);

            if (scanStatusResponse == null)
            {
                logger.LogError("Failed to get scan results from polling (timeout or error)");
                return new VirusScanResult
                {
                    Outcome = VirusScanOutcome.Error,
                    MalwareName = null,
                    ScannerVersion = scannerVersion,
                    Message = "Scan polling timed out or failed"
                };
            }

            // Process the final scan result
            logger.LogInformation("Final scan result for {FileName}: {Status}", fileName, scanStatusResponse.Status);

            var outcome = MapScanOutcome(scanStatusResponse.Status);
            var message = outcome switch
            {
                VirusScanOutcome.Clean => $"File is clean. Engine: {scanStatusResponse.Engine}",
                VirusScanOutcome.Infected => $"Malware detected: {scanStatusResponse.Malware}",
                VirusScanOutcome.Error => $"Scan error: {scanStatusResponse.Raw ?? "Unknown error"}",
                _ => "Scan completed"
            };

            return new VirusScanResult
            {
                Outcome = outcome,
                MalwareName = scanStatusResponse.Malware,
                ScannerVersion = scannerVersion,
                Message = message
            };
        }
        catch (HttpRequestException ex)
        {
            logger.LogError(ex, "HTTP error calling virus scanner API for file: {FileName}", fileName);
            return new VirusScanResult
            {
                Outcome = VirusScanOutcome.Error,
                MalwareName = null,
                ScannerVersion = "Unknown",
                Message = $"Virus scanner API error: {ex.Message}"
            };
        }
        catch (TaskCanceledException ex)
        {
            logger.LogError(ex, "Virus scan timeout for file: {FileName}", fileName);
            return new VirusScanResult
            {
                Outcome = VirusScanOutcome.Error,
                MalwareName = null,
                ScannerVersion = "Unknown",
                Message = "Virus scan timeout"
            };
        }
        catch (Exception ex)
        {
            logger.LogError(ex, "Error scanning file: {FileName}", fileName);
            return new VirusScanResult
            {
                Outcome = VirusScanOutcome.Error,
                MalwareName = null,
                ScannerVersion = "Unknown",
                Message = $"Scan failed: {ex.Message}"
            };
        }
    }

    /// <summary>
    /// Gets the version of the virus scanner.
    /// </summary>
    private async Task<string> GetScannerVersionAsync(string baseUrl, string versionEndpoint, CancellationToken cancellationToken)
    {
        try
        {
            var versionUrl = $"{baseUrl.TrimEnd('/')}{versionEndpoint}";
            var response = await _httpClient.GetAsync(versionUrl, cancellationToken);
            
            if (!response.IsSuccessStatusCode)
            {
                logger.LogWarning("Failed to get scanner version. Status: {StatusCode}", response.StatusCode);
                return "Unknown";
            }

            var versionBody = await response.Content.ReadAsStringAsync(cancellationToken);
            var versionResponse = JsonSerializer.Deserialize<VirusScannerVersionResponse>(versionBody, JsonOptions);
            
            return versionResponse?.ClamavVersion ?? "Unknown";
        }
        catch (Exception ex)
        {
            logger.LogWarning(ex, "Error getting scanner version");
            return "Unknown";
        }
    }

    /// <summary>
    /// Polls the scan status URL until the scan is complete or timeout occurs.
    /// </summary>
    private async Task<AsyncScanStatusResponse?> PollScanStatusAsync(
        string baseUrl,
        string statusUrl,
        CancellationToken cancellationToken)
    {
        var pollingInterval = TimeSpan.FromSeconds(
            configuration.GetValue<int?>(VirusScannerApiPollingIntervalSecondsKey) ?? DefaultPollingIntervalSeconds);
        
        var maxTimeout = TimeSpan.FromSeconds(
            configuration.GetValue<int?>(VirusScannerApiMaxPollingTimeoutSecondsKey) ?? DefaultMaxPollingTimeoutSeconds);
        
        var fullStatusUrl = statusUrl.StartsWith("http", StringComparison.OrdinalIgnoreCase)
            ? statusUrl
            : $"{baseUrl.TrimEnd('/')}{statusUrl}";
        
        logger.LogInformation(
            "Starting to poll scan status at: {StatusUrl} (interval: {Interval}s, timeout: {Timeout}s)",
            fullStatusUrl,
            pollingInterval.TotalSeconds,
            maxTimeout.TotalSeconds);
        
        var startTime = DateTimeOffset.UtcNow;
        var attempt = 0;
        
        while (true)
        {
            attempt++;
            var elapsed = DateTimeOffset.UtcNow - startTime;
            
            // Check timeout
            if (elapsed >= maxTimeout)
            {
                logger.LogError(
                    "Polling timeout reached after {Elapsed}s and {Attempts} attempts",
                    elapsed.TotalSeconds,
                    attempt);
                return null;
            }
            
            try
            {
                logger.LogDebug("Polling attempt {Attempt} at {Elapsed}s", attempt, elapsed.TotalSeconds);
                
                var response = await _httpClient.GetAsync(fullStatusUrl, cancellationToken);
                response.EnsureSuccessStatusCode();
                
                var responseBody = await response.Content.ReadAsStringAsync(cancellationToken);
                var statusResponse = JsonSerializer.Deserialize<AsyncScanStatusResponse>(responseBody, JsonOptions);
                
                if (statusResponse == null)
                {
                    logger.LogWarning("Failed to parse status response");
                    return null;
                }
                
                logger.LogInformation(
                    "Poll attempt {Attempt}: Status = {Status}",
                    attempt,
                    statusResponse.Status);
                
                // Check if scan is complete
                if (IsTerminalStatus(statusResponse.Status))
                {
                    logger.LogInformation(
                        "Scan completed after {Elapsed}s and {Attempts} attempts with status: {Status}",
                        elapsed.TotalSeconds,
                        attempt,
                        statusResponse.Status);
                    return statusResponse;
                }
                
                // Wait before next poll (not a terminal state, still queued/scanning)
                await Task.Delay(pollingInterval, cancellationToken);
            }
            catch (HttpRequestException ex)
            {
                logger.LogError(ex, "HTTP error polling status URL: {StatusUrl}", fullStatusUrl);
                return null;
            }
            catch (TaskCanceledException)
            {
                logger.LogWarning("Polling cancelled");
                throw;
            }
            catch (Exception ex)
            {
                logger.LogError(ex, "Unexpected error polling status");
                return null;
            }
        }
    }

    /// <summary>
    /// Maps the API scan status to VirusScanOutcome enum.
    /// ClamAV API returns: "clean", "infected", "error", "queued", "scanning"
    /// </summary>
    private static VirusScanOutcome MapScanOutcome(string? status)
    {
        return status?.ToLowerInvariant() switch
        {
            "clean" => VirusScanOutcome.Clean,
            "infected" => VirusScanOutcome.Infected,
            "error" => VirusScanOutcome.Error,
            _ => VirusScanOutcome.Error  // Default to error for unexpected values
        };
    }
    
    /// <summary>
    /// Checks if the scan status is a terminal state (scan complete).
    /// </summary>
    private static bool IsTerminalStatus(string? status)
    {
        return status?.ToLowerInvariant() switch
        {
            "clean" or "infected" or "error" => true,
            _ => false
        };
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

    private sealed class VirusScanApiResponse
    {
        [JsonPropertyName("status")]
        public string? Status { get; init; }
        
        [JsonPropertyName("engine")]
        public string? Engine { get; init; }
        
        [JsonPropertyName("malware")]
        public string? Malware { get; init; }
        
        [JsonPropertyName("fileName")]
        public string? FileName { get; init; }
        
        [JsonPropertyName("size")]
        public long? Size { get; init; }
        
        [JsonPropertyName("signatureDbTime")]
        public DateTimeOffset? SignatureDbTime { get; init; }
        
        [JsonPropertyName("raw")]
        public string? Raw { get; init; }
    }

    private sealed class VirusScannerVersionResponse
    {
        [JsonPropertyName("clamavVersion")]
        public string? ClamavVersion { get; init; }
    }

    private sealed class AsyncScanSubmitResponse
    {
        [JsonPropertyName("jobId")]
        public string? JobId { get; init; }
        
        [JsonPropertyName("status")]
        public string? Status { get; init; }
        
        [JsonPropertyName("statusUrl")]
        public string? StatusUrl { get; init; }
    }

    private sealed class AsyncScanStatusResponse
    {
        [JsonPropertyName("status")]
        public string? Status { get; init; }
        
        [JsonPropertyName("engine")]
        public string? Engine { get; init; }
        
        [JsonPropertyName("malware")]
        public string? Malware { get; init; }
        
        [JsonPropertyName("fileName")]
        public string? FileName { get; init; }
        
        [JsonPropertyName("size")]
        public long? Size { get; init; }
        
        [JsonPropertyName("signatureDbTime")]
        public DateTimeOffset? SignatureDbTime { get; init; }
        
        [JsonPropertyName("raw")]
        public string? Raw { get; init; }
    }
}

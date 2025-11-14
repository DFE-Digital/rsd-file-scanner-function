using GovUK.Dfe.CoreLibs.Messaging.Contracts.Messages.Enums;
using GovUK.Dfe.FileScanner.Models;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.Logging;
using System.Text;
using GovUK.Dfe.ClamAV.Api.Client.Contracts;

namespace GovUK.Dfe.FileScanner.Services;

/// <summary>
/// Service for scanning files for viruses using an external virus scanner API.
/// </summary>
public class VirusScannerService(
    ILogger<VirusScannerService> logger,
    IConfiguration configuration,
    IClamAvApiClient clamAvApiClient)
    : IVirusScannerService
{
    // Configuration keys
    private const string VirusScannerApiBaseUrlKey = "VirusScannerApi:BaseUrl";
    private const string VirusScannerApiPollingIntervalSecondsKey = "VirusScannerApi:PollingIntervalSeconds";
    private const string VirusScannerApiMaxPollingTimeoutSecondsKey = "VirusScannerApi:MaxPollingTimeoutSeconds";
    
    // Default values for scanning
    private const int DefaultPollingIntervalSeconds = 5;
    private const int DefaultMaxPollingTimeoutSeconds = 300; // 5 minutes

    /// <inheritdoc/>
    public async Task<VirusScanResult> ScanFileByUrlAsync(
        string fileUrl,
        string fileName,
        CancellationToken cancellationToken)
    {
        try
        {
            var baseUrl = configuration[VirusScannerApiBaseUrlKey];
            
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

            logger.LogInformation("Submitting file for async scan: {FileName} using API: {BaseUrl}", 
                fileName, baseUrl);

            // Get scanner version
            var scannerVersion = await GetScannerVersionAsync(cancellationToken);

            // Encode the file URL to base64
            var fileUrlBytes = Encoding.UTF8.GetBytes(fileUrl);
            var base64EncodedUrl = Convert.ToBase64String(fileUrlBytes);

            // Submit the file URL for async scanning
            var payload = new ScanUrlRequest
            {
                Url = base64EncodedUrl,
                IsBase64 = true
            };

            var asyncSubmitResponse = await clamAvApiClient.ScanAsyncUrlAsync(payload, cancellationToken);

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
            var scanStatusResponse = await PollScanStatusAsync(asyncSubmitResponse.JobId, cancellationToken);

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
    private async Task<string> GetScannerVersionAsync(CancellationToken cancellationToken)
    {
        try
        {
            var versionResponse = await clamAvApiClient.GetVersionAsync(cancellationToken);

            return versionResponse?.ClamAvVersion ?? "Unknown";
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
    private async Task<AsyncScanStatusResponse?> PollScanStatusAsync(string jobId, CancellationToken cancellationToken)
    {
        var pollingInterval = TimeSpan.FromSeconds(
            configuration.GetValue<int?>(VirusScannerApiPollingIntervalSecondsKey) ?? DefaultPollingIntervalSeconds);
        
        var maxTimeout = TimeSpan.FromSeconds(
            configuration.GetValue<int?>(VirusScannerApiMaxPollingTimeoutSecondsKey) ?? DefaultMaxPollingTimeoutSeconds);
        
        
        logger.LogInformation(
            "Starting to poll scan status (interval: {Interval}s, timeout: {Timeout}s)",
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
                
                var statusResponse = await clamAvApiClient.GetScanStatusAsync(jobId, cancellationToken);

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

                    return new AsyncScanStatusResponse
                    {
                        Status = statusResponse.Status,
                        Engine = statusResponse.Engine,
                        Malware = statusResponse.Malware,
                        FileName = statusResponse.FileName,
                    };
                }
                
                // Wait before next poll (not a terminal state, still queued/scanning)
                await Task.Delay(pollingInterval, cancellationToken);
            }
            catch (HttpRequestException ex)
            {
                logger.LogError(ex, "HTTP error polling status JobId: {jobId}", jobId);
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
    /// ClamAV API returns: "clean", "infected", "error", "queued", "downloading", "scanning"
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
}


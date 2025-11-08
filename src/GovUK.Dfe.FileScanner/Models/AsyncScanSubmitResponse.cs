using System.Text.Json.Serialization;

namespace GovUK.Dfe.FileScanner.Models;

/// <summary>
/// Response from the virus scanner API when submitting a file for async scanning.
/// </summary>
public sealed class AsyncScanSubmitResponse
{
    [JsonPropertyName("jobId")]
    public string? JobId { get; init; }
    
    [JsonPropertyName("status")]
    public string? Status { get; init; }
    
    [JsonPropertyName("statusUrl")]
    public string? StatusUrl { get; init; }
}


using System.Text.Json.Serialization;

namespace GovUK.Dfe.FileScanner.Models;

/// <summary>
/// Response from the virus scanner API when polling for scan status.
/// </summary>
public sealed class AsyncScanStatusResponse
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


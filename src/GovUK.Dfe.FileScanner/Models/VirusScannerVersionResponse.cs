using System.Text.Json.Serialization;

namespace GovUK.Dfe.FileScanner.Models;

/// <summary>
/// Response from the virus scanner API version endpoint.
/// </summary>
public sealed class VirusScannerVersionResponse
{
    [JsonPropertyName("clamavVersion")]
    public string? ClamavVersion { get; init; }
}


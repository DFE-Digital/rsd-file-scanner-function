using GovUK.Dfe.CoreLibs.Messaging.Contracts.Messages.Enums;

namespace GovUK.Dfe.FileScanner.Models;

/// <summary>
/// Represents the result of a virus scan operation.
/// </summary>
public sealed class VirusScanResult
{
    public required VirusScanOutcome Outcome { get; init; }
    public string? MalwareName { get; init; }
    public required string ScannerVersion { get; init; }
    public string? Message { get; init; }
}


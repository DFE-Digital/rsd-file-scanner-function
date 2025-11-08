using GovUK.Dfe.FileScanner.Models;

namespace GovUK.Dfe.FileScanner.Services;

/// <summary>
/// Service interface for virus scanning operations.
/// </summary>
public interface IVirusScannerService
{
    /// <summary>
    /// Scans a file by URL using the virus scanner API with async scanning and polling.
    /// </summary>
    /// <param name="fileUrl">The URL of the file to scan</param>
    /// <param name="fileName">The name of the file</param>
    /// <param name="cancellationToken">Cancellation token</param>
    /// <returns>The virus scan result</returns>
    Task<VirusScanResult> ScanFileByUrlAsync(
        string fileUrl,
        string fileName,
        CancellationToken cancellationToken);
}


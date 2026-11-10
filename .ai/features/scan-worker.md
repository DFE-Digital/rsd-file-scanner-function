# Feature: Scan worker

`FileScanner.cs` + `VirusScannerService.cs` + `ScanResultRouting.cs`.

Poll ClamAV until `clean`/`infected`/`error` (`VirusScannerApi:PollingIntervalSeconds`, default 5; `VirusScannerApi:MaxPollingTimeoutSeconds`, default 300). Publish result with inbound routing properties. Manual message settlement.

A `404` from `GET /scan/async/{jobId}` (`ClamAvApiException.StatusCode == 404`) is treated as "not visible yet" and polling continues until the timeout (**Verified**). It used to end the scan at once with an `Error` outcome, which is what happened whenever ClamAV ran more than one replica with its in-memory job store and the poll reached a replica that did not create the job. Other HTTP errors still end polling immediately.

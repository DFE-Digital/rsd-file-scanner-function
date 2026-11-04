# Feature: Scan worker

`FileScanner.cs` + `VirusScannerService.cs` + `ScanResultRouting.cs`.

Poll ClamAV until `clean`/`infected`/`error` (default 5s interval, 300s max — confirm keys). Publish result with inbound routing properties. Manual message settlement.

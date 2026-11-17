# Known pitfalls

- 5s delay before cache lookup.
- Debug log `CODE VERSION: 2024-12-10-V4`.
- End-to-end test hook in `FileScanner.cs` (see `AGENTS.md` #7).
- README vs code config keys and subscription name.
- Results are cached by file hash. Changing that (for example to always rescan) is a product decision; see `features/scan-worker.md`.
- Abandon on generic errors → retries; poison after max delivery.
- Missing `ClamAvApiClient` in template → easy local misconfig.
- A ClamAV `404` on status poll used to become an immediate `Error` result. It is now retried until the polling timeout, so a genuinely lost job (ClamAV restart, expired job) shows up as a timeout after `MaxPollingTimeoutSeconds` instead.

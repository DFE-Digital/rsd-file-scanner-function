# Known pitfalls

- 5s delay before cache lookup.
- Debug log `CODE VERSION: 2024-12-10-V4`.
- Fake infected filename.
- README vs code config keys and subscription name.
- Hash cache: identical bytes skip ClamAV (cost vs “must always rescan” policy).
- Abandon on generic errors → retries; poison after max delivery.
- Missing `ClamAvApiClient` in template → easy local misconfig.

# History lessons

The pipeline design is recorded in the FlexForms ADRs in flexforms-api and in flexforms-web `docs/FlexForms-Process-Map.md`.

No written record survives for the scan-result cache design or orphaned-blob cleanup. Durable principles: cache successful outcomes by hash, and don’t conflate blob lifecycle cleanup with the scan cache.

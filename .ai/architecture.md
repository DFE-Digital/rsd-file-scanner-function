# Architecture (file scanner)

`FileScanner.Run` — Service Bus trigger `%TOPIC_NAME%` / `%SUBSCRIPTION_NAME%` (`local.settings.json.template`: topic `file-scanner-requests`, subscription `file-scanner-function-app` — README may say `file-scanner-function`).

Deserialize MassTransit-style `MessageWrapper.message` → `ScanRequestedEvent`. Validate `FileUri` + `FileHash` or dead-letter.

`Program.cs`: `AddDfEMassTransit` publish-only, Redis `ICacheService`, `AddClamAvApiClient`.

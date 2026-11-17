# Architecture (file scanner)

**Verified** against source on 2026-11-17. Platform context: [`ecosystem.md`](ecosystem.md).

## Files (`src/GovUK.Dfe.FileScanner/`, ~1,000 lines)

| File | Role |
|------|------|
| `Program.cs` | `HostBuilder().ConfigureFunctionsWebApplication()`; App Insights worker; `AddDfEMassTransit` publish-only (`ScanResultEvent` → entity `TopicNames.ScanResult`, JSON serializer, no consumers); `AddRedisCaching`; `AddClamAvApiClient<IClamAvApiClient, ClamAvApiClient>` |
| `FileScanner.cs` | The only function. `[ServiceBusTrigger("%TOPIC_NAME%", "%SUBSCRIPTION_NAME%", Connection = "ServiceBus")]` |
| `Services/VirusScannerService.cs` | ClamAV client wrapper: Base64-encodes `FileUri`, `POST /scan/async/url` (`IsBase64 = true`), polls `GET /scan/async/{jobId}`, maps status, reads `/version` |
| `ScanResultRouting.cs` | Copies tenant/template/user routing from the inbound message to the result; re-stamps a cached result for the current requester |
| `Models/` | `MessageWrapper` (MassTransit envelope `message`), ClamAV response models, `VirusScanResult` |

`FileScanner.Run` deserialises `MessageWrapper.message` → `ScanRequestedEvent`. Missing `FileUri` or `FileHash`, or invalid JSON → dead-letter. Then `ScanResultRouting.FromInbound` → `ProcessScanWithCacheAsync` → publish → complete. Cancellation or any other exception → abandon (redelivery until max delivery count, then DLQ).

## Scan with cache

1. Key `file-scan-result:{FileHash}`; `Task.Delay(5000)` first (rationale not recorded, keep unless you find it).
2. Cache hit → `ScanResultRouting.ForRequester(cached, request, routing, correlationId)` so the current tenant/user is notified, not the original requester.
3. Miss → `ScanFileByUrlAsync` (a hard-coded test filename produces an `Infected` result for end-to-end tests; see `FileScanner.cs` and `AGENTS.md`).
4. Exceptions become an `Error` result (still published). Only non-`Error` outcomes are cached (`GetOrAddAsync`, duration key `FileScanner`).

## Routing

Application properties `TenantId`, `TenantName`, `TemplateId`, `UserId`, `serviceName`, and the same values in `Metadata` (`TenantId`, `TenantName`, `templateId`, `userId`). FlexForms API and Web consumers filter in code on these.

## ClamAV status mapping

`clean` → Clean, `infected` → Infected, `error` → Error; `queued`/`downloading`/`scanning` keep polling. Poll every `VirusScannerApi:PollingIntervalSeconds` (5) up to `VirusScannerApi:MaxPollingTimeoutSeconds` (300). A `404` on poll is retried (job not visible yet on another ClamAV replica); other HTTP errors stop polling.

## Configuration

`ServiceBus` (connection), `TOPIC_NAME` (`file-scanner-requests`), `SUBSCRIPTION_NAME` (`file-scanner-function-app`), `ConnectionStrings:Redis` / `Redis` (CoreLibs caching), `ClamAvApiClient:BaseUrl|ClientId|ClientSecret|Authority|Scope|MiClientId`, `VirusScannerApi:PollingIntervalSeconds|MaxPollingTimeoutSeconds`, `CacheSettings`, `MassTransit:*` (template sets `AzureServiceBus:AutoCreateEntities` and `ConfigureEndpoints` to false and `UseWebSockets` true). The template's `RESULTS_TOPIC_NAME`, `VirusScannerApi:BaseUrl`, `AsyncScanUrlEndpoint`, `VersionEndpoint` are not read by the code (results go to `TopicNames.ScanResult`; the URL comes from `ClamAvApiClient:BaseUrl`).

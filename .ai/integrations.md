# Integrations

Inbound: FlexForms `FileUploadedDomainEventHandler` (and any other `ScanRequestedEvent` publisher).

Outbound: ClamAV API client; `IEventPublisher.PublishAsync` `ScanResultEvent` to `TopicNames.ScanResult`.

ClamAV keeps async jobs in Redis only when its `ConnectionStrings:Redis` is set; otherwise status polls must reach the replica that created the job. The worker retries `404` polls until its timeout (see `.ai/features/scan-worker.md`), but that only makes multi-replica ClamAV without Redis less likely to fail, not correct.

FlexForms API **and** Web both consume results.

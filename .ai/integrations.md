# Integrations

Inbound: FlexForms `FileUploadedDomainEventHandler` (and any other `ScanRequestedEvent` publisher).

Outbound: ClamAV API client; `IEventPublisher.PublishAsync` `ScanResultEvent` to `TopicNames.ScanResult`.

FlexForms API **and** Web both consume results.

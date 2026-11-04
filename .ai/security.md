# Security

Inbound trust is the Service Bus connection. Outbound ClamAV uses Entra client credentials / MI (`ClamAvApiClient` section). SAS URLs in messages are **capabilities** — do not log them. Cache-by-hash must not leak tenant identity (routing restamp on hit).

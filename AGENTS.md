# rsd-file-scanner-function — Agent entry point

Azure Functions v4 **.NET 8 isolated** worker. Consumes `ScanRequestedEvent` from `file-scanner-requests`, calls ClamAV API, publishes `ScanResultEvent` to `file-scanner-results`.

Contracts live in **CoreLibs.Messaging.Contracts**, not this repo.

## Constraints

1. Do not upload file bytes to ClamAV — pass `FileUri` Base64 to `/scan/async/url`.
2. Redis cache key `file-scan-result:{FileHash}`. On hit, **re-stamp routing** for the current requester (`ForRequester`) so the wrong tenant is not notified.
3. Copy tenant/template/user headers via `ScanResultRouting.FromInbound`. FlexForms consumers match in code, not SQL filters.
4. `host.json`: `autoCompleteMessages: false`. Complete/abandon/dead-letter explicitly.
5. Config: API URL/auth is `ClamAvApiClient:*`. Polling is `VirusScannerApi:PollingIntervalSeconds` / `MaxPollingTimeoutSeconds`. README keys are partly stale (`RESULTS_TOPIC_NAME`, `BaseUrl`, `PollingTimeoutSeconds`).
6. **No GitHub workflows** except CODEOWNERS. **No Terraform.** Deployment is external/unverified.
7. **No tests.** Hard-coded filename `da279850ec326ffabd3e5b2970b0af4c.jpg` fakes infection — don’t remove without replacing the test strategy.
8. There is a `Task.Delay(5000)` before cache lookup in `FileScanner.cs` — latency on every message; don’t “clean up” without finding out why it was added (rationale not recorded).

## Knowledge map

[`.ai/architecture.md`](.ai/architecture.md) · [`.ai/integrations.md`](.ai/integrations.md) · [`.ai/known-pitfalls.md`](.ai/known-pitfalls.md) · [`.ai/features/scan-worker.md`](.ai/features/scan-worker.md) · [`.ai/history-lessons.md`](.ai/history-lessons.md)

## Knowledge maintenance

Coordinate topic/event changes with CoreLibs + FlexForms API/Web. Trust code over docs, and fix the docs when they disagree.

### Definition of done (mandatory)

This is enforced in CI: the **Knowledge base check** workflow fails a pull request that changes `src/` without touching `README.md`, `AGENTS.md` or `.ai/`, unless the PR has the `no-docs` label (adding the label re-runs it automatically).

A task is **not complete** until you have checked whether it changed anything the knowledge base describes. Before finishing, update every affected doc in the same change, then list them in your final summary or PR description — **or** state “No knowledge impact” with a one-line reason.

| If you changed… | Update |
|-----------------|--------|
| Message handling, settlement, dead-lettering | `.ai/features/scan-worker.md`, `.ai/architecture.md` |
| Cache keys or routing headers | `.ai/features/scan-worker.md`, `.ai/security.md`, and flag flexforms-api/web consumers |
| Config keys or polling | `.ai/development-workflows.md`, `README.md` |
| ClamAV client usage | `.ai/integrations.md` |
| A fix for an incident or footgun | `.ai/known-pitfalls.md` |
| Something that makes an existing statement wrong | Correct or delete it — never leave it stale |

This repository is **public**. Never write secrets, SAS URLs, or descriptions of unfixed security weaknesses into docs.

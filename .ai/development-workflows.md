# Development

Copy `local.settings.json.template`. Needs Service Bus, Redis, ClamAV BaseUrl + identity.

The only workflow is `.github/workflows/knowledge-check.yml` (PR docs gate). No build/test/deploy workflow. `serviceDependencies.json` is App Insights only. IaC location **unverified**.

## Runtime (**Verified**)

- Targets `net10.0` (isolated worker, Functions v4). The Azure Function App's stack must be **.NET 10 isolated** (Linux `DOTNET-ISOLATED|10.0`); a .NET 8 stack will not start this build. Deployment config lives outside this repo, so change it there when deploying.
- CoreLibs packages are on their .NET 10 majors (`Caching` 2.x, `Messaging.*` 1.x). Those majors only retargeted the framework; message contracts are unchanged on the wire.
- `Microsoft.ApplicationInsights.WorkerService` stays on **2.x**. 3.x is OpenTelemetry-based and `Microsoft.Azure.Functions.Worker.ApplicationInsights` still depends on the 2.x SDK. Bump them together only once the Functions package supports 3.x.
- `GovUK.Dfe.ClamAV.Api.Client` is on **1.0.0** (the net10.0 release from rsd-clamav-api, **Verified** in the csproj on 2026-11-17).

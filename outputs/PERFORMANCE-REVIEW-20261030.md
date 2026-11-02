# Performance review

2026-10-30. Code review only: no production code changes, new benchmarks or speedup claims in this increment.

## Priority 1: remove repeated dashboard side effects

MainWindow.UpdateSandboxDashboard calls UpdateImmyBotPage and SaveHistorySnapshot. It is called during polling and from page/display updates. UpdateImmyBotPage regenerates and syntax-highlights three script documents and calls LoadLogoPreview, which reads/decodes the PNG again. SaveHistorySnapshot calls catalog persistence and AnalysisHistoryService.Save, which reads the entire bounded history list and rewrites it. Most calls need only changed live-stage/label updates.

Recommended implementation: separate live presentation from persistence. Refresh script documents only when source script or appearance changes; decode a logo only when its path/content changes; persist history at explicit analysis transitions. Keep final result/catalog acceptance independent from UI visibility. Catalog Remember already deduplicates the same proof object; the history JSON rewrite and script/logo work still recur. Validate final saved results and same-path replacement behavior after any change.

## Priority 2: avoid unchanged-checkpoint parsing

IssTimer_Tick reads install-analysis.checkpoint.json, builds a JsonNode tree, serializes it back into JSON and deserializes InstallAnalysis for live updates. Unchanged checkpoints can repeat this work. Track a conservative change marker for presentation updates and deserialize once per changed snapshot. Final acceptance must still read and validate the committed evidence; a timestamp cache must not become a trust decision.

## Priority 3: remove redundant installer-selection reads

InstallerIdentityService.Inspect hashes the installer. InstallerCatalogService.ApplyExactMatch immediately hashes it again during ApplyBestMatch. Large installers on slower storage or USB can incur repeated reads. Share a verified, stable file snapshot/hash within a single inspection operation. Do not reuse a stale path-only hash: replaced-file and TOCTOU checks must remain intact. Fresh final/catalog/update verification hashes are separate security checks and should not be removed merely for performance.

## Priority 4: move folder enumeration off the UI thread

RefreshTestQueue recursively enumerates and sorts the test folder synchronously and adds items one by one to the observable collection. Large queues, slow disks or nested folders can freeze the page. Enumerate in a cancellable background operation, then apply the queue on the UI dispatcher in a batch while preserving selection and existing run guards.

## Other candidates

InstallerCatalogService.Open repeats schema-existence/migration checks for each database connection. A database-identity-aware initialization strategy could reduce this work, but must preserve import/restore/test database behavior. Profile before prioritizing it over the UI update path.

InstallerIdentityService starts Windows PowerShell for each Authenticode check. Process startup overhead is a profiling candidate; any replacement must preserve actual signature/trust validation, including catalog signatures. Merely reading a signing certificate is not equivalent.

Windows guest boot and vendor installer delays remain external contributors. This review does not establish that these optimizations will shorten Windows Sandbox boot or resolve .NET provisioning/servicing failures.

# BITS completion observations and local file fingerprints

Development increment, 2026-10-29. Base version remains 0.12.9; informational version `0.12.9-bits-completion-20261029`. No public release or full-roadmap completion is asserted.

## Implemented behavior

The private Sandbox trace now combines three independent observations for supported single-file BITS downloads:

1. Event 16403 associates the requested remote URI and local path with an observed active installer-tree client lifetime.
2. Read-only current-user job samples establish Download direction, Transferred state, exactly one file, complete native job byte/file counters, and matching full source/destination. URI matching uses a private digest; exported evidence retains only the requested HTTP(S) origin. Credentials, URI path/query and private matching digests are not exported.
3. Event 4 supplies a matching job owner, file count, byte count and later completion time. Cancellation, observed ownership changes, conflicting mapping/source/path, unsupported multi-file jobs, unknown counts and out-of-order streams withhold attribution. A client may exit before its service job completes; the original mapping lifetime remains explicit.

Each mapping explains why completion is or is not established. Read-only sample/transfer/completion counters describe coverage; missing records do not prove absence. Job polling is limited to 64 current-user jobs per 500-ms interval and 15 minutes. Fast jobs, other-user/service-owned jobs, collector startup and trace loss/limits can prevent attribution. Raw ETLs remain inside discarded guests; no job is completed, cancelled, resumed or modified by the production collector.

After observed completion, the guest optionally fingerprints a local file snapshot under a read lock that denies concurrent writes/deletion while open. Observed unsafe/network/reparse paths, reserved device names, input/output/collector paths and non-payload extensions are excluded. Limits: eight files, 64 MiB each, 128 MiB total, and a three-second budget checked between reads. A length mismatch, missing/deleted/locked file or exceeded budget retains an unavailable explanation and no digest. A same-size replacement yields the digest of the **current local snapshot**, with content identity explicitly unverified.

This is service-reported completion plus later local measurement. There is no expected server/publisher digest for arbitrary installer downloads, so these records do **not** establish network-to-file content integrity, unchanged bytes since completion, final redirect origin, publisher trust or an Internet requirement. They do not promote catalog trust or bypass lifecycle validation.

The readable report, payload graph, `payload-file-activity.json` and new `bits-download-evidence.json` retain these separate facts. Completed temporary payloads remain in the graph even when deleted before fingerprinting. Diagnostic exports include the new artifact. The existing read-only AI allowlist covers the parent trace evidence; no live AI or authenticated ImmyBot calls are used.

## Verification

- Build/publish: zero warnings/errors.
- **447 .NET/WPF checks** pass, including 35 new completion/fingerprint/graph/export cases. Covered failures include upload direction, missing samples/signals, queued/failed/partial states, mismatched owner/source/path/bytes, cancellation, ownership change, event order, unavailable locks, deletion, changed length, same-size replacement and size budgets.
- **93 Windows PowerShell 5.1 checks** pass: 45 evidence, 19 file probes, 8 DLL observations, 8 response-script contracts and 13 service cases. Total automated suite: **540**.
- All 11 discovery families and the guest trace worker parse; the reducer/fingerprinter compiles with the guest framework compiler.
- A fresh real Sandbox fixture passed six inert loopback HTTP cases: completed direct and redirected downloads retain correct local hashes; cancelled, unacknowledged and HTTP-failed jobs receive no completion record; a completed transfer whose local file changed length retains completion evidence but receives no fingerprint. The redirect traversed a second local port while exported evidence retained the original requested origin. No payload was executed.
- The live fixture independently compared event timing with explicit client acknowledgment. Event 4 occurred after acknowledgment; an unacknowledged Transferred job emitted no such completion signal.
- The existing real two-process kernel file-writer fixture passed with the new worker, confirming that completed writes still bind to distinct observed process lifetimes.
- A fresh actual CCleaner Test Mode run passed initial install/removal, clean reinstall, final removal/absence, durable detection/attempt/graph history, baseline reload and diagnostic export. Its optional trace retained 14 file-writer observations before reaching the parse time limit; no BITS completion was observed in that run. This remains partial telemetry, not proof of no downloads. Original USB bytes were unchanged and Sandbox teardown was confirmed empty. This is one current-source regression, not a new full USB campaign.
- Dependency audit reports no known vulnerable packages from the configured source.
- Initial live attempts found that the PowerShell module's per-file `IsTransferComplete` remained false even with Transferred state, complete job counters and complete file bytes. Production uses native **job** counters for the supported one-file case. The mismatch and unsuccessful attempts are retained, followed by the passing fresh run. An initial fixture cleanup/JSON-array handling issue was also corrected.

Primary references: [BITS job states](https://learn.microsoft.com/en-us/windows/win32/api/bits/ne-bits-bg_job_state), [Complete semantics and integrity limits](https://learn.microsoft.com/en-us/windows/win32/api/bits/nf-bits-ibackgroundcopyjob-complete), [native job progress](https://learn.microsoft.com/en-us/windows/win32/api/bits/ns-bits-bg_job_progress), and [read-only Get-BitsTransfer scope](https://learn.microsoft.com/en-us/powershell/module/bitstransfer/get-bitstransfer?view=windowsserver2025-ps). Event fields were inspected from the installed Microsoft-Windows-Bits-Client manifest and exercised in the guest.

## Evidence and remaining work

Automated run: `Bits-Completion-Test-Location.txt` and `Bits-Completion-Runtime.txt`. Live BITS evidence: `Bits-Completion-Live-Location.txt`, `Bits-Completion-Live.txt`, sanitized native completion metadata and fixture-stage timestamps. File-writer regression: `Bits-Completion-Kernel-Live.txt` and its location pointer. Current-source Test Mode acceptance: `Bits-Completion-Runner-Live.txt`, `Bits-Completion-Runner-Location.txt`, and USB before/after hash records. Earlier USB campaign records remain tied to their earlier snapshots.

Roadmap items 7 and 13 remain partial for other download mechanisms, multi-file/other-user jobs, complete trace coverage, redirected origin and content-integrity binding. Broader vendor prerequisites, actual vendor response-file lifecycles, further positive retest interactions, public signing and unresolved vendor failures remain open.

Portable: `InstallerAnalyzer-0.12.9-Bits-Completion-Development-20261029.zip`. Source: `InstallerAnalyzer-Bits-Completion-Source-20261029.zip`. Digests: `SHA256SUMS-BITS-COMPLETION-20261029.txt`. Each archive entry is re-read against its embedded manifest; the candidate's BUILD-INFO records production-source/native-SQLite identities. Host certificate stores/security settings remain unchanged.

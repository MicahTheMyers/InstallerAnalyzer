# Installer Analyzer roadmap progress

Current version: **0.12.10** (2026-11-01). **565 .NET/WPF and 182 PowerShell checks passed**; all 11 generated source assemblies parse. The guest-only .NET 3.5 fix passed in fresh Sandbox sessions with automatic Microsoft source retrieval, real CLR execution and a complete production-engine MSI install/remove/reinstall/remove test; a separate VM is no longer required for this tested case. Latest source: outputs/InstallerAnalyzer-0.12.10-Sandbox-NetFx3-Fix-Source-20261101.zip. See outputs/NETFX3-SANDBOX-INVESTIGATION.md for scope and evidence. Items 4, 7 and 13 remain partial; InstallShield recording and public signed upgrade acceptance remain open. Historical acceptance notes follow.


Current working-copy version: **0.12.10**, updated 2026-10-30. This unsigned source snapshot consolidates the recent assistant, Sandbox, UI, security and performance work. The full roadmap remains open; no GitHub release has been published. Earlier version references below describe historical snapshots.

## InstallShield recording source increment

The separate legacy recorder now uses the shared schema-3 lifecycle engine, watchdog, timeouts, checkpoints, identity/absence checks and strict response replay logs. **559 automated checks pass** (451 .NET/WPF and 108 PowerShell). Live recording remains unaccepted: Computer Use returned a black Sandbox display with no guest controls; see outputs/INSTALLSHIELD-RECORDER.md. This source increment is not yet packaged; the latest packaged development candidate remains the BITS completion snapshot.

## Latest BITS completion increment

Additional response-file acceptance on 2026-10-29: official RSPile 3.033 vendor install/uninstall responses passed install → remove → reinstall → remove in a fresh Sandbox without a license key or activation command. All four process/log results were zero; USB hashes and teardown were checked. This is vendor-reference replay, not validation of the Analyzer's separate recording path. See `outputs/INSTALLSHIELD-VENDOR-REPLAY.md`; the production build and automated-check count below are unchanged.

Supported single-file current-user BITS downloads now join scoped source/local mapping, read-only native job progress and completion-event owner/count/bytes/timing. A later locked file fingerprint is measured separately. Unknown/failed/cancelled/conflicting cases stay unverified; final redirects and network-to-file content integrity are not claimed. 540 automated checks pass (447 .NET/WPF, 93 PowerShell), all 11 source families parse, and a real six-case loopback fixture passes direct/redirect completion, refusal cases and changed local length. See `outputs/BITS-COMPLETED-DOWNLOADS.md` for acceptance and limits. Candidate: `outputs/Bits-Completion-Candidate/InstallerAnalyzer.exe`, informational version `0.12.9-bits-completion-20261029`. Items 4, 7 and 13 remain partial.

## Earlier prerequisite observations increment

The next prerequisite step adds exact declared-service availability checks in Sandbox and matching-package terminal MSI property observations with explicit phase boundaries. Raw property values are not retained in the new normalized evidence, and service presence/absence never alone establishes a requirement. 505 automated checks pass (412 .NET/WPF and 93 PowerShell); a separate real read-only service fixture and a fresh complete WinDirStat lifecycle/property/artifact check pass. All 11 generated families parse. Eight set MSI properties were observed in the matching terminal block; unreported properties remained unknown. See `outputs/PREREQUISITE-OBSERVATIONS.md` for current acceptance and optional trace limits. Candidate: `outputs/Prerequisite-Observations-Candidate/InstallerAnalyzer.exe`, informational version `0.12.9-prerequisite-observations-20261029`.

Roadmap items 4, 7 and 13 remain partial. Completed-download verification is the next separate work stream.

## Earlier conditions, source-mapping and interaction increment

All three requested work streams have started. The source now includes conservative MSI condition evaluation, BITS requested-source/local-file mappings tied to active client lifetimes, stale/replaced-file retest guards, and response-file script/package coverage. The candidate is `outputs/Roadmap-Conditions-Candidate/InstallerAnalyzer.exe`, informational version `0.12.9-roadmap-conditions-20261029`.

469 automated checks pass (389 .NET/WPF and 80 PowerShell), plus 44 independent native MSI condition comparisons and a real inert loopback BITS transfer in fresh disposable Sandboxes. All 11 generated script families parse. Unknown properties, MSI sequencing, transfer completion/redirect/content origin, broader service prerequisites and a real vendor response-file lifecycle remain explicit limits. Items 4, 7 and 13 remain partial. See `outputs/ROADMAP-CONDITIONS-AND-INTERACTIONS.md` for exact scope and evidence.

## Earlier DLL-prerequisite and cancellation increment

Source inspection now retains bounded direct/delay-load PE import declarations. Before-install Sandbox observations record literal DLL presence/version in staged and architecture-specific Windows directories; API sets, managed AnyCPU ambiguity, unresolved loader paths and access failures remain unknown. Fresh Logitech evidence names three absent Visual C++ DLLs in both checked locations, while retaining the original loader-error boundary.

392 automated checks pass (320 .NET/WPF, 45 evidence PowerShell, 19 file probes, 8 DLL probes). Real Test Mode cancellation passed at Sandbox startup and after installer launch with typed stopped/untested outcomes, retained diagnostics, no catalog/baseline promotion and confirmed teardown. A real signed-but-untrusted PE was refused by production publisher verification before staging/transport/launch. The positive synthetic signed-updater test now passes after explicit guest-only trust approval; no host trust changes or public signing were performed.

The new development candidate is outputs/Dll-Prerequisite-Candidate/InstallerAnalyzer.exe, informational version 0.12.9-dll-prerequisites-20261029. Evidence: outputs/DLL-PREREQUISITES-AND-CANCELLATION.md. Roadmap items 4, 7 and 13 remain partial, and the wider signing/interaction acceptance is unfinished.
## Earlier payload writer attribution increment

The source now includes a bounded optional kernel file trace inside Sandbox. Completed writes are correlated through file opens, file-object/IRP identity, successful operation completion and issuing-thread/process lifetimes. PID/thread reuse, failed writes and unsupported paths do not acquire attribution. Trace-only temporary payloads survive in normalized reports even if deleted before the directory scan. Network observations now retain process birth and observation time; network-active writers remain candidates, never proof of a successful download or an Internet requirement.

Current verification: 309 .NET/WPF checks, 45 existing PowerShell checks and 19 prerequisite file-probe checks pass (373 total), plus all 11 generated script families parse and a real two-process Sandbox trace fixture passes. The 15-source USB campaign and four final-source retests are complete. The reviewed result is 8 passes, 4 without a validated silent strategy, 1 interactive-uninstall block, 1 prerequisite block and 1 inconclusive timeout; these records are separate from automated fixture counts. The first campaign exposed a multi-process JSON handling bug after a passing CCleaner lifecycle; that attempt is preserved and the corrected campaign restarts from a new root.

The latest development candidate is outputs/Payload-Attribution-Candidate/InstallerAnalyzer.exe, informational version 0.12.9-payload-attribution-20261028. It includes the prerequisite and payload increments. It is unsigned development output, not a new official release. Original items 4, 7 and 13 remain partial where condition evaluation or actual download origin cannot be proved.
## Earlier prerequisite file-search increment

MSI metadata now retains bounded AppSearch/DrLocator/Signature declarations. Sandbox collects read-only, exact local file/directory observations before installation, including file size and version metadata. Recursive, ambiguous, unresolved, network and reparse paths remain unknown. Unsupported MSI version/date/language criteria are not guessed. File absence or criteria mismatch never alone establishes a missing prerequisite. Evidence is included in Intelligence and allow-listed diagnostic artifacts.

The increment passed 277 .NET/WPF checks, 45 existing PowerShell checks and 19 focused file-probe checks; all 11 generated script families parse. Broader vendor/service discovery, complex MSI condition evaluation and opaque download attribution remain open. The earlier packaged updater candidate does not include this source increment; no new release is asserted.

Open-source signing research and repository readiness gaps are documented in `InstallerAnalyzer/docs/SIGNING-READINESS.md`. SignPath is the preparation target, subject to acceptance. No license was selected, signing application submitted or remote repository changed.
## Earlier verification: updater fixtures pass after test-machine configuration

The updater now requires a SHA-256 digest, an approved HTTPS repository/download path, the current application's valid signing certificate, and matching signed product/version metadata. It locks and rechecks staged files before a single installer launch, rejects unsafe redirects and incomplete/oversized downloads, and no longer labels unchecked downloads verified. Unsigned development builds can check releases but cannot automatically install them. Exact certificate pinning requires a separately trusted transition when certificates rotate.

This source compiles with zero warnings/errors and retains clear dependency audits. After the user disabled Smart App Control on the test machine, the normal verification entry point passed **271 .NET/WPF checks**, including **54 updater security checks**. The matching Windows PowerShell fixtures passed **45 checks**. The earlier blocked test-DLL launch remains recorded as historical evidence; no alternate execution route was used and the assistant did not change security settings. See `outputs/UPDATER-SECURITY-FIX.md`.

The latest development candidate is `outputs/Updater-Security-Fix-Candidate/InstallerAnalyzer.exe` (`0.12.9-updater-security-fix-20261028`). Defender reported no threats in that folder. Its code/project/assets match the updater-security snapshot, before the subsequent prerequisite file-search increment. Actual signed update-installer handoff remains unverified. All 54 UI matrix renders were generated; representative small-window Analyze, Test Mode and Catalog renders were inspected, not every image or interaction.

A fresh post-unblock WinDirStat Sandbox lifecycle also passed, including initial install/removal, clean reinstall, final uninstall/absence, measured MSI/registry/executable detection, timestamps and isolated catalog history. The USB source hash was preserved and Sandbox teardown was confirmed. This is one smoke test, not the full USB campaign. See `outputs/POST-UNBLOCK-VERIFICATION.md`.

## Earlier executed verification: SQLite security fix

The current source replaces the vulnerable native SQLite 2.1.6 dependency with SQLite **3.53.4** through the maintained SQLitePCLRaw bundle **3.0.5**. Application and verification transitive dependency audits now report no known vulnerabilities. The published native DLL hash matches the patched package, and the old native package is absent from the published dependency graph.

The normal verification entry point ran successfully: **217 .NET/WPF checks and 45 Windows PowerShell checks passed**, including the loaded native SQLite security baseline, catalog/history/import/backup/restore, new roadmap fixtures and six-theme/three-size UI layout assertions. No security settings were changed. Smart App Control remains enabled; its earlier test-build block did not recur. This does not establish why the earlier build was rejected or guarantee future unsigned builds will be accepted.

The current development candidate is `outputs/SQLite-Security-Fix-Candidate/InstallerAnalyzer.exe` with informational version `0.12.9-sqlite-security-fix-20261028`. Defender reported no threats in that candidate folder. A fresh live installer/USB campaign has not been rerun for this patch. The updater-verification and other hardening findings remain separate follow-up work. See `outputs/SQLITE-SECURITY-FIX.md` for evidence.

## Historical verification boundary before the security fix

The last successfully executed roadmap snapshot passed **97 .NET/WPF checks and 28 Windows PowerShell checks**, plus fresh WinDirStat and CCleaner Sandbox lifecycles and an actual Test Mode runner lifecycle after the evidence-completion race fix.

Subsequent MSI metadata/UpgradeCode/registry-probe additions, refined payload correlation, and the full-roadmap changes below compile with zero warnings/errors, but **their new runtime checks have not run**. Windows Application Control blocked loading the new unsigned InstallerAnalyzer.dll before the harness entered its tests (0x800711C7; Code Integrity events 3033/3077; enterprise policy {0283ac0f-fff1-49ae-ada1-8a933130cad6}). The block is recorded in `outputs/Roadmap-MSI-Application-Control.json`. No signing/security policy was changed, and no alternate execution path was used to bypass it.

The earlier 125 checks must not be presented as validation of those later additions or of the entire latest packaged executable. Runtime verification of the latest package requires the normal approved signing/allow-list process.

## Full-roadmap implementation pass

The item-by-item implementation and acceptance ledger is in [ROADMAP-ACCEPTANCE.md](ROADMAP-ACCEPTANCE.md). Source implementation, static verification and executed lifecycle proof are separate states. The roadmap is not declared complete.

- Historical pre-history-service Test Mode summaries now migrate asynchronously into persistent run history. Migration preserves the originals and baseline, deduplicates copied summaries, labels imported provenance, and uses only recorded matching hashes. It never hashes today's same-named installer to invent an older identity.
- Native read-only Windows Installer product-state detection supports MSI packages without an Add/Remove Programs entry. Unknown, advertised or other-user baseline/removal states cannot become invented absence. No Win32_Product enumeration or repair is used.
- Read-only MSI component registry keypaths provide application-specific value-presence detection with explicit hive and 32/64-bit view. Unresolved MSI formatting stays unresolved; raw registry values are not collected.
- Executable path/version, exact service plus executable, and measured directory rules supplement the stronger identity methods. A machine-wide service delta alone cannot become product detection evidence. Access/query failures remain unknown rather than absent.
- Before/after runtime observations cover .NET Framework, registered Desktop Runtime, Visual C++ v14, JavaSoft registrations and Evergreen WebView2. A bounded read-only DISM feature query observes NetFx3. Runtime availability is separate from an established installer requirement; no prerequisite is installed automatically.
- Bounded static/button label reads from tracked, birth-time-checked installer windows improve prerequisite, authentication, reboot and optional-offer evidence. Edit/password/combo/rich-edit controls are excluded. Cross-process text reads use a timeout; inaccessible/custom controls remain unobserved. API details: [GetWindowText](https://learn.microsoft.com/en-us/windows/win32/api/winuser/nf-winuser-getwindowtexta), [SendMessageTimeout](https://learn.microsoft.com/en-us/windows/win32/api/winuser/nf-winuser-sendmessagetimeoutw).
- Bundle assessments distinguish the primary application, runtime candidates, declared dependency candidates, explicit optional offers, the existing McAfee protection policy and unknown secondary products. A common publisher does not prove a dependency.
- Reboot evidence is observed after initial installation and removal. Changed pending-file-operation state is detected without saving its private paths; unchanged preexisting state is excluded. Negated runtime/reboot messages do not establish requirements.
- Payload enumeration now has time, item and depth limits, skips reparse links, and records incomplete coverage. Reports distinguish response files, configuration files, archives and deployment candidates without collecting their contents.
- The script toolbar wraps at smaller widths. A pending UI fixture matrix covers Analyze, Test Mode and Catalog across six themes and three sizes. Fixtures isolate settings, catalog and Test Mode storage.
- New normalized runtime, UI-label and bundle artifacts are included in the diagnostic/AI allowlists. AI remains read-only, disabled by default and Test Mode gated.

The latest source passes Windows PowerShell 5.1 parsing and helper-wiring checks for all 11 installer families. The embedded window-probe C# also compiled independently without being executed. After the SQLite security patch, the normal .NET/WPF harness and PowerShell fixtures executed successfully as recorded above. Static parsing and mocked fixtures do not replace fresh live installer lifecycle tests.

## Existing roadmap foundations

- A dedicated searchable Catalog page with strategy details, validation history, failure counts, retest, confirmed removal, import/export, consistent SQLite backup, and restore/merge.
- Per-proof catalog history, including Analyzer version, source, arguments, lifecycle results, detection evidence, elapsed time when available, and confidence. Replaying an older proof after a newer one no longer increments the validation count.
- Imported records remain untrusted candidates. Import/restore preserves existing local validations; it never marks imported installer data locally validated. Restore is a merge, not replacement of the live database.
- Related-version candidates require a valid Authenticode signature, matching certificate, installer family, architecture and product identity. The newest, runtime-unverified addition supports matching nonempty MSI UpgradeCodes even when display names differ, and rejects conflicting UpgradeCodes despite matching display names. A candidate is not a validated deployment. Legacy catalog rows without signing metadata cannot participate until revalidated.
- Installer SHA-256 and Authenticode status in the static intelligence report.
- Newest, runtime-unverified MSI metadata reader: opens the MSI database read-only to inspect ProductName, Manufacturer, version, ProductCode, UpgradeCode, platform, LaunchCondition and AppSearch/RegLocator declarations. It does not open an installation session or execute MSI actions. API reference: [Microsoft MsiOpenDatabase](https://learn.microsoft.com/en-us/windows/win32/api/msiquery/nf-msiquery-msiopendatabasew).
- Newest, runtime-unverified Sandbox MSI registry probes: honor 32/64-bit RegLocator views, collect presence rather than raw values, and retain unknown states for formatted paths, unsupported roots and file/directory signatures. Launch-condition declarations, registry observations and actual prerequisite failures remain distinct; complex MSI conditions are not guessed.
- Measured detection rules for MSI ProductCode, MSIX package identity, uninstall registry keys, registry/version, and observed Windows services. Only false/true/false lifecycle evidence earns a validated detection label. An unmeasured filesystem baseline remains unknown. The Analyze detection output can use the best independently tested rule.
- Prerequisite evidence from existing window titles, installer-tree process commands, and bounded MSI log excerpts. Recognizes .NET Framework, Desktop Runtime, Visual C++, WebView2, Java and DirectX signals. A generic missing-DLL exit is not misrepresented as a particular missing runtime. Nothing automatically provisions prerequisites.
- Reboot exit-code and newly appearing pending-reboot evidence. Post-reboot validation is explicitly not claimed.
- Installer-scoped process and established TCP-connection observations, with PID-birth checks and bounded collection. Remote addresses are omitted. A connection is not labeled a download or proof that Internet access is required.
- Service/driver/scheduled-task installation and removal observations, preserving unknown states when a query fails.
- Classified payload observations and a persisted relationship graph that keeps original deployment source, deployment mechanism, application identity and uninstaller distinct. An extracted child is not substituted as the deployment source.
- Newest, runtime-unverified payload refinement: recognizes an exact MSI path in a system msiexec installation command and records output-file references in installer child download commands. A command-text reference is explicitly not proof that a download ran or succeeded.
- Deterministic local explanations, a readable Intelligence tab, and separate normalized summary, strategy, prerequisite, detection, component, network and graph artifacts.
- Selected/failed/full diagnostic bundle export with allow-listed files, bounded sizes, best-effort text redaction, and no installer binaries. Screenshots are opt-in and are not redacted.
- An execution service separate from WPF for sequential, cancellation-aware queues. No recurring/background schedule was created.
- Existing read-only/off-by-default AI Assist receives normalized diagnostic fields. No write-capable AI behavior or public community service was added.

## Evidence and checks

Saved verification logs and live results are in `outputs/` and `verification-results/`.

- .NET/WPF fixture tests cover catalog transactions/history, replay prevention, signed inheritance gates, import trust, backup/restore merging, diagnostic redaction and exclusions, detection scripts, explanations, sequential queues and Catalog controls.
- Windows PowerShell 5.1 parses the generated discovery scripts for all installer families. Mocked execution checks detection states, service/driver/task snapshots, failed-query states, and scoped process/network observation including PID reuse.
- Fresh direct Sandbox lifecycle checks passed for WinDirStat and CCleaner. The tests used isolated catalog databases and left the USB installers unchanged.
- An actual Test Mode run exposed a host-recovery race: the host promoted the final-absence checkpoint before detection-removal evidence was written. Schema 3 adds an explicit evidence-complete checkpoint; older schemas retain their recovery behavior. The initial failing run is retained, not counted as proof of the fix.
- The repeated actual Test Mode run passed after that fix, retaining independently validated detection, strategy attempts, raw diagnostics and relationship evidence. Its baseline survived reload, and diagnostic export succeeded. Sandbox teardown left no running environment.
- Catalog layout PNGs are rendered from the application's own WPF controls with fixture data. They are not evidence of mouse-driven desktop interaction.
- ImmyBot connection/upload/deployment, live AI requests and host installer execution were excluded.

## Remaining work and coverage limits

The following need further implementation or broader execution coverage; enum/model availability does not establish a complete detector:

1. Review the newly generated UI matrix images and run a fresh USB regression campaign. Current fixture/layout assertions pass, but earlier selected-installer live passes do not validate this source's installer lifecycle behavior.
2. Broaden prerequisite/vendor fixtures. MSI condition declarations and registry observations are not a complete MSI condition/AppSearch evaluator; private runtimes, unsupported locators and vendor-specific supporting services may remain unknown.
3. Improve causal attribution of extracted/downloaded payloads to their producing process. Exact observed execution paths and explicit download-output command references are supported, but opaque downloads and timestamp-only files remain uncertain. A TCP connection is not proof of a download or an Internet requirement.
4. Exercise optional/dependency classification against additional installers. Unknown secondary products remain unknown; explicit UI controls may be inaccessible or disappear before observation.
5. Service-only products without a discoverable primary identity or removal mechanism cannot receive a fabricated fully validated recipe. Driver presence is an observation, not proof of driver functionality.
6. More tolerant certificate renewal remains unimplemented. Exact validated certificate matching deliberately falls back to normal discovery rather than weakening trust.

Automatic prerequisite provisioning, a complicated scheduler, public GitHub community synchronization, write-capable AI and reboot continuation in a disposable VM are outside the requested immediate behavior. Community compatibility currently means portable structured candidate data and explicit trust boundaries. Post-reboot/VM execution is a future foundation, not an unfinished requirement to build that VM system now.

## Build and verify

Use .NET SDK 8 on Windows. From this directory:

```powershell
dotnet build InstallerAnalyzer/InstallerAnalyzer.csproj -c Release
dotnet run --project Verification/Verification.csproj -c Release -- verification-results/new-unique-fixture-folder
powershell.exe -NoProfile -NonInteractive -ExecutionPolicy Bypass -File Verification/Test-RoadmapEvidence.ps1 -GeneratedFolder verification-results/new-unique-fixture-folder/roadmap
```

The PowerShell policy argument applies only to that verification process; no system execution-policy setting is changed. The script loads only named evidence helpers with mock inputs; it never executes an installer on the host.

For isolated live checks when no other Sandbox is running:

```powershell
dotnet run --project Verification/Verification.csproj -c Release -- verification-results/new-live-folder --live D:\WinDirStat-x64.msi
dotnet run --project Verification/Verification.csproj -c Release -- verification-results/new-runner-folder --live-runner D:\ccsetup630.exe
```

Use a new output folder for each run. The live runner uses a test-only directory override and isolated catalog; it does not replace the user's catalog or history. Preserve the per-run logs, raw output and generated script when comparing builds.

Final payload/runtime acceptance details are in outputs/PAYLOAD-USB-CAMPAIGN-RESULTS.md. CCleaner passed the actual Test Mode queue with history/baseline/export; Chrome passed again; final trace observations retain explicit coverage limits. Shared-file loading failures were fixed in both the app and harness. The full roadmap remains open at items 4, 7 and 13 and the outstanding wider acceptance/signing work.

Signed updater mechanics verified 2026-10-29: real Authenticode chain/publisher pin, digest/product/version checks, single inert setup launch and real different-trusted-certificate rejection passed inside a fresh disposable Sandbox. Teardown confirmed empty. Host trust and unsigned development binary unchanged. See outputs/SIGNED-UPDATER-SANDBOX-VERIFICATION.md; actual public signed Inno Setup upgrade/provider acceptance remains pending.

Sandbox display follow-up: guest desktop health was confirmed independently; visible clean starts and an application restart still yielded black Computer Use capture. The machine graphics-policy write requires administrator approval. An apply/restore diagnostic is prepared, not applied or proven. See outputs/SANDBOX-DISPLAY-RECOVERY.md. All diagnostic Sandboxes are closed.

Startup increment: confirmed-empty Sandbox cleanup dropped from 10.287s to 0.259s in one local before/after test. Hidden histories load on navigation; automatic updates start after first render. All 451 .NET/WPF checks pass. Windows guest boot/display delay is not measured by that improvement. The user's other machine opens Sandbox after about 15 seconds, so the prior graphics workaround is not currently justified. Details: outputs/STARTUP-PERFORMANCE.md.

Startup-readiness increment: the former 35-second Test Mode startup deadline is replaced with a bounded three-minute analysis-heartbeat wait, phase progress and a small guest bootstrap that retains script errors. Startup exceptions preserve their session diagnostics. 580 checks pass (463 .NET/WPF, 117 PowerShell), plus a real inert Sandbox bootstrap/heartbeat handoff in 11.0s with teardown confirmed. RSPile recording acceptance and the cause on the other machine remain unconfirmed. See outputs/STARTUP-READINESS.md.

Claude provider increment (2026-10-30): Settings > AI Assist now includes Claude (Anthropic), with a separate Windows-protected key and remembered model. The assistant remains read-only, off by default, Test Mode gated and explicit-send only. Release build and 540 .NET/WPF checks passed using mocked HTTP and fixture credentials; no live Claude call was made. Prior 137 PowerShell checks remain applicable; guest scripts are unchanged. Latest source: outputs/InstallerAnalyzer-Claude-Assistant-Source-20261030.zip. See outputs/CLAUDE-READONLY-ASSISTANT.md. Wider roadmap acceptance remains open.


2026-11-01 full-Windows VM follow-up: command-line NetFx3 installation and real CLR 2.0/LINQ runtime PASS on a guest with a clean pre-install component store. DISM exit 0; feature Enabled; no reboot needed. Guest shut down, host NetFx3 remains disabled. This does not validate automatic app provisioning or a dependent vendor lifecycle. See outputs/NETFX3-FULL-VM-ACCEPTANCE.md.


2026-11-01 NetFx3 provisioning increment: bounded guest-only feature setup and runtime verification now precede supported requirements; successful unattended provisioning permits one retry. Fresh Sandbox 12006 is classified with full-VM guidance and no retry; the same production helper passes in a full Windows VM. 562 .NET/WPF and 175 PowerShell checks pass; all 11 source families parse. No dependent vendor lifecycle is claimed. Latest source: outputs/InstallerAnalyzer-0.12.10-NetFx3-Provisioning-Source-20261101.zip. See outputs/NETFX3-PROVISIONING.md.


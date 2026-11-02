# RSPile vendor response-file acceptance

2026-10-29. Production build remains 0.12.9-bits-completion-20261029; this run adds verification scripts and evidence, not a new application release. Existing 540 automated checks belong to the prior application verification; these four live stages are separate.

## Result

A fresh disposable Windows Sandbox completed RSPile 3.033's vendor-supplied response-file sequence with no license key supplied and no activation command invoked by the fixture:

| Stage | Process exit | InstallShield log | Expected product registration |
|---|---:|---:|---|
| Initial install | 0 | ResultCode=0 | Present |
| Initial uninstall | 0 | ResultCode=0 | Absent |
| Reinstall | 0 | ResultCode=0 | Present |
| Final uninstall | 0 | ResultCode=0 | Absent |

The measured identity was `RSPile`, version `3.033`, publisher `Rocscience`. The vendor's documented single-file prefix `/s /a /s` was used with explicit `/f1` response-file and `/f2` log paths; uninstall also used `/uninst`. This is not a claim that the generic `/s /f1` export recipe or the Analyzer's own recorder was exercised.

No reboot was requested by the measured phase exit codes. No titled/control-bearing installer UI was observed after the startup grace period. Untitled runtime-worker windows with no readable controls were retained separately; this is not exhaustive visual proof that no pixels were displayed. The process ran unattended without entering activation information. It does not establish application functionality, licensing entitlement, offline operation, complete filesystem cleanup or absence of licensing-network traffic.

The bundled Visual C++ 2015-2022 x64 prerequisite installed its Minimum and Additional Runtime packages, version 14.38.33130, before RSPile. An initial three-minute attempt timed out during this prerequisite and was retained. Runtime logs then showed the minimum package completing successfully and the additional package still running. A new fresh run with a seven-minute initial phase budget completed the initial install in about 4 minutes 40 seconds; subsequent removal/reinstall/removal completed normally. No Windows security settings were weakened and no separate prerequisite-provisioning workaround was used.

McAfee bundle protection was active, using the production discovery engine's watchdog helpers. The read-only production window probe was also reused. The full discovery script was not executed or treated as a vendor-recording proof. No catalog or persistent baseline trust was created by this fixture.

## Integrity and isolation

Inputs were copied from the USB through a read-only mapping to guest-local storage. All eight original USB input hashes matched their pre-test manifest after the run. The installer SHA-256 remains `836D1500D36E2885F58CEB082616766A92867EFBDA95290B5986266B3B4EF32F`. No installer was executed on the host. Sandbox teardown was confirmed empty.

Evidence pointers: `InstallShield-Vendor-Live-Location.txt`, `InstallShield-Vendor-Live.txt`, and `InstallShield-Vendor-Initial-Timeout.txt`. The successful root contains `vendor-replay.json`, four InstallShield logs, before/installed registration snapshots and runtime log tails. Inputs/provenance: `RSPile-Official-USB-Manifest.json` and `RSPile-Official-Download.md`.

Fixture sources: `Verification/InstallShieldVendorReplayFixture.ps1` and `Verification/Test-InstallShieldVendorReplay.ps1`. The host runner captures its new Sandbox ID for cleanup and does not intentionally stop unrelated sessions. Its final ownership-guard change was syntax-checked after the completed live run; no production code changed.

## Remaining recording acceptance

This clears license-key entry as a blocker for the tested vendor response-file sequence. It does not validate recording new response files with Installer Analyzer, generated deployment scripts, cancellation during recording, or recorder-specific history/export behavior. The old `BuildRecorderScript` route has a separate proof format and execution path from the hardened discovery engine and needs modern lifecycle/monitoring integration before it can earn current acceptance. Do not promote this vendor-reference fixture into a successful Analyzer-recording result.

Vendor reference: [Rocscience silent install/uninstall instructions](https://www.rocscience.com/downloads/general/silent).

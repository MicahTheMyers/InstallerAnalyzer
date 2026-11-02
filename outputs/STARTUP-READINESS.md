# Sandbox startup readiness — 2026-10-29

The user reports that Sandbox reaches its desktop and closes about 5–10 seconds later, followed by a Test Mode startup failure. Inspection found a 35-second deadline measured from viewer launch, which includes guest boot and logon. That deadline can terminate a healthy but slow guest soon after its desktop appears. The exact cause on the user's other machine is not yet established from diagnostics.

## Changes

- Test Mode waits up to three minutes, measured with a monotonic clock, for a nonempty analysis heartbeat. It displays attempt number, elapsed/budget and whether the guest bootstrap has started.
- A small guest bootstrap writes its own marker before invoking the full analysis script. Parse/runtime errors escaping the analysis script are captured in `sandbox-guest-startup-error.txt`.
- The bootstrap marker, host logs and a visible desktop do not count as analysis readiness or lifecycle success. Only the analysis heartbeat completes startup; all lifecycle acceptance gates remain in place.
- Guest-script failures surface immediately. A guest that reached its bootstrap without progressing is diagnosed rather than repeatedly restarted. A launch with no guest bootstrap can retry once after teardown; the former five short attempts are removed.
- The unnecessary four-second delay before the first Test Mode launch is removed. The prior confirmed-empty cleanup optimization is retained.
- Startup exceptions carry their session back to Test Mode, allowing mapped artifacts to be copied into the test's retained diagnostics. Host attempt history, guest marker and guest error are included in diagnostic exports.

## Verification

**580 checks passed:** 463 .NET/WPF plus 117 Windows PowerShell checks (47 evidence, 19 prerequisite files, 13 services, 8 DLL observations, 8 response-script contracts, 13 InstallShield response/log cases and 9 new guest bootstrap cases).

New cases cover a simulated heartbeat arriving at 60 seconds, the three-minute deadline, distinct guest/analysis states, missing/empty heartbeats, host-only artifacts, cancellation, transient file-sharing errors, bounded guest errors, and retained diagnostic exports. Windows PowerShell executed only inert valid, parse-error and runtime-error scripts for bootstrap coverage.

A fresh real Windows Sandbox executed the production bootstrap and an inert heartbeat fixture in **11.0 seconds**, then the owned Sandbox was stopped and the inventory was empty. No installer, activation command, security setting or certificate change was involved. This validates bootstrap/startup handoff only; it does not validate RSPile recording or reproduce the other machine's startup failure.

Evidence: `outputs/Startup-Readiness-Checks.txt`, `outputs/Startup-Bootstrap-Checks.txt`, `outputs/Startup-Readiness-Live.txt`, and locations in `outputs/Startup-Readiness-Test-Location.txt` and `outputs/Startup-Live-Location.txt`.

Next acceptance: build this source on the other machine and retry RSPile in Test Mode / Full Analysis. If it fails, export diagnostics so the new host/guest startup files can identify whether boot/logon, output mapping or script startup failed. The base application version remains 0.12.9; no release or complete roadmap claim is made.

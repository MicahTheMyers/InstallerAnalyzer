# Performance optimizations

2026-10-30. Development source 0.12.9-performance-20261030; no new official release or completed roadmap claim.

## Changes

1. Dashboard presentation no longer persists history on each refresh. History/catalog save calls remain at initial inspection, completed handoff, stopped analysis and timeout/environment-loss finalization. Hidden History pages refresh their list on navigation instead of immediately rereading the file after every save.
2. ImmyBot scripts refresh from the dashboard only when the result/proof/primary-entry objects change, or when explicitly regenerated/navigated. Highlighted documents are reused when script text, text/background colors and document identity are unchanged. Script generation is shared with the script inspector rather than repeated a second time. Logo previews reuse the decoded bitmap while path/size/timestamps match; explicit Replace/Re-extract bypass the preview cache. Same-path changed images use a stream to avoid WPF URI-cache reuse.
3. Initial installer inspection/catalog matching share one inspection hash while a read-only file handle denies writers and replacement. Standalone catalog lookups, retest verification, final catalog acceptance and updater security checks still hash the current file independently. EXE Authenticode and MSI metadata reads were verified under this lock.
4. Queue enumeration/filtering/sorting runs on a worker task. The UI applies one collection replacement while preserving existing item objects and selections. New refreshes cancel/supersede older ones; stale scans cannot replace an active run's queue. Starting tests while a scan is pending is guarded. Regression/catalog retest flows and live verification helpers await queue completion.

A native compatibility check also exposed inherited PowerShell 7 module directories preventing Windows PowerShell 5.1 from loading its signature checker. Only the inspection subprocess now receives the built-in Windows PowerShell module directory and uses the module-qualified Authenticode cmdlet. The caller's environment is unchanged; failure is explicitly unavailable rather than a successful signature.

## Validation and measured scope

Build: zero warnings/errors. 517 .NET/WPF checks passed (19 new focused performance/compatibility checks, including 512-entry async queue responsiveness/selection/stale-result guards, document/theme/logo invalidation, zero history writes across 100 unchanged presentation updates, stable-file write/replacement refusal, fresh stale-identity rejection, real Authenticode and MSI reads). Existing updater and regression-replacement fixtures remain passing. The preceding 137 PowerShell checks remain applicable; guest-script source was not changed or rerun for this increment.

Local inert WPF fixture, 100 refreshes: unchanged dashboard work took 4.7794 ms. An explicit forced-full-refresh comparison, rebuilding documents/reloading the logo/saving history as the old path did, took 751.5636 ms. This is a controlled operation comparison, not a before/after old-binary benchmark, an overall application speedup, or a Windows Sandbox boot measurement. Performance-Measurements.json preserves scope and raw values. No vendor installer or Sandbox lifecycle was executed for this increment.

## Remaining scope

Checkpoint JSON still has a separate opportunity for read/parse optimization; it was not one of the four changes requested in the concise review. Repeated database schema checks and PowerShell process-launch cost remain profiling candidates. Terminal catalog acceptance retains a fresh file hash and can still perform disk work at the end of a run. Windows guest boot/vendor execution time and .NET 3.5 servicing failures are not fixed by these UI optimizations. Full Analyzer-recorded InstallShield lifecycle acceptance remains open.

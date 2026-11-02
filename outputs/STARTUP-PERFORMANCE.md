# Startup optimization — 2026-10-29

The user confirms Sandbox opens on another machine, with roughly 15 seconds of black display before it appears. That result does not justify applying the earlier graphics-policy diagnostic. The graphics workaround remains unproven and unapplied; a black automated capture alone does not establish a broken physical display.

## Measured source changes

When the supported Sandbox CLI confirms no running environment and there are no Sandbox client processes, Installer Analyzer now skips the old teardown delay. Previously even an empty machine executed four 1.5-second cleanup polls, additional CLI launches, and a final 3-second wait. Existing clients, running environments and unavailable/unknown CLI state retain the existing cleanup path. Fresh guest isolation and lifecycle verification are unchanged.

One before/after local measurement with confirmed empty Sandbox inventory:

| Measurement | Before | After |
| --- | ---: | ---: |
| Empty-session cleanup | 10,287 ms | 259 ms |
| Main window constructor | 285 ms | 294 ms |
| Main window first render, including constructor | 452 ms | 450 ms |

The change removes approximately 10 seconds **before** the Sandbox viewer launches. It does not establish a reduction in Windows' own boot/rendering time after the black viewer appears. The WPF measurement did not reproduce a slow main window on this machine. Measurements are individual local runs, not a guarantee for another machine, a cold disk cache, native bundle extraction or antivirus scanning.

Analysis and regression histories now load on their respective page navigation instead of synchronously before the first main-window frame. Test Mode folders are created when used rather than on every startup. The automatic update check runs once after the first rendered frame. Existing history/baseline/retest functionality remains covered by the regression checks.

## Verification

- All 451 .NET/WPF checks pass after the changes. The unchanged PowerShell acceptance remains 108 checks, for 559 previously established combined checks; no new PowerShell acceptance run or live installer lifecycle is claimed for this source-only startup increment.
- The new `--startup-profile` mode refuses existing/unknown Sandbox inventory and existing viewer processes. It records actual empty cleanup and real WPF ContentRendered timings with isolated settings and automatic updates disabled.
- Before and after evidence: `outputs/Startup-Performance-Before.txt` and `outputs/Startup-Performance-After.txt`; detailed JSON under `verification-results/startup-before-20261029` and `verification-results/startup-after-20261029`.
- Full regression log: `outputs/Startup-Regression-Checks.txt`.

The application remains development base version 0.12.9. The full roadmap and Analyzer-created response-file live acceptance remain open. The source snapshot includes the earlier recorder fixes, optional graphics diagnostic helpers and these startup changes; the optional diagnostic is not part of normal building or testing.

Follow-up: a fresh diagnostic Sandbox was given a 45-second minimum wait before capture. The automated capture remained black with no accessible guest controls; this does not override the user's observation on the other machine or establish the physical display state here. No installer was run, and the owned guest and viewer were closed. See outputs/Sandbox-Long-Wait-Result.json. No additional application source changes were needed after that check.

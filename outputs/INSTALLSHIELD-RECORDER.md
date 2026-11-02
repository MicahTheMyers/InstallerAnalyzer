# InstallShield recorder modernization — 2026-10-29

The source now routes Full Analysis response recording through the shared schema-3 lifecycle engine. The previous separate recorder could not satisfy current lifecycle acceptance and did not apply its bundled-software protection parameter.

Recording now uses bounded process monitoring, heartbeats/checkpoints, the McAfee watchdog, primary-identity detection, initial removal/absence verification, a single recorded install replay candidate, monitored final removal, and final evidence collection. Interactive recording phases allow the wizard; replay phases retain UI rejection. Package arguments are preserved as literal data. MSI/registered quiet uninstall paths remain available when an uninstall response is unnecessary.

New response files must contain an InstallShield response header, response-file marker and a positive dialog count within a 1 MiB limit. Silent response replays additionally require a freshly created log with exactly one ResultCode=0, successful process exit, identity detection/removal and the existing lifecycle acceptance gates. Both successful and failed replay logs are retained in diagnostic exports. Recording alone does not establish a passing deployment.

Verification: **559 automated checks passed**: 451 .NET/WPF, 47 generated-script/evidence checks, 19 prerequisite-file checks, 13 service checks, 8 DLL observation checks, 8 generated response-script contracts and 13 new response/log checks. The 11 source families and embedded framework reducer also parse/compile. Process launches in response-script contract checks are mocked; these checks do not replace a live recording.

First live recording attempt: fresh disposable Sandbox, matching installer hash, no vendor response files mapped or copied, McAfee protection active. The production recorder launched RSPile with /r and an explicit output path, and kept writing heartbeats. Computer Use returned a black Sandbox display with no accessible guest controls after activation/reconnection. No wizard inputs were attempted. No setup.iss or uninstall.iss was produced. The attempt was retained as INCONCLUSIVE, the owned Sandbox was stopped, all 8 USB files were verified unchanged, and no Sandbox remained running.

First attempt evidence: `verification-results/iss-record-live-bc066747f04447fea3d78a5d7228c6ef/recording-attempt-status.json` and its Output folder. Subsequent display recovery attempts are recorded separately.

Pending: actual Analyzer-created response recording/replay, generated deployment replay, recording cancellation and further positive retest interactions. Prior vendor-supplied response replay remains a separate successful reference. No new packaged release or completed roadmap claim is made.

Second display recovery attempt: fresh Sandbox with vGPU disabled and explicit connection still returned a black display/no guest controls. Evidence: C:\Users\Server\Documents\Codex\2026-10-28\so-what-all-has-happened-since\verification-results\iss-record-live-ec9a85dfd8f2428793b55399cb189dfd\recording-attempt-status.json. No wizard inputs or response files; owned Sandbox stopped; all 8 USB hashes unchanged; Sandbox list empty.

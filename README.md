# Installer Analyzer for ImmyBot v0.10.9

Installer Analyzer analyzes Windows installers, validates install/uninstall workflows in Windows Sandbox, and generates ImmyBot deployment scripts and upload assets.

## v0.9.4
- Increased application scrollbar width to 12 px.
- Increased scrollbar thumb size for easier mouse targeting.
- Improved thumb contrast for normal, hover, and drag states.
- Retains all v0.9.2 installer analysis, Sandbox, ImmyBot, packaging, logo, and GitHub update functionality.

## Build
Run `BuildInstaller.bat` to build the self-contained application and Windows installer.

## Update test
Publish the generated `Release/InstallerAnalyzer-Setup.exe` as GitHub release tag `v0.9.4`. An installed v0.9.2 should then detect and install the update from About > Check for Updates.


### v0.10.9 Ensoft QSetup deployment intelligence

- Fixes NSIS uninstall candidates whose executable paths contain spaces.
- Separates executable paths from command-line arguments before launching lifecycle commands.
- Labels installer-family uninstall candidates separately from vendor-provided quiet uninstall commands.
- Wraps Sandbox lifecycle errors and stage messages for readability.


### v0.10.5 lifecycle reliability

- Adds detection-backed lifecycle validation, package-specific arguments, NSIS candidate uninstall validation, and Squirrel per-user discovery.
- Exit code 0 alone is no longer treated as a validated silent reinstall.

### v0.9.5 appearance update
Adds Dark, Light, and full Purple themes plus independently selectable Blue, Purple, Teal, and Orange accents.


### v0.10.5 intelligence and workflow update
- Added local analysis history with reopen and clear controls.
- Added detection-method ranking for MSI ProductCode, Windows Installer/uninstall registry, DisplayVersion, and install-location candidates.
- Added a PowerShell Inspector that flags missing scripts, unsafe `$InstallerFolder` assumptions, response-file gaps, user-specific paths, and missing execution/exit handling.
- Added an ImmyBot Deployment Intelligence panel that clearly separates static script checks from Sandbox lifecycle validation.
- Preserved the stable v0.8.2+ Sandbox lifecycle and v0.9.5 theme/updater behavior.


### v0.10.5 Squirrel.Windows support
- Detects Squirrel.Windows installers with high-confidence framework fingerprints.
- Suggests `--silent`, recognizes per-user `%LocalAppData%` deployment, and correctly reports that `.iss` response files are not required.
- History now includes confidence and static-vs-Sandbox validation state.

# Installer Analyzer for ImmyBot v0.9.4

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

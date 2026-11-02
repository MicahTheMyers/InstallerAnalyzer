# Installer Analyzer v0.12.10

Windows installer analysis and unattended deployment validation for ImmyBot.

The application source is in `InstallerAnalyzer/`; the verification project is
in `Verification/`. This layout matches the verified development source package.

## Build on Windows

Install the .NET 8 SDK, then run:

```powershell
dotnet build InstallerAnalyzer/InstallerAnalyzer.csproj -c Release
dotnet run --project Verification/Verification.csproj -c Release -- verification-results/local-checks
```

For a self-contained application, run `BUILD-LATEST.cmd` and then
`Build/InstallerAnalyzer.exe`. Windows Sandbox must be enabled for live installer tests.

## Latest verified changes

- Automatic guest-only .NET Framework 3.5 provisioning on supported requirements.
- Sandbox update-source correction, matching missing .NET resource restoration,
  verified Microsoft feature-source retrieval, and a real CLR runtime check.
- Fresh Windows 11 x64 26100.9711 Sandbox: production-engine MSI install,
  uninstall, reinstall, uninstall, clean baseline and final absence checks passed.
- 565 .NET/WPF and 182 PowerShell checks passed; all 11 generated source assemblies parse.
- Includes Claude read-only assistant support, Sandbox controls/timer, taskbar,
  navigation, theme and performance improvements.

See [application documentation](InstallerAnalyzer/README.md),
[release notes](InstallerAnalyzer/docs/releases/v0.12.10.md),
[Sandbox fix evidence](outputs/NETFX3-SANDBOX-INVESTIGATION.md), and
[roadmap status](ROADMAP-STATUS.md) for scope and remaining work.

This is development source. The verified .NET 3.5 result covers the Windows build
above; it does not establish every vendor installer or complete the separate
InstallShield recording milestone. No Windows feature payloads or private keys
are included.

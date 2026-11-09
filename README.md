# Installer Analyzer v0.13.27

Windows installer analysis and unattended deployment validation for ImmyBot and Datto RMM.

Download the Windows setup or portable executable from [GitHub Releases](https://github.com/MicahTheMyers/InstallerAnalyzer/releases/latest). See the [v0.13.27 release notes](InstallerAnalyzer/docs/releases/v0.13.27.md).

## Build on Windows

Install the .NET 8 SDK and run:

```powershell
dotnet build InstallerAnalyzer/InstallerAnalyzer.csproj -c Release
dotnet run --project Verification/Verification.csproj -c Release -- verification-results/local-checks
```

For a self-contained build, run `InstallerAnalyzer/Build.bat`. Enable Windows Sandbox for live installer tests.

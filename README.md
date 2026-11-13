# Installer Analyzer v0.14.5

Windows installer analysis and unattended deployment validation for ImmyBot and Datto RMM.

Download the Windows setup or portable executable from [GitHub Releases](https://github.com/MicahTheMyers/InstallerAnalyzer/releases/latest). See the [v0.14.4 release notes](InstallerAnalyzer/docs/releases/v0.14.4.md).

## Verify release downloads

New releases built with the attestation workflow include GitHub build provenance for both Windows executables. With GitHub CLI, verify the file you downloaded:

```powershell
gh attestation verify InstallerAnalyzer-Setup.exe --repo MicahTheMyers/InstallerAnalyzer --signer-workflow MicahTheMyers/InstallerAnalyzer/.github/workflows/release.yml
```

For the portable edition, use InstallerAnalyzer-Portable.exe in the same command. Windows Authenticode signing is separate from GitHub build provenance.

## Build on Windows

Install the .NET 8 SDK and run:

```powershell
dotnet build InstallerAnalyzer/InstallerAnalyzer.csproj -c Release
dotnet run --project Verification/Verification.csproj -c Release -- verification-results/local-checks
```

For a self-contained build, run `InstallerAnalyzer/Build.bat`. Enable Windows Sandbox for live installer tests.

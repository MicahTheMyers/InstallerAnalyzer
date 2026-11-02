# Analyze page Sandbox toggle

2026-10-30. Source increment based on 0.12.9.

The toggle called UpdateSandboxControls, which collapsed the Generate setup.iss and Open ISS folder buttons without an InstallShield selection. Initial XAML left them visible, so toggling the mode caused an unexpected layout change. Both buttons now remain visible; unavailable actions remain disabled. Constructor initialization applies the same state before the first render. The response requirement checkbox remains specific to InstallShield.

Changing the mode still selects Sandbox or local recording. This change does not launch any installer or alter Windows Sandbox availability.

485 .NET/WPF checks pass, including four focused visibility/disabled-state checks across off/on transitions. Build: zero warnings/errors. The existing 137 PowerShell checks passed in the preceding increment; their source is unchanged. Full InstallShield live recording acceptance remains open.

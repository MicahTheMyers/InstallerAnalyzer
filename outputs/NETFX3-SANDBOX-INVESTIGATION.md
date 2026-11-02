# .NET 3.5 Sandbox fix — 2026-11-01

The production prerequisite helper now installs and verifies .NET 3.5 inside Windows Sandbox. A separate full Windows VM is no longer required for the tested Windows 11 x64 26100.9711 Sandbox case. Version remains 0.12.10.

## Causes established in fresh guests

1. Sandbox sets UseWUServer=1 with WUServer/WUStatusServer `127.0.0.1:80`. This malformed URL causes 12006 / 0x80072EE6. Correcting only that guest setting moves servicing forward but exposes a second failure.
2. Sandbox omits registered WinSxS .NET resource/performance/configuration component directories. CBS reports MissingFileSystemResource and DISM returns 14098 / 0x80073712. Controlled WCF, Workflow and WPF restoration trials progressively isolated the missing components.
3. The normal Windows Update source path exceeded the bounded servicing timeout. The helper now retrieves the matching Microsoft NetFx3 CAB directly from official feature media on supported x64 builds.

## Implemented behavior

Before an installer with an explicit .NET 3.5 requirement runs, the app stages a bounded set of local Windows .NET component resources as read-only guest input. The guest repairs missing directories only when an exact matching guest manifest already exists. Existing component directories are skipped. Staged files have SHA-256 checks; component identities and file names are constrained. No host Windows feature, component store, update policy or security setting is modified.

The policy correction applies only to the exact malformed Sandbox loopback placeholder when selected. Real WSUS endpoints and valid URLs are preserved. Resource preparation is scoped to that same Sandbox condition.

For x64 builds 26100/26200, the helper downloads only the 71,321,276-byte NetFx3 CAB from pinned official Microsoft feature media through validated HTTP byte ranges. It verifies the full CAB SHA-256 before DISM uses it. It does not download the entire 6.25 GB ISO, run an external executable, or bypass Windows package validation. A locally provided matching NetFx3Source cache remains supported. Downloads need Internet access.

DISM runs once with a bounded ten-minute timeout and no restart. A slower fresh repeat exceeded the initial three-minute limit; the allowance was increased while retaining one attempt, heartbeats and explicit timeout failure. Success requires both feature state Enabled and a compiled CLR 2.0 program using System.Core/LINQ returning the expected result. A clear prerequisite discovered after an attempted install permits only one provisioning attempt and one installer retry. Failures preserve diagnostics and do not demand a full VM by default.

## Verified evidence

- Fresh integrated helper with an explicitly provided CAB: PASS.
- Fresh integrated helper with no CAB supplied: automatic official source retrieval PASS; DISM exit 0; RuntimeVerified=true; Provisioned=true; RequiresFullWindowsVM=false; no reboot.
- 37 matching missing resource directories restored in the guarded integrated guest tests.
- Real CLR output: 2.0.50727.9157; LINQ probe exit 0.
- Automated regression: 565 .NET/WPF checks and 182 PowerShell checks passed. All 11 generated source assemblies parse.
- Production-engine MSI lifecycle PASS: automatic NetFx3 setup, initial install/uninstall, clean baseline, silent reinstall/uninstall and final absence verification. The registry-only MSI fixture has a real .NET 3.5 AppSearch/LaunchCondition. Original fixture hash unchanged; owned Sandbox stopped; zero environments remain. Evidence: NetFx3-Sandbox-Acceptance.json.

Evidence pointers in the original workspace: NetFx3-Auto-Source-Location.txt, NetFx3-Integrated-Cab-Location.txt, NetFx3-Engine-Lifecycle-Location.txt. No Microsoft component payloads, CAB/ISO images, VM disks or credentials are included in the source package.

## Limits

Live runtime acceptance covers this machine's Windows 11 x64 26100.9711 Sandbox. Build 26200 source selection is implemented but not live-tested here; other builds use their normal servicing/source path. Builds 28000+ still report a separate standalone-runtime requirement if not already installed. A host without matching readable component resources may need additional servicing investigation. These results do not establish every third-party installer's lifecycle or complete the separate InstallShield recording roadmap milestone.

Earlier ScanHealth was interrupted during investigation; it is not a clean-baseline health result. Earlier full-VM-only guidance in NETFX3-PROVISIONING.md is superseded by this report.

Primary references used in diagnosis:
- https://learn.microsoft.com/en-us/windows/win32/winhttp/error-messages
- https://learn.microsoft.com/id-ID/troubleshoot/windows-client/deployment/error-80072ee6-downlaod-wsus-update
- https://learn.microsoft.com/en-us/windows/security/application-security/application-isolation/windows-sandbox/windows-sandbox-architecture
- https://learn.microsoft.com/en-us/azure/virtual-desktop/windows-11-language-packs
- https://learn.microsoft.com/en-us/dotnet/framework/install/dotnet-35-windows-11-faq

# Application Control and InstallShield recording

Updated 2026-10-29. Development source remains based on 0.12.9; no new release or completed roadmap is claimed.

## Accepted source changes

Analyzer captures bounded, run-scoped Code Integrity event 3077 evidence correlated to the staged installer process. Confirmed enforced blocks are classified ApplicationControlBlocked, owned by Environment, and exported in app-control-evidence.json. Missing, stale, audit-only, ambiguous or unrelated evidence is not treated as a confirmed block. A successful lifecycle retains precedence. The collector handles the actual native event fields, including spaced field names and PolicyGUID versus the version-valued PolicyID.

Installer Sandbox configurations now disable vGPU and use software graphics. One earlier default-graphics guest crashed; this does not establish a graphics root cause or guarantee a display fix. Recording errors distinguish timeouts, exit codes and invalid response files.

Final verification: 481 .NET/WPF checks and 137 Windows PowerShell checks passed (618 total), and all 11 generated source families parsed. The build had zero warnings/errors. The local SDK is 8.0.427 with Windows Desktop runtime 8.0.33; a system-wide SDK installation was not necessary for these checks.

## Native evidence

A fresh official Advanced IP Scanner download exactly matched the existing source SHA-256, 26D5748FFE6BD95E3FEE6CE184D388A1A681006DC23A0F08D53C083C593C193B, and its outer Authenticode signature was Valid. Guest policy VerifiedAndReputableDesktop blocked its extracted temporary executable. A real Full Analysis run verified the new ApplicationControlBlocked category and exported correlated evidence. This is an expected-failure diagnostic acceptance, not a passing installer lifecycle or a repair of the vendor component.

RSPile initially encountered a different guest block: Windows GdiPlus.dll. The same bytes were catalog-signed and Valid on the host but NotSigned in the guest. Read-only host CryptoAPI catalog discovery identified the matching Microsoft-signed OS catalog. In one disposable guest, registering that verified catalog in the Windows OS catalog subsystem restored Valid / IsOSBinary for the unchanged DLL. Guest policy state remained 1 before and after; no certificates or policy settings changed. An initial registration in the default subsystem did not resolve the signature and remains recorded as an unsuccessful experiment.

The catalog repair is verification-only. Production does not automatically alter OS catalogs, trust or policy, and stock fresh guests may still encounter this environment problem. No catalog or installer binary is distributed in the source package.

## Current live milestone

RSPile's recording wizard is visible in the repaired guest and requests its bundled Visual C++ and Sentinel runtimes. The test is awaiting action-time UI installation confirmation. No Analyzer-created response recording, silent reinstall, final uninstall, generated deployment replay or full recording acceptance is claimed. Vendor-provided response replay previously passed separately.

Evidence pointers: Catalog-Repair-Guest-Location.txt, Sandbox-Signing-Probe-Location.txt, Windows-Catalog-Discovery-Location.txt, RSPile-Recording-Full-Location.txt and IP-Scanner-Policy-Software-Location.txt. App-Control-Live-Acceptance.json records the expected IP Scanner failure assertion. Raw experiment artifacts remain local under verification-results, outside the source ZIP.

Items 4 (broader prerequisite discovery), 7 (payload inspection) and 13 (broader download attribution) remain partial. Public signed-upgrade acceptance and additional installer interaction coverage also remain open.

Follow-up: the original wizard wait expired at its 15-minute recording deadline while awaiting approval. That result is preserved. After prerequisite approval, a fresh guest repeated the verified catalog preparation, installed Visual C++ 14.38.33130 with exit 0/no restart, and has a running hasplms Sentinel service. The main RSPile Complete/default-folder wizard now awaits its action-time installation confirmation. All eight original USB hashes were rechecked unchanged. No main-product installation or recorded lifecycle pass is claimed yet.

Latest result: the follow-up recording also reached its 15-minute deadline while waiting at the main-product installation confirmation. ValidationError records that timeout; InitialInstallValidated, SilentReinstallValidated, SilentUninstallValidated and LifecycleValidated are false. Prerequisite success remains separate from product lifecycle acceptance. A fresh recording run is required.

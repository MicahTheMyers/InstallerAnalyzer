import json
from pathlib import Path

r = Path(__file__).resolve().parent.parent
def update(p, f):
    path = r / p
    path.write_text(f(path.read_text(encoding='utf-8-sig')), encoding='utf-8')
intro = '''## Current v0.13 preview — 2026-11-02

**0.13.0-preview.1** adds the Datto RMM page and validated component-kit export. **604 .NET/WPF + 184 PowerShell checks pass**, all 11 source families parse, and 18 live LocalSystem checks pass in a fresh Sandbox, including two real install/remove cycles. Datto tenant acceptance is pending the user's office test. Public latest remains v0.12.10. See [Datto support](outputs/DATTO-RMM-SUPPORT.md) and [office steps](InstallerAnalyzer/docs/DATTO-RMM-OFFICE-TEST.md).

## Earlier v0.13 planning'''
update('ROADMAP-STATUS.md', lambda t: t.replace('## v0.13 planning', intro).replace('Datto RMM is planned, not implemented.', 'Datto RMM initial export is implemented in local 0.13.0-preview.1; tenant acceptance is pending.'))
update('ROADMAP-ACCEPTANCE.md', lambda t: '\n'.join('| 24 | Datto RMM deployment support | Initial implementation complete in 0.13.0-preview.1: dedicated page and validated Batch/PowerShell ZIP creation kit. | 604 .NET/WPF + 184 PowerShell checks and 11 syntax checks pass. 18 live checks include two real install/remove cycles as LocalSystem. Real Datto tenant job pending the user office test. Native CPT and direct API remain future scope. |' if line.startswith('| 24 |') else line for line in t.split('\n')))
update('InstallerAnalyzer/docs/roadmap/v0.13.md', lambda t: t.replace('Application version remains 0.12.10 until v0.13 development begins. Planned items below are not completion claims.', 'Local version is 0.13.0-preview.1; public latest remains v0.12.10. Completion scope is stated per item.').replace('Status: planned; implementation and Datto RMM acceptance have not started.', 'Status: initial implementation and local acceptance complete (2026-11-02). 604 .NET/WPF + 184 PowerShell checks and 11 syntax checks pass; 18 fresh Sandbox checks include two real install/remove cycles as LocalSystem. Datto tenant acceptance remains pending the user office test. Export is a ZIP creation kit, not native CPT. See ../DATTO-RMM-OFFICE-TEST.md.'))
update('InstallerAnalyzer/README.md', lambda t: t.replace('# Installer Analyzer for ImmyBot v0.12.10', '# Installer Analyzer — 0.13.0-preview.1').replace('Windows installer analysis and unattended deployment validation for ImmyBot.', 'Windows installer analysis and unattended deployment validation for ImmyBot and Datto RMM.\n\nThis local preview adds Datto RMM component-kit export and completed InstallShield reference recording/replay. Datto tenant acceptance is pending; public latest remains v0.12.10. See [office test instructions](docs/DATTO-RMM-OFFICE-TEST.md).'))
p = r / 'outputs/ACTIVE-ROADMAP-WORK.json'
s = json.loads(p.read_text(encoding='utf-8-sig'))
s.update(Phase='Datto initial export and local acceptance complete; awaiting user office platform test', Version='0.13.0-preview.1', Candidate='outputs/InstallerAnalyzer-0.13.0-preview.1-DattoRMM-Portable-20261102.zip', Source='outputs/InstallerAnalyzer-0.13.0-preview.1-DattoRMM-Source-20261102.zip', Verification='604 .NET/WPF + 184 PowerShell checks pass; 11 source syntax checks; 18 live LocalSystem checks; Sandbox teardown empty.', Report='outputs/DATTO-RMM-SUPPORT.md', WorkingCopyStatus='Unreleased 0.13.0-preview.1; published v0.12.10 and tag unchanged')
s['DattoRmm']['Status'] = 'Initial local implementation complete; tenant acceptance pending user office test'
s['Remaining'] = [v for v in s['Remaining'] if not v.startswith('Datto RMM')] + ['Datto RMM tenant acceptance: user will test at office']
p.write_text(json.dumps(s, indent=2), encoding='utf-8')

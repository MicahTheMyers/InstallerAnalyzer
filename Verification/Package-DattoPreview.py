"""Package the local Datto preview without vendor inputs or build intermediates."""
import hashlib, json, shutil, zipfile, sys
import xml.etree.ElementTree as ET
from pathlib import Path

root = Path(__file__).resolve().parent.parent
out = root / 'outputs'
version = ET.parse(root / 'InstallerAnalyzer/InstallerAnalyzer.csproj').findtext('./PropertyGroup/Version')
snapshot = sys.argv[1] if len(sys.argv) > 1 else 'DattoRMM'
snapshot_date = sys.argv[2] if len(sys.argv) > 2 else '20261102'
if not snapshot.isalnum():
    raise ValueError('Snapshot name must be alphanumeric')
if len(snapshot_date) != 8 or not snapshot_date.isdigit():
    raise ValueError('Snapshot date must be YYYYMMDD')
label = 'InstallerAnalyzer-' + version + '-' + snapshot
stage = root / 'verification-results' / (label + '-source-stage')
stage.mkdir(parents=True, exist_ok=True)
excluded = {'bin', 'obj', 'Build', '.git', '.vs', '__pycache__'}
for folder in ('InstallerAnalyzer', 'Verification'):
    for src in (root / folder).rglob('*'):
        if src.is_file() and not any(x in excluded for x in src.relative_to(root).parts):
            dest = stage / src.relative_to(root)
            dest.parent.mkdir(parents=True, exist_ok=True)
            shutil.copy2(src, dest)
for rel in ('ROADMAP-STATUS.md', 'ROADMAP-ACCEPTANCE.md',
            'outputs/ACTIVE-ROADMAP-WORK.json', 'outputs/DATTO-RMM-SUPPORT.md',
            'outputs/Datto-RMM-Acceptance.json', 'outputs/INSTALLSHIELD-V013-PROGRESS.md',
            'outputs/InstallShield-v013-Acceptance.json'):
    dest = stage / rel
    dest.parent.mkdir(parents=True, exist_ok=True)
    shutil.copy2(root / rel, dest)
(stage / 'BUILD-PREVIEW.cmd').write_text('@echo off\r\ncd /d "%~dp0"\r\ndotnet publish InstallerAnalyzer\\InstallerAnalyzer.csproj -c Release -r win-x64 --self-contained true -p:PublishSingleFile=true -p:IncludeNativeLibrariesForSelfExtract=true -p:UseSharedCompilation=false -o Portable\r\n', encoding='utf-8')
guide = (root / 'InstallerAnalyzer/docs/DATTO-RMM-OFFICE-TEST.md').read_text(encoding='utf-8-sig')
if snapshot == 'NetFx3Preflight':
    report = root / 'outputs/GINT-NETFX3-PREFLIGHT.md'
    shutil.copy2(report, stage / 'outputs' / report.name)
    receipt = root / 'outputs/Gint-NetFx3-Acceptance.json'
    if receipt.exists():
        shutil.copy2(receipt, stage / 'outputs' / receipt.name)
    guide = '# .NET 3.5 Sandbox preflight — ' + version + '\n\nFor gINT, enable **Settings → Windows Sandbox → Prepare .NET Framework 3.5 before Sandbox installers**. Close the existing Sandbox and launch a fresh analysis. This applies to Analyze and Test Mode. The feature is provisioned by command line and its runtime verified before installer launch. The host is unchanged. See outputs/GINT-NETFX3-PREFLIGHT.md in the source archive for scope and verification.\n\n' + guide
if snapshot in ('GintDetection', 'GintTargetIdentity', 'GintMainStage', 'GintConnectionHandoff'):
    for name in ('GINT-DETECTION.md', 'Gint-Detection-Acceptance.json', 'Gint-Static-Classification.json',
                 'Gint-Detection-After.json', 'Gint-Cabinet-Evidence.json', 'Gint-Inner-Msi-Evidence.json'):
        shutil.copy2(out / name, stage / 'outputs' / name)
    guide = '# gINT detection — ' + version + '\n\nThe tested Bentley gINT 10.02.00.04 EXE is now identified as Bootstrapper using its version-company metadata and a validated embedded CAB directory. Silent switches remain unset and ISS recording is not assumed. Full gINT lifecycle validation remains pending.\n\nFor the .NET 3.5 prerequisite, enable **Settings → Windows Sandbox → Prepare .NET Framework 3.5 before Sandbox installers** and launch a fresh Sandbox. In the latest local trace, DISM succeeded but Windows Application Control blocked the generated CLR test executable before gINT launch. No security control was changed or bypassed; this preview does not claim that live test passed.\n\nSee outputs/GINT-DETECTION.md in the source archive for findings and scope. The source and portable packages do not contain the vendor installer or extracted MSI.\n\n' + guide
if snapshot in ('GintTargetIdentity', 'GintMainStage', 'GintConnectionHandoff'):
    for name in ('GINT-TARGET-IDENTITY.md', 'Gint-Target-Identity-Acceptance.json'):
        shutil.copy2(out / name, stage / 'outputs' / name)
    guide = '# gINT target identity — ' + version + '\n\nThis build prevents CONNECTION Client and other prerequisites from replacing the expected gINT product. Timed-out or prerequisite-only discovery cannot start lifecycle removal. Validation failures are shown as failures.\n\nYour supplied run confirms that .NET 3.5 provisioning/runtime verification worked, but gINT was not registered and its main MSI was still running when the old build began cleanup. For retest, enable the .NET 3.5 preflight, start a fresh Sandbox and finish the main gINT wizard after the prerequisite installer. Only a completed lifecycle enables deployment export.\n\nFull gINT lifecycle acceptance remains pending. See outputs/GINT-TARGET-IDENTITY.md in the source archive. Previous detection/Datto notes follow as historical context.\n\n' + guide
if snapshot in ('GintMainStage', 'GintConnectionHandoff'):
    for name in ('GINT-MAIN-MSI-STARTUP.md', 'Gint-Main-Stage-Acceptance.json'):
        shutil.copy2(out / name, stage / 'outputs' / name)
    guide = '# gINT main MSI stage — ' + version + '\n\nA tracked main gINT MSI now gets its own bounded wait after prerequisites, with a thirty-minute total bootstrapper discovery cap. Analyzer reports the stage and preserves its setup log before teardown.\n\nDirect startup tests using both Windows Installer client architectures created the gINT welcome dialog after roughly two minutes of package verification, without accepting terms or installing the product. This does not establish a full gINT lifecycle or the exact cause of the user-reported unseen wizard.\n\nFor retest, enable the Sandbox .NET 3.5 preflight and start a fresh analysis. Finish the main gINT wizard when it appears. If it remains unseen, send the output again; it should include bootstrapper-main-msi-log-1.txt when the vendor creates its expected temp log. The Datto/ImmyBot export guards still require a complete lifecycle. See outputs/GINT-MAIN-MSI-STARTUP.md in the source archive.\n\nPrevious preview notes follow as historical context.\n\n' + guide
if snapshot == 'GintConnectionHandoff':
    for name in ('GINT-CONNECTION-HANDOFF.md', 'Gint-Connection-Handoff-Acceptance.json'):
        shutil.copy2(out / name, stage / 'outputs' / name)
    guide = '# CONNECTION Client handoff diagnostics — ' + version + '\n\nThe latest user run passed .NET 3.5 verification, but CONNECTION Client setup wrappers remained active and gINT MSI never started. This build captures that prerequisite setup’s current installation logs and enforced policy events matched to exact observed child executable images. It does not change security policy or claim to fix the vendor handoff.\n\nEnable the .NET 3.5 Sandbox preflight and start a fresh analysis. If the handoff stops again, retain the Output folder: it should include bootstrapper-prerequisite-log-N.txt when vendor logs are available, plus bootstrapper-child-app-control.json for the scoped policy query. The analysis records collection status even when logs/events are unavailable.\n\nA local isolated control found an enforced block of mbahost.dll; whether the same happened on the user machine remains unconfirmed. Full gINT lifecycle and deployment export acceptance remain pending. See outputs/GINT-CONNECTION-HANDOFF.md in the source archive.\n\nEarlier preview notes follow as historical context.\n\n' + guide
(stage / 'README-PREVIEW.md').write_text('# Source preview\n\nRequires .NET 8 SDK and Windows. Run BUILD-PREVIEW.cmd to create a self-contained portable build. Verification/Verification.csproj contains the local checks.\n\n' + guide, encoding='utf-8')
sources = sorted(p for p in stage.rglob('*') if p.is_file() and p.name != 'SOURCE-SHA256.json' and not any(x in excluded for x in p.relative_to(stage).parts))
manifest = {p.relative_to(stage).as_posix(): hashlib.sha256(p.read_bytes()).hexdigest() for p in sources}
(stage / 'SOURCE-SHA256.json').write_text(json.dumps(manifest, indent=2), encoding='utf-8')
source_zip = out / (label + '-Source-' + snapshot_date + '.zip')
with zipfile.ZipFile(source_zip, 'w', zipfile.ZIP_DEFLATED, compresslevel=6) as z:
    for p in sources + [stage / 'SOURCE-SHA256.json']:
        z.write(p, p.relative_to(stage).as_posix())
publish = Path((out / 'Datto-RMM-Publish-Location.txt').read_text(encoding='utf-8-sig').strip()) / 'Portable'
portable_zip = out / (label + '-Portable-' + snapshot_date + '.zip')
with zipfile.ZipFile(portable_zip, 'w', zipfile.ZIP_DEFLATED, compresslevel=6) as z:
    for p in sorted(publish.rglob('*')):
        if p.is_file() and p.suffix.lower() != '.pdb':
            z.write(p, p.relative_to(publish).as_posix())
    z.writestr('README-OFFICE-TEST.md', guide)
checksums = []
for p in (source_zip, portable_zip):
    with zipfile.ZipFile(p) as z:
        assert z.testzip() is None
        assert all(not n.startswith('/') and '..' not in Path(n).parts for n in z.namelist())
    checksums.append(hashlib.sha256(p.read_bytes()).hexdigest() + '  ' + p.name)
(out / ('SHA256SUMS-' + snapshot + '-' + snapshot_date + '.txt')).write_text('\n'.join(checksums) + '\n', encoding='ascii')
print(json.dumps({'Stage': str(stage), 'Source': str(source_zip), 'Portable': str(portable_zip), 'SourceFiles': len(manifest), 'ZipIntegrity': 'PASS'}, indent=2))

using System.IO;
using System.IO.Compression;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using System.Text.RegularExpressions;
using InstallerAnalyzer.Models;

namespace InstallerAnalyzer.Services;

public sealed record DattoRmmScripts(string Launcher, string Component, string Install, string Detection, string Uninstall);

public static class DattoRmmDeploymentService
{
    public static string? BlockReason(AnalysisResult? source, UninstallEntry? entry, InstallAnalysis? proof, string? responses)
    {
        if (source is null || entry is null || !LifecycleValidationService.IsComplete(proof)) return "Complete the install/removal lifecycle in Sandbox first.";
        if (!string.Equals(entry.Key, proof!.PrimaryKey, StringComparison.OrdinalIgnoreCase)) return "Select the application that passed the recorded lifecycle.";
        if (VirtualBoxReducedProfile.IsProfile(proof)) return "The VirtualBox profile requires its MSI cabinet and Visual C++ attachments. Datto export for this profile needs separate validation.";
        var components = proof.ComponentDeployment is not null;
        if (components && (proof.ValidationSchemaVersion < 3 || !proof.EvidenceCollectionComplete)) return "A fresh complete component-recipe lifecycle is required for this export.";
        if (components && (!GintDeploymentPlanService.IsCanonical(proof.ComponentDeployment) ||
            !string.Equals(proof.InstallerSha256, GintDeploymentPlanService.SourceHash, StringComparison.OrdinalIgnoreCase) ||
            !string.Equals(entry.ProductCode, GintDeploymentPlanService.ProductCode, StringComparison.OrdinalIgnoreCase)))
            return "Component recipe identity or attachment evidence changed. Run fresh gINT validation.";
        if (components && source.NeedsIss) return "The gINT component recipe does not use response-file mode. Restore the analyzed installer type.";
        if (source.IsPerUser || source.Kind == InstallerKind.Msix || IsUserScope(entry.Key) || IsUserScope(entry.InstallLocation))
            return "This export supports machine-wide installations under LocalSystem. Per-user and MSIX deployments need separate context validation.";
        if (!File.Exists(source.FilePath) || Path.GetExtension(source.FilePath).ToLowerInvariant() is not (".exe" or ".msi")) return "A single original MSI or EXE installer is required.";
        if (source.Kind == InstallerKind.Msi && !source.FilePath.EndsWith(".msi", StringComparison.OrdinalIgnoreCase)) return "An extracted MSI requires separate payload packaging.";
        if (source.FilePath.EndsWith(".msi", StringComparison.OrdinalIgnoreCase) && source.Kind != InstallerKind.Msi) return "Restore the MSI installer type or run fresh validation.";
        if (proof.SelectedSilentStrategy?.StartsWith("Recorded InstallShield",StringComparison.OrdinalIgnoreCase)==true && !source.NeedsIss) return "Restore recorded response-file mode or run fresh validation.";
        if (!Regex.IsMatch(proof.InstallerSha256 ?? "", "^[A-Fa-f0-9]{64}$")) return "A source SHA-256 from the completed analysis is required.";
        if (!components && !string.IsNullOrWhiteSpace(proof.DeploymentSource) && !string.Equals(Path.GetFileName(proof.DeploymentSource), source.FileName, StringComparison.OrdinalIgnoreCase))
            return "This strategy uses a separate deployment payload; original-file export is not supported for it yet.";
        if (string.IsNullOrWhiteSpace(proof.CombinedSilentArguments ?? proof.BaseSilentArguments)) return "A validated silent installation command is required.";
        if (!components && !string.IsNullOrWhiteSpace(proof.NetFx3Provisioning.Evidence)) return "This installer requires .NET 3.5 prerequisite planning for the target devices before Datto export.";
        if (Regex.IsMatch(proof.CombinedSilentArguments ?? proof.BaseSilentArguments ?? "", @"(?i)(?:^|\s)TRANSFORMS\s*="))
            return "MSI transforms require a multi-file deployment package, which is not supported by this export yet.";
        var arguments = (proof.CombinedSilentArguments ?? proof.BaseSilentArguments ?? "") + " " + proof.UninstallCandidate;
        if (Regex.IsMatch(arguments, @"(?i)(?:^|\s|[/\-])(?:password|passwd|pwd|token|apikey|api_key|secret|clientsecret|licensekey)\s*(?:=|:|\s)"))
            return "Credential-bearing installer arguments need a runtime-variable integration before export.";
        var rule = proof.DetectionStrategies.Where(d => d.Validated).OrderByDescending(d => d.Rank).FirstOrDefault();
        if (rule is null || ValidatedDetectionScriptService.Generate(proof) is null) return "A lifecycle-tested detection script is required.";
        if (rule.Type == "MsixPackageIdentity" || rule.RegistryHive == "CurrentUser" || IsUserScope(rule.RegistryPath) || IsUserScope(rule.Identity) || IsUserScope(rule.ExecutablePath))
            return "The selected detection rule depends on a user profile and cannot be used under LocalSystem.";
        if (source.NeedsIss && !ValidResponse(responses, "setup.iss")) return "The recorded setup.iss response file is missing or invalid.";
        if (proof.UninstallResponseFileCreated && !ValidResponse(responses, "uninstall.iss")) return "The recorded uninstall.iss response file is missing or invalid.";
        if (string.IsNullOrWhiteSpace(proof.UninstallCandidate)) return "A validated uninstall command is required.";
        return null;
    }

    private static bool IsUserScope(string? value) => Regex.IsMatch(value ?? "", @"(?i)HKCU:|HKEY_CURRENT_USER|\\Users\\|%APPDATA%|%LOCALAPPDATA%|%USERPROFILE%");
    private static bool ValidResponse(string? root, string name)
    {
        try
        {
        if (string.IsNullOrWhiteSpace(root)) return false;
        var file = new FileInfo(Path.Combine(root, name));
        if (!file.Exists || file.Length is <= 0 or > 1048576) return false;
        var text = File.ReadAllText(file.FullName);
        return text.Contains("[InstallShield Silent]", StringComparison.OrdinalIgnoreCase) &&
            text.Contains("File=Response File", StringComparison.OrdinalIgnoreCase) && Regex.IsMatch(text, @"(?im)^Count\s*=\s*[1-9]\d*\s*$");
        }
        catch (Exception ex) when (ex is IOException or UnauthorizedAccessException) { return false; }
    }

    private static Dictionary<string, string> Sources(AnalysisResult source, InstallAnalysis proof, string? responses)
    {
        if (proof.ComponentDeployment is not null) return GintDeploymentPlanService.ExportSources(source.FilePath, proof.ComponentDeployment);
        var files = new Dictionary<string, string> { ["installer" + Path.GetExtension(source.FilePath).ToLowerInvariant()] = source.FilePath };
        if (source.NeedsIss) files["setup.iss"] = Path.Combine(responses!, "setup.iss");
        if (proof.UninstallResponseFileCreated) files["uninstall.iss"] = Path.Combine(responses!, "uninstall.iss");
        return files;
    }

    public static DattoRmmScripts Generate(AnalysisResult source, UninstallEntry entry, InstallAnalysis proof, string? responses)
    {
        var reason = BlockReason(source, entry, proof, responses); if (reason is not null) throw new InvalidOperationException(reason);
        var hashes = proof.ComponentDeployment is not null ? new Dictionary<string,string>(proof.ComponentDeployment.Files) :
            Sources(source, proof, responses).ToDictionary(f => f.Key, f => f.Key.StartsWith("installer.", StringComparison.Ordinal) ? proof.InstallerSha256! : RegressionHistoryService.HashFile(f.Value));
        var config = Convert.ToBase64String(JsonSerializer.SerializeToUtf8Bytes(new { Installer = hashes.Keys.First(), Files = hashes }));
        // Display names belong in JSON metadata. Keep executable script literals independent of product names.
        var install = proof.ComponentDeployment is not null ? GintDeploymentPlanService.InstallScript : ImmyBotScriptGenerator.Generate(source, proof.CombinedSilentArguments ?? proof.BaseSilentArguments ?? "", "Validated application");
        var detection = ValidatedDetectionScriptService.Generate(proof)!;
        var uninstall = proof.UninstallResponseFileCreated
            ? ImmyBotScriptGenerator.GenerateUninstall(entry, "Validated application", proof)
            : NativeUninstall(proof.UninstallCandidate!);
        var replacements = new Dictionary<string,string> { ["__CONFIG__"]=config,["__INSTALL__"]=install,["__DETECT__"]=detection,["__UNINSTALL__"]=uninstall };
        var component = Regex.Replace(ComponentTemplate, "__CONFIG__|__INSTALL__|__DETECT__|__UNINSTALL__", m => replacements[m.Value]);
        return new(Launcher, component, install, detection, uninstall);
    }

    private static string NativeUninstall(string command) => """
$command = '__COMMAND__'
if ($command -match '^\s*"([^"]+)"\s*(.*)$' -or $command -match '^\s*([^\s"]+)\s*(.*)$') {
    $file=$Matches[1]; $arguments=$Matches[2]
} else { throw 'Invalid validated uninstall command.' }
if ($file -ieq 'msiexec.exe') { $file=Join-Path $env:WINDIR 'System32\msiexec.exe' }
$Process=Start-Process -FilePath $file -ArgumentList $arguments -Wait -PassThru
if ($Process.ExitCode -notin @(0,1605,3010)) { throw ('Uninstall failed with exit code '+$Process.ExitCode) }
""".Replace("__COMMAND__", command.Replace("'", "''"));

    public static void Export(string destination, AnalysisResult source, UninstallEntry entry, InstallAnalysis proof, string? responses)
    {
        var scripts = Generate(source, entry, proof, responses);
        var files = Sources(source, proof, responses);
        var output = Path.GetFullPath(destination);
        if (files.Values.Any(f => string.Equals(Path.GetFullPath(f), output, StringComparison.OrdinalIgnoreCase))) throw new InvalidOperationException("Export cannot replace a source file.");
        var temporary = output + "." + Guid.NewGuid().ToString("N") + ".tmp";
        var locks = new List<FileStream>();
        try
        {
            using var original = new FileStream(source.FilePath, FileMode.Open, FileAccess.Read, FileShare.Read);
            if (!Convert.ToHexString(SHA256.HashData(original)).Equals(proof.InstallerSha256, StringComparison.OrdinalIgnoreCase)) throw new InvalidDataException("Installer bytes changed after validation. Retest the installer before export.");
            foreach (var path in files.Values) locks.Add(new FileStream(path, FileMode.Open, FileAccess.Read, FileShare.Read));
            if (locks.Any(f => f.Length > 3_000_000_000L) || locks.Sum(f => f.Length) > 4_999_000_000L) throw new InvalidOperationException("The component exceeds Datto RMM attachment limits.");
            if (proof.ComponentDeployment is not null)
            {
                int attachment = 0;
                foreach (var file in files)
                    if (!Convert.ToHexString(SHA256.HashData(locks[attachment++])).Equals(proof.ComponentDeployment.Files[file.Key], StringComparison.OrdinalIgnoreCase)) throw new InvalidDataException("Component attachment changed: " + file.Key);
            }
            // Rebind response hashes while all exported source files are locked against replacement.
            scripts = Generate(source, entry, proof, responses);
            using (var zip = ZipFile.Open(temporary, ZipArchiveMode.Create))
            {
                void Text(string name, string text) { using var writer = new StreamWriter(zip.CreateEntry(name).Open(), new UTF8Encoding(name.EndsWith(".ps1", StringComparison.Ordinal))); writer.Write(text); }
                Text("Component.cmd", scripts.Launcher); Text("DattoComponent.ps1", scripts.Component); Text("README.md", Instructions + (proof.ComponentDeployment is null ? "" : GintInstructions));
                Text("component-settings.json", JsonSerializer.Serialize(new { Name = entry.DisplayName, Target = "Datto RMM", Category = "Applications", ScriptType = "Batch", RunAs = "LocalSystem", PowerShell = "Windows PowerShell 5.1, 64-bit", TimeoutSeconds = proof.ComponentDeployment is null ? 1200 : 2400, InputVariable = new { Name = "IAAction", Type = "Selection", Default = "Detect", Values = new[] { "Detect", "Install", "Uninstall" } }, WarningPostCondition = "IA_REBOOT_REQUIRED=1", SandboxValidated = true, DattoTenantValidated = false, ComponentRecipe = proof.ComponentDeployment?.Recipe, SandboxCompatibility = proof.SandboxCompatibility }, new JsonSerializerOptions { WriteIndented = true }));
                var index = 0;
                foreach (var file in files) { var stream = locks[index++]; stream.Position = 0; using var target = zip.CreateEntry(file.Key, CompressionLevel.Optimal).Open(); stream.CopyTo(target); }
            }
            File.Move(temporary, output, true);
        }
        finally { foreach (var stream in locks) stream.Dispose(); if (File.Exists(temporary)) File.Delete(temporary); }
    }

    public const string Launcher = """
@echo off
setlocal
set "IA_POWERSHELL=%SystemRoot%\System32\WindowsPowerShell\v1.0\powershell.exe"
if exist "%SystemRoot%\Sysnative\WindowsPowerShell\v1.0\powershell.exe" set "IA_POWERSHELL=%SystemRoot%\Sysnative\WindowsPowerShell\v1.0\powershell.exe"
"%IA_POWERSHELL%" -NoProfile -NonInteractive -File ".\DattoComponent.ps1"
exit /b %errorlevel%
""";

    public const string Instructions = """
# Datto RMM deployment component

Extract this ZIP. In Datto RMM > Automation > Components > Create Component:
1. Choose Applications and Batch. Paste Component.cmd into the script editor.
2. Add DattoComponent.ps1 and every installer/response attachment from this ZIP to Files. Keep their names unchanged. README.md and component-settings.json are setup guidance; they are not required attachments.
3. Add a Selection variable named IAAction with values Detect, Install, Uninstall; default Detect. Values are strings exposed through $env:IAAction.
4. Set a 1200-second timeout (increase for a slower package). Run as LocalSystem. The launcher selects 64-bit Windows PowerShell 5.1. It does not change execution policy; environments enforcing script signing need the PowerShell attachment signed through their normal process.
5. Add a warning post-condition for output containing IA_REBOOT_REQUIRED=1. Code 3010 is reported as a reboot warning; the component does not reboot the device. Unproven postconditions still fail.
6. Run Detect on a disposable test device, then test Install and Uninstall before assigning production devices.

Output: IA_DETECTED=1/0; IA_ACTION; IA_REBOOT_REQUIRED=1 when needed. Exit 0 means the requested action completed and detection matched; Detect returns exit 0 for either known presence or known absence. Exit 1 means failure/unknown. This is an application component, not a custom monitor protocol.

This ZIP is a component-creation kit, not a native .cpt import. After creating/testing the component in Datto RMM, its normal Export action can produce a native .cpt. Tenant/API upload and job submission are not performed by Installer Analyzer.

Supported initial scope: lifecycle-validated single-file machine-wide MSI/EXE deployments and recorded InstallShield response files. Per-user, MSIX, transforms, separate extracted payloads, external .NET 3.5 prerequisite provisioning and credential-bearing arguments need additional integration. Sandbox proof does not establish Datto tenant acceptance. No Datto credentials are requested or included. Review generated installer arguments before sharing the kit.

Official documentation:
https://rmm.datto.com/help/en/Content/3NEWUI/Automation/Components/CreateAComponent.htm
https://rmm.datto.com/help/en/Content/3NEWUI/Automation/Components/Scripting.htm
https://rmm.datto.com/help/en/Content/3NEWUI/Automation/Components/InputVariables.htm
""";

    public const string GintInstructions = """

## gINT component recipe

Attach all six payload files, including gINT.msi and its five bundled prerequisites. Do not upload the outer Gint.exe instead. Set the job timeout to 2400 seconds. Install verifies every attachment and prerequisite before starting the main MSI. Existing compatible shared runtimes are retained. Uninstall removes only gINT; shared prerequisites remain.

Component Files checklist: DattoComponent.ps1, gINT.msi, vc8redist_x86.exe, vc9redist_x86.exe, vc14redist_x86.exe, AccessDatabaseEngine.exe, Setup_CONNECTIONclientx64_10_00_17_010.exe. Upload these extracted files individually with their original names. The ZIP is a delivery kit; this script does not unpack an attached ZIP. Confirm every upload succeeded, save the component, then run a fresh Quick Job. A missing-file error means the endpoint did not receive the required attachment at the expected location; no installer has run yet.

The component enables .NET Framework 3.5 and installs the VBScript optional feature by command line when missing. These Windows features require access to the organization's approved Windows Update/feature source; this kit does not redistribute Windows image files. If provisioning fails or needs a reboot before becoming usable, resolve that condition and rerun. No device reboot is initiated. IA_REBOOT_REQUIRED=1 remains a warning, not proof of successful installation.

The legacy vendor prerequisites contain unsigned helper code. Sandbox acceptance used legacy-installer compatibility. This component does not turn off Smart App Control, change application-control policy, add antivirus exclusions, import certificates, or change licensing. A target that denies the vendor helper needs an administrator-approved compatible environment. Test on a disposable Datto-managed device before production rollout. No Datto tenant test has been claimed.
""";

    private const string ComponentTemplate = """
#Requires -Version 5.1
$ErrorActionPreference = 'Stop'
function Invoke-IAInstall {
__INSTALL__
    return [int]$Process.ExitCode
}
function Invoke-IADetect {
__DETECT__
}
function Invoke-IAUninstall {
__UNINSTALL__
    return [int]$Process.ExitCode
}
function Test-IADetected {
    $value = @(Invoke-IADetect)
    if ($value.Count -ne 1 -or $value[0] -isnot [bool]) { throw 'Detection must return exactly one Boolean.' }
    return $value[0]
}
function Assert-IAAttachments([string]$folder,$files) {
    $missing=@($files.PSObject.Properties | Where-Object { -not (Test-Path -LiteralPath (Join-Path $folder $_.Name) -PathType Leaf) } | ForEach-Object {$_.Name})
    if($missing.Count -gt 0){
        throw ('Missing component attachments: '+($missing -join ', ')+'. Expected folder: '+$folder+'. Add the extracted files to the Datto component Files section with these exact names, confirm upload success, save the component, and rerun the job.')
    }
}
$IAFiles = New-Object 'System.Collections.Generic.List[System.IO.FileStream]'
$IAExit = 0
try {
    if ([Security.Principal.WindowsIdentity]::GetCurrent().User.Value -ne 'S-1-5-18') { throw 'Run this machine-wide component as LocalSystem.' }
    if (-not [Environment]::Is64BitProcess) { throw 'Use Component.cmd to select 64-bit PowerShell.' }
    $IAAction = if ([string]::IsNullOrWhiteSpace($env:IAAction)) { 'Detect' } else { $env:IAAction.Trim() }
    if ($IAAction -notin @('Detect','Install','Uninstall')) { throw 'IAAction must be Detect, Install or Uninstall.' }
    $IAConfig = [Text.Encoding]::UTF8.GetString([Convert]::FromBase64String('__CONFIG__')) | ConvertFrom-Json
    $InstallerFolder = (Get-Location).Path
    Assert-IAAttachments $InstallerFolder $IAConfig.Files
    foreach ($item in $IAConfig.Files.PSObject.Properties) {
        $path = Join-Path $InstallerFolder $item.Name
        $stream = [IO.File]::Open($path, [IO.FileMode]::Open, [IO.FileAccess]::Read, [IO.FileShare]::Read)
        $IAFiles.Add($stream)
        if ((Get-FileHash -InputStream $stream -Algorithm SHA256).Hash -ne $item.Value) { throw ('Attachment checksum mismatch: '+$item.Name) }
    }
    $InstallerFile = Join-Path $InstallerFolder $IAConfig.Installer
    Write-Output ('IA_ACTION='+$IAAction)
    $detected = Test-IADetected
    if ($IAAction -ne 'Detect') {
        $expected = $IAAction -eq 'Install'
        if ($detected -ne $expected) {
            $code = if ($expected) { Invoke-IAInstall } else { Invoke-IAUninstall }
            if ($code -eq 3010) { Write-Output 'IA_REBOOT_REQUIRED=1' }
            $matched = $false
            for ($i=0; $i -lt 10; $i++) {
                $detected = Test-IADetected
                if ($detected -eq $expected) { $matched=$true; break }
                Start-Sleep 3
            }
            if (-not $matched) { throw 'The requested deployment postcondition was not verified.' }
        }
    }
    Write-Output ('IA_DETECTED='+[int]$detected)
} catch { Write-Output ('IA_ERROR='+$_.Exception.Message); $IAExit=1 }
finally { foreach ($stream in $IAFiles) { $stream.Dispose() } }
exit $IAExit
""";
}

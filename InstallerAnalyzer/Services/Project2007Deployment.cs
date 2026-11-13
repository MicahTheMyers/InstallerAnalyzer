using System.IO;
using InstallerAnalyzer.Models;

namespace InstallerAnalyzer.Services;

internal static class Project2007Deployment
{
    internal const string Configuration = """<Configuration Product="PrjPro"><Display Level="none" CompletionNotice="no" SuppressModal="yes" /><Setting Id="SETUP_REBOOT" Value="Never" /></Configuration>""";
    private const string GuestArguments = "/config \"C:\\InstallerOutput\\project2007-silent.xml\"";
    internal const string AttachmentInstructions = "Keep installer-source.zip intact and available for both installation and removal. If the deployment platform does not stage the attachment for removal, stage it beside the uninstall script before running it.";

    internal static bool Matches(InstallerArchive archive, InstallAnalysis? proof)
    {
        if (proof is null || !LifecycleValidationService.IsComplete(proof) || !archive.Matches(proof) ||
            proof.ValidationSchemaVersion < 3 || proof.ComponentDeployment is not null || proof.UninstallResponseFileCreated ||
            !Same(proof.DeploymentMechanism, "Microsoft Office 2007 MSI suite") ||
            !Same(proof.ExpectedPrimaryProduct, "Microsoft Office Project Professional 2007") ||
            !Same(proof.SelectedSilentStrategy, "Project 2007 Setup with silent configuration") ||
            !Same(Path.GetFileName(archive.Entry), "setup.exe") ||
            !Same(proof.CombinedSilentArguments, GuestArguments))
            return false;
        var setup = @"C:\InstallerArchive\" + archive.Entry;
        return Same(proof.DeploymentSource, setup) &&
            Same(proof.SilentInstallCommand, $"\"{setup}\" {GuestArguments}") &&
            Same(proof.UninstallCandidate, $"\"{setup}\" /uninstall PRJPRO {GuestArguments}") &&
            proof.PrimaryKey?.EndsWith(@"\Microsoft\Windows\CurrentVersion\Uninstall\PRJPRO", StringComparison.OrdinalIgnoreCase) == true &&
            proof.NewUninstallEntries.Any(e => Same(e.Key, proof.PrimaryKey) && Same(e.DisplayName, proof.ExpectedPrimaryProduct));
    }

    internal static string Generate(InstallerArchive archive, InstallAnalysis proof, bool uninstall)
    {
        var check = uninstall || string.IsNullOrWhiteSpace(proof.NetFx3Provisioning.Evidence) ? "" : """
$ProjectFramework = Get-ItemProperty -LiteralPath @(
    'HKLM:\SOFTWARE\Microsoft\NET Framework Setup\NDP\v3.5'
    'HKLM:\SOFTWARE\WOW6432Node\Microsoft\NET Framework Setup\NDP\v3.5'
) -Name Install -ErrorAction SilentlyContinue | Where-Object { $_.Install -eq 1 }
if (-not $ProjectFramework) { throw 'Install .NET Framework 3.5 on the target and complete any required restart before deploying Project 2007.' }
""";
        return "# " + AttachmentInstructions + Environment.NewLine + archive.WrapInstallScript($$"""
{{check}}
# Recreate the silent XML used in Sandbox. No product key or license acceptance is added.
$ProjectConfig = Join-Path $ArchiveFolder ('IA-Project-' + [guid]::NewGuid().ToString('N') + '.xml')
[IO.File]::WriteAllText($ProjectConfig, '{{Configuration}}' + [Environment]::NewLine, [Text.UTF8Encoding]::new($true))
$ProjectArguments = '{{(uninstall ? "/uninstall PRJPRO " : "")}}/config "' + $ProjectConfig + '"'
$Process = Start-Process -FilePath $InstallerFile -ArgumentList $ProjectArguments -WorkingDirectory (Split-Path -Parent $InstallerFile) -PassThru -Wait -ErrorAction Stop
if ($Process.ExitCode -notin @(0, 3010)) { throw ('Project 2007 Setup failed with exit code ' + $Process.ExitCode) }
if ($Process.ExitCode -eq 3010) { Write-Warning 'Project 2007 Setup requested a restart.' }
""");
    }

    private static bool Same(string? left, string? right) => string.Equals(left, right, StringComparison.OrdinalIgnoreCase);
}

using System.IO;
using InstallerAnalyzer.Models;

namespace InstallerAnalyzer.Services;

internal static class VirtualBoxReducedProfile
{
    internal const string MsiHash = "67875D993FE2460F4515FC4571FEEFFE0B3542F2AC450920332F8A1D53D566E8";
    internal const string Mechanism = "VirtualBox 7.2.22 core, USB and bridged networking";
    internal const string Arguments = "/qn /norestart VBOX_START=0 ADDLOCAL=VBoxApplication,VBoxUSB,VBoxNetwork,VBoxNetworkFlt";

    private static readonly (string Name, string Hash)[] Attachments =
    [
        ("common.cab", "800A60DC8E5E71BDC85A6DCF7FC3820E3921A8B10B5BB8AD1C469B02F98C4004"),
        ("vc_redist.x64.exe", "843068991DAAA1F73AD9F6239BCE4D0F6A07A51F18C37EA2A867E9BECA71295C")
    ];

    internal static void Stage(string installer, string target)
    {
        var source = installer + ".dependencies";
        var destination = Directory.CreateDirectory(target + ".dependencies").FullName;
        foreach (var (name, hash) in Attachments)
        {
            var file = Path.Combine(source, name);
            if (!File.Exists(file))
                throw new InvalidOperationException($"VirtualBox requires {name} in {Path.GetFileName(source)}.");
            var copy = Path.Combine(destination, name);
            if (!File.Exists(copy)) File.Copy(file, copy);
            if (!string.Equals(MsixDependencyService.Hash(copy), hash, StringComparison.OrdinalIgnoreCase))
                throw new InvalidOperationException($"VirtualBox attachment hash did not match: {name}.");
        }
    }

    internal static bool IsProfile(InstallAnalysis? proof) => proof?.DeploymentMechanism == Mechanism;
}

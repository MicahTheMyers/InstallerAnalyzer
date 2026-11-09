using System.IO;
using System.Security.Cryptography;
using System.Text;
using InstallerAnalyzer.Models;

namespace InstallerAnalyzer.Services;

public static partial class InstallerCatalogService
{
    private const string RecordingMechanism = "Recorded InstallShield";

    private static CatalogRecording? CaptureRecording(InstallAnalysis proof, string? folder)
    {
        if (folder is null || proof.ValidationSchemaVersion < 3 || !proof.EvidenceCollectionComplete ||
            proof.SelectedSilentStrategy != "Recorded InstallShield response file" ||
            !proof.UninstallResponseFileCreated ||
            !(proof.SilentInstallCommand?.Contains("/f1\"C:\\InstallerOutput\\setup.iss\"", StringComparison.OrdinalIgnoreCase) ?? false) ||
            !(proof.UninstallCandidate?.Contains("/f1\"C:\\InstallerOutput\\uninstall.iss\"", StringComparison.OrdinalIgnoreCase) ?? false)) return null;
        CatalogResponseFile Read(string name)
        {
            var path = Path.Combine(folder, name);
            if (new FileInfo(path).Length is <= 0 or > 262144) throw new InvalidDataException("Invalid response file size.");
            var bytes = File.ReadAllBytes(path);
            return new() { Base64 = Convert.ToBase64String(bytes), Sha256 = Convert.ToHexString(SHA256.HashData(bytes)) };
        }
        try
        {
            var recording = new CatalogRecording { Setup = Read("setup.iss"), Uninstall = Read("uninstall.iss") };
            return ValidRecording(recording) ? recording : null;
        }
        catch (IOException) { return null; }
    }

    private static bool ValidRecording(CatalogRecording? recording)
    {
        if (recording is null) return false;
        bool Valid(CatalogResponseFile? file)
        {
            if (file?.Base64 is null || file.Base64.Length > 349528) return false;
            try
            {
                var bytes = Convert.FromBase64String(file.Base64);
                if (bytes.Length is <= 0 or > 262144 || !Convert.ToHexString(SHA256.HashData(bytes)).Equals(file.Sha256, StringComparison.OrdinalIgnoreCase)) return false;
                var text = (bytes.Length >= 2 && bytes[0] == 255 && bytes[1] == 254 ? Encoding.Unicode : Encoding.UTF8).GetString(bytes);
                return text.Contains("[InstallShield Silent]", StringComparison.OrdinalIgnoreCase);
            }
            catch (FormatException) { return false; }
        }
        return Valid(recording.Setup) && Valid(recording.Uninstall);
    }

    private static bool ValidRecordingRecord(CatalogRecord record) =>
        record.Family == InstallerKind.InstallShield.ToString() && record.ComponentDeployment is null &&
        record.DeploymentMechanism == RecordingMechanism && record.InstallArguments == "" && ValidRecording(record.Recording);
}

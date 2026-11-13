using System.IO;
using System.IO.Compression;
using System.Text.Json;
using InstallerAnalyzer.Models;

namespace InstallerAnalyzer.Services;

internal sealed record RecordedSandboxReplay(InstallAnalysis Proof, string RegistryKey, byte[] Setup, byte[] Uninstall)
{
    private const int ResponseLimit = 1024 * 1024;
    private const int AnalysisLimit = 32 * 1024 * 1024;

    internal static string? FindRegistryKey(InstallAnalysis? proof)
    {
        if (proof is not { InitialInstallValidated: true, InitialUninstallValidated: true,
            CleanBaselineVerified: true, UninstallResponseFileCreated: true, InitialUninstallExitCode: 0 or 3010 } ||
            string.IsNullOrWhiteSpace(proof.InstallerSha256) || string.IsNullOrWhiteSpace(proof.UninstallCandidate))
            return null;
        // A failed replay can replace PrimaryKey with a prerequisite. The original detection
        // evidence still identifies the product observed before the first removal.
        var keys = (proof.DetectionStrategies ?? []).Where(rule => rule.Type == "UninstallRegistryKey" &&
                rule.BeforeInstall == false && rule.AfterInstall == true && !string.IsNullOrWhiteSpace(rule.RegistryPath))
            .Select(rule => rule.RegistryPath!).Distinct(StringComparer.OrdinalIgnoreCase).Take(2).ToArray();
        return keys.Length == 1 ? keys[0] : null;
    }

    internal static RecordedSandboxReplay FromFolder(InstallAnalysis proof, string folder)
    {
        return Create(proof, ReadFile("setup.iss"), ReadFile("uninstall.iss"));

        byte[] ReadFile(string name)
        {
            using var stream = File.OpenRead(Path.Combine(folder, name));
            return ReadBounded(stream, stream.Length, ResponseLimit);
        }
    }

    private static RecordedSandboxReplay Create(InstallAnalysis proof, byte[] setup, byte[] uninstall) =>
        new(proof, FindRegistryKey(proof) ??
            throw new InvalidDataException("The report must contain a recorded install, verified first removal, and a single application identity."),
            setup, uninstall);

    private static byte[] ReadBounded(Stream stream, long length, int limit)
    {
        if (length <= 0 || length > limit) throw new InvalidDataException("Invalid recording file size.");
        var bytes = new byte[(int)length];
        stream.ReadExactly(bytes);
        if (stream.ReadByte() != -1) throw new InvalidDataException("Recording file exceeds its declared size.");
        return bytes;
    }

    internal static RecordedSandboxReplay FromZip(string path)
    {
        using var zip = ZipFile.OpenRead(path);
        ZipArchiveEntry Entry(string name)
        {
            var entries = zip.Entries.Where(entry => entry.Name.Equals(name, StringComparison.OrdinalIgnoreCase)).Take(2).ToArray();
            return entries.Length == 1 ? entries[0] : throw new InvalidDataException($"The report must contain exactly one {name}.");
        }
        var analysis = Entry("install-analysis.json");
        using var stream = analysis.Open();
        var proof = JsonSerializer.Deserialize<InstallAnalysis>(ReadBounded(stream, analysis.Length, AnalysisLimit),
            new JsonSerializerOptions { PropertyNameCaseInsensitive = true })
            ?? throw new InvalidDataException("Missing installation analysis.");
        return Create(proof, ReadEntry("setup.iss"), ReadEntry("uninstall.iss"));

        byte[] ReadEntry(string name)
        {
            var entry = Entry(name);
            using var response = entry.Open();
            return ReadBounded(response, entry.Length, ResponseLimit);
        }
    }

    internal void VerifySource(string path, InstallerArchive? archive)
    {
        if (!string.Equals(Proof.InstallerSha256, RegressionHistoryService.HashFile(path), StringComparison.OrdinalIgnoreCase) ||
            (archive is null ? !string.IsNullOrEmpty(Proof.InstallerArchiveSha256) || !string.IsNullOrEmpty(Proof.InstallerArchiveEntry)
                : !archive.Matches(Proof)))
            throw new InvalidDataException("Select the exact installer and ZIP entry used to make this recording.");
    }
}

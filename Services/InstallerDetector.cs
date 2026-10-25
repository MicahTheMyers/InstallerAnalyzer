using System.IO;
using System.Diagnostics;
using System.Reflection.PortableExecutable;
using System.Text;
using InstallerAnalyzer.Models;

namespace InstallerAnalyzer.Services;

public sealed class InstallerDetector
{
    private static readonly string[] Markers =
    {
        "Inno Setup", "inno setup setup data", "Nullsoft", "NSIS", "Nullsoft Install System",
        "InstallShield", "InstallShield Setup Launcher", "InstallShield Setup Kernel",
        "InstallShield Setup Script Driver", "InstallShield Script Engine", "InstallScript",
        "ApphelpCheckInstallShieldPackage", "SI_INSTALLSCRIPT_MSI", "SI_SILENT_MODE",
        "WixBundle", "WiX Toolset", "setup.iss", "/f1"
    };

    public AnalysisResult Analyze(string path)
    {
        var r = new AnalysisResult { FilePath = path };
        var vi = FileVersionInfo.GetVersionInfo(path);
        r.ProductName = vi.ProductName ?? "";
        r.CompanyName = vi.CompanyName ?? "";
        r.FileVersion = vi.FileVersion ?? "";
        r.Architecture = GetArchitecture(path);

        if (Path.GetExtension(path).Equals(".msi", StringComparison.OrdinalIgnoreCase))
        {
            r.Kind = InstallerKind.Msi; r.Confidence = 100;
            r.SuggestedArguments = "/qn /norestart";
            r.Evidence.Add("File extension is .msi (Windows Installer package).");
            return r;
        }

        // Scan the ENTIRE installer in chunks. v0.1 only scanned the first 64 MiB,
        // which misses signatures in large bootstrapper EXEs such as Settle3 (~360 MiB).
        var found = ScanMarkers(path);
        var scores = new Dictionary<InstallerKind, int>();
        void Hit(InstallerKind k, int score, string evidence)
        {
            scores[k] = scores.GetValueOrDefault(k) + score;
            if (!r.Evidence.Contains(evidence)) r.Evidence.Add(evidence);
        }

        if (Has(found, "Inno Setup") || Has(found, "inno setup setup data"))
            Hit(InstallerKind.InnoSetup, 90, "Strong Inno Setup signature detected in executable data.");

        if (Has(found, "Nullsoft") || Has(found, "NSIS") || Has(found, "Nullsoft Install System"))
            Hit(InstallerKind.Nsis, 85, "NSIS/Nullsoft marker detected in executable data.");

        if (Has(found, "InstallShield"))
            Hit(InstallerKind.InstallShield, 55, "InstallShield marker detected in executable data.");
        if (Has(found, "InstallShield Setup Kernel"))
            Hit(InstallerKind.InstallShield, 20, "InstallShield Setup Kernel signature detected.");
        if (Has(found, "InstallShield Setup Script Driver") || Has(found, "InstallShield Script Engine"))
            Hit(InstallerKind.InstallShield, 15, "InstallShield InstallScript engine/driver signature detected.");
        if (Has(found, "InstallScript") || Has(found, "SI_INSTALLSCRIPT_MSI"))
            Hit(InstallerKind.InstallShield, 10, "InstallScript runtime marker detected.");
        if (Has(found, "ApphelpCheckInstallShieldPackage"))
            Hit(InstallerKind.InstallShield, 10, "Windows InstallShield compatibility marker detected.");

        if (Has(found, "WixBundle") || Has(found, "WiX Toolset"))
            Hit(InstallerKind.WixBurn, 90, "WiX Burn bundle marker detected.");

        if (Has(found, "setup.iss") || Has(found, "/f1"))
        {
            Hit(InstallerKind.InstallShield, 15, "InstallShield response-file marker detected.");
            r.NeedsIss = true;
        }

        var meta = $"{r.ProductName} {r.CompanyName}";
        if (meta.Contains("InstallShield", StringComparison.OrdinalIgnoreCase))
            Hit(InstallerKind.InstallShield, 20, "Version metadata references InstallShield.");
        if (meta.Contains("Inno Setup", StringComparison.OrdinalIgnoreCase))
            Hit(InstallerKind.InnoSetup, 20, "Version metadata references Inno Setup.");

        if (scores.Count == 0)
        {
            r.Kind = InstallerKind.Unknown; r.Confidence = 0;
            r.SuggestedArguments = "";
            r.Evidence.Add("No supported installer signature was detected. Review manually.");
            return r;
        }

        var best = scores.OrderByDescending(x => x.Value).First();
        r.Kind = best.Key; r.Confidence = Math.Min(best.Value, 99);
        r.SuggestedArguments = r.Kind switch
        {
            InstallerKind.InnoSetup => "/VERYSILENT /SUPPRESSMSGBOXES /NORESTART /SP-",
            InstallerKind.Nsis => "/S",
            InstallerKind.WixBurn => "/quiet /norestart",
            InstallerKind.InstallShield when r.NeedsIss => "/s /f1`\"$ResponseFile`\"",
            InstallerKind.InstallShield => "/s",
            _ => ""
        };
        return r;
    }

    private static bool Has(HashSet<string> found, string marker) => found.Contains(marker);

    private static HashSet<string> ScanMarkers(string path)
    {
        var found = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
        const int chunkSize = 4 * 1024 * 1024;
        const int overlap = 512;
        var buffer = new byte[chunkSize + overlap];
        var carry = 0;

        using var fs = File.OpenRead(path);
        while (true)
        {
            var read = fs.Read(buffer, carry, chunkSize);
            if (read <= 0) break;
            var count = carry + read;
            var text = Encoding.Latin1.GetString(buffer, 0, count);

            foreach (var marker in Markers)
                if (!found.Contains(marker) && text.Contains(marker, StringComparison.OrdinalIgnoreCase))
                    found.Add(marker);

            if (found.Count == Markers.Length) break;
            carry = Math.Min(overlap, count);
            Buffer.BlockCopy(buffer, count - carry, buffer, 0, carry);
        }
        return found;
    }

    private static string GetArchitecture(string path)
    {
        try
        {
            using var fs = File.OpenRead(path);
            using var pe = new PEReader(fs);
            return pe.PEHeaders.CoffHeader.Machine switch
            {
                System.Reflection.PortableExecutable.Machine.Amd64 => "x64",
                System.Reflection.PortableExecutable.Machine.I386 => "x86",
                System.Reflection.PortableExecutable.Machine.Arm64 => "ARM64",
                _ => pe.PEHeaders.CoffHeader.Machine.ToString()
            };
        }
        catch { return "Unknown"; }
    }
}

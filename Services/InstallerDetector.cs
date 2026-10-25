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
        "WixBundle", "WiX Toolset", "setup.iss", "/f1",
        "Squirrel.Windows", "SquirrelSetup.log", "SquirrelTemp", "Update.exe", "-full.nupkg", "\\packages\\", "app-",
        "Nullsoft.NSIS.exehead", "NullsoftInst", "nsis.sf.net/NSIS_Error",
        "7z SFX", "NVIDIA Installer Splash", "NvidiaAppSetupInt", "NVIDIA Corporation\\NVIDIA App",
        "QSetupStub", "QSetup Installation Suite", "QSetupBridge", "Pantaray\\QSetup", "QSetup.language.ini"
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
        if (Has(found, "Nullsoft.NSIS.exehead"))
            Hit(InstallerKind.Nsis, 14, "Exact Nullsoft NSIS executable-head manifest detected.");
        if (Has(found, "NullsoftInst") || Has(found, "nsis.sf.net/NSIS_Error"))
            Hit(InstallerKind.Nsis, 10, "Additional NSIS runtime signature detected.");

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

        // NVIDIA App's outer bootstrapper is a customized 7-Zip SFX, not InstallShield.
        // Require NVIDIA-specific evidence so ordinary 7-Zip self-extractors are not mislabeled.
        if (Has(found, "7z SFX") && Has(found, "NVIDIA Installer Splash"))
            Hit(InstallerKind.NvidiaSfx, 75, "NVIDIA customized 7-Zip SFX bootstrapper detected.");
        if (Has(found, "NvidiaAppSetupInt"))
            Hit(InstallerKind.NvidiaSfx, 20, "NVIDIA App internal setup executable signature detected.");
        if (Has(found, "NVIDIA Corporation\\NVIDIA App"))
            Hit(InstallerKind.NvidiaSfx, 10, "NVIDIA App product path signature detected.");

        // Squirrel.Windows packages are per-user bootstrapper installers. Generic strings such as
        // Update.exe/app- are only supporting evidence; Squirrel-specific markers carry the score.
        if (Has(found, "Squirrel.Windows"))
            Hit(InstallerKind.Squirrel, 70, "Strong Squirrel.Windows framework signature detected.");
        if (Has(found, "SquirrelSetup.log") || Has(found, "SquirrelTemp"))
            Hit(InstallerKind.Squirrel, 20, "Squirrel setup/logging signature detected.");
        if (Has(found, "-full.nupkg"))
            Hit(InstallerKind.Squirrel, 15, "Embedded Squirrel full NuGet package marker detected.");
        if (Has(found, "Update.exe"))
            Hit(InstallerKind.Squirrel, 5, "Squirrel-style Update.exe marker detected.");
        if (Has(found, "\\packages\\") || Has(found, "app-"))
            Hit(InstallerKind.Squirrel, 5, "Squirrel package/application directory marker detected.");

        // QSetup has highly specific vendor/framework fingerprints. These deliberately carry
        // more weight than generic MSI/WiX/InstallShield strings that may occur inside payloads.
        if (Has(found, "QSetupStub"))
            Hit(InstallerKind.QSetup, 55, "Definitive QSetupStub bootstrapper signature detected.");
        if (Has(found, "QSetup Installation Suite"))
            Hit(InstallerKind.QSetup, 35, "QSetup Installation Suite framework signature detected.");
        if (Has(found, "QSetupBridge"))
            Hit(InstallerKind.QSetup, 20, "QSetupBridge component signature detected.");
        if (Has(found, "Pantaray\\QSetup"))
            Hit(InstallerKind.QSetup, 20, "Pantaray QSetup registry/path signature detected.");
        if (Has(found, "QSetup.language.ini"))
            Hit(InstallerKind.QSetup, 10, "QSetup language resource signature detected.");

        if (Has(found, "setup.iss") || Has(found, "/f1"))
            Hit(InstallerKind.InstallShield, 15, "InstallShield response-file marker detected.");

        var meta = $"{r.ProductName} {r.CompanyName}";
        // NVIDIA App stores some product signatures as UTF-16 resources, while the outer SFX
        // exposes a reliable ASCII "7z SFX" marker. Combine that container fingerprint with
        // signed/version metadata instead of treating incidental compatibility strings as InstallShield.
        if (Has(found, "7z SFX") && meta.Contains("NVIDIA", StringComparison.OrdinalIgnoreCase))
            Hit(InstallerKind.NvidiaSfx, 95, "7-Zip SFX container plus NVIDIA product metadata identifies the NVIDIA bootstrapper.");
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

        // Present evidence in context: weak signatures from embedded payloads should not look
        // equivalent to the definitive signatures that won classification.
        if (r.Kind == InstallerKind.QSetup && r.Evidence.Remove("NSIS/Nullsoft marker detected in executable data."))
            r.Evidence.Add("ℹ Incidental NSIS/Nullsoft marker also present; ignored because definitive QSetup signatures won classification.");
        if (r.Kind != InstallerKind.InstallShield && r.Evidence.Remove("InstallShield response-file marker detected."))
            r.Evidence.Add("ℹ InstallShield response-file text also present; ignored because InstallShield did not win classification.");

        // A response file is a strategy property, not a generic string-match property. Only
        // classify it as required when InstallShield actually wins the evidence comparison.
        r.NeedsIss = r.Kind == InstallerKind.InstallShield && (Has(found, "setup.iss") || Has(found, "/f1"));
        if (r.Kind == InstallerKind.Squirrel)
        {
            r.IsPerUser = true;
            r.ExpectedInstallRoot = "%LocalAppData%";
            r.Evidence.Add("Squirrel.Windows uses a per-user deployment model; InstallShield .iss response files are not required.");
        }
        else if (r.Kind == InstallerKind.QSetup)
        {
            r.Evidence.Add("QSetup has native unattended switches; an InstallShield .iss response file is not required.");
            r.Evidence.Add("QSetup /Hide lifecycle strategy is Sandbox validated; package-specific parameters may still be required.");
        }
        r.SuggestedArguments = r.Kind switch
        {
            InstallerKind.InnoSetup => "/VERYSILENT /SUPPRESSMSGBOXES /NORESTART /SP-",
            InstallerKind.Nsis => "/S",
            InstallerKind.WixBurn => "/quiet /norestart",
            InstallerKind.Squirrel => "--silent",
            InstallerKind.NvidiaSfx => "-s",
            InstallerKind.QSetup => "/Hide",
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

using System.IO;
using System.Diagnostics;
using System.Reflection.PortableExecutable;
using System.Text;
using System.Text.RegularExpressions;
using System.IO.Compression;
using System.Xml.Linq;
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
        "QSetupStub", "QSetup Installation Suite", "QSetupBridge", "Pantaray\\QSetup", "QSetup.language.ini",
        "OfficeClickToRun", "OfficeC2RClient", "ClickToRun", "O365HomePremRetail", "Microsoft Office",
        "Adobe Bootstrapper Application", "ADOBE APPLICATION Manager", "Adobe_Download_"
    };

    public AnalysisResult Analyze(string path)
    {
        var result = AnalyzeCore(path);
        result.Identity = InstallerIdentityService.Inspect(path);
        if (result.Kind == InstallerKind.Msi)
        {
            var metadata = MsiMetadataService.Read(path); result.Identity.Msi = metadata;
            if (metadata.ProductName.Length > 0) result.ProductName = metadata.ProductName;
            if (metadata.Manufacturer.Length > 0) result.CompanyName = metadata.Manufacturer;
            if (metadata.ProductVersion.Length > 0) result.FileVersion = metadata.ProductVersion;
            if (metadata.Platform.Length > 0) result.Architecture = metadata.Platform;
            result.Evidence.Add("MSI metadata: " + metadata.Status + ". ProductCode " + metadata.ProductCode + "; UpgradeCode " + metadata.UpgradeCode);
            foreach (var condition in metadata.LaunchConditions.Take(12)) result.Evidence.Add("Declared MSI launch condition: " + condition.Condition + " — " + condition.Description);
        }
        return result;
    }

    private AnalysisResult AnalyzeCore(string path)
    {
        var r = new AnalysisResult { FilePath = path };
        var extension = Path.GetExtension(path);
        if (extension.Equals(".msi", StringComparison.OrdinalIgnoreCase))
        {
            r.Kind = InstallerKind.Msi; r.Confidence = 100; r.SuggestedArguments = "/qn /norestart";
            r.Architecture = "Windows Installer"; r.ProductName = Path.GetFileNameWithoutExtension(path);
            r.Evidence.Add("Definitive package identity: .msi Windows Installer package.");
            r.Evidence.Add("MSI response files are not required; lifecycle validation uses msiexec and the discovered ProductCode.");
            return r;
        }
        if (extension.Equals(".msix", StringComparison.OrdinalIgnoreCase) || extension.Equals(".appx", StringComparison.OrdinalIgnoreCase) || extension.Equals(".msixbundle", StringComparison.OrdinalIgnoreCase) || extension.Equals(".appxbundle", StringComparison.OrdinalIgnoreCase))
        {
            AnalyzeMsixPackage(path, r); return r;
        }
        var vi = FileVersionInfo.GetVersionInfo(path);
        r.ProductName = vi.ProductName ?? ""; r.CompanyName = vi.CompanyName ?? ""; r.FileVersion = vi.FileVersion ?? ""; r.Architecture = GetArchitecture(path);
        if (string.Equals(r.CompanyName.Trim(), "Microsoft Corporation", StringComparison.OrdinalIgnoreCase) &&
            string.Equals(vi.OriginalFilename, "MicrosoftEdgeUpdateSetup.exe", StringComparison.OrdinalIgnoreCase) &&
            Regex.IsMatch(Path.GetFileName(path), @"^MicrosoftEdgeWebView2(?:Setup|RuntimeInstaller(?:X64|X86|ARM64))\.exe$", RegexOptions.IgnoreCase))
        {
            r.Kind = InstallerKind.Bootstrapper;
            r.Confidence = 95;
            r.ProductName = "Microsoft Edge WebView2 Runtime";
            r.SuggestedArguments = "/silent /install";
            r.Evidence.Add("Microsoft Edge WebView2 Runtime setup uses the documented /silent /install command.");
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
            Hit(InstallerKind.Nsis, 25, "Generic NSIS/Nullsoft marker detected; treated as supporting evidence because bootstrapper payloads can contain this text.");
        if (Has(found, "Nullsoft.NSIS.exehead"))
            Hit(InstallerKind.Nsis, 60, "Definitive Nullsoft NSIS executable-head manifest detected.");
        if (Has(found, "NullsoftInst") || Has(found, "nsis.sf.net/NSIS_Error"))
            Hit(InstallerKind.Nsis, 20, "Additional NSIS runtime signature detected.");

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
        if (Has(found, "-full.nupkg") && Has(found, "Update.exe") &&
            (Has(found, "SquirrelSetup.log") || Has(found, "SquirrelTemp")))
            Hit(InstallerKind.Squirrel, 45, "Correlated full NuGet payload, Update.exe and Squirrel logging signatures identify a Squirrel deployment package.");
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
        var bentley = BentleyBootstrapperService.Inspect(path, r.CompanyName);
        if (bentley is not null)
        {
            Hit(InstallerKind.Bootstrapper, 95, "Bentley prerequisite bootstrapper: version company metadata plus a bounded PE-resource CAB directory containing Settings.ini, PrereqInst32.exe and an MSI payload.");
            r.Evidence.Add("Embedded MSI payload: " + string.Join(", ", bentley.Files.Where(f => f.Name.EndsWith(".msi", StringComparison.OrdinalIgnoreCase)).Select(f => f.Name)) + ". Payload names establish packaging, not successful installation or prerequisite requirements.");
        }
        // NVIDIA App stores some product signatures as UTF-16 resources, while the outer SFX
        // exposes a reliable ASCII "7z SFX" marker. Combine that container fingerprint with
        // signed/version metadata instead of treating incidental compatibility strings as InstallShield.
        if (Has(found, "7z SFX") && meta.Contains("NVIDIA", StringComparison.OrdinalIgnoreCase))
            Hit(InstallerKind.NvidiaSfx, 95, "7-Zip SFX container plus NVIDIA product metadata identifies the NVIDIA bootstrapper.");
        if (meta.Contains("InstallShield", StringComparison.OrdinalIgnoreCase))
            Hit(InstallerKind.InstallShield, 20, "Version metadata references InstallShield.");
        if (meta.Contains("Inno Setup", StringComparison.OrdinalIgnoreCase))
            Hit(InstallerKind.InnoSetup, 20, "Version metadata references Inno Setup.");

        // Adobe Reader/Acrobat web installers expose Adobe Download Manager file metadata,
        // but that describes the bootstrapper itself rather than the application being deployed.
        // Prefer the Adobe bootstrapper identity and let Sandbox discovery replace the preliminary
        // product/version with the authoritative Acrobat uninstall-registry identity.
        var adobeMetadata = meta.Contains("Adobe", StringComparison.OrdinalIgnoreCase)
            && (r.ProductName.Contains("Download Manager", StringComparison.OrdinalIgnoreCase)
                || Path.GetFileName(path).Contains("Reader", StringComparison.OrdinalIgnoreCase)
                || Path.GetFileName(path).Contains("Acrobat", StringComparison.OrdinalIgnoreCase));
        var adobeBootstrapperEvidence = Has(found, "Adobe Bootstrapper Application")
            || Has(found, "ADOBE APPLICATION Manager") || Has(found, "Adobe_Download_");
        var adobeOfflineReader = AdobeReaderInstaller.IsOfflinePackage(path, vi);
        if (adobeOfflineReader)
        {
            Hit(InstallerKind.Bootstrapper, 95, "Adobe Reader offline self-extractor metadata detected.");
            r.ProductName = "Adobe Acrobat Reader";
        }
        else if (adobeMetadata && adobeBootstrapperEvidence)
        {
            Hit(InstallerKind.Bootstrapper, 95, "Adobe Acrobat/Reader bootstrapper signature and Adobe metadata detected.");
            r.ProductName = "Adobe Acrobat/Reader Bootstrapper";
            r.CompanyName = "Adobe";
            if (r.Architecture.Equals("x86", StringComparison.OrdinalIgnoreCase))
                r.Architecture = "x86 bootstrapper (payload architecture discovered in Sandbox)";
            r.Evidence.Add("Adobe Download Manager metadata identifies the launcher, not the deployed Acrobat/Reader application; Sandbox discovery will refine product, version, and architecture.");
        }

        // Microsoft Office web/bootstrapper installers are Click-to-Run launchers. They often
        // contain incidental NSIS/InstallShield strings from embedded resources, so recognize
        // Microsoft Office metadata plus Click-to-Run/product evidence as a bootstrapper family.
        var officeMetadata = meta.Contains("Microsoft Office", StringComparison.OrdinalIgnoreCase)
            && meta.Contains("Microsoft", StringComparison.OrdinalIgnoreCase);
        var officeC2rEvidence = Has(found, "OfficeClickToRun") || Has(found, "OfficeC2RClient")
            || Has(found, "ClickToRun") || Has(found, "O365HomePremRetail") || Has(found, "Microsoft Office");
        if (officeMetadata && officeC2rEvidence)
            Hit(InstallerKind.Bootstrapper, 90, "Microsoft Office metadata and Click-to-Run bootstrapper evidence detected.");
        else if (officeMetadata)
            Hit(InstallerKind.Bootstrapper, 75, "Microsoft Office bootstrapper metadata detected; Sandbox will confirm Click-to-Run behavior.");

        if (scores.Count == 0)
        {
            r.Kind = InstallerKind.Unknown; r.Confidence = 0;
            r.SuggestedArguments = "";
            r.Evidence.Add("No supported installer signature was detected. Review manually.");
            return r;
        }

        var best = scores.OrderByDescending(x => x.Value).First();
        r.Confidence = Math.Min(best.Value, 99);
        // Weak embedded signatures are evidence, not permission to choose a deployment strategy.
        // This prevents bootstrapper/downloader EXEs (for example OfficeSetup.exe) from inheriting
        // /S merely because an embedded payload contains a generic NSIS marker.
        if (best.Value < 50)
        {
            r.Kind = InstallerKind.Unknown;
            r.SuggestedArguments = "";
            r.NeedsIss = false;
            r.Evidence.Add($"Best embedded installer signature scored only {r.Confidence}%; deployment strategy withheld pending Sandbox discovery.");
            return r;
        }
        r.Kind = best.Key;

        // Present evidence in context: weak signatures from embedded payloads should not look
        // equivalent to the definitive signatures that won classification.
        if (r.Kind == InstallerKind.QSetup && r.Evidence.Remove("NSIS/Nullsoft marker detected in executable data."))
            r.Evidence.Add("ℹ Incidental NSIS/Nullsoft marker also present; ignored because definitive QSetup signatures won classification.");
        if (r.Kind != InstallerKind.InstallShield && r.Evidence.Remove("InstallShield response-file marker detected."))
            r.Evidence.Add("ℹ InstallShield response-file text also present; ignored because InstallShield did not win classification.");

        // A response file is a strategy property, not a generic string-match property. Only
        // classify it as required when InstallShield actually wins the evidence comparison.
        r.NeedsIss = r.Kind == InstallerKind.InstallShield && (Has(found, "setup.iss") || Has(found, "/f1"));
        if (r.Kind == InstallerKind.InnoSetup)
        {
            r.Evidence.Add("Inno Setup uses native silent switches; setup.iss and uninstall.iss response files are not required.");
        }
        else if (r.Kind == InstallerKind.Squirrel)
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
        else if (r.Kind == InstallerKind.Bootstrapper && bentley is not null)
        {
            r.Evidence.Add("Bentley bootstrapper detected. No silent switches, standalone-MSI portability or InstallShield response-file requirement are assumed; Sandbox must validate the deployment strategy.");
        }
        else if (r.Kind == InstallerKind.Bootstrapper && (adobeOfflineReader || (adobeMetadata && adobeBootstrapperEvidence)))
        {
            r.Evidence.Add("Adobe bootstrapper detected. Silent deployment arguments are intentionally withheld until Windows Sandbox validates the vendor strategy.");
        }
        else if (r.Kind == InstallerKind.Bootstrapper && officeMetadata)
        {
            r.Evidence.Add("Microsoft Click-to-Run behavior will be confirmed dynamically in Windows Sandbox; no conventional MSI/NSIS silent switches are assumed.");
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
        if (r.Kind == InstallerKind.InnoSetup &&
            string.Equals(r.ProductName.Trim(), "Visual Studio Code", StringComparison.OrdinalIgnoreCase) &&
            string.Equals(r.CompanyName.Trim(), "Microsoft Corporation", StringComparison.OrdinalIgnoreCase) &&
            string.Equals(vi.FileDescription?.Trim(), "Visual Studio Code Setup", StringComparison.OrdinalIgnoreCase))
        {
            // The default Inno task can launch Code.exe even during silent setup.
            r.SuggestedArguments += " /MERGETASKS=!runcode";
            r.Evidence.Add("Visual Studio Code silent setup skips launching the editor after installation.");
        }
        return r;
    }

    private static void AnalyzeMsixPackage(string path, AnalysisResult r)
    {
        r.Kind = InstallerKind.Msix; r.Confidence = 100; r.SuggestedArguments = ""; r.NeedsIss = false;
        r.Evidence.Add("Definitive package identity: MSIX/AppX package container.");
        r.Evidence.Add("MSIX/AppX deployment uses Add-AppxPackage; InstallShield response files are not applicable.");
        try
        {
            var identity = ReadMsixIdentity(path);
            if (identity is not null)
            {
                r.ProductName = identity.Attribute("Name")?.Value ?? Path.GetFileNameWithoutExtension(path);
                r.CompanyName = identity.Attribute("Publisher")?.Value ?? ""; r.FileVersion = identity.Attribute("Version")?.Value ?? "";
                r.Architecture = identity.Attribute("ProcessorArchitecture")?.Value ?? "Package bundle";
                r.Evidence.Add($"Package identity: {r.ProductName}; version {r.FileVersion}; architecture {r.Architecture}.");
            }
        }
        catch (Exception ex) { r.ProductName = Path.GetFileNameWithoutExtension(path); r.Architecture = "MSIX/AppX"; r.Evidence.Add("Package manifest could not be read during static analysis: " + ex.Message); }
    }

    internal static XElement? ReadMsixIdentity(string path)
    {
        using var zip = ZipFile.OpenRead(path);
        var manifest = zip.GetEntry("AppxManifest.xml") ?? zip.GetEntry("AppxMetadata/AppxBundleManifest.xml");
        if (manifest is null) return null;
        using var stream = manifest.Open();
        return XDocument.Load(stream).Root?.Elements().FirstOrDefault(element => element.Name.LocalName == "Identity");
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
            // PE resources and bootstrapper metadata commonly store family signatures as UTF-16LE.
            // Check both byte alignments because embedded payload boundaries are not guaranteed even.
            var wide = Encoding.Unicode.GetString(buffer, 0, count - count % 2);
            var wideOdd = count > 1 ? Encoding.Unicode.GetString(buffer, 1, (count - 1) / 2 * 2) : "";

            foreach (var marker in Markers)
                if (!found.Contains(marker) && (text.Contains(marker, StringComparison.OrdinalIgnoreCase) ||
                    wide.Contains(marker, StringComparison.OrdinalIgnoreCase) || wideOdd.Contains(marker, StringComparison.OrdinalIgnoreCase)))
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

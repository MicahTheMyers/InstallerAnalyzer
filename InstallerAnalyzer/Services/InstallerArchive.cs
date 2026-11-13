using System.IO;
using System.IO.Compression;
using System.Security.Cryptography;
using System.Text;
using InstallerAnalyzer.Models;

namespace InstallerAnalyzer.Services;

public sealed record InstallerArchive(string Path, string Entry, string Sha256)
{
    public const string AttachmentName = "installer-source.zip";
    private const long MaxBytes = 8L * 1024 * 1024 * 1024;
    private const int MaxEntries = 100_000;
    internal string? OfficeCorePackage { get; private init; }

    public static string[] ListInstallers(string path)
    {
        using var stream = File.OpenRead(path);
        using var zip = new ZipArchive(stream);
        return ReadEntries(zip).Where(pair => !IsDirectory(pair.Value) && IsInstaller(pair.Key))
            .Select(pair => pair.Key).OrderBy(name => name, StringComparer.OrdinalIgnoreCase).ToArray();
    }

    public static InstallerArchive Inspect(string path, string entry, string folder, out string installer)
    {
        using var stream = File.OpenRead(path);
        var hash = Convert.ToHexString(SHA256.HashData(stream));
        stream.Position = 0;
        using var zip = new ZipArchive(stream);
        var entries = ReadEntries(zip);
        var source = new InstallerArchive(path, entry, hash) { OfficeCorePackage = FindOfficeCorePackage(entry, entries) };
        installer = source.Extract(entries, folder, entryOnly: true);
        return source;
    }

    public string Stage(string folder)
    {
        using var stream = OpenVerified();
        using var zip = new ZipArchive(stream);
        return Extract(ReadEntries(zip), folder, entryOnly: false);
    }

    public FileStream OpenVerified()
    {
        var stream = File.OpenRead(Path);
        try
        {
            if (!string.Equals(Convert.ToHexString(SHA256.HashData(stream)), Sha256, StringComparison.OrdinalIgnoreCase))
                throw new InvalidDataException("The installer ZIP changed. Select it again and rerun Sandbox validation.");
            stream.Position = 0;
            return stream;
        }
        catch { stream.Dispose(); throw; }
    }

    public bool Matches(InstallAnalysis? proof) =>
        string.Equals(proof?.InstallerArchiveSha256, Sha256, StringComparison.OrdinalIgnoreCase) &&
        string.Equals(proof?.InstallerArchiveEntry, Entry, StringComparison.Ordinal);

    public bool SupportsDeployment(InstallAnalysis? proof) => ArchiveBindingBlockReason(proof) is null;

    public string? DeploymentBlockReason(InstallAnalysis? proof)
    {
        if (!LifecycleValidationService.IsComplete(proof))
            return "Complete Sandbox validation of this ZIP and its selected setup before deployment.";
        return ArchiveBindingBlockReason(proof);
    }

    private string? ArchiveBindingBlockReason(InstallAnalysis? proof)
    {
        if (!Matches(proof) || !string.Equals(proof!.DeploymentSource, @"C:\InstallerArchive\" + Entry, StringComparison.OrdinalIgnoreCase))
            return "The original ZIP and selected setup must match the completed Sandbox validation.";
        if (Project2007Deployment.Matches(this, proof)) return null;
        var install = proof.CombinedSilentArguments ?? proof.BaseSilentArguments;
        var uninstall = proof.UninstallCandidate;
        // The InstallShield generators rebind these two response files to their packaged copies.
        if (proof.SelectedSilentStrategy?.StartsWith("Recorded InstallShield", StringComparison.OrdinalIgnoreCase) == true)
            install = install?.Replace(@"C:\InstallerOutput\setup.iss", "", StringComparison.OrdinalIgnoreCase);
        if (proof.UninstallResponseFileCreated)
            uninstall = uninstall?.Replace(@"C:\InstallerOutput\uninstall.iss", "", StringComparison.OrdinalIgnoreCase);
        if (UsesSandboxPath(install) || UsesSandboxPath(uninstall))
            return "Sandbox validation passed. Export requires packaging the setup files or configuration referenced inside Sandbox.";
        return null;
    }

    private static bool UsesSandboxPath(string? command) =>
        command?.Contains(@"C:\InstallerArchive\", StringComparison.OrdinalIgnoreCase) == true ||
        command?.Contains(@"C:\InstallerInput\", StringComparison.OrdinalIgnoreCase) == true ||
        command?.Contains(@"C:\InstallerOutput\", StringComparison.OrdinalIgnoreCase) == true;

    private static string? FindOfficeCorePackage(string selected, Dictionary<string, ZipArchiveEntry> entries)
    {
        if (!System.IO.Path.GetFileName(selected).Equals("setup.exe", StringComparison.OrdinalIgnoreCase)) return null;
        var prefix = selected[..^"setup.exe".Length];
        var localFiles = entries.Where(pair => pair.Value.Length > 0 && !IsDirectory(pair.Value) &&
            pair.Key.StartsWith(prefix, StringComparison.OrdinalIgnoreCase))
            .Select(pair => pair.Key[prefix.Length..].Split('\\')).Where(parts => parts.Length == 2).ToArray();
        var hasOfficeLanguagePack = localFiles.Any(parts => parts[0].StartsWith("Office.", StringComparison.OrdinalIgnoreCase) &&
            parts[1].Equals("OfficeMUI.msi", StringComparison.OrdinalIgnoreCase));
        var packages = localFiles.Where(parts => parts[0].EndsWith(".WW", StringComparison.OrdinalIgnoreCase) &&
            parts[0].Length > 3 && parts[1].Equals(parts[0][..^3] + "WW.msi", StringComparison.OrdinalIgnoreCase) &&
            (hasOfficeLanguagePack || (entries.TryGetValue(prefix + parts[0] + "\\setup.xml", out var manifest) && manifest.Length > 0)))
            .Take(2).ToArray();
        return packages.Length == 1 ? string.Join("\\", packages[0]) : null;
    }

    private string Extract(Dictionary<string, ZipArchiveEntry> entries, string folder, bool entryOnly)
    {
        if (!IsInstaller(Entry) || !entries.TryGetValue(Entry, out var selected) || IsDirectory(selected))
            throw new InvalidDataException("The selected EXE or MSI is missing from the installer ZIP.");
        var buffer = new byte[81920];
        foreach (var (relativePath, entry) in entries)
        {
            if (entryOnly && !relativePath.Equals(Entry, StringComparison.OrdinalIgnoreCase)) continue;
            var target = System.IO.Path.Combine(folder, relativePath);
            if (IsDirectory(entry)) Directory.CreateDirectory(target);
            else
            {
                Directory.CreateDirectory(System.IO.Path.GetDirectoryName(target)!);
                using var source = entry.Open();
                using var destination = new FileStream(target, FileMode.CreateNew, FileAccess.Write);
                long remaining = entry.Length;
                int count;
                while ((count = source.Read(buffer)) != 0)
                {
                    if (count > remaining) throw new InvalidDataException("A ZIP entry exceeds its declared size: " + relativePath);
                    destination.Write(buffer, 0, count);
                    remaining -= count;
                }
                if (remaining != 0) throw new InvalidDataException("A ZIP entry ended before its declared size: " + relativePath);
            }
        }
        return System.IO.Path.Combine(folder, Entry);
    }

    private static bool IsInstaller(string path) => System.IO.Path.GetExtension(path).ToLowerInvariant() is ".exe" or ".msi";
    private static bool IsDirectory(ZipArchiveEntry entry) => entry.FullName.EndsWith('/') || entry.FullName.EndsWith('\\');

    private static Dictionary<string, ZipArchiveEntry> ReadEntries(ZipArchive zip)
    {
        if (zip.Entries.Count > MaxEntries)
            throw new InvalidDataException(FormattableString.Invariant($"The installer ZIP exceeds {MaxEntries:N0} entries."));
        var entries = new Dictionary<string, ZipArchiveEntry>(StringComparer.OrdinalIgnoreCase);
        long bytes = 0;
        foreach (var entry in zip.Entries)
        {
            var directory = IsDirectory(entry);
            var name = entry.FullName.Replace('/', '\\');
            if (directory) name = name[..^1];
            if ((entry.ExternalAttributes & (int)FileAttributes.ReparsePoint) != 0 ||
                (entry.ExternalAttributes >> 16 & 0xf000) == 0xa000 ||
                name.Split('\\').Any(UnsafeSegment) || !entries.TryAdd(name, entry))
                throw new InvalidDataException("The installer ZIP contains an unsafe or duplicate path: " + entry.FullName);
            if (directory && entry.Length != 0) throw new InvalidDataException("A ZIP directory contains file data: " + name);
            if (entry.Length > MaxBytes - bytes) throw new InvalidDataException("The installer ZIP exceeds 8 GiB when extracted.");
            bytes += entry.Length;
        }
        foreach (var name in entries.Keys)
            for (var parent = System.IO.Path.GetDirectoryName(name); !string.IsNullOrEmpty(parent); parent = System.IO.Path.GetDirectoryName(parent))
                if (entries.TryGetValue(parent, out var entry) && !IsDirectory(entry))
                    throw new InvalidDataException("The installer ZIP uses the same path for a file and folder: " + parent);
        return entries;
    }

    private static bool UnsafeSegment(string segment)
    {
        if (segment.Length == 0 || segment.EndsWith(' ') || segment.EndsWith('.') ||
            segment.IndexOfAny(System.IO.Path.GetInvalidFileNameChars()) >= 0) return true;
        var stem = segment.Split('.')[0].TrimEnd().ToUpperInvariant();
        return stem is "CON" or "PRN" or "AUX" or "NUL" or "CONIN$" or "CONOUT$" ||
            stem.Length == 4 && (stem.StartsWith("COM") || stem.StartsWith("LPT")) && "0123456789¹²³".Contains(stem[3]);
    }

    public string WrapInstallScript(string script)
    {
        var encodedEntry = Convert.ToBase64String(Encoding.UTF8.GetBytes(Entry));
        return $$"""
$ArchiveFile = $null
$IAPackageFolder = Get-Variable -Name InstallerFolder -ValueOnly -ErrorAction SilentlyContinue
$IAPackagedFile = Get-Variable -Name InstallerFile -ValueOnly -ErrorAction SilentlyContinue
$IARoots = @($IAPackageFolder, $PSScriptRoot, (Get-Location).Path)
if ($IAPackagedFile) { $IARoots += Split-Path -Parent $IAPackagedFile }
foreach ($IARoot in $IARoots) {
    if (-not $IARoot) { continue }
    $IACandidate = Join-Path $IARoot '{{AttachmentName}}'
    if (Test-Path -LiteralPath $IACandidate -PathType Leaf) { $ArchiveFile = $IACandidate; break }
}
if (-not $ArchiveFile) {
    # ImmyBot can extract the original upload into a folder beside its cached ZIP.
    $IACandidates = @($IAPackagedFile)
    if ($IAPackageFolder) { $IACandidates += $IAPackageFolder.TrimEnd('\', '/') + '.zip' }
    foreach ($IACandidate in $IACandidates) {
        if ($IACandidate -and [IO.Path]::GetExtension($IACandidate) -ieq '.zip' -and
            (Test-Path -LiteralPath $IACandidate -PathType Leaf)) {
            $ArchiveFile = $IACandidate
            break
        }
    }
}
if (-not $ArchiveFile) { throw 'Missing installer-source.zip. Upload the generated ImmyBot package or add installer-source.zip as an individual Datto component attachment.' }
$ArchiveStream = $null
$ArchiveFolder = Join-Path ([IO.Path]::GetTempPath()) ('IA-Installer-' + [guid]::NewGuid().ToString('N'))
try {
    $ArchiveStream = [IO.File]::Open($ArchiveFile, [IO.FileMode]::Open, [IO.FileAccess]::Read, [IO.FileShare]::Read)
    if ((Get-FileHash -InputStream $ArchiveStream -Algorithm SHA256).Hash -ne '{{Sha256}}') {
        throw 'Installer ZIP differs from the ZIP validated in Sandbox.'
    }
    Add-Type -AssemblyName System.IO.Compression.FileSystem
    [IO.Compression.ZipFile]::ExtractToDirectory($ArchiveFile, $ArchiveFolder)
    $InstallerFile = Join-Path $ArchiveFolder ([Text.Encoding]::UTF8.GetString([Convert]::FromBase64String('{{encodedEntry}}')))
{{script}}
}
finally {
    if ($null -ne $ArchiveStream) { $ArchiveStream.Dispose() }
    if (Test-Path -LiteralPath $ArchiveFolder) { Remove-Item -LiteralPath $ArchiveFolder -Recurse -Force -ErrorAction SilentlyContinue }
}
""";
    }
}

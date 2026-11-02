using System.IO;
using System.Security.Cryptography;
using System.Text;
using InstallerAnalyzer.Models;
using InstallerAnalyzer.Services;

internal static class PeDependencyChecks
{
    private static byte[] Fixture(bool x64 = true)
    {
        var b = new byte[1536];
        void U16(int o, ushort v) => BitConverter.GetBytes(v).CopyTo(b, o);
        void U32(int o, uint v) => BitConverter.GetBytes(v).CopyTo(b, o);
        b[0] = 77; b[1] = 90; U32(60, 128); b[128] = 80; b[129] = 69;
        U16(132, x64 ? (ushort)0x8664 : (ushort)0x14c); U16(134, 1); U16(148, x64 ? (ushort)240 : (ushort)224);
        var o = 152; U16(o, x64 ? (ushort)0x20b : (ushort)0x10b);
        U32(o + 32, 4096); U32(o + 36, 512); U32(o + 56, 8192); U32(o + 60, 512);
        U16(o + 68, 3); var d = o + (x64 ? 112 : 96); U32(d - 4, 16);
        U32(d + 8, 4096); U32(d + 12, 40); U32(d + 13 * 8, 4160); U32(d + 13 * 8 + 4, 64);
        var s = o + (x64 ? 240 : 224); Encoding.ASCII.GetBytes(".rdata").CopyTo(b, s);
        U32(s + 8, 1024); U32(s + 12, 4096); U32(s + 16, 1024); U32(s + 20, 512);
        U32(512 + 12, 4352); U32(576, 1); U32(580, 4384);
        Encoding.ASCII.GetBytes("VCRUNTIME140.dll\0").CopyTo(b, 768);
        Encoding.ASCII.GetBytes("api-ms-win-core-test-l1-1-0.dll\0").CopyTo(b, 800);
        return b;
    }
    public static void Run(string root, Action<bool,string> check)
    {
        var path = Path.Combine(root, "inert-pe-data.bin");
        File.WriteAllBytes(path, Fixture()); var original = SHA256.HashData(File.ReadAllBytes(path));
        var pe = PeDependencyService.Read(path);
        check(pe.Status == "Read-only PE declarations" && pe.Architecture == "x64" && pe.Imports.Count == 2, "PE32+ normal and delay import directories are read as data");
        check(pe.Imports.Any(i => i.Module == "VCRUNTIME140.dll" && i.Kind == "Direct") && pe.Imports.Any(i => i.ApiSetContract && i.Kind == "Delay-load"), "Direct dependencies, conditional delay loads and API-set contracts remain distinct");
        check(original.SequenceEqual(SHA256.HashData(File.ReadAllBytes(path))), "PE inspection never modifies or executes fixture bytes");
        File.WriteAllBytes(path, Fixture(false));
        check(PeDependencyService.Read(path).Architecture == "x86", "PE32 import architecture is retained");
        var bad = Fixture(); BitConverter.GetBytes(uint.MaxValue).CopyTo(bad, 524); File.WriteAllBytes(path, bad);
        check(PeDependencyService.Read(path).Status == "Partial / unavailable", "Out-of-file import RVAs are rejected");
        bad = Fixture(); Encoding.ASCII.GetBytes("../evil.dll\0").CopyTo(bad, 768); File.WriteAllBytes(path, bad);
        check(PeDependencyService.Read(path).Imports.Count == 0, "Import names cannot become directory traversal probes");
        bad = Fixture(); BitConverter.GetBytes(2_000_000).CopyTo(bad, 60); File.WriteAllBytes(path, bad);
        check(PeDependencyService.Read(path).Status == "Partial / unavailable", "Hostile PE header offsets are bounded before header parsing");
        File.WriteAllText(path, "not an executable");
        check(PeDependencyService.Read(path).Status == "Not a PE image", "Non-PE input is not labelled as having no dependencies");
        var own = PeDependencyService.Read(Path.Combine(AppContext.BaseDirectory, "Verification.dll"));
        check(own.Status == "Read-only PE declarations" && own.Architecture == "Managed AnyCPU", "Managed AnyCPU images do not fabricate native x86 system-path observations");
        if (File.Exists(@"D:\lghub_installer.exe"))
        {
            var logitech = PeDependencyService.Read(@"D:\lghub_installer.exe");
            check(logitech.Imports.Any(i => i.Module.Equals("VCRUNTIME140_1.dll", StringComparison.OrdinalIgnoreCase)), "Real Logitech source declares the observed Visual C++ import without host execution");
            File.WriteAllText(Path.Combine(root, "logitech-pe-declarations.json"), System.Text.Json.JsonSerializer.Serialize(logitech));
        }
        var proof = new InstallAnalysis { DllFiles = [new() { Module = "VCRUNTIME140.dll", Kind = "Direct", Present = false, Location = "Windows directory", Evidence = "Other loader paths are unresolved" }] };
        IntelligenceReportService.Enrich(proof, null, null);
        check(proof.Intelligence.Prerequisites.Single().Status.Contains("unknown") && !proof.Intelligence.Prerequisites[0].Status.Contains("Missing"), "A DLL absent from one search location does not become a proven missing prerequisite");
    }
}

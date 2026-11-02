using System.IO;
using System.Reflection;
using System.Security.Cryptography;
using System.Windows.Media;
using System.Windows.Media.Imaging;
using InstallerAnalyzer.Services;

internal static class ApplicationLogoChecks
{
    public static void Run(string root, Action<bool, string> check)
    {
        var folder = Path.Combine(root, "logos"); Directory.CreateDirectory(folder);
        var read = typeof(ApplicationLogoService).GetMethod("ReadEmbeddedIcon", BindingFlags.NonPublic | BindingFlags.Static)!;
        BitmapSource? Read(string path) => (BitmapSource?)read.Invoke(null, new object[] { path });
        var executable = Path.Combine(AppContext.BaseDirectory, "InstallerAnalyzer.exe");
        var before = SHA256.HashData(File.ReadAllBytes(executable));
        var embedded = Read(executable);
        check(embedded is { PixelWidth: 256, PixelHeight: 256 }, "Logo extraction preserves the real 256px primary executable icon");
        if (embedded is not null)
        {
            var png = new PngBitmapEncoder(); png.Frames.Add(BitmapFrame.Create(embedded));
            using var output = File.Create(Path.Combine(folder, "native-logo.png")); png.Save(output);
        }
        check(before.SequenceEqual(SHA256.HashData(File.ReadAllBytes(executable))), "Logo resource inspection leaves executable bytes unchanged");
        var frames = new List<byte[]>();
        foreach (var size in new[] { 32, 256 })
        {
            var pixels = Enumerable.Repeat((byte)255, size * size * 4).ToArray();
            var image = BitmapSource.Create(size, size, 96, 96, PixelFormats.Bgra32, null, pixels, size * 4);
            var png = new PngBitmapEncoder(); png.Frames.Add(BitmapFrame.Create(image));
            using var stream = new MemoryStream(); png.Save(stream); frames.Add(stream.ToArray());
        }
        var ico = Path.Combine(folder, "multi-size.ico");
        using (var output = new BinaryWriter(File.Create(ico)))
        {
            output.Write((ushort)0); output.Write((ushort)1); output.Write((ushort)2);
            var offset = 38;
            for (var i = 0; i < frames.Count; i++)
            {
                output.Write((byte)(i == 0 ? 32 : 0)); output.Write((byte)(i == 0 ? 32 : 0));
                output.Write((ushort)0); output.Write((ushort)1); output.Write((ushort)32);
                output.Write(frames[i].Length); output.Write(offset); offset += frames[i].Length;
            }
            foreach (var frame in frames) output.Write(frame);
        }
        check(Read(ico) is { PixelWidth: 256 }, "Logo extraction selects the largest native ICO frame rather than its first small frame");
        var malformed = Path.Combine(folder, "malformed.ico"); File.WriteAllBytes(malformed, new byte[24]);
        check(Read(malformed) is null, "Malformed icon resources are refused without an application launch");
        var oversized = File.ReadAllBytes(ico);
        var pngOffset = BitConverter.ToInt32(oversized, 18);
        System.Buffers.Binary.BinaryPrimitives.WriteUInt32BigEndian(oversized.AsSpan(pngOffset + 16, 4), 100000);
        File.WriteAllBytes(malformed, oversized);
        check(Read(malformed) is null, "Oversized PNG dimensions inside an ICO are refused before decoding");
    }
}

using System.IO;
using System.Runtime.InteropServices;
using System.Windows;
using System.Windows.Interop;
using System.Windows.Media.Imaging;

namespace InstallerAnalyzer.Services;

public static class ApplicationLogoService
{
    [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
    private struct SHFILEINFO
    {
        public IntPtr hIcon;
        public int iIcon;
        public uint dwAttributes;
        [MarshalAs(UnmanagedType.ByValTStr, SizeConst = 260)] public string szDisplayName;
        [MarshalAs(UnmanagedType.ByValTStr, SizeConst = 80)] public string szTypeName;
    }

    [DllImport("shell32.dll", CharSet = CharSet.Unicode)]
    private static extern IntPtr SHGetFileInfo(string pszPath, uint dwFileAttributes, out SHFILEINFO psfi, uint cbFileInfo, uint uFlags);
    [DllImport("user32.dll")] private static extern bool DestroyIcon(IntPtr hIcon);
    private delegate bool ResourceNameCallback(IntPtr module, IntPtr type, IntPtr name, IntPtr parameter);
    [DllImport("kernel32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
    private static extern IntPtr LoadLibraryEx(string path, IntPtr file, uint flags);
    [DllImport("kernel32.dll")] private static extern bool FreeLibrary(IntPtr module);
    [DllImport("kernel32.dll", CharSet = CharSet.Unicode)]
    private static extern bool EnumResourceNames(IntPtr module, IntPtr type, ResourceNameCallback callback, IntPtr parameter);
    [DllImport("kernel32.dll", CharSet = CharSet.Unicode)]
    private static extern IntPtr FindResource(IntPtr module, IntPtr name, IntPtr type);
    [DllImport("kernel32.dll")] private static extern uint SizeofResource(IntPtr module, IntPtr resource);
    [DllImport("kernel32.dll")] private static extern IntPtr LoadResource(IntPtr module, IntPtr resource);
    [DllImport("kernel32.dll")] private static extern IntPtr LockResource(IntPtr resource);

    private const uint SHGFI_ICON = 0x100;
    private const uint SHGFI_LARGEICON = 0x0;

    public static string? ExtractPng(string sourcePath)
    {
        if (!File.Exists(sourcePath)) return null;
        var embedded = ReadEmbeddedIcon(Path.GetFullPath(sourcePath));
        if (embedded is not null) return SavePng(sourcePath, embedded);
        if (SHGetFileInfo(sourcePath, 0, out var info, (uint)Marshal.SizeOf<SHFILEINFO>(), SHGFI_ICON | SHGFI_LARGEICON) == IntPtr.Zero || info.hIcon == IntPtr.Zero) return null;
        try
        {
            var bitmap = Imaging.CreateBitmapSourceFromHIcon(info.hIcon, Int32Rect.Empty, BitmapSizeOptions.FromEmptyOptions());
            bitmap.Freeze();
            return SavePng(sourcePath, bitmap);
        }
        finally { DestroyIcon(info.hIcon); }
    }

    private static BitmapSource? ReadEmbeddedIcon(string path)
    {
        if (!new[] { ".exe", ".dll", ".ico" }.Contains(Path.GetExtension(path), StringComparer.OrdinalIgnoreCase)) return null;
        var module = IntPtr.Zero;
        try
        {
            if (Path.GetExtension(path).Equals(".ico", StringComparison.OrdinalIgnoreCase))
            {
                if (new FileInfo(path).Length > 16 * 1024 * 1024) return null;
                using var input = File.OpenRead(path);
                return LargestFrame(input);
            }
            // Map resources as data only: no entry point or imported code is executed.
            module = LoadLibraryEx(path, IntPtr.Zero, 0x00000002 | 0x00000020);
            if (module == IntPtr.Zero) return null;
            byte[]? group = null;
            ResourceNameCallback callback = (handle, type, name, _) =>
            {
                group = ReadResource(handle, name, type, 6 + 256 * 14);
                return false; // Keep the primary icon group; do not select unrelated artwork.
            };
            EnumResourceNames(module, new IntPtr(14), callback, IntPtr.Zero);
            GC.KeepAlive(callback);
            if (group is null || group.Length < 6 || BitConverter.ToUInt16(group, 0) != 0 || BitConverter.ToUInt16(group, 2) != 1) return null;
            var count = BitConverter.ToUInt16(group, 4);
            if (count == 0 || count > 256 || group.Length < 6 + count * 14) return null;
            var candidates = Enumerable.Range(0, count).Select(i => 6 + i * 14)
                .OrderByDescending(i => (group[i] == 0 ? 256 : group[i]) * (group[i + 1] == 0 ? 256 : group[i + 1]))
                .ThenByDescending(i => BitConverter.ToUInt16(group, i + 6));
            foreach (var offset in candidates)
            {
                try
                {
                    var bytes = ReadResource(module, new IntPtr(BitConverter.ToUInt16(group, offset + 12)), new IntPtr(3), 16 * 1024 * 1024);
                    if (bytes is null || bytes.Length != BitConverter.ToUInt32(group, offset + 8) || !HasBoundedDimensions(bytes)) continue;
                    using var ico = new MemoryStream();
                    using (var writer = new BinaryWriter(ico, System.Text.Encoding.UTF8, true))
                    {
                        writer.Write((ushort)0); writer.Write((ushort)1); writer.Write((ushort)1);
                        writer.Write(group, offset, 8); writer.Write(bytes.Length); writer.Write(22); writer.Write(bytes);
                    }
                    ico.Position = 0;
                    var image = LargestFrame(ico);
                    if (image is not null) return image;
                }
                catch (Exception ex) when (ex is IOException or NotSupportedException or ArgumentException or FormatException or COMException) { }
            }
        }
        catch (Exception ex) when (ex is IOException or NotSupportedException or ArgumentException or FormatException or COMException or System.ComponentModel.Win32Exception) { }
        finally { if (module != IntPtr.Zero) FreeLibrary(module); }
        return null;
    }

    private static byte[]? ReadResource(IntPtr module, IntPtr name, IntPtr type, int limit)
    {
        var resource = FindResource(module, name, type);
        if (resource == IntPtr.Zero) return null;
        var size = SizeofResource(module, resource);
        if (size == 0 || size > limit) return null;
        var pointer = LockResource(LoadResource(module, resource));
        if (pointer == IntPtr.Zero) return null;
        var bytes = new byte[(int)size]; Marshal.Copy(pointer, bytes, 0, bytes.Length);
        return bytes;
    }

    private static BitmapSource? LargestFrame(Stream input)
    {
        if (input.Length < 6 || input.Length > 16 * 1024 * 1024) return null;
        using (var reader = new BinaryReader(input, System.Text.Encoding.UTF8, true))
        {
            if (reader.ReadUInt16() != 0 || reader.ReadUInt16() != 1) return null;
            var count = reader.ReadUInt16();
            if (count == 0 || count > 256 || input.Length < 6 + 16 * count) return null;
            for (var i = 0; i < count; i++)
            {
                input.Position = 6 + 16 * i + 8;
                var length = reader.ReadUInt32(); var offset = reader.ReadUInt32();
                if (length < 16 || length > 16 * 1024 * 1024 || offset < 6 + 16 * count || (long)offset + length > input.Length) return null;
                input.Position = offset;
                if (!HasBoundedDimensions(reader.ReadBytes((int)Math.Min(length, 32)))) return null;
            }
        }
        input.Position = 0;
        var decoder = new IconBitmapDecoder(input, BitmapCreateOptions.PreservePixelFormat, BitmapCacheOption.OnLoad);
        var frame = decoder.Frames.Where(f => f.PixelWidth <= 1024 && f.PixelHeight <= 1024)
            .OrderByDescending(f => (long)f.PixelWidth * f.PixelHeight).ThenByDescending(f => f.Format.BitsPerPixel).FirstOrDefault();
        frame?.Freeze();
        return frame;
    }

    private static bool HasBoundedDimensions(byte[] bytes)
    {
        if (bytes.Length < 16) return false;
        if (bytes.AsSpan(0, 8).SequenceEqual(new byte[] { 137, 80, 78, 71, 13, 10, 26, 10 }))
        {
            if (bytes.Length < 24 || !bytes.AsSpan(12, 4).SequenceEqual("IHDR"u8)) return false;
            var width = System.Buffers.Binary.BinaryPrimitives.ReadUInt32BigEndian(bytes.AsSpan(16, 4));
            var height = System.Buffers.Binary.BinaryPrimitives.ReadUInt32BigEndian(bytes.AsSpan(20, 4));
            return width is > 0 and <= 1024 && height is > 0 and <= 1024;
        }
        var header = BitConverter.ToUInt32(bytes, 0);
        var dibWidth = header == 12 ? BitConverter.ToUInt16(bytes, 4) : BitConverter.ToInt32(bytes, 4);
        var dibHeight = header == 12 ? BitConverter.ToUInt16(bytes, 6) : BitConverter.ToInt32(bytes, 8);
        return header is 12 or 40 or 52 or 56 or 108 or 124 && dibWidth is > 0 and <= 1024 && dibHeight is > 0 and <= 2048;
    }

    private static string SavePng(string sourcePath, BitmapSource bitmap)
    {
        var folder = Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData), "InstallerAnalyzer", "logos");
        Directory.CreateDirectory(folder);
        var output = Path.Combine(folder, Path.GetFileNameWithoutExtension(sourcePath) + "-Logo.png");
        var encoder = new PngBitmapEncoder(); encoder.Frames.Add(BitmapFrame.Create(bitmap));
        using var stream = File.Create(output); encoder.Save(stream);
        return output;
    }
}

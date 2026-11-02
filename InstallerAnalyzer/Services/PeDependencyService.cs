using System.IO;
using System.Reflection.PortableExecutable;
using System.Text;
using System.Text.RegularExpressions;
using InstallerAnalyzer.Models;
namespace InstallerAnalyzer.Services;

// Reads PE data tables only. Never loads an image or resolves/executes its imports.
public static class PeDependencyService
{
    public static PeDependencies Read(string path)
    {
        var result = new PeDependencies();
        try
        {
            using var file = new FileStream(path, FileMode.Open, FileAccess.Read, FileShare.Read);
            if (file.Length < 64) return result;
            var dos = new byte[64]; file.ReadExactly(dos);
            if (dos[0] != 'M' || dos[1] != 'Z') return result;
            var peOffset = BitConverter.ToInt32(dos, 60);
            if (peOffset < 64 || peOffset > 1024 * 1024 || peOffset > file.Length - 24) throw new InvalidDataException("PE header offset exceeds its read range.");
            file.Position = peOffset; var coff = new byte[24]; file.ReadExactly(coff);
            if (BitConverter.ToUInt16(coff, 6) > 96 || BitConverter.ToUInt16(coff, 20) > 4096) throw new InvalidDataException("PE header/section limit reached.");
            file.Position = 0;
            using var image = new PEReader(file, PEStreamOptions.LeaveOpen);
            var header = image.PEHeaders.PEHeader ?? throw new InvalidDataException("Optional PE header unavailable.");
            result.Architecture = image.PEHeaders.CoffHeader.Machine switch
            {
                Machine.I386 when header.Magic == PEMagic.PE32 => "x86",
                Machine.Amd64 when header.Magic == PEMagic.PE32Plus => "x64",
                Machine.Arm64 when header.Magic == PEMagic.PE32Plus => "arm64", _ => "Unknown"
            };
            var clr = image.PEHeaders.CorHeader;
            if (image.PEHeaders.CoffHeader.Machine == Machine.I386 && clr is not null && (clr.Flags & CorFlags.ILOnly) != 0 &&
                (clr.Flags & (CorFlags.Requires32Bit | CorFlags.Prefers32Bit)) == 0) result.Architecture = "Managed AnyCPU";
            var bytesRead = 0;
            byte[] ReadRva(uint rva, int length)
            {
                if (length < 1 || (bytesRead += length) > 256 * 1024) throw new InvalidDataException("Import read budget reached.");
                var matches = image.PEHeaders.SectionHeaders.Where(s => rva >= (uint)s.VirtualAddress && (ulong)rva - (uint)s.VirtualAddress + (uint)length <= (uint)s.SizeOfRawData).ToArray();
                if (matches.Length != 1) throw new InvalidDataException("Import RVA is outside a unique raw section.");
                var offset = checked((long)matches[0].PointerToRawData + rva - matches[0].VirtualAddress);
                if (offset < 0 || offset > file.Length - length) throw new InvalidDataException("Import data is outside the source file.");
                file.Position = offset; var data = new byte[length]; file.ReadExactly(data); return data;
            }
            void ReadTable(DirectoryEntry directory, bool delayed)
            {
                if (directory.RelativeVirtualAddress == 0 && directory.Size == 0) return;
                var width = delayed ? 32 : 20;
                if (directory.RelativeVirtualAddress <= 0 || directory.Size < width) throw new InvalidDataException("Invalid import directory.");
                for (var index = 0; index < 128 && result.Imports.Count < 256; index++)
                {
                    if ((index + 1L) * width > directory.Size) throw new InvalidDataException("Import table terminator exceeds its declared bounds.");
                    var row = ReadRva(checked((uint)directory.RelativeVirtualAddress + (uint)(index * width)), width);
                    if (row.All(b => b == 0)) return;
                    var nameRva = BitConverter.ToUInt32(row, delayed ? 4 : 12);
                    if (delayed && (BitConverter.ToUInt32(row, 0) & 1) == 0)
                    {
                        if ((ulong)nameRva < header.ImageBase || (ulong)nameRva - header.ImageBase > uint.MaxValue) throw new InvalidDataException("Unsupported delay-import virtual address.");
                        nameRva = (uint)((ulong)nameRva - header.ImageBase);
                    }
                    var name = new StringBuilder();
                    for (uint i = 0; i < 256; i++)
                    {
                        var ch = ReadRva(checked(nameRva + i), 1)[0]; if (ch == 0) break;
                        if (ch > 127 || i == 255) throw new InvalidDataException("Unterminated or non-ASCII import name.");
                        name.Append((char)ch);
                    }
                    var module = name.ToString();
                    if (!Regex.IsMatch(module, @"\A[A-Za-z0-9_][A-Za-z0-9_.-]{0,246}\.dll\z", RegexOptions.IgnoreCase) || module.Contains("..")) throw new InvalidDataException("Import name is not a literal DLL basename.");
                    if (!result.Imports.Any(i => i.Module.Equals(module, StringComparison.OrdinalIgnoreCase) && i.Kind == (delayed ? "Delay-load" : "Direct")))
                        result.Imports.Add(new() { Module = module, Kind = delayed ? "Delay-load" : "Direct", ApiSetContract = module.StartsWith("api-ms-", StringComparison.OrdinalIgnoreCase) || module.StartsWith("ext-ms-", StringComparison.OrdinalIgnoreCase) });
                }
                throw new InvalidDataException("Import descriptor limit reached.");
            }
            ReadTable(header.ImportTableDirectory, false); ReadTable(header.DelayImportTableDirectory, true);
            result.Status = "Read-only PE declarations";
        }
        catch (Exception ex) when (ex is IOException or BadImageFormatException or ArgumentException or OverflowException or UnauthorizedAccessException or InvalidDataException)
        { result.Status = "Partial / unavailable"; result.Limitations.Add(ex.Message); }
        result.Limitations.Add("Direct imports are declared dependencies; delay-load imports may be conditional. API sets are loader contracts. File observations do not reproduce loader search, side-by-side, package graph or transitive dependency resolution.");
        return result;
    }
}

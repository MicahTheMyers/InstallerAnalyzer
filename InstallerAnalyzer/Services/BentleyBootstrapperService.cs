using System.Buffers.Binary;
using System.IO;
using System.Reflection.PortableExecutable;
using System.Text;

namespace InstallerAnalyzer.Services;

public sealed record EmbeddedCabinetFile(string Name, uint Bytes);
public sealed record BentleyBootstrapperEvidence(long CabinetOffset, uint CabinetBytes, IReadOnlyList<EmbeddedCabinetFile> Files);

// Read only the CAB directory in the declared PE resource region. No payload is expanded or run.
public static class BentleyBootstrapperService
{
    public static BentleyBootstrapperEvidence? Inspect(string path, string company)
    {
        if (!company.StartsWith("Bentley Systems", StringComparison.OrdinalIgnoreCase)) return null;
        try
        {
            using var stream = File.OpenRead(path);
            using var pe = new PEReader(stream, PEStreamOptions.LeaveOpen);
            var directory = pe.PEHeaders.PEHeader?.ResourceTableDirectory;
            if (directory is null || directory.Value.Size <= 0) return null;
            var resource = directory.Value;
            var section = pe.PEHeaders.SectionHeaders.FirstOrDefault(s => resource.RelativeVirtualAddress >= s.VirtualAddress &&
                (long)resource.RelativeVirtualAddress + resource.Size <= (long)s.VirtualAddress + s.SizeOfRawData);
            if (section.SizeOfRawData <= 0) return null;
            long start = (long)section.PointerToRawData + resource.RelativeVirtualAddress - section.VirtualAddress;
            long end = start + resource.Size;
            if (start < 0 || end > stream.Length) return null;
            var prefix = new byte[Math.Min(resource.Size, 1024 * 1024)];
            stream.Position = start; stream.ReadExactly(prefix);
            int candidates = 0;
            for (int i = 0; i + 36 <= prefix.Length; i++)
            {
                if (!prefix.AsSpan(i, 4).SequenceEqual("MSCF"u8)) continue;
                if (++candidates > 16) break;
                long offset = start + i;
                var header = prefix.AsSpan(i, 36);
                uint size = BinaryPrimitives.ReadUInt32LittleEndian(header[8..]);
                uint table = BinaryPrimitives.ReadUInt32LittleEndian(header[16..]);
                int folders = BinaryPrimitives.ReadUInt16LittleEndian(header[26..]);
                int count = BinaryPrimitives.ReadUInt16LittleEndian(header[28..]);
                // Initial scope is a non-spanned CAB without reserved fields, version 1.3.
                if (header[24] != 3 || header[25] != 1 || folders is < 1 or > 32 || count is < 3 or > 256 ||
                    BinaryPrimitives.ReadUInt16LittleEndian(header[30..]) != 0 ||
                    BinaryPrimitives.ReadUInt32LittleEndian(header[4..]) != 0 ||
                    BinaryPrimitives.ReadUInt32LittleEndian(header[12..]) != 0 ||
                    BinaryPrimitives.ReadUInt32LittleEndian(header[20..]) != 0 ||
                    size < 36 || offset + size > end || table < 36 + folders * 8 || table >= size || table > 1024 * 1024) continue;
                long fileTableEnd = Math.Min(offset + size, offset + table + 128 * 1024);
                stream.Position = offset + 36;
                bool valid = true; uint firstData = size;
                using var reader = new BinaryReader(stream, Encoding.UTF8, leaveOpen: true);
                for (int folder = 0; folder < folders; folder++)
                {
                    uint dataOffset = reader.ReadUInt32(); ushort blocks = reader.ReadUInt16(); reader.ReadUInt16();
                    if (blocks == 0 || dataOffset <= table || dataOffset >= size) valid = false;
                    firstData = Math.Min(firstData, dataOffset);
                }
                if (!valid) continue;
                fileTableEnd = Math.Min(fileTableEnd, offset + firstData);
                stream.Position = offset + table;
                var files = new List<EmbeddedCabinetFile>();
                var names = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
                for (int file = 0; file < count && valid; file++)
                {
                    if (stream.Position + 17 > fileTableEnd) { valid = false; break; }
                    uint bytes = reader.ReadUInt32(); reader.ReadUInt32(); ushort folder = reader.ReadUInt16();
                    reader.ReadUInt16(); reader.ReadUInt16(); ushort attributes = reader.ReadUInt16();
                    var nameBytes = new List<byte>(); bool terminated = false;
                    while (nameBytes.Count < 260 && stream.Position < fileTableEnd)
                    {
                        byte value = reader.ReadByte(); if (value == 0) { terminated = true; break; } nameBytes.Add(value);
                    }
                    if (!terminated || folder >= folders) { valid = false; break; }
                    string name = (attributes & 0x80) != 0 ? new UTF8Encoding(false, true).GetString(nameBytes.ToArray()) : Encoding.Latin1.GetString(nameBytes.ToArray());
                    // Only the flat package layout is supported; names are never used to extract files.
                    if (name.Length == 0 || name.Contains('/') || name.Contains('\\') || name.Contains(':') || name.Contains("..") ||
                        name.Any(char.IsControl) || !names.Add(name)) { valid = false; break; }
                    files.Add(new(name, bytes));
                }
                if (valid && files.Any(f => f.Name.Equals("Settings.ini", StringComparison.OrdinalIgnoreCase) && f.Bytes > 0) &&
                    files.Any(f => f.Name.Equals("PrereqInst32.exe", StringComparison.OrdinalIgnoreCase) && f.Bytes > 0) &&
                    files.Any(f => f.Name.EndsWith(".msi", StringComparison.OrdinalIgnoreCase) && f.Bytes > 0))
                    return new(offset, size, files);
            }
        }
        catch (Exception ex) when (ex is IOException or UnauthorizedAccessException or BadImageFormatException or ArgumentException or OverflowException) { }
        return null;
    }
}

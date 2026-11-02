using System.IO;
using System.Text;

namespace InstallerAnalyzer.Services;

internal static class AnalysisArtifactReader
{
    // The guest replaces checkpoints and can still be committing the terminal result.
    // Permit those writes/deletes while reading one open-file snapshot; retry transient sharing failures.
    public static string ReadText(string path, int maxCharacters = 16 * 1024 * 1024)
    {
        if (maxCharacters is < 1 or > 16 * 1024 * 1024) throw new ArgumentOutOfRangeException(nameof(maxCharacters));
        for (var attempt = 0; ; attempt++)
            try
            {
                using var file = new FileStream(path, FileMode.Open, FileAccess.Read, FileShare.ReadWrite | FileShare.Delete);
                if (file.Length > maxCharacters * 4L + 4) throw new InvalidDataException("Analysis artifact exceeds its read limit.");
                using var reader = new StreamReader(file, Encoding.UTF8, true, 4096);
                var text = new StringBuilder(); var buffer = new char[4096];
                while (text.Length < maxCharacters)
                {
                    var count = reader.Read(buffer, 0, Math.Min(buffer.Length, maxCharacters - text.Length));
                    if (count == 0) return text.ToString();
                    text.Append(buffer, 0, count);
                }
                if (reader.Peek() >= 0) throw new InvalidDataException("Analysis artifact exceeds its read limit.");
                return text.ToString();
            }
            catch (IOException) when (attempt < 2) { Thread.Sleep(40); }
    }
}

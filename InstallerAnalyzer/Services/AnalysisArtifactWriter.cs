using System.IO;

namespace InstallerAnalyzer.Services;

internal static class AnalysisArtifactWriter
{
    public static void Write(string path, string content)
    {
        var temporary = path + "." + Guid.NewGuid().ToString("N") + ".tmp";
        try
        {
            File.WriteAllText(temporary, content);
            File.Move(temporary, path, true);
        }
        finally { try { if (File.Exists(temporary)) File.Delete(temporary); } catch { } }
    }
}

using System.IO;

namespace InstallerAnalyzer;

public partial class MainWindow
{
    private string? _archiveInspectionFolder;

    private string? ChooseArchiveInstaller(string[] entries)
    {
        if (entries.Length == 0)
            throw new InvalidDataException("The ZIP does not contain an EXE or MSI installer.");
        var picker = new ArchiveInstallerWindow(this, entries);
        return picker.ShowDialog() == true ? picker.SelectedInstaller : null;
    }

    private static void DeleteArchiveInspection(string? folder)
    {
        if (folder is null) return;
        try { Directory.Delete(folder, recursive: true); }
        catch (IOException) { }
        catch (UnauthorizedAccessException) { }
    }
}

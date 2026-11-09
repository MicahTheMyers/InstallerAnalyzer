namespace InstallerAnalyzer.Models;

// Byte-preserving attachments, bound to an exact installer hash by their catalog record.
public sealed class CatalogRecording
{
    public CatalogResponseFile Setup { get; set; } = new();
    public CatalogResponseFile Uninstall { get; set; } = new();
}

public sealed class CatalogResponseFile
{
    public string Sha256 { get; set; } = "";
    public string Base64 { get; set; } = "";
}

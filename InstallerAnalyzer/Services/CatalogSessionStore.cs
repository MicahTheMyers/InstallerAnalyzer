using System.IO;
using System.Security.Cryptography;
using System.Text;

namespace InstallerAnalyzer.Services;

internal sealed class CatalogSessionStore(Uri endpoint, string? tlsFingerprint)
{
    private readonly string _path = Path.Combine(
        Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData), "InstallerAnalyzer",
        "catalog-session-" + Convert.ToHexString(SHA256.HashData(
            Encoding.UTF8.GetBytes(endpoint.AbsoluteUri + "|" + tlsFingerprint?.ToUpperInvariant()))) + ".dpapi");

    public string? Load()
    {
        try
        {
            var bytes = ProtectedData.Unprotect(File.ReadAllBytes(_path), null, DataProtectionScope.CurrentUser);
            var token = Encoding.ASCII.GetString(bytes);
            return token.Length == 64 && token.All(Uri.IsHexDigit) ? token : null;
        }
        catch (FileNotFoundException) { return null; }
        catch (DirectoryNotFoundException) { return null; }
        catch (CryptographicException) { return null; }
    }

    public void Save(string token)
    {
        Directory.CreateDirectory(Path.GetDirectoryName(_path)!);
        var temporary = _path + "." + Guid.NewGuid().ToString("N") + ".tmp";
        try
        {
            File.WriteAllBytes(temporary, ProtectedData.Protect(Encoding.ASCII.GetBytes(token), null, DataProtectionScope.CurrentUser));
            File.Move(temporary, _path, overwrite: true);
        }
        finally { File.Delete(temporary); }
    }

    public void Clear(string? token)
    {
        if (token is not null && Load() == token)
            File.Delete(_path);
    }
}

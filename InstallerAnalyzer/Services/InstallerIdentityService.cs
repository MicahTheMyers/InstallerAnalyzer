using System.Diagnostics;
using System.IO;
using System.Text;
using System.Text.Json;
using InstallerAnalyzer.Models;

namespace InstallerAnalyzer.Services;

public static class InstallerIdentityService
{
    public static InstallerIdentity Inspect(string path)
    {
        var identity = new InstallerIdentity { Sha256 = RegressionHistoryService.HashFile(path), Pe = PeDependencyService.Read(path) };
        try
        {
            // Get-AuthenticodeSignature validates the signature; extracting a certificate alone does not.
            var literal = "'" + path.Replace("'", "''") + "'";
            var script = "$ErrorActionPreference='Stop'; $ProgressPreference='SilentlyContinue'; $s=Microsoft.PowerShell.Security\\Get-AuthenticodeSignature -LiteralPath " + literal + "; " +
                "[pscustomobject]@{Status=$s.Status.ToString();Thumbprint=$s.SignerCertificate.Thumbprint;Subject=$s.SignerCertificate.Subject}|ConvertTo-Json -Compress";
            var startInfo = new ProcessStartInfo
            {
                FileName = Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.Windows), "System32", "WindowsPowerShell", "v1.0", "powershell.exe"),
                Arguments = "-NoProfile -NonInteractive -EncodedCommand " + Convert.ToBase64String(Encoding.Unicode.GetBytes(script)),
                UseShellExecute = false, CreateNoWindow = true, RedirectStandardOutput = true, RedirectStandardError = true
            };
            // PowerShell 7 launchers can pass incompatible module directories to
            // Windows PowerShell 5.1. Resolve the built-in trust checker from its
            // own module directory without changing the caller's environment.
            startInfo.Environment["PSModulePath"] = Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.Windows), "System32", "WindowsPowerShell", "v1.0", "Modules");
            using var process = Process.Start(startInfo);
            if (process is null) return identity;
            var output = process.StandardOutput.ReadToEndAsync();
            var errors = process.StandardError.ReadToEndAsync();
            if (!process.WaitForExit(12000))
            {
                try { process.Kill(true); } catch { }
                identity.SignatureStatus = "Check timed out";
                return identity;
            }
            if (process.ExitCode != 0 || !output.Wait(1000)) { identity.SignatureStatus = "Check failed"; return identity; }
            using var json = JsonDocument.Parse(output.Result);
            identity.SignatureStatus = json.RootElement.GetProperty("Status").GetString() ?? "Unknown";
            identity.SignerThumbprint = json.RootElement.GetProperty("Thumbprint").GetString() ?? "";
            identity.SignerSubject = json.RootElement.GetProperty("Subject").GetString() ?? "";
        }
        catch { identity.SignatureStatus = "Check unavailable"; }
        return identity;
    }
}

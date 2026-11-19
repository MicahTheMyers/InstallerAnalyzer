using System.Diagnostics;
using System.IO;
using System.Text;
using System.Text.Json;

namespace InstallerAnalyzer.Services;

internal static class SandboxScriptValidator
{
    internal static string[] Validate(string script)
    {
        SandboxScriptStore.CheckLength(script);
        var path = Path.Combine(Path.GetTempPath(), "IA-script-check-" + Guid.NewGuid().ToString("N") + ".ps1");
        try
        {
            File.WriteAllText(path, script, new UTF8Encoding(true));
            return ValidateFile(path);
        }
        finally { if (File.Exists(path)) File.Delete(path); }
    }

    internal static string[] ValidateFile(string path)
    {
        // Parse the file with the same PowerShell version as the guest. The file is never executed on the host.
        var command = "$ErrorActionPreference='Stop';$tokens=$null;$errors=$null;" +
            "[void][System.Management.Automation.Language.Parser]::ParseFile('" + path.Replace("'", "''") + "',[ref]$tokens,[ref]$errors);" +
            "ConvertTo-Json -Compress -InputObject @($errors | Select-Object -First 8 | ForEach-Object { 'Line '+$_.Extent.StartLineNumber+', column '+$_.Extent.StartColumnNumber+': '+$_.Message })";
        var start = new ProcessStartInfo
        {
            FileName = Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.Windows), "System32", "WindowsPowerShell", "v1.0", "powershell.exe"),
            Arguments = "-NoProfile -NonInteractive -EncodedCommand " + Convert.ToBase64String(Encoding.Unicode.GetBytes(command)),
            UseShellExecute = false, CreateNoWindow = true, RedirectStandardOutput = true, RedirectStandardError = true
        };
        start.Environment["PSModulePath"] = Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.Windows), "System32", "WindowsPowerShell", "v1.0", "Modules");
        using var process = Process.Start(start) ?? throw new IOException("PowerShell could not start the syntax check.");
        var output = process.StandardOutput.ReadToEndAsync();
        var errors = process.StandardError.ReadToEndAsync();
        if (!process.WaitForExit(15000))
        {
            try { process.Kill(true); } catch { }
            throw new IOException("The PowerShell syntax check timed out.");
        }
        if (process.ExitCode != 0) throw new IOException("The PowerShell syntax check failed. " + errors.GetAwaiter().GetResult());
        return JsonSerializer.Deserialize<string[]>(output.GetAwaiter().GetResult()) ?? [];
    }
}

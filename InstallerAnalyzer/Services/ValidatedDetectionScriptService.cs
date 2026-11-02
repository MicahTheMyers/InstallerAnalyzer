using System.Text.RegularExpressions;
using InstallerAnalyzer.Models;

namespace InstallerAnalyzer.Services;

public static class ValidatedDetectionScriptService
{
    public static string? Generate(InstallAnalysis? proof)
    {
        var rule = proof?.DetectionStrategies.Where(d => d.Validated).OrderByDescending(d => d.Rank).FirstOrDefault();
        if (rule is null) return null;
        string Quote(string value) => "'" + value.Replace("'", "''") + "'";
        var header = "# Lifecycle-tested detection: " + rule.Type + "\n# Presence: before=False; installed=True; after uninstall=False\n";
        if (rule.Type == "MsiProductCode" && rule.Provider == "WindowsInstallerProductState")
        {
            if (!Guid.TryParse(rule.Identity, out var code) || code == Guid.Empty) return null;
            return header + "$engine = $null\ntry {\n $engine = New-Object -ComObject WindowsInstaller.Installer\n" +
                " $state = [int]$engine.GetType().InvokeMember('ProductState', [Reflection.BindingFlags]::GetProperty, $null, $engine, @(" + Quote(code.ToString("B")) + "))\n" +
                " if ($state -eq 5) { $true } elseif ($state -eq -1) { $false } else { throw ('MSI product state requires review: ' + $state) }\n" +
                "} finally { if ($null -ne $engine) { [void][Runtime.InteropServices.Marshal]::FinalReleaseComObject($engine) } }\n";
        }
        if (rule.Type == "ApplicationRegistryValue")
        {
            if (rule.RegistryHive is not ("LocalMachine" or "CurrentUser") || rule.RegistryView is not ("Registry32" or "Registry64")) return null;
            return header + "$base = $null; $key = $null\ntry {\n $base = [Microsoft.Win32.RegistryKey]::OpenBaseKey([Microsoft.Win32.RegistryHive]::" + rule.RegistryHive + ", [Microsoft.Win32.RegistryView]::" + rule.RegistryView + ")\n" +
                " $key = $base.OpenSubKey(" + Quote(rule.RegistrySubKey) + ", $false)\n" +
                " if ($null -eq $key) { $false } else { [bool]@($key.GetValueNames() | Where-Object { $_ -eq " + Quote(rule.ValueName) + " }).Count }\n" +
                "} finally { if ($null -ne $key) { $key.Dispose() }; if ($null -ne $base) { $base.Dispose() } }\n";
        }
        if (rule.Type == "WindowsService")
            return header + "$name = " + Quote(rule.Identity) + "\n[bool]@(Get-Service -ErrorAction Stop | Where-Object { $_.ServiceName -eq $name }).Count\n";
        if (rule.Type == "ServiceAndExecutable")
            return header + "$name = " + Quote(rule.Identity) + "\nif (@(Get-Service -ErrorAction Stop | Where-Object { $_.ServiceName -eq $name }).Count -eq 0) { $false; return }\ntry { $null = Get-Item -LiteralPath " + Quote(rule.ExecutablePath) + " -ErrorAction Stop; $true } catch { if ($_.CategoryInfo.Category -eq 'ObjectNotFound') { $false } else { throw } }\n";
        if (rule.Type == "ExecutablePathAndVersion" && !string.IsNullOrWhiteSpace(rule.Version))
            return header + "$path = " + Quote(rule.Identity) + "\ntry { $null = Get-Item -LiteralPath $path -ErrorAction Stop; [bool]([Diagnostics.FileVersionInfo]::GetVersionInfo($path).FileVersion -eq " + Quote(rule.Version) + ") } catch { if ($_.CategoryInfo.Category -eq 'ObjectNotFound') { $false } else { throw } }\n";
        if (rule.Type == "InstallationDirectory")
            return header + "try { [bool](Get-Item -LiteralPath " + Quote(rule.Identity) + " -ErrorAction Stop).PSIsContainer } catch { if ($_.CategoryInfo.Category -eq 'ObjectNotFound') { $false } else { throw } }\n";
        if (rule.Type == "MsixPackageIdentity")
            return header + "$package = " + Quote(rule.Identity) + "\n[bool]@(Get-AppxPackage -ErrorAction Stop | Where-Object { $_.PackageFullName -eq $package }).Count\n";
        if (rule.Type is not ("MsiProductCode" or "UninstallRegistryKey" or "RegistryAndVersion") ||
            !Regex.IsMatch(rule.RegistryPath, @"^(?i:HKLM:|HKCU:|(?:Microsoft\.PowerShell\.Core\\)?Registry::HKEY_(?:LOCAL_MACHINE|CURRENT_USER)\\)")) return null;
        var script = header + "$key = " + Quote(rule.RegistryPath) + "\n";
        return rule.Type == "RegistryAndVersion"
            ? script + "try { $entry = Get-ItemProperty -LiteralPath $key -ErrorAction Stop; [bool]($entry.DisplayVersion -eq " + Quote(rule.Version ?? "") + ") } catch { if ($_.CategoryInfo.Category -eq 'ObjectNotFound') { $false } else { throw } }\n"
            : script + "try { $null = Get-Item -LiteralPath $key -ErrorAction Stop; $true } catch { if ($_.CategoryInfo.Category -eq 'ObjectNotFound') { $false } else { throw } }\n";
    }
}

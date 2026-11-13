using System.IO;
using System.Reflection;
using System.Text.Json;
using System.Windows.Controls.Primitives;
using InstallerAnalyzer;
using InstallerAnalyzer.Models;
using InstallerAnalyzer.Services;

internal static class SandboxCompatibilityChecks
{
    public static void Run(MainWindow window, string root, Action<bool, string> check)
    {
        check(window.FindName("SandboxCompatibilityCheck") is ToggleButton, "Sandbox compatibility has a Settings switch");
        var settingsType = typeof(MainWindow).GetNestedType("AppSettings", BindingFlags.NonPublic)!;
        var settings = Activator.CreateInstance(settingsType, true)!;
        var property = settingsType.GetProperty("SandboxInstallerCompatibility")!;
        check(!(bool)property.GetValue(settings)!, "Fresh settings retain the default guest security policy");
        property.SetValue(settings, true);
        var restored = JsonSerializer.Deserialize(JsonSerializer.Serialize(settings, settingsType), settingsType)!;
        check((bool)property.GetValue(restored)!, "Sandbox compatibility preference survives a settings round trip");
        var core = typeof(SandboxIssRecorder).GetMethod("BuildDiscoveryScriptCore", BindingFlags.NonPublic | BindingFlags.Static)!;
        string Build(bool enabled) => (string)core.Invoke(null, new object[] { "fixture.msi", InstallerKind.Msi, "/qn /norestart", "", true, true, new MsiMetadata(), false, "", "", enabled, null!, null! })!;
        var enabled = Build(true);
        check(enabled.Contains("Ensure-SandboxInstallerCompatibility $true") && enabled.IndexOf("Ensure-SandboxInstallerCompatibility $true", StringComparison.Ordinal) < enabled.IndexOf("$script:NativeMsiBaselineState=", StringComparison.Ordinal), "Enabled guest preparation runs before installer discovery");
        var localBuilder = typeof(SandboxIssRecorder).GetMethod("BuildDiscoveryScript", BindingFlags.NonPublic | BindingFlags.Static)!;
        var local = (string)localBuilder.Invoke(null, new object[] { "fixture.exe", InstallerKind.Unknown, "", "", true, false })!;
        check(Build(false).Contains("Ensure-SandboxInstallerCompatibility $false") && local.Contains("Ensure-SandboxInstallerCompatibility $false"), "Disabled and local analysis never request a policy change");
        File.WriteAllText(Path.Combine(root, "sandbox-compatibility-enabled.ps1"), enabled);
        var failure = FailureClassificationService.Classify("FAIL", "SANDBOX COMPATIBILITY FAILED", new InstallAnalysis { SandboxCompatibility = new() { Requested = true, Status = "Failed" } }, "Sandbox lifecycle");
        check(failure.Owner == "Sandbox" && failure.Category == FailureCategory.SandboxStartupFailure, "Compatibility preparation failure belongs to Sandbox rather than the installer");
        var observed = new InstallAnalysis { SandboxCompatibility = new() { Requested = true, Prepared = true, Status = "Prepared", BeforeState = 1, AfterState = 0, Detail = "Smart App Control is off in this disposable guest." } };
        check(IntelligenceReportService.Generate(null, observed).Contains(observed.SandboxCompatibility.Detail), "Readable report discloses the guest compatibility environment");
        check(JsonSerializer.Deserialize<InstallAnalysis>("{}")!.SandboxCompatibility.Requested == false, "Older analyses do not imply that compatibility was enabled");
        var strict = new RegressionRun { Mode = "FullAnalysis", Tests = new() { new() { InstallerSha256 = "A", Result = "PASS" } } };
        var compatible = new RegressionRun { Mode = "FullAnalysis", SandboxInstallerCompatibility = true, Tests = new() { new() { InstallerSha256 = "A", Result = "PASS" } } };
        check(RegressionHistoryService.Compare(compatible, strict)[0].Classification == "NOT COMPARABLE", "Different guest security settings cannot create a false regression or improvement");
    }
}

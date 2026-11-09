using System.Diagnostics;
using System.IO;
using System.Text.Json;
using InstallerAnalyzer.Models;
using InstallerAnalyzer.Services;

internal static class GintNetFx3Checks
{
    public static int Run(string root, string installer)
    {
        string wsb = Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData), "Microsoft", "WindowsApps", "wsb.exe");
        string Command(params string[] args)
        {
            var info = new ProcessStartInfo(wsb) { UseShellExecute = false, RedirectStandardOutput = true, RedirectStandardError = true, CreateNoWindow = true };
            foreach (var arg in args) info.ArgumentList.Add(arg);
            using var process = Process.Start(info)!;
            var output = process.StandardOutput.ReadToEnd(); var error = process.StandardError.ReadToEnd(); process.WaitForExit();
            if (process.ExitCode != 0) throw new IOException(error + output);
            return output;
        }
        string[] Ids()
        {
            using var json = JsonDocument.Parse(Command("list", "--raw"));
            return json.RootElement.GetProperty("WindowsSandboxEnvironments").EnumerateArray().Select(e => e.GetProperty("Id").GetString()!).ToArray();
        }
        if (Ids().Length != 0) throw new InvalidOperationException("Existing Sandbox left untouched");
        var hash = RegressionHistoryService.HashFile(installer); string? owned = null;
        try
        {
            var session = SandboxIssRecorder.Start(installer, InstallerKind.InstallShield, true, "/s", "", true, prepareNetFx3: true);
            File.WriteAllText(Path.Combine(root, "session-path.txt"), session.SessionFolder);
            var deadline = DateTime.UtcNow.AddMinutes(20); bool ready = false;
            while (DateTime.UtcNow < deadline)
            {
                if (owned is null) { var ids = Ids(); if (ids.Length > 1) throw new IOException("Ambiguous Sandbox ownership"); if (ids.Length == 1) owned = ids[0]; }
                if (File.Exists(session.CheckpointPath))
                {
                    try
                    {
                        using var json = JsonDocument.Parse(File.ReadAllText(session.CheckpointPath));
                        var result = json.RootElement;
                        if (result.GetProperty("NetFx3Provisioning").GetProperty("RuntimeVerified").GetBoolean() && result.GetProperty("WorkflowStage").GetString() == "Record InstallShield installation response file") { ready = true; break; }
                    }
                    catch (JsonException) { }
                }
                if (File.Exists(session.CompleteFlagPath)) throw new IOException("Analysis completed before interactive startup: " + File.ReadAllText(session.AnalysisPath));
                Thread.Sleep(1000);
            }
            if (!ready || owned is null) throw new TimeoutException("NetFx3 preflight did not reach interactive installer startup");
            // Give the vendor prerequisite launcher time to create its windows; no wizard buttons or terms are accepted.
            Thread.Sleep(45000);
            File.WriteAllText(Path.Combine(session.SessionFolder, "Input", "Probe-Gint.ps1"), "$items=@(Get-Process | Where-Object {$_.MainWindowHandle -ne 0} | Select-Object ProcessName,MainWindowTitle)\n$items | ConvertTo-Json | Set-Content C:\\InstallerOutput\\gint-windows.json -Encoding UTF8\n");
            var probe = "powershell.exe -NoProfile -NonInteractive -ExecutionPolicy RemoteSigned -File C:\\InstallerInput\\Probe-Gint.ps1";
            File.WriteAllText(Path.Combine(root, "window-probe-exec.json"), Command("exec", "--id", owned, "--command", probe, "--run-as", "ExistingLogin", "--raw"));
            var windowsPath = Path.Combine(session.OutputFolder, "gint-windows.json");
            for (int i = 0; i < 15 && !File.Exists(windowsPath); i++) Thread.Sleep(1000);
            File.Copy(session.CheckpointPath, Path.Combine(root, "checkpoint.json"), true);
            var windows = File.Exists(windowsPath) ? File.ReadAllText(windowsPath) : "";
            File.WriteAllText(Path.Combine(root, "gint-windows.json"), windows);
            bool passed = windows.Contains("gINT", StringComparison.OrdinalIgnoreCase) && !windows.Contains("Windows Features", StringComparison.OrdinalIgnoreCase);
            File.WriteAllText(Path.Combine(root, "acceptance.json"), JsonSerializer.Serialize(new { Passed = passed, RuntimeVerified = ready, InstallerStartupOnly = true, FullLifecycleValidated = false, TermsAccepted = false, SourceHashUnchanged = hash == RegressionHistoryService.HashFile(installer), Session = session.SessionFolder }));
            Console.WriteLine(passed ? "PASS gINT startup after production NetFx3 preflight; no Windows Features window; full lifecycle untested" : "FAIL gINT startup window could not be established; inspect evidence");
            return passed ? 0 : 1;
        }
        finally
        {
            if (owned is not null && Ids().Contains(owned)) Command("stop", "--id", owned);
            Console.WriteLine("Remaining Sandbox environments: " + Ids().Length);
        }
    }
}

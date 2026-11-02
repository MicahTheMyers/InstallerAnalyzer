using System.Diagnostics;
using System.Security;
using System.Text;
using System.IO;
using InstallerAnalyzer.Models;

namespace InstallerAnalyzer.Services;

public sealed class SandboxIssSession
{
    public required string SessionFolder { get; init; }
    public required string OutputFolder { get; init; }
    public required string IssPath { get; init; }
    public required string WsbPath { get; init; }
    public string AnalysisPath => Path.Combine(OutputFolder, "install-analysis.json");
    public string CheckpointPath => Path.Combine(OutputFolder, "install-analysis.checkpoint.json");
    public string HeartbeatPath => Path.Combine(OutputFolder, "analysis-heartbeat.txt");
    public string DebugPath => Path.Combine(OutputFolder, "analysis-debug.jsonl");
    public string CompleteFlagPath => Path.Combine(OutputFolder, "analysis-complete.flag");
    public DateTime StartedAt { get; init; } = DateTime.Now;
    public bool RequiresIss { get; init; }
}

public static partial class SandboxIssRecorder
{
    // The modern client can remain open on an error screen after its environment dies.
    // Null means unsupported/unknown; only a successful CLI response can prove absence.
    public static bool? IsEnvironmentRunning()
    {
        try
        {
            using var proc = Process.Start(new ProcessStartInfo { FileName = "wsb.exe", Arguments = "list --raw",
                UseShellExecute = false, RedirectStandardOutput = true, RedirectStandardError = true, CreateNoWindow = true });
            if (proc is null) return null;
            var output = proc.StandardOutput.ReadToEndAsync();
            var error = proc.StandardError.ReadToEndAsync();
            if (!proc.WaitForExit(4000)) { try { proc.Kill(); } catch { } return null; }
            if (proc.ExitCode != 0 || !output.Wait(1000)) return null;
            using var json = System.Text.Json.JsonDocument.Parse(output.Result);
            return json.RootElement.TryGetProperty("WindowsSandboxEnvironments", out var environments) && environments.ValueKind == System.Text.Json.JsonValueKind.Array
                ? environments.GetArrayLength() > 0 : null;
        }
        catch { return null; }
    }
    public static bool IsSandboxAvailable()
    {
        var windows = Environment.GetFolderPath(Environment.SpecialFolder.Windows);
        return File.Exists(Path.Combine(windows, "System32", "WindowsSandbox.exe"));
    }

    public static SandboxIssSession Start(string installerPath, InstallerKind kind, bool requiresIss, string baseSilentArguments, string additionalPackageArguments, bool blockBundledMcAfee, bool silentOnly = false)
    {
        if (!File.Exists(installerPath)) throw new FileNotFoundException("Installer not found.", installerPath);
        if (silentOnly && requiresIss)
            throw new InvalidOperationException("NO SILENT STRATEGY: This package requires a recorded response file. Run Full Analysis to record it before unattended testing.");
        if (!IsSandboxAvailable()) throw new InvalidOperationException("Windows Sandbox was not found. Enable 'Windows Sandbox' in Windows Features, then restart Windows.");

        var root = Path.Combine(Path.GetTempPath(), "InstallerAnalyzer", "ISS-" + DateTime.Now.ToString("yyyyMMdd-HHmmss"));
        var input = Path.Combine(root, "Input");
        var output = Path.Combine(root, "Output");
        Directory.CreateDirectory(input);
        Directory.CreateDirectory(output);

        var installerName = Path.GetFileName(installerPath);
        var copiedInstaller = Path.Combine(input, installerName);
        File.Copy(installerPath, copiedInstaller, true);
        File.WriteAllText(Path.Combine(input, "pe-dependencies.json"), System.Text.Json.JsonSerializer.Serialize(PeDependencyService.Read(copiedInstaller)), new UTF8Encoding(false));

        var ps1 = Path.Combine(input, "Record-Iss.ps1");
        using (var source = typeof(SandboxIssRecorder).Assembly.GetManifestResourceStream("InstallerAnalyzer.PayloadTraceReducer.cs")!)
        using (var target = File.Create(Path.Combine(input, "PayloadTraceReducer.cs"))) source.CopyTo(target);
        var metadata = kind == InstallerKind.Msi ? MsiMetadataService.Read(copiedInstaller) : new MsiMetadata();
        if (File.Exists(installerPath + ".config") && new FileInfo(installerPath + ".config").Length <= 65536)
            File.Copy(installerPath + ".config", copiedInstaller + ".config", true);
        var netFxRequirement = NetFx3RequirementService.Detect(copiedInstaller, metadata);
        NetFx3SandboxSource.Stage(input);
        var sourceCache = Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData), "InstallerAnalyzer", "NetFx3Source");
        if (Directory.Exists(sourceCache))
        {
            var sourceFiles = Directory.EnumerateFiles(sourceCache, "*NetFx3*.cab").Take(8).ToArray();
            if (sourceFiles.Length > 0 && sourceFiles.Sum(p => new FileInfo(p).Length) <= 200L * 1024 * 1024)
            {
                var destination = Path.Combine(input, "NetFx3Source"); Directory.CreateDirectory(destination);
                foreach (var sourceFile in sourceFiles) File.Copy(sourceFile, Path.Combine(destination, Path.GetFileName(sourceFile)));
            }
        }
        File.WriteAllText(ps1, BuildDiscoveryScriptCore(installerName, requiresIss ? InstallerKind.InstallShield : kind,
            requiresIss ? "" : baseSilentArguments, additionalPackageArguments, blockBundledMcAfee, silentOnly, metadata,
            recordResponses: requiresIss, netFxRequirement: netFxRequirement), new UTF8Encoding(false));

        var wsb = Path.Combine(root, "Record-setup-iss.wsb");
        File.WriteAllText(Path.Combine(input, "Start-Analysis.ps1"), GuestBootstrapScript, new UTF8Encoding(false));
        File.WriteAllText(wsb, BuildWsb(input, output), new UTF8Encoding(false));

        Process.Start(new ProcessStartInfo { FileName = wsb, UseShellExecute = true });

        return new SandboxIssSession
        {
            SessionFolder = root,
            OutputFolder = output,
            IssPath = Path.Combine(output, "setup.iss"),
            WsbPath = wsb,
            RequiresIss = requiresIss
        };
    }


    public static SandboxIssSession StartLocal(string installerPath)
    {
        if (!File.Exists(installerPath)) throw new FileNotFoundException("Installer not found.", installerPath);

        var root = Path.Combine(Path.GetTempPath(), "InstallerAnalyzer", "ISS-Local-" + DateTime.Now.ToString("yyyyMMdd-HHmmss"));
        var output = Path.Combine(root, "Output");
        Directory.CreateDirectory(output);
        var issPath = Path.Combine(output, "setup.iss");
        var arguments = $"/r /f1\"{issPath}\"";

        Process.Start(new ProcessStartInfo
        {
            FileName = installerPath,
            Arguments = arguments,
            UseShellExecute = true
        });

        return new SandboxIssSession
        {
            SessionFolder = root,
            OutputFolder = output,
            IssPath = issPath,
            WsbPath = string.Empty,
            RequiresIss = true
        };
    }

    private static string BuildDiscoveryScript(string installerName, InstallerKind kind, string baseSilentArguments, string additionalPackageArguments, bool blockBundledMcAfee, bool silentOnly)
        => BuildDiscoveryScriptCore(installerName, kind, baseSilentArguments, additionalPackageArguments, blockBundledMcAfee, silentOnly, new MsiMetadata());

    private static string BuildDiscoveryScriptCore(string installerName, InstallerKind kind, string baseSilentArguments, string additionalPackageArguments, bool blockBundledMcAfee, bool silentOnly, MsiMetadata msiMetadata, bool recordResponses = false, string netFxRequirement = "")
    {
        var escaped = installerName.Replace("'", "''");
        var kindName = kind.ToString().Replace("'", "''");
        var baseSilent = (baseSilentArguments ?? string.Empty).Replace("'", "''");
        var additional = (additionalPackageArguments ?? string.Empty).Replace("'", "''");
        var blockMcAfee = blockBundledMcAfee ? "$true" : "$false";
        var silentOnlyValue = silentOnly ? "$true" : "$false";
        var script = """
$ErrorActionPreference = 'Stop'
$Installer = 'C:\InstallerInput\__INSTALLER__'
$Analysis = 'C:\InstallerOutput\install-analysis.json'
$Heartbeat = 'C:\InstallerOutput\analysis-heartbeat.txt'
function Set-AnalysisHeartbeat([string]$stage='activity') { try { ((Get-Date).ToString('o')+'|'+$stage) | Add-Content $Heartbeat -Encoding ASCII } catch {} }
Set-AnalysisHeartbeat 'analysis-start'
$BaseSilentArguments = '__BASE_ARGS__'
$AdditionalPackageArguments = '__ADDITIONAL_ARGS__'
$SilentInstallArguments = (@($BaseSilentArguments,$AdditionalPackageArguments) | Where-Object { -not [string]::IsNullOrWhiteSpace($_) }) -join ' '
$InstallerKind = '__KIND__'
$EffectiveSilentInstaller = $Installer
$DiscoveredInstallerKind = $null
$DeploymentMechanism = $null
$DeploymentSource = $Installer
$IdentitySource = $null
$StartedAt = Get-Date
$BeforeProcessIds = @(Get-Process -ErrorAction SilentlyContinue | ForEach-Object { $_.Id })
$BlockBundledMcAfee = __BLOCK_MCAFEE__
$SilentOnly = __SILENT_ONLY__
$RecordResponses = __RECORD_RESPONSES__
$SetupIss = 'C:\InstallerOutput\setup.iss'
$UninstallIss = 'C:\InstallerOutput\uninstall.iss'
$RecordedUninstallParts = $null
$McAfeeWatchdog = $null
$McAfeeWatchdogLog = Join-Path $env:TEMP 'InstallerAnalyzer-McAfeeWatchdog.log'
$StagedVendorSetup = $null
$StagedVendorSetupDirectory = $null

function Start-McAfeeWatchdog {
    if(-not $BlockBundledMcAfee){ return $null }
    if(([IO.Path]::GetFileName($Installer)) -match '(?i)mcafee'){ return $null }
    Remove-Item $McAfeeWatchdogLog -Force -ErrorAction SilentlyContinue
    $watchdog = @'
$ErrorActionPreference='SilentlyContinue'
$log=Join-Path $env:TEMP 'InstallerAnalyzer-McAfeeWatchdog.log'
$stop=Join-Path $env:TEMP 'InstallerAnalyzer-McAfeeWatchdog.stop'
Remove-Item $stop -Force -ErrorAction SilentlyContinue
while(-not (Test-Path $stop)){
  foreach($p in @(Get-Process -ErrorAction SilentlyContinue)){
    try {
      $name=[string]$p.ProcessName
      $path=''; $company=''; $product=''
      try{$path=[string]$p.Path}catch{}
      try{$company=[string]$p.MainModule.FileVersionInfo.CompanyName}catch{}
      try{$product=[string]$p.MainModule.FileVersionInfo.ProductName}catch{}
      $identity=($name+' '+$path+' '+$company+' '+$product)
      if($identity -match '(?i)mcafee|SSScheduler|mc-webview-cnt|McUICnt|McSvHost|mfe[a-z0-9_-]*'){
        Add-Content -Path $log -Value ((Get-Date).ToString('o')+' BLOCKED PID='+$p.Id+' NAME='+$name+' PATH='+$path)
        & taskkill.exe /PID $p.Id /T /F 2>$null | Out-Null
      }
    } catch {}
  }
  Start-Sleep -Milliseconds 500
}
'@
    $bytes=[Text.Encoding]::Unicode.GetBytes($watchdog)
    $encoded=[Convert]::ToBase64String($bytes)
    return Start-Process powershell.exe -ArgumentList @('-NoProfile','-NonInteractive','-WindowStyle','Hidden','-EncodedCommand',$encoded) -WindowStyle Hidden -PassThru
}
function Stop-McAfeeWatchdog {
    if($null -eq $McAfeeWatchdog){ return }
    try { Set-Content -Path (Join-Path $env:TEMP 'InstallerAnalyzer-McAfeeWatchdog.stop') -Value 'stop' -Encoding ASCII } catch {}
    try { if(-not $McAfeeWatchdog.WaitForExit(3000)){ Stop-Process -Id $McAfeeWatchdog.Id -Force -ErrorAction SilentlyContinue } } catch {}
}
$McAfeeWatchdog = Start-McAfeeWatchdog

function Get-UninstallSnapshot {
    $paths = @('HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\*','HKLM:\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall\*','HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\*')
    $entries=@(Get-ItemProperty $paths -ErrorAction SilentlyContinue | Where-Object { $_.DisplayName } | ForEach-Object {
        [PSCustomObject]@{ Key=$_.PSPath; DisplayName=$_.DisplayName; DisplayVersion=$_.DisplayVersion; Publisher=$_.Publisher; InstallLocation=$_.InstallLocation; UninstallString=$_.UninstallString; QuietUninstallString=$_.QuietUninstallString; WindowsInstaller=$_.WindowsInstaller; ProductCode=if ($_.PSChildName -match '^\{[0-9A-Fa-f-]+\}$') {$_.PSChildName}else{$null} }
    })
    if($null -ne $script:MsiStaticMetadata -and [string]$script:MsiStaticMetadata.ProductCode -match '^\{[0-9A-Fa-f-]{36}\}$' -and @($entries|Where-Object {$_.ProductCode -eq $script:MsiStaticMetadata.ProductCode}).Count -eq 0){
      $native=Get-NativeMsiProductEntry
      if($null -ne $native){$entries+=@($native)}
    }
    $entries
    # A bootstrapper may register MSIX without a conventional uninstall key.
    Get-AppxPackage -PackageTypeFilter Main,Bundle -ErrorAction SilentlyContinue | Where-Object {-not $_.IsFramework -and $_.PackageFullName -match '^[A-Za-z0-9._-]+$'} | ForEach-Object {
        $remove='powershell.exe -NoProfile -NonInteractive -Command "Remove-AppxPackage -Package '+$_.PackageFullName+' -ErrorAction Stop"'
        [PSCustomObject]@{Key=('APPX::'+$_.Name);DisplayName=$_.Name;DisplayVersion=$_.Version.ToString();Publisher=$_.Publisher;InstallLocation=$_.InstallLocation;UninstallString=$null;QuietUninstallString=$remove;WindowsInstaller=0;ProductCode=$_.PackageFullName}
    }
}
function Select-Primary($entries) {
    $stem = [IO.Path]::GetFileNameWithoutExtension($Installer).ToLowerInvariant() -replace '(setup|installer|install)','' -replace '[^a-z0-9]',''
    $best=$null; $bestScore=[int]::MinValue
    foreach($e in $entries){
        $name=([string]$e.DisplayName).ToLowerInvariant() -replace '[^a-z0-9]',''; $score=0
        if([string]::IsNullOrWhiteSpace($name) -or [string]::IsNullOrWhiteSpace([string]$e.Key)){continue}
        if($stem -and ($name.Contains($stem) -or $stem.Contains($name))){$score+=70}
        if($e.InstallLocation){$score+=15}; if($e.UninstallString){$score+=10}; if($e.QuietUninstallString){$score+=15}; if($e.DisplayVersion){$score+=5}
        if($name -match 'microsoftvisualc|redistributable|runtime|netframework|webview2'){$score-=50}
        if($score -gt $bestScore){$best=$e;$bestScore=$score}
    }
    if($bestScore -lt 0){return $null}
    return $best
}
function Split-Command([string]$command) {
    if([string]::IsNullOrWhiteSpace($command)){return $null}
    $command=$command.Trim()
    # Registry uninstall strings are not consistently quoted. Prefer the executable
    # boundary so paths containing spaces (for example Program Files (x86)) stay intact.
    if($command -match '^\s*"?(.+?\.exe)"?\s*(.*)$'){ return @($matches[1].Trim('"'),$matches[2]) }
    if($command -match '^\s*"([^"]+)"\s*(.*)$'){ return @($matches[1],$matches[2]) }
    if($command -match '^\s*(\S+)\s*(.*)$'){ return @($matches[1],$matches[2]) }
    return $null
}
function Test-IdentityMatch($expected,$actual) {
    if($null -eq $expected -or $null -eq $actual){return $false}
    if($expected.Key -and $actual.Key -and $expected.Key -eq $actual.Key){return $true}
    if($expected.ProductCode -and $actual.ProductCode -and $expected.ProductCode -eq $actual.ProductCode){return $true}
    if([string]::IsNullOrWhiteSpace([string]$expected.DisplayName) -or $expected.DisplayName -ne $actual.DisplayName){return $false}
    # Names alone are not sufficient when the installed publisher is known.
    if($expected.Publisher -and $expected.Publisher -ne $actual.Publisher){return $false}
    return $true
}
function Test-Detected($primary) {
    if($null -eq $primary){return $false}
    if($primary.Key -like 'MSI::*'){return Test-NativeMsiProductDetected ([string]$primary.ProductCode)}
    if($primary.Key -like 'FILE::*'){ return Test-Path $primary.InstallLocation }
    return (@(Get-UninstallSnapshot | Where-Object {Test-IdentityMatch $primary $_}).Count -gt 0)
}
function Find-Reinstalled($primary) {
    if($null -eq $primary){return $null}
    if($primary.Key -like 'MSI::*'){
      $candidate=Get-NativeMsiProductEntry
      if($null -ne $candidate -and $candidate.ProductCode -eq $primary.ProductCode){return $candidate}
      return $null
    }
    if($primary.Key -like 'FILE::*') {
      $candidate=Find-SquirrelApplication
      if(Test-IdentityMatch $primary $candidate){return $candidate};return $null
    }
    $snapshot=@(Get-UninstallSnapshot)
    $exact=@($snapshot | Where-Object {$_.Key -and $_.Key -eq $primary.Key})
    if($exact.Count -gt 0){return $exact[0]}
    $same=@($snapshot | Where-Object {Test-IdentityMatch $primary $_})
    if($same.Count -gt 1){return $null} # Do not choose an arbitrary installed instance.
    if($same.Count -gt 0){ return $same[0] }; return $null
}
function Find-SquirrelApplication {
    $roots=@($env:LOCALAPPDATA)
    foreach($root in $roots){
      $updates=Get-ChildItem -Path $root -Filter Update.exe -File -Recurse -ErrorAction SilentlyContinue | Where-Object {$_.FullName -notmatch '\\SquirrelTemp\\'} | Sort-Object LastWriteTime -Descending
      foreach($u in $updates){
        $dir=$u.Directory.FullName
        $apps=@(Get-ChildItem -Path $dir -Directory -Filter 'app-*' -ErrorAction SilentlyContinue | Sort-Object LastWriteTime -Descending)
        if($apps.Count -gt 0){
          $exe=Get-ChildItem -Path $apps[0].FullName -Filter '*.exe' -File -ErrorAction SilentlyContinue | Where-Object {$_.Name -notmatch 'Update|Squirrel'} | Select-Object -First 1
          $name=if($exe){$exe.VersionInfo.ProductName}else{$u.Directory.Name}; if([string]::IsNullOrWhiteSpace($name)){$name=$u.Directory.Name}
          $ver=if($exe){$exe.VersionInfo.ProductVersion}else{$null}
          return [PSCustomObject]@{Key=('FILE::'+$dir);DisplayName=$name;DisplayVersion=$ver;Publisher=if($exe){$exe.VersionInfo.CompanyName}else{$null};InstallLocation=$dir;UninstallString=('"'+$u.FullName+'" --uninstall');QuietUninstallString=$null;WindowsInstaller=$null;ProductCode=$null}
        }
      }
    }
    return $null
}
if(-not ('InstallerAnalyzerWindowProbe' -as [type])) {
Add-Type @'
using System;
using System.Collections.Generic;
using System.Runtime.InteropServices;
using System.Text;
public static class InstallerAnalyzerWindowProbe {
  public delegate bool EnumWindowsProc(IntPtr hWnd, IntPtr lParam);
  [DllImport("user32.dll")] static extern bool EnumWindows(EnumWindowsProc lpEnumFunc, IntPtr lParam);
  [DllImport("user32.dll")] static extern bool IsWindowVisible(IntPtr hWnd);
  [DllImport("user32.dll")] static extern uint GetWindowThreadProcessId(IntPtr hWnd, out uint processId);
  [DllImport("user32.dll", CharSet=CharSet.Unicode)] static extern int GetWindowText(IntPtr hWnd, StringBuilder text, int count);
  [DllImport("user32.dll")] static extern bool EnumChildWindows(IntPtr hWnd, EnumWindowsProc callback, IntPtr lParam);
  [DllImport("user32.dll", CharSet=CharSet.Unicode)] static extern int GetClassName(IntPtr hWnd, StringBuilder text, int count);
  [DllImport("user32.dll", CharSet=CharSet.Unicode, SetLastError=true)] static extern IntPtr SendMessageTimeout(IntPtr hWnd, uint message, UIntPtr count, StringBuilder text, uint flags, uint timeout, out UIntPtr result);
  [DllImport("user32.dll", EntryPoint="GetWindowLongW")] static extern int GetWindowStyle(IntPtr hWnd, int index);
  public static string[] ReadStaticLabels(long window, int expectedPid) {
    var handle=new IntPtr(window); uint owner; GetWindowThreadProcessId(handle,out owner);
    var result=new List<string>(); if(owner!=(uint)expectedPid) return result.ToArray(); int visited=0;
    var clock=System.Diagnostics.Stopwatch.StartNew();
    EnumChildWindows(handle,(child,state)=>{
      if(++visited>96 || result.Count>=32 || clock.ElapsedMilliseconds>=1000) return false;
      uint pid; GetWindowThreadProcessId(child,out pid); if(pid!=(uint)expectedPid || !IsWindowVisible(child)) return true;
      var kind=new StringBuilder(128);GetClassName(child,kind,kind.Capacity);var name=kind.ToString();
      if(!(name.Equals("Static",StringComparison.OrdinalIgnoreCase) || name.Equals("Button",StringComparison.OrdinalIgnoreCase) || name.StartsWith("WindowsForms10.STATIC",StringComparison.OrdinalIgnoreCase) || name.StartsWith("WindowsForms10.BUTTON",StringComparison.OrdinalIgnoreCase))) return true;
      if(name.Equals("Static",StringComparison.OrdinalIgnoreCase) || name.StartsWith("WindowsForms10.STATIC",StringComparison.OrdinalIgnoreCase)) {
        int style=GetWindowStyle(child,-16)&31; if(style!=0 && style!=1 && style!=2 && style!=11 && style!=12) return true;
      }
      // WM_GETTEXT only for allow-listed static/button controls. Never edit, password, combo or rich-edit controls.
      var text=new StringBuilder(512); UIntPtr copied;
      if(SendMessageTimeout(child,13,new UIntPtr((uint)text.Capacity),text,34,75,out copied)==IntPtr.Zero) return true;
      var value=text.ToString().Trim();if(value.Length>0)result.Add(value);
      return true;
    },IntPtr.Zero);
    return result.ToArray();
  }
  public static string[] VisibleWindows(int[] processIds) {
    var ids = new HashSet<int>(processIds); var found = new List<string>();
    EnumWindows((h, l) => { uint pid; GetWindowThreadProcessId(h, out pid); if(ids.Contains((int)pid) && IsWindowVisible(h)) { var b=new StringBuilder(512); GetWindowText(h,b,b.Capacity); var t=b.ToString().Trim(); found.Add(h.ToInt64()+"|"+((int)pid)+"|"+(t.Length==0?"<untitled visible window>":t)); } return true; }, IntPtr.Zero);
    return found.ToArray();
  }
  public static string[] DesktopWindows() {
    var found = new List<string>();
    EnumWindows((h, l) => { if(!IsWindowVisible(h)) return true; uint pid; GetWindowThreadProcessId(h, out pid); var b=new StringBuilder(512); GetWindowText(h,b,b.Capacity); var t=b.ToString().Trim(); if(t.Length>0) found.Add(h.ToInt64()+"|"+((int)pid)+"|"+t); return true; }, IntPtr.Zero);
    return found.ToArray();
  }
}
'@
}
function Update-TrackedProcessTree([System.Collections.Generic.HashSet[int]]$tracked) {
    $all=@(Get-CimInstance Win32_Process -ErrorAction SilentlyContinue)
    $changed=$true
    while($changed){
      $changed=$false
      foreach($x in $all){
        if($tracked.Contains([int]$x.ParentProcessId) -and -not $tracked.Contains([int]$x.ProcessId)){
          [void]$tracked.Add([int]$x.ProcessId); $changed=$true
        }
      }
    }
    Observe-InstallerTree $all $tracked
    return $all
}
function Get-TrackedProcessIds([System.Collections.Generic.HashSet[int]]$tracked) {
    # Windows PowerShell 5.1 can throw "Argument types do not match" when @($tracked)
    # enumerates a generic HashSet[int]. Copy it explicitly into a normal PS array.
    $ids=@()
    foreach($trackedId in $tracked){$ids += [int]$trackedId}
    return $ids
}
function Get-StringSetItems($set) {
    $items=@(); if($null -ne $set){foreach($item in $set){$items += [string]$item}}; return $items
}
function Get-ObjectListItems($list) {
    $items=@(); if($null -ne $list){foreach($item in $list){$items += $item}}; return $items
}
function Invoke-BoundedTaskKill([int]$processId,[int]$waitMilliseconds=4000) {
    # taskkill itself can block while Windows is tearing down a bootstrapper tree. Never let
    # candidate cleanup inherit an unbounded native-process wait.
    try {
      $psi=New-Object System.Diagnostics.ProcessStartInfo
      $psi.FileName="$env:SystemRoot\System32\taskkill.exe"
      $psi.Arguments=('/PID '+$processId+' /T /F')
      $psi.UseShellExecute=$false; $psi.CreateNoWindow=$true
      $tk=New-Object System.Diagnostics.Process; $tk.StartInfo=$psi
      [void]$tk.Start()
      if(-not $tk.WaitForExit($waitMilliseconds)){try{$tk.Kill()}catch{};return $false}
      return $true
    } catch { return $false }
}
function Stop-TrackedProcessTree([System.Collections.Generic.HashSet[int]]$tracked,[int]$MaxSeconds=30) {
    # v0.11.38: cleanup is explicitly bounded. A rejected candidate must never strand the
    # lifecycle before the next strategy can start.
    Set-AnalysisHeartbeat 'candidate-cleanup-tree-start'
    $deadline=(Get-Date).AddSeconds([Math]::Max(5,$MaxSeconds))
    $ids=@(Get-TrackedProcessIds $tracked) | Sort-Object -Descending
    foreach($id in $ids){
      if((Get-Date) -ge $deadline){break}
      Set-AnalysisHeartbeat ('candidate-cleanup-taskkill-'+$id)
      [void](Invoke-BoundedTaskKill $id 3500)
    }
    do {
      $trackedIds=@(Get-TrackedProcessIds $tracked)
      $alive=@(Get-Process -ErrorAction SilentlyContinue | Where-Object {$_.Id -in $trackedIds})
      if($alive.Count -eq 0){Set-AnalysisHeartbeat 'candidate-cleanup-tree-complete';return $true}
      foreach($a in $alive){try{$a.Kill()}catch{}}
      Set-AnalysisHeartbeat ('candidate-cleanup-waiting-'+$alive.Count)
      Start-Sleep -Milliseconds 250
    } while((Get-Date) -lt $deadline)
    Set-AnalysisHeartbeat 'candidate-cleanup-tree-timeout'
    return $false
}
function Get-DesktopWindowSnapshot {
    $map=@{}
    foreach($w in [InstallerAnalyzerWindowProbe]::DesktopWindows()){
      $parts=$w -split '\|',3
      if($parts.Count -lt 3){continue}
      $map[$parts[0]]=[PSCustomObject]@{Hwnd=$parts[0];Pid=[int]$parts[1];Title=$parts[2]}
    }
    return $map
}
function Test-IgnoredDesktopWindow($window) {
    if($null -eq $window){return $true}
    $title=[string]$window.Title
    if([string]::IsNullOrWhiteSpace($title)){return $true}
    if($title -match '^(Program Manager|Windows Sandbox|Task Switching|Search|Start)$'){return $true}
    try {
      if($window.Pid -eq $PID){return $true}
      $pn=(Get-Process -Id $window.Pid -ErrorAction Stop).ProcessName
      if($pn -match '^(explorer|ShellExperienceHost|SearchHost|StartMenuExperienceHost|TextInputHost|WindowsSandboxClient|conhost|taskkill)$'){return $true}
    } catch {}
    return $false
}
function Test-InstalledApplicationProcess([int]$processId,$entry,[string]$candidateFile) {
    if($null -eq $entry){return $false}
    try {
      $p=Get-Process -Id $processId -ErrorAction Stop
      if($p.ProcessName -match '^(setup|install|installer|unins.*|msiexec|update)$'){return $false}
      $path=[string]$p.Path
      if([string]::IsNullOrWhiteSpace($path) -or $path.Equals($candidateFile,[StringComparison]::OrdinalIgnoreCase)){return $false}
      $uninstall=Split-Command ([string]$entry.UninstallString)
      if($uninstall -and $path.Equals($uninstall[0],[StringComparison]::OrdinalIgnoreCase)){return $false}
      $location=[string]$entry.InstallLocation
      if([string]::IsNullOrWhiteSpace($location)){
        if(-not $uninstall -or -not [IO.Path]::IsPathRooted($uninstall[0])){return $false}
        $location=Split-Path -Parent $uninstall[0]
        $allowedRoots=@($env:ProgramFiles,${env:ProgramFiles(x86)},$env:LOCALAPPDATA) | Where-Object {$_}
        if(@($allowedRoots | Where-Object {$location.StartsWith(($_.TrimEnd('\')+'\'),[StringComparison]::OrdinalIgnoreCase)}).Count -eq 0){return $false}
        if($location -match '(?i)\\(Temp|Package Cache|InstallerInput)(\\|$)'){return $false}
      }
      $root=$location.TrimEnd('\')+'\'
      if($root.Length -le 4){return $false}
      return $path.StartsWith($root,[StringComparison]::OrdinalIgnoreCase)
    } catch {return $false}
}
function Stop-DesktopWindowOwner($window,[System.Collections.Generic.HashSet[int]]$tracked) {
    Set-AnalysisHeartbeat 'candidate-ui-reject-stop-owner-start'
    if($null -ne $window -and $window.Pid -gt 0){
      [void]$tracked.Add([int]$window.Pid)
      [void](Invoke-BoundedTaskKill ([int]$window.Pid) 3500)
    }
    $stopped=Stop-TrackedProcessTree $tracked 30
    Set-AnalysisHeartbeat ('candidate-ui-reject-stop-owner-finished-'+$stopped)
    return $stopped
}
function Get-NormalizedProcessExitCode([string]$file,[string]$arguments,[int]$exitCode) {
    # Chromium's setup.exe returns InstallStatus values for uninstall (19=success,
    # 29=reboot required). Preserve the raw value in diagnostics and require absence proof.
    # https://chromium.googlesource.com/chromium/src/+/main/chrome/installer/util/util_constants.h
    if($file -match '(?i)\\Installer\\setup\.exe$' -and $arguments -match '(?i)--uninstall' -and
       $arguments -match '(?i)--force-uninstall' -and $arguments -match '(?i)--(channel|system-level|multi-install)'){
      if($exitCode -eq 19){return 0}
      if($exitCode -eq 29){return 3010}
    }
    return $exitCode
}
function Invoke-NativeProcess([string]$file,[string]$arguments,[bool]$MonitorUi=$false,[bool]$AbortOnUi=$false,[int]$MaxSeconds=0,$DetectionTarget=$null,[bool]$CompleteWhenDetected=$false) {
    $launchPhase=if($null -eq $DetectionTarget){'Discovery install'}else{'Silent reinstall'}
    $installedWindowTarget=$DetectionTarget
    $lastIdentityProbe=Get-Date
    # Capture the desktop BEFORE launching the candidate so even a window created immediately
    # by the bootstrapper cannot accidentally become part of the baseline.
    if($CompleteWhenDetected){Write-Checkpoint ($launchPhase+' launch: capturing desktop baseline')}
    $baseline=if($MonitorUi){Get-DesktopWindowSnapshot}else{@{}}
    if($CompleteWhenDetected){Write-Checkpoint ($launchPhase+' launch: desktop baseline captured')}
    # v0.11.13 stays on the known-good v0.11.9 Sandbox launch path.  As a
    # second in-process signal, remember the processes/windows that existed
    # before the candidate starts.  This does not create another Sandbox
    # session, watcher process, scheduled task, or network connection.
    if($CompleteWhenDetected){Write-Checkpoint ($launchPhase+' launch: capturing process baseline')}
    $baselineProcessIds=if($MonitorUi){@((Get-Process -ErrorAction SilentlyContinue).Id)}else{@()}
    if($CompleteWhenDetected){Write-Checkpoint ('Silent reinstall launch: process baseline captured; count='+$baselineProcessIds.Count)}
    $psi = New-Object System.Diagnostics.ProcessStartInfo
    $psi.FileName = $file; $psi.Arguments = $arguments; $psi.UseShellExecute = $false; $psi.CreateNoWindow = $true
    if($CompleteWhenDetected){Write-Checkpoint ($launchPhase+' launch: ProcessStartInfo ready')}
    $proc = New-Object System.Diagnostics.Process; $proc.StartInfo = $psi
    if($CompleteWhenDetected){Write-Checkpoint ($launchPhase+' launch: calling Process.Start')}
    [void]$proc.Start()
    if($CompleteWhenDetected){Write-Checkpoint ($launchPhase+' launch: Process.Start returned PID '+$proc.Id)}
    $tracked=New-Object 'System.Collections.Generic.HashSet[int]'; [void]$tracked.Add([int]$proc.Id)
    $ui=New-Object 'System.Collections.Generic.HashSet[string]'; $aborted=$false
    $uiDiagnostics=New-Object 'System.Collections.Generic.List[object]'
    $lastUiDiagnostic=[DateTime]::MinValue
    $unexpectedSince=@{}
    $rootExit=$null
    $startedAt=Get-Date; $completedByDetection=$false; $timedOut=$false
    while($true){
      Set-AnalysisHeartbeat 'native-process-monitor'
      try{$all=Update-TrackedProcessTree $tracked}catch{$all=@()}
      # v0.12.7: registered application paths disambiguate post-install UI. Some installers launch the installed
      # application immediately after a successful unattended install. Once the expected identity
      # exists, do not misclassify that application window as interactive installer UI.
      if($CompleteWhenDetected -and ((Get-Date)-$lastIdentityProbe).TotalSeconds -ge 1){
        try {
          $refreshed=if($null -ne $DetectionTarget){Find-Reinstalled $DetectionTarget}else{Select-Primary @(Get-UninstallSnapshot | Where-Object {$_.Key -notin $beforeKeys})}
          if($null -ne $refreshed){$installedWindowTarget=$refreshed}
        } catch {}
        $lastIdentityProbe=Get-Date
      }
      if($MonitorUi){
        try {
          $now=Get-DesktopWindowSnapshot
          # UI diagnostics stay entirely inside this already-running analysis
          # process and are returned through install-analysis.json. No new watcher,
          # mapped folder, startup command, IPC channel, or Sandbox session is used.
          if(((Get-Date)-$lastUiDiagnostic).TotalMilliseconds -ge 500 -and $uiDiagnostics.Count -lt 120){
            $procWindows=@()
            foreach($dp in @(Get-Process -ErrorAction SilentlyContinue)){
              try{$dp.Refresh()}catch{}
              if($dp.MainWindowHandle -ne 0 -and -not [string]::IsNullOrWhiteSpace($dp.MainWindowTitle)){
                $procWindows+=($dp.Id.ToString()+'|'+$dp.ProcessName+'|'+$dp.MainWindowHandle.ToString()+'|'+$dp.MainWindowTitle)
              }
            }
            $uiDiagnostics.Add([PSCustomObject]@{
              Timestamp=(Get-Date).ToString('o')
              AnalysisPid=$PID
              AnalysisSessionId=(Get-Process -Id $PID -ErrorAction SilentlyContinue).SessionId
              CandidatePid=$proc.Id
              CandidateSessionId=(Get-Process -Id $proc.Id -ErrorAction SilentlyContinue).SessionId
              EnumWindows=@($now.Values | ForEach-Object { $_.Pid.ToString()+'|'+$_.Hwnd+'|'+$_.Title })
              ProcessMainWindows=@($procWindows)
              TrackedProcessIds=@(Get-TrackedProcessIds $tracked)
            })
            $lastUiDiagnostic=Get-Date
          }
          foreach($key in @($now.Keys)){
            if($baseline.ContainsKey($key)){continue}
            $w=$now[$key]
            if(Test-IgnoredDesktopWindow $w){continue}
            if($CompleteWhenDetected -and $w.Pid -ne $proc.Id -and (Test-InstalledApplicationProcess $w.Pid $installedWindowTarget $file)){continue}
            if(-not $unexpectedSince.ContainsKey($key)){$unexpectedSince[$key]=Get-Date}
            # v0.12.2: a generic Inno "Setup" window is not by itself proof that interaction is
            # required. Some Inno packages keep this owner/progress HWND alive while a fully
            # unattended install proceeds. Ignore only this generic title; application detection
            # still has to succeed, otherwise the candidate times out/rejects normally.
            if($InstallerKind -eq 'InnoSetup' -and $w.Title -eq 'Setup'){continue}
            $uiPersistenceMs=600
            # Some launchers register the app just after starting it. Give a successfully
            # exited installer a bounded grace period to publish identity; never synthesize success.
            if($CompleteWhenDetected -and $proc.HasExited -and $proc.ExitCode -eq 0){$uiPersistenceMs=3000}
            if(((Get-Date)-$unexpectedSince[$key]).TotalMilliseconds -ge $uiPersistenceMs){
              $desc=($w.Pid.ToString()+' :: '+$w.Title)
              Record-InstallerUiEvidence $w $tracked
              [void]$ui.Add($desc)
              if($AbortOnUi){
                $aborted=$true
                Stop-DesktopWindowOwner $w $tracked
                break
              }
            }
          }
          if($aborted){break}
          foreach($key in @($unexpectedSince.Keys)){if(-not $now.ContainsKey($key)){$unexpectedSince.Remove($key)}}

          # Fallback for bootstrapper UI whose HWND is not returned by EnumWindows
          # to this PowerShell host. MainWindowHandle/MainWindowTitle are queried
          # directly from processes in the same existing Sandbox session.
          foreach($gp in @(Get-Process -ErrorAction SilentlyContinue)){
            if($baselineProcessIds -contains $gp.Id -and -not $tracked.Contains([int]$gp.Id)){continue}
            try { $gp.Refresh() } catch {}
            if($gp.MainWindowHandle -eq 0 -or [string]::IsNullOrWhiteSpace($gp.MainWindowTitle)){continue}
            $pw=[PSCustomObject]@{Hwnd=$gp.MainWindowHandle.ToString();Pid=[int]$gp.Id;Title=[string]$gp.MainWindowTitle}
            if(Test-IgnoredDesktopWindow $pw){continue}
            if($CompleteWhenDetected -and $gp.Id -ne $proc.Id -and (Test-InstalledApplicationProcess $gp.Id $installedWindowTarget $file)){continue}
            $pkey=('PID:'+ $gp.Id + ':' + $gp.MainWindowHandle)
            if(-not $unexpectedSince.ContainsKey($pkey)){$unexpectedSince[$pkey]=Get-Date;continue}
            if($InstallerKind -eq 'InnoSetup' -and $gp.MainWindowTitle -eq 'Setup'){continue}
            $processUiPersistenceMs=500
            if($CompleteWhenDetected -and $proc.HasExited -and $proc.ExitCode -eq 0){$processUiPersistenceMs=3000}
            if(((Get-Date)-$unexpectedSince[$pkey]).TotalMilliseconds -ge $processUiPersistenceMs){
              $desc=($gp.Id.ToString()+' :: '+$gp.ProcessName+' :: '+$gp.MainWindowTitle)
              Record-InstallerUiEvidence $pw $tracked
              [void]$ui.Add($desc)
              if($AbortOnUi){$aborted=$true;Stop-DesktopWindowOwner $pw $tracked;break}
            }
          }
          if($aborted){break}
        } catch {}
      }
      try{$proc.Refresh()}catch{}
      if($proc.HasExited -and $null -eq $rootExit){try{$rootExit=$proc.ExitCode}catch{$rootExit=-2}}
      # v0.11.38: a bootstrapper may leave normal application/helper descendants alive forever.
      # During reinstall validation, keep waiting for the installer exit code while ignoring
      # only application processes confirmed beneath its registered installation directory.
      # Registration can precede the end of the install transaction. Retain the real root
      # process exit code; only exclude a proven installed application's launched processes.
      if($MaxSeconds -gt 0 -and ((Get-Date)-$startedAt).TotalSeconds -ge $MaxSeconds){$timedOut=$true;break}
      # Bootstrapper parents often exit after handing work to a child. Keep watching every PID
      # already discovered until the entire tracked tree is gone.
      $trackedIds=@(Get-TrackedProcessIds $tracked)
      $alive=@($all | Where-Object {[int]$_.ProcessId -in $trackedIds})
      if($CompleteWhenDetected -and $null -ne $installedWindowTarget -and $proc.HasExited){
        $alive=@($alive | Where-Object {-not (Test-InstalledApplicationProcess ([int]$_.ProcessId) $installedWindowTarget $file)})
      }
      if($proc.HasExited -and ($alive.Count -eq 0 -or (Test-MsiClientCommand $file))){break}
      Start-Sleep -Milliseconds 150
    }
    if($completedByDetection -or $timedOut){try{Stop-TrackedProcessTree $tracked}catch{}}
    try{$proc.WaitForExit(2000)|Out-Null}catch{}
    $completedAt=Get-Date
    $exit=if($aborted){-1001}elseif($completedByDetection){0}elseif($timedOut){-1002}elseif($null -ne $rootExit){$rootExit}elseif($proc.HasExited){$proc.ExitCode}else{-2}
    if($exit -in @(3010,1641)){$result.RebootRequired=$true}
    return [PSCustomObject]@{ StartedAt=$startedAt.ToString('o'); CompletedAt=$completedAt.ToString('o'); ExitCode=(Get-NormalizedProcessExitCode $file $arguments $exit); RawExitCode=$exit; StdOut=''; StdErr=''; UiDetected=($ui.Count -gt 0); VisibleWindows=@(Get-StringSetItems $ui); AbortedForUi=$aborted; TrackedProcessIds=@(Get-TrackedProcessIds $tracked); UiDiagnostics=@(Get-ObjectListItems $uiDiagnostics); CompletedByDetection=$completedByDetection; TimedOut=$timedOut }
}
function Test-InstallShieldResponse([string]$path) {
    if(-not (Test-Path -LiteralPath $path -PathType Leaf)){return $false}
    $item=Get-Item -LiteralPath $path
    if($item.Length -eq 0 -or $item.Length -gt 1048576){return $false}
    $text=[IO.File]::ReadAllText($path)
    return ($text -match '(?im)^\[InstallShield Silent\]\s*$' -and $text -match '(?im)^File=Response File\s*$' -and $text -match '(?im)^Count=[1-9][0-9]*\s*$')
}
function Test-InstallShieldReplayLog([string]$path) {
    if(-not (Test-Path -LiteralPath $path -PathType Leaf)){return $false}
    $item=Get-Item -LiteralPath $path
    if($item.Length -eq 0 -or $item.Length -gt 1048576){return $false}
    $codes=@([regex]::Matches([IO.File]::ReadAllText($path),'(?im)^ResultCode=(-?[0-9]+)\s*$'))
    return ($codes.Count -eq 1 -and $codes[0].Groups[1].Value -eq '0')
}
function New-InstallCandidate([string]$name,[string]$file,[string]$arguments,[string]$kind,[int]$score,[string]$reason) {
    return [PSCustomObject]@{Name=$name;File=$file;Arguments=$arguments;Kind=$kind;Score=$score;Reason=$reason}
}
function Test-MsiClientCommand([string]$file) {
    if($file -ieq 'msiexec.exe'){return $true}
    return ($file -ieq (Join-Path ([Environment]::SystemDirectory) 'msiexec.exe') -or
        $file -ieq (Join-Path $env:windir 'SysWOW64\msiexec.exe'))
}
function Test-ProcessResultSuccess($execution) {
    return ($null -ne $execution -and $null -ne $execution.ExitCode -and
        $execution.ExitCode -in @(0,3010) -and -not $execution.UiDetected -and -not $execution.TimedOut -and -not $execution.AbortedForUi)
}
function Get-UninstallExecutionArguments([string]$file,[string]$arguments,[string]$phase) {
    if((Test-MsiClientCommand $file) -and $arguments -notmatch '(?i)(^|\s)/l[a-z*!+]*\s'){
      if($phase -notin @('initial','final')){throw 'Invalid uninstall diagnostic phase.'}
      return ($arguments+' /L*v+! "'+(Join-Path ([IO.Path]::GetDirectoryName($Analysis)) ('msi-uninstall-'+$phase+'.log'))+'"')
    }
    return $arguments
}
function Wait-ApplicationAbsent($primary,[string]$phase='Initial',[int]$maxPolls=20) {
    for($poll=1;$poll -le $maxPolls;$poll++){
      $detected=Test-Detected $primary
      Set-AnalysisHeartbeat ($phase.ToLowerInvariant()+'-absence-verification')
      Write-Checkpoint ($phase+' absence verification '+$poll+'/'+$maxPolls+': detected='+$detected)
      if(-not $detected){return $true}
      if($poll -lt $maxPolls){Start-Sleep 3}
    }
    return $false
}
function Get-MsiRemovalUiActions([string]$file) {
    if($file -notlike '*.msi' -or -not (Test-Path -LiteralPath $file)){return @()}
    $engine=$null;$database=$null;$view=$null
    $evidence=New-Object 'System.Collections.Generic.List[object]'
    try {
      $engine=New-Object -ComObject WindowsInstaller.Installer
      $database=$engine.GetType().InvokeMember('OpenDatabase','InvokeMethod',$null,$engine,@($file,0))
      $view=$database.GetType().InvokeMember('OpenView','InvokeMethod',$null,$database,@('SELECT `Action`, `Condition` FROM `InstallExecuteSequence`'))
      [void]$view.GetType().InvokeMember('Execute','InvokeMethod',$null,$view,$null)
      while($record=$view.GetType().InvokeMember('Fetch','InvokeMethod',$null,$view,$null)){
        try {
          $action=[string]$record.GetType().InvokeMember('StringData','GetProperty',$null,$record,1)
          $condition=[string]$record.GetType().InvokeMember('StringData','GetProperty',$null,$record,2)
          if($action -match '(?i)show.*dialog|dialog|prompt' -and $condition -match '(?i)(^|\W)REMOVE(\W|$)'){
            $evidence.Add([PSCustomObject]@{Action=$action;Condition=$condition})
          }
        } finally {[void][Runtime.InteropServices.Marshal]::ReleaseComObject($record)}
      }
    } catch {} finally {
      foreach($com in @($view,$database,$engine)){if($null -ne $com){try{[void][Runtime.InteropServices.Marshal]::ReleaseComObject($com)}catch{}}}
    }
    return @($evidence.ToArray())
}
function Get-MsiEmbeddedInstanceTransforms([string]$file) {
    $names=New-Object 'System.Collections.Generic.List[string]'
    $installerCom=$null;$database=$null;$view=$null
    try {
      $installerCom=New-Object -ComObject WindowsInstaller.Installer
      $database=$installerCom.OpenDatabase($file,0)
      $view=$database.OpenView('SELECT `Name` FROM `_Storages`');$view.Execute()
      while($record=$view.Fetch()){
        try {$name=[string]$record.StringData(1);if($name -match '^[A-Za-z0-9_.-]{1,80}$' -and $name -match '(?i)instance'){$names.Add($name)}}
        finally {[void][Runtime.InteropServices.Marshal]::FinalReleaseComObject($record)}
      }
    } catch {} finally {
      if($view){try{$view.Close()}catch{}}
      foreach($item in @($view,$database,$installerCom)){if($null -ne $item){try{[void][Runtime.InteropServices.Marshal]::FinalReleaseComObject($item)}catch{}}}
    }
    return $names.ToArray()
}
function Get-MsiInstallCandidates {
    $base=if([string]::IsNullOrWhiteSpace($SilentInstallArguments)){'/qn /norestart'}else{$SilentInstallArguments}
    $items=@(New-InstallCandidate 'Known MSI strategy' $Installer $base 'Msi' 100 'Preferred Windows Installer quiet strategy with verbose logging.')
    if($base -notmatch '(?i)\bTRANSFORMS\s*='){
      foreach($name in @(Get-MsiEmbeddedInstanceTransforms $Installer | Sort-Object | Select-Object -First 3)){
        $items+=New-InstallCandidate ('Embedded MSI instance transform: '+$name) $Installer ($base+' TRANSFORMS=":'+$name+'" MSINEWINSTANCE=1') 'Msi' 85 'Instance transform discovered in the package storage table; must pass a complete clean Sandbox lifecycle.'
      }
    }
    return $items
}
function Get-SilentInstallCandidates($observedSilent,$files) {
    $list=New-Object 'System.Collections.Generic.List[object]'
    if($InstallerKind -eq 'Msi'){ $list.Add((New-InstallCandidate 'Known MSI strategy' $Installer $SilentInstallArguments 'Msi' 100 'MSI package uses the deterministic Windows Installer quiet strategy.')) }
    elseif($InstallerKind -eq 'InnoSetup'){ $list.Add((New-InstallCandidate 'Known Inno Setup strategy' $Installer $SilentInstallArguments 'Exe' 98 'Installer family was identified before execution.')) }
    elseif($InstallerKind -eq 'Nsis'){ $list.Add((New-InstallCandidate 'Known NSIS strategy' $Installer $SilentInstallArguments 'Exe' 98 'Installer family was identified before execution.')) }
    elseif($InstallerKind -eq 'Squirrel'){ $list.Add((New-InstallCandidate 'Known Squirrel strategy' $Installer $SilentInstallArguments 'Exe' 98 'Installer family was identified before execution.')) }
    elseif($InstallerKind -eq 'QSetup'){ $list.Add((New-InstallCandidate 'Known QSetup strategy' $Installer $SilentInstallArguments 'Exe' 98 'Installer family was identified before execution.')) }
    else {
      $installerLeaf=[IO.Path]::GetFileName($Installer)
      $looksLikeAdobeReader=($installerLeaf -match '(?i)(reader|acrordr|adobe)') -or ($observedSilent -and ([string]$observedSilent.File -match '(?i)\\Adobe\\'))
      # v0.11.38: Adobe bootstrapper strategies already proven to display UI are not
      # reintroduced through the generic/static candidate path. Prefer the base vendor
      # switches, then a locally staged durable copy of Adobe's captured setup.exe.
      if($looksLikeAdobeReader){$list.Add((New-InstallCandidate 'Adobe Reader base silent strategy' $Installer '/sAll /rs /re' 'Exe' 94 'Adobe Reader vendor base silent switches; visible UI is rejected automatically.'))}
      if($looksLikeAdobeReader -and $StagedVendorSetup -and (Test-Path $StagedVendorSetup) -and $observedSilent -and -not [string]::IsNullOrWhiteSpace($observedSilent.Arguments)){
        $list.Add((New-InstallCandidate 'Staged Adobe vendor setup executable' $StagedVendorSetup $observedSilent.Arguments 'Exe' 90 'A validation-only copy of Adobe''s complete cached setup directory captured before uninstall, preserving setup.exe sibling payload/context.'))
      }
      if($observedSilent -and -not [string]::IsNullOrWhiteSpace($observedSilent.Arguments)){
        if((Test-Path $observedSilent.File) -and $observedSilent.File -ne $Installer){$list.Add((New-InstallCandidate 'Observed silent child executable' $observedSilent.File $observedSilent.Arguments 'Exe' 88 'Exact child executable and command line observed during successful discovery.'))}
        if(-not $looksLikeAdobeReader){$list.Add((New-InstallCandidate 'Original bootstrapper + observed vendor arguments' $Installer $observedSilent.Arguments 'Exe' 92 'Arguments were observed on a successful installer child process.'))}
      }
      if(-not [string]::IsNullOrWhiteSpace($SilentInstallArguments) -and -not $looksLikeAdobeReader){$list.Add((New-InstallCandidate 'Static-analysis preferred strategy' $Installer $SilentInstallArguments 'Exe' 80 'Preferred arguments came from installer-family/static analysis.'))}
      foreach($f in @($files | Where-Object {$_ -like '*.exe' -and (Test-Path $_) -and $_ -match '(?i)\\setup\.exe$'} | Select-Object -First 2)){
        if($observedSilent -and -not [string]::IsNullOrWhiteSpace($observedSilent.Arguments)){$list.Add((New-InstallCandidate 'Captured vendor setup executable' $f $observedSilent.Arguments 'Exe' 72 'Vendor setup executable discovered during the successful bootstrapper run.'))}
      }
      $safeRoots=@($env:TEMP,$env:LOCALAPPDATA,$env:ProgramData) | Where-Object {$_}
      foreach($f in @($files | Where-Object {$candidate=$_; $_ -like '*.msi' -and (Test-Path $_) -and (@($safeRoots | Where-Object {$candidate.StartsWith($_,[StringComparison]::OrdinalIgnoreCase)}).Count -gt 0)} | Select-Object -First 2)){
        $list.Add((New-InstallCandidate 'Captured standalone MSI candidate' $f '/qn /norestart' 'Msi' 68 'MSI was captured in a transient staging location rather than an installed application cache.'))
      }
    }
    $dedupe=@{}; return @($list | Sort-Object Score -Descending | Where-Object {$k=($_.Kind+'|'+$_.File+'|'+$_.Arguments).ToLowerInvariant(); if($dedupe.ContainsKey($k)){$false}else{$dedupe[$k]=$true;$true}} | Select-Object -First 8)
}
function Get-UnattendedProbeCandidates {
    $list=New-Object 'System.Collections.Generic.List[object]'
    # v0.12.4 Strategy Discovery Engine phase 1. These probes run only inside the disposable
    # Sandbox and are rejected if visible installer UI appears or no installed identity is found.
    if(-not [string]::IsNullOrWhiteSpace($SilentInstallArguments)){
      $list.Add((New-InstallCandidate 'Static-analysis preferred strategy' $Installer $SilentInstallArguments 'Exe' 90 'Installer-family/static analysis supplied a preferred unattended command.'))
    }
    if($InstallerKind -eq 'QSetup'){
      $list.Add((New-InstallCandidate 'QSetup hidden + silent strategy' $Installer '/Hide /silent' 'Exe' 88 'QSetup commonly combines hidden and silent switches; validate rather than assume.'))
    }
    if($InstallerKind -eq 'WixBurn'){
      $list.Add((New-InstallCandidate 'WiX Burn quiet strategy' $Installer '/quiet /norestart' 'Exe' 95 'Standard WiX Burn unattended switches.'))
      $list.Add((New-InstallCandidate 'WiX Burn silent alias strategy' $Installer '-quiet -norestart' 'Exe' 72 'Alternate Burn-style switch spelling; validated in Sandbox before use.'))
    }
    # Generic hypotheses are intentionally lower confidence. They are safe to explore because
    # Test Mode runs them in an isolated Sandbox, aborts visible UI, and requires a discovered
    # installed identity before accepting a strategy.
    foreach($probe in @(
      @('Generic quiet strategy','/quiet /norestart',58),
      @('Silent install operation (long options)','--install --silent',57),
      @('Silent install operation','/silent /install',56),
      @('Generic silent strategy','/silent /norestart',54),
      @('Quiet install operation','/quiet /install /norestart',52),
      @('Generic slash-S strategy','/S',50),
      @('Generic very-silent strategy','/VERYSILENT /SUPPRESSMSGBOXES /NORESTART /SP-',48),
      @('Generic silent strategy (dash)','--silent',44),
      @('Short silent strategy','-s',40)
    )){$list.Add((New-InstallCandidate $probe[0] $Installer $probe[1] 'Exe' ([int]$probe[2]) 'Generated hypothesis for an otherwise unknown/custom bootstrapper; must pass Sandbox validation.'))}
    $dedupe=@{}; return @($list | Sort-Object Score -Descending | Where-Object {$k=($_.File+'|'+$_.Arguments).ToLowerInvariant();if($dedupe.ContainsKey($k)){$false}else{$dedupe[$k]=$true;$true}} | Select-Object -First 8)
}
function Invoke-InstallCandidateCore($candidate,$detectionTarget=$null) {
    Write-Checkpoint ('Silent reinstall invoke entered: '+$candidate.Name)
    Write-Checkpoint ('Silent reinstall launch file: '+$candidate.File)
    Write-Checkpoint ('Silent reinstall arguments prepared; length='+([string]$candidate.Arguments).Length)
    if($candidate.Kind -eq 'Msi'){ $msiLog='C:\InstallerOutput\msi-install.log'; return Invoke-NativeProcess 'msiexec.exe' (("/i `"$($candidate.File)`" " + $candidate.Arguments + " /L*v `"$msiLog`"").Trim()) $true $true 600 $detectionTarget $true}
    # Bound each reinstall candidate to ten minutes and stop as soon as the expected application
    # is detected. This prevents Adobe/other bootstrappers from hanging on normal descendants.
    return Invoke-NativeProcess $candidate.File $candidate.Arguments $true $true 600 $detectionTarget $true
}
function Invoke-InstallCandidate($candidate,$detectionTarget=$null) {
    if($script:NetFx3Terminal){throw ('PREREQUISITE REQUIRED: '+$result.NetFx3Provisioning.Detail)}
    $uiStart=@($result.UiTextEvidence).Count
    $response=Invoke-InstallCandidateCore $candidate $detectionTarget
    if($response.ExitCode -ne 0 -or $response.UiDetected){
      $evidence=@($result.UiTextEvidence | Select-Object -Skip $uiStart | ForEach-Object {$_.Labels} | Where-Object {Test-NetFx3RequirementText ([string]$_)} | Select-Object -First 1)
      if($evidence.Count -eq 0 -and $candidate.Kind -eq 'Msi' -and (Test-Path 'C:\InstallerOutput\msi-install.log')){
        $evidence=@(Get-Content 'C:\InstallerOutput\msi-install.log' -Tail 80 | Where-Object {Test-NetFx3RequirementText ([string]$_)} | Select-Object -First 1)
      }
      if($evidence.Count -gt 0 -and -not $result.NetFx3Provisioning.RuntimeVerified){
        Ensure-NetFx3 ([string]$evidence[0])
        # Exactly one retry, only after successful feature/runtime verification.
        return Invoke-InstallCandidateCore $candidate $detectionTarget
      }
    }
    return $response
}
function Get-SecondGenerationCandidates($files) {
    $list=New-Object 'System.Collections.Generic.List[object]'
    $safeRoots=@($env:TEMP,$env:LOCALAPPDATA,$env:ProgramData) | Where-Object {$_}
    foreach($f in @($files | Where-Object {$candidate=$_; $_ -like '*.msi' -and (Test-Path $_) -and (@($safeRoots | Where-Object {$candidate.StartsWith($_,[StringComparison]::OrdinalIgnoreCase)}).Count -gt 0)} | Select-Object -First 4)){
      $list.Add((New-InstallCandidate 'Discovered child MSI' $f '/qn /norestart' 'Msi' 82 'Second-generation candidate discovered from a payload extracted by the original bootstrapper.'))
    }
    foreach($f in @($files | Where-Object {$_ -like '*.exe' -and (Test-Path $_) -and $_ -match '(?i)\\(setup|install|installer)\.exe$'} | Select-Object -First 3)){
      foreach($probe in @(@('/quiet /norestart',68),@('/silent /norestart',64),@('/S',60),@('/VERYSILENT /SUPPRESSMSGBOXES /NORESTART /SP-',58))){
        $list.Add((New-InstallCandidate 'Discovered child executable' $f $probe[0] 'Exe' ([int]$probe[1]) 'Second-generation candidate generated from an extracted child installer.'))
      }
    }
    $dedupe=@{}; return @($list | Sort-Object Score -Descending | Where-Object {$k=($_.Kind+'|'+$_.File+'|'+$_.Arguments).ToLowerInvariant();if($dedupe.ContainsKey($k)){$false}else{$dedupe[$k]=$true;$true}} | Select-Object -First 8)
}
function Get-SilentUninstallCandidates($entry) {
    if($entry.Key -like 'APPX::*' -and -not [string]::IsNullOrWhiteSpace([string]$entry.QuietUninstallString)){return @([string]$entry.QuietUninstallString)}
    $list=New-Object 'System.Collections.Generic.List[string]'
    if(-not [string]::IsNullOrWhiteSpace([string]$entry.QuietUninstallString)){$list.Add([string]$entry.QuietUninstallString)}
    $msi=Get-MsiUninstallCommand $entry; if($msi){$list.Add($msi)}
    if(-not [string]::IsNullOrWhiteSpace([string]$entry.UninstallString)){
      $u=[string]$entry.UninstallString
      $sp=Split-Command $u
      if($sp){
        $exe=$sp[0]
        $args=[string]$sp[1]
        if($args -match '(?i)(^|\s)(/qn|/quiet|/silent|/verysilent|/S|--silent|-s)(\s|$)'){$list.Add($u)}
        if($InstallerKind -eq 'QSetup' -and $args -match '(?i)(^|\s)/hide(\s|$)'){$list.Add($u)}
        # Preserve the registry's operation/product arguments. Never intentionally test a plain
        # interactive uninstaller or throw away its required --uninstall/product selector.
        if([IO.Path]::GetFileName($exe) -match '(?i)^msiexec(\.exe)?$'){
          if($u -match '\{[0-9A-Fa-f-]{36}\}'){$list.Add(('msiexec.exe /x '+$matches[0]+' /qn /norestart'))}
        } else {
          $prefix=('"'+$exe+'" '+$args).Trim()
          # QSetup documents /Hide for both setup and removal. Product variables are package
          # specific and must come from user-supplied arguments, not invented EULA names.
          if($InstallerKind -eq 'QSetup' -and $args -notmatch '(?i)(^|\s)/hide(\s|$)'){$list.Add(($prefix+' /Hide'))}
          # Chromium-family setup command semantics (also used by downstream vendors):
          # https://www.chromium.org/administrators/common-problems-and-solutions/
          if($args -match '(?i)--uninstall' -and $args -match '(?i)--(channel|system-level|multi-install)'){
            $list.Add(($prefix+' --force-uninstall'))
          }
          # Reuse a switch that already passed installation before trying unrelated EXE
          # conventions. Operation/product selectors still come from the registry command.
          if($SilentInstallArguments -match '(?i)(^|\s)(/VERYSILENT|/SILENT|/quiet|--silent|/S)(\s|$)'){
            $list.Add(($prefix+' '+$matches[2]))
          }
          if($InstallerKind -eq 'InnoSetup' -or [IO.Path]::GetFileName($exe) -match '(?i)^unins\d*\.exe$'){
            $list.Add(($prefix+' /VERYSILENT /SUPPRESSMSGBOXES /NORESTART'))
          }
          $list.Add(($prefix+' /S'))
          $list.Add(($prefix+' /VERYSILENT /SUPPRESSMSGBOXES /NORESTART'))
          $list.Add(($prefix+' /quiet /norestart'))
          if($args -match '(?i)--uninstall'){$list.Add(($prefix+' -s'))}
        }
      }
    }
    $seen=@{}; return @($list | Where-Object {$_ -and -not $seen.ContainsKey($_.ToLowerInvariant()) -and ($seen[$_.ToLowerInvariant()]=$true)})
}
function Get-MsiUninstallCommand($entry) {
    if($entry.WindowsInstaller -eq 1 -and $entry.ProductCode){ return "msiexec.exe /x $($entry.ProductCode) /qn /norestart" }
    return $null
}
function Get-InnoUninstallCommand($entry) {
    if($InstallerKind -eq 'InnoSetup' -and $entry.UninstallString){
        $p=Split-Command $entry.UninstallString; if($p){ return ('"'+$p[0]+'" /VERYSILENT /SUPPRESSMSGBOXES /NORESTART') }
    }
    return $null
}
function Get-NewInstallerFiles {
    $files=New-Object 'System.Collections.Generic.HashSet[string]' ([StringComparer]::OrdinalIgnoreCase)
    $roots=@($env:TEMP,$env:LOCALAPPDATA,$env:ProgramData,$env:ProgramFiles,${env:ProgramFiles(x86)}) | Where-Object { $_ -and (Test-Path $_) } | Select-Object -Unique
    $deadline=(Get-Date).AddSeconds(3);$visited=0;$incomplete=$false
    foreach($root in $roots){
      $pending=New-Object 'System.Collections.Generic.Stack[object]';$pending.Push([PSCustomObject]@{Path=$root;Depth=0})
      while($pending.Count -gt 0){
        if((Get-Date) -ge $deadline -or $visited -ge 12000 -or $files.Count -ge 120){$incomplete=$true;break}
        $folder=$pending.Pop()
        try {
          if(([IO.File]::GetAttributes($folder.Path) -band [IO.FileAttributes]::ReparsePoint) -ne 0){$incomplete=$true;continue}
          foreach($path in [IO.Directory]::EnumerateFileSystemEntries($folder.Path)){
            if((Get-Date) -ge $deadline -or $visited++ -ge 12000 -or $files.Count -ge 120){$incomplete=$true;break}
            $attributes=[IO.File]::GetAttributes($path)
            if(($attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0){$incomplete=$true;continue}
            if(($attributes -band [IO.FileAttributes]::Directory) -ne 0){
              if($folder.Depth -lt 8){$pending.Push([PSCustomObject]@{Path=$path;Depth=($folder.Depth+1)})}else{$incomplete=$true}
            }elseif([IO.Path]::GetExtension($path).ToLowerInvariant() -in @('.exe','.msi','.msix','.appx','.msp','.msixbundle','.appxbundle','.cab','.zip','.7z','.iss','.rsp','.response','.config','.ini') -and [IO.File]::GetLastWriteTime($path) -ge $StartedAt){
              if($path -notlike 'C:\InstallerInput\*'){[void]$files.Add($path)}
            }
          }
        }catch{$incomplete=$true}
      }
    }
    if($incomplete){$result['PayloadScanIncomplete']=$true}
    $observed=@(Get-StringSetItems $files)
    $result.DiscoveredInstallerFiles=@(@($result.DiscoveredInstallerFiles)+$observed | Select-Object -Unique | Select-Object -First 120)
    return $observed
}
function Test-ClickToRun($processes,$primary) {
    if($primary -and (([string]$primary.UninstallString) -match '(?i)OfficeClickToRun\.exe' -or ([string]$primary.InstallLocation) -match '(?i)Microsoft Office')){ return $true }
    return [bool](@($processes | Where-Object {$_ -match '(?i)OfficeClickToRun\.exe|OfficeC2RClient\.exe'}).Count -gt 0)
}
function Get-ObservedSilentChild($processes) {
    foreach($line in $processes){
      if($line -notmatch '::\s*(.+)$'){continue}
      $cmd=$matches[1].Trim()
      if($cmd -notmatch '(?i)(/sAll|/silent|/verysilent|--silent)'){continue}
      $exe=$null; $args=''
      if($cmd -match '^"([^"]+)"\s*(.*)$'){$exe=$matches[1];$args=$matches[2]}
      elseif($cmd -match '^([^\s]+)\s*(.*)$'){$exe=$matches[1];$args=$matches[2]}
      if($exe -and $exe -ne $Installer){ return [PSCustomObject]@{File=$exe;Arguments=$args} }
    }
    return $null
}
function Watch-Bootstrapper([int]$RootPid,[string[]]$BeforeKeys) {
    $tracked = New-Object 'System.Collections.Generic.HashSet[int]'; [void]$tracked.Add($RootPid)
    $seen = New-Object 'System.Collections.Generic.HashSet[int]'
    $processLog = New-Object 'System.Collections.Generic.List[string]'
    $fileLog = New-Object 'System.Collections.Generic.HashSet[string]'
    $primary=$null; $new=@(); $quietSince=$null; $deadline=(Get-Date).AddMinutes(15)
    $infra='^(msiexec|OfficeClickToRun|OfficeC2RClient|setup|installer|install|update|Reader_en_install)'
    $postInstall='^(Acrobat|AdobeCollabSync|ShowAppPickerForPDF|msedge|msedgewebview2|explorer|SSScheduler|mc-webview-cnt|identity_helper)$'
    while((Get-Date) -lt $deadline){
      Set-AnalysisHeartbeat 'bootstrapper-discovery'
      $all=@(Get-CimInstance Win32_Process -ErrorAction SilentlyContinue)
      $changed=$true
      while($changed){
        $changed=$false
        foreach($proc in $all){
          if($proc.ProcessId -in $BeforeProcessIds){continue}
          if($tracked.Contains([int]$proc.ParentProcessId) -and -not $tracked.Contains([int]$proc.ProcessId)){[void]$tracked.Add([int]$proc.ProcessId);$changed=$true}
        }
      }
      foreach($proc in $all){
        if($proc.ProcessId -in $BeforeProcessIds){continue}
        $relevant=$tracked.Contains([int]$proc.ProcessId) -or ($proc.Name -match $infra)
        if(-not $relevant){continue}
        if($seen.Add([int]$proc.ProcessId)){
          $cmd=if($proc.CommandLine){$proc.CommandLine}else{$proc.Name}
          $processLog.Add(("$($proc.Name) [PID $($proc.ProcessId), PPID $($proc.ParentProcessId)] :: $cmd"))
        }
      }
      foreach($f in @(Get-NewInstallerFiles)){[void]$fileLog.Add($f)}
      $after=@(Get-UninstallSnapshot); $new=@($after | Where-Object {$_.Key -notin $BeforeKeys}); $primary=Select-Primary $new
      if(-not $primary -and $InstallerKind -eq 'Squirrel'){$primary=Find-SquirrelApplication}
      # Completion is based on installer infrastructure, not every descendant. Adobe/Edge/WebView
      # and other launched product processes can live for the rest of the Sandbox session.
      $active=@($all | Where-Object {
        if($_.ProcessId -in $BeforeProcessIds){return $false}
        if($_.Name -match $postInstall){return $false}
        if($_.Name -notmatch $infra){return $false}
        if($_.Name -match '^OfficeClickToRun' -and ([string]$_.CommandLine) -match '(?i)\s/service(?:\s|$)'){return $false}
        return $true
      })
      if($primary -and $active.Count -eq 0){if(-not $quietSince){$quietSince=Get-Date}; if(((Get-Date)-$quietSince).TotalSeconds -ge 24){break}}else{$quietSince=$null}
      Start-Sleep 3
    }
    return [PSCustomObject]@{Processes=@($processLog);Files=@($fileLog);Primary=$primary;NewEntries=@($new);TimedOut=((Get-Date) -ge $deadline)}
}
function Write-JsonAtomic([string]$path,$value) {
    $temporary=$path+'.'+[guid]::NewGuid().ToString('N')+'.tmp'
    try {
      $json=ConvertTo-Json -InputObject $value -Depth 12
      [IO.File]::WriteAllText($temporary,$json,(New-Object Text.UTF8Encoding($false)))
      for($writeAttempt=1;$writeAttempt -le 4;$writeAttempt++){
        try {
          if([IO.File]::Exists($path)){[IO.File]::Replace($temporary,$path,[System.Management.Automation.Language.NullString]::Value)}else{[IO.File]::Move($temporary,$path)}
          break
        } catch [IO.IOException] {
          if($writeAttempt -eq 4){throw}
          Start-Sleep -Milliseconds 75
        }
      }
    } finally {if([IO.File]::Exists($temporary)){[IO.File]::Delete($temporary)}}
}
function Test-LifecycleEvidence($proof) {
    if($null -eq $proof -or -not $proof.DiscoverySucceeded -or $proof.ValidationError){return $false}
    $captured=[DateTimeOffset]::MinValue
    if($proof.ValidationSchemaVersion -lt 2 -or -not [DateTimeOffset]::TryParse([string]$proof.CapturedAt,[ref]$captured)){return $false}
    if(($proof.ValidationSchemaVersion -ge 3 -and -not $proof.EvidenceCollectionComplete) -or -not $proof.InitialInstallValidated -or -not $proof.InitialUninstallValidated -or -not $proof.CleanBaselineVerified -or
       $proof.InitialUninstallExitCode -notin @(0,3010)){return $false}
    if(-not $proof.SilentReinstallValidated -or $null -eq $proof.SilentReinstallExitCode -or
       $proof.SilentReinstallExitCode -notin @(0,3010) -or $proof.SilentReinstallUiDetected){return $false}
    if(-not $proof.SilentUninstallValidated -or $null -eq $proof.SilentUninstallExitCode -or
       $proof.SilentUninstallExitCode -notin @(0,3010) -or $proof.SilentUninstallUiDetected -or
       $null -eq $proof.PostUninstallDetected -or $proof.PostUninstallDetected){return $false}
    return (@($proof.NewUninstallEntries | Where-Object {$_.Key -and $_.Key -eq $proof.PrimaryKey -and $_.DisplayName}).Count -gt 0)
}
function Write-Result($r) { $r.CapturedAt=(Get-Date).ToString('o'); Write-JsonAtomic $Analysis $r }
__ROADMAP_HELPERS__

$result=[ordered]@{ ValidationSchemaVersion=3; EvidenceCollectionComplete=$false; UiTextEvidence=@(); RuntimeEnvironment=@(); PrerequisiteProbes=@(); PrerequisiteFiles=@(); DetectionStrategies=@(); Components=@(); ProcessTree=@(); NetworkActivity=@(); NewRebootIndicators=@(); PostRebootValidated=$false; InitialInstallValidated=$false; InitialUninstallValidated=$false; InitialUninstallExitCode=$null; CleanBaselineVerified=$false; RebootRequired=$false; SessionId=([guid]::NewGuid().ToString()); InstallerSha256=$null; Installer=[IO.Path]::GetFileName($Installer); InstallerExitCode=-1; CapturedAt=(Get-Date).ToString('o'); NewUninstallEntries=@(); PrimaryKey=$null; UninstallValidationMethod='Discovery only'; UninstallRecordingAttempted=$false; UninstallResponseFileCreated=$false; RecordedUninstallExitCode=$null; BaseSilentArguments=$BaseSilentArguments; AdditionalPackageArguments=$AdditionalPackageArguments; CombinedSilentArguments=$SilentInstallArguments; SilentInstallCommand=('"'+$Installer+'" '+$SilentInstallArguments).Trim(); SilentInstallStdOut=$null; SilentInstallStdErr=$null; SilentReinstallExitCode=$null; SilentReinstallValidated=$false; SilentReinstallUiDetected=$false; SilentReinstallVisibleWindows=@(); SilentUninstallExitCode=$null; SilentUninstallRawExitCode=$null; SilentUninstallUiDetected=$false; SilentUninstallVisibleWindows=@(); UiDiagnostics=@(); SilentStrategyCandidates=@(); SilentStrategyAttempts=@(); SelectedSilentStrategy=$null; PostUninstallDetected=$null; SilentUninstallValidated=$false; DiscoverySucceeded=$false; DiscoveryMethod=$null; DeploymentMechanism=$null; DeploymentSource=$Installer; IdentitySource=$null; UninstallCandidate=$null; ValidationError=$null; BootstrapperProcesses=@(); DiscoveredInstallerFiles=@(); BlockedBundledSoftware=@(); BlockedBundledSoftwareVerifiedAbsent=$null; WorkflowStage='Initial installation / discovery'; WorkflowStageUpdatedAt=(Get-Date).ToString('o'); WorkflowStageHistory=@() }
# v0.12.7: Strategy Discovery can execute candidates before the later lifecycle section is reached.
# Keep checkpoint/debug helpers available from the start of analysis so Invoke-InstallCandidate and
# Invoke-NativeProcess can safely report progress in Silent Only mode.
$result['NetFx3Provisioning']=[ordered]@{Status='Not required';Evidence='';Detail='';Attempted=$false;Provisioned=$false;RuntimeVerified=$false;RequiresFullWindowsVM=$false;RestartNeeded=$false;ExitCode=$null}
$checkpoint='C:\InstallerOutput\install-analysis.checkpoint.json'
$debugLog='C:\InstallerOutput\analysis-debug.jsonl'
function Write-DebugEvent([string]$eventName, $data=$null) {
  try {
    $entry=[ordered]@{ Timestamp=(Get-Date).ToString('o'); Event=$eventName; WorkflowStage=$result.WorkflowStage; AnalysisPid=$PID }
    if($null -ne $data){$entry.Data=$data}
    ([PSCustomObject]$entry | ConvertTo-Json -Depth 7 -Compress) | Add-Content -Path $debugLog -Encoding UTF8
  } catch { }
}
function Write-DebugProcessSnapshot([string]$reason) {
  try {
    $procs=@(Get-CimInstance Win32_Process -ErrorAction SilentlyContinue | Where-Object { $_.Name -match '(?i)msiexec|setup|install|adobe|acrobat|reader' } | Select-Object ProcessId,ParentProcessId,Name,ExecutablePath,CommandLine)
    Write-DebugEvent ('Process snapshot: '+$reason) $procs
  } catch { }
}
function Write-Checkpoint([string]$stage) {
  $now=(Get-Date).ToString('o')
  $result.WorkflowStage=$stage; $result.WorkflowStageUpdatedAt=$now; $result.CapturedAt=$now
  $history=@($result.WorkflowStageHistory) + @([PSCustomObject]@{Stage=$stage;At=$now})
  $result.WorkflowStageHistory=$history
  Write-DebugEvent ('Stage: '+$stage)
  Write-JsonAtomic $checkpoint $result
}
if($InstallerKind -eq 'Msi'){$result.SilentInstallCommand=('msiexec.exe /i `"'+$Installer+'`" '+$SilentInstallArguments).Trim()}
if($InstallerKind -eq 'Msix'){$result.SilentInstallCommand=('Add-AppxPackage -Path `"'+$Installer+'`"')}
try {
    $script:NativeMsiBaselineState=Get-NativeMsiProductState ([string]$script:MsiStaticMetadata.ProductCode)
    $result['MsiProductStateBefore']=$script:NativeMsiBaselineState
    $script:MsiApplicationRegistryBaseline=@(Get-MsiApplicationRegistryBaseline)
    $result.RuntimeEnvironment=@(Get-RuntimeEnvironmentSnapshot 'Before install')
    $script:DetectionDirectoryBaseline=@(Get-DetectionDirectoryBaseline)
    $result.PrerequisiteProbes=@(Get-MsiPrerequisiteProbeEvidence)
    $result['PrerequisiteServices']=@(Get-MsiPrerequisiteServiceEvidence)
    $result.PrerequisiteFiles=@(Get-MsiPrerequisiteFileEvidence)
    $result['DllFiles']=@(Get-PeDllFileEvidence)
    $script:BeforeComponents=Get-ComponentEvidenceSnapshot
    $script:BeforeRebootEvidence=@(Get-PendingRebootEvidence)
    $result.InstallerSha256=(Get-FileHash -LiteralPath $Installer -Algorithm SHA256).Hash
    Ensure-NetFx3 ([Text.Encoding]::UTF8.GetString([Convert]::FromBase64String('__NETFX_EVIDENCE__')))
    Start-PayloadTrace
    if($InstallerKind -eq 'Msix'){
      $beforePackages=@(Get-AppxPackage | ForEach-Object {$_.PackageFullName})
      try { Add-AppxPackage -Path $Installer -ErrorAction Stop; $result.InstallerExitCode=0 } catch { throw "MSIX/AppX installation failed: $($_.Exception.Message)" }
      Start-Sleep 4
      $pkg=Get-AppxPackage | Where-Object {$_.PackageFullName -notin $beforePackages} | Select-Object -First 1
      if(-not $pkg){throw 'MSIX/AppX package installation completed, but no newly installed package could be identified.'}
      $primary=[PSCustomObject]@{Key=('APPX::'+$pkg.PackageFullName);DisplayName=$pkg.Name;DisplayVersion=$pkg.Version.ToString();Publisher=$pkg.Publisher;InstallLocation=$pkg.InstallLocation;UninstallString=('Remove-AppxPackage -Package '+$pkg.PackageFullName);QuietUninstallString=$null;WindowsInstaller=$null;ProductCode=$pkg.PackageFullName}
      $result.NewUninstallEntries=@($primary); $result.PrimaryKey=$primary.Key; $result.DiscoverySucceeded=$true; $result.DiscoveryMethod='MSIX/AppX package registration'; $result.UninstallValidationMethod='Remove-AppxPackage'; $result.UninstallCandidate=$primary.UninstallString
      Set-InstalledComponentEvidence
      Initialize-DetectionEvidence $primary @($beforePackages | ForEach-Object {[PSCustomObject]@{ProductCode=$_}})
      Remove-AppxPackage -Package $pkg.PackageFullName -ErrorAction Stop; Start-Sleep 3
      if(Get-AppxPackage -PackageTypeFilter Main,Bundle | Where-Object {$_.PackageFullName -eq $pkg.PackageFullName}){throw 'MSIX/AppX package remained detected after silent uninstall.'}
      $result.InitialInstallValidated=$true; $result.InitialUninstallExitCode=0; $result.InitialUninstallValidated=$true; $result.CleanBaselineVerified=$true
      try { Add-AppxPackage -Path $Installer -ErrorAction Stop; $result.SilentReinstallExitCode=0 } catch { $result.SilentReinstallExitCode=1; throw "MSIX/AppX silent reinstall failed: $($_.Exception.Message)" }
      Start-Sleep 3; $current=Get-AppxPackage | Where-Object {$_.Name -eq $pkg.Name} | Select-Object -First 1
      $result.SilentReinstallValidated=($null -ne $current)
      if(-not $current){throw 'MSIX/AppX package was not detected after reinstall.'}
      Remove-AppxPackage -Package $current.PackageFullName -ErrorAction Stop; $result.SilentUninstallExitCode=0; Start-Sleep 3
      $result.PostUninstallDetected=[bool](Get-AppxPackage | Where-Object {$_.Name -eq $pkg.Name})
      Complete-RoadmapRemovalEvidence
      $result.SilentUninstallValidated=-not $result.PostUninstallDetected
      if(-not $result.SilentUninstallValidated){$result.ValidationError='MSIX/AppX final removal verification did not pass.'}
    } else {
    $before=@(Get-UninstallSnapshot); $beforeKeys=@($before | ForEach-Object {$_.Key})
    $primary=$null; $new=@(); $p=$null
    if($RecordResponses){
      Write-Checkpoint 'Record InstallShield installation response file'
      $recordArguments=('/r /f1"'+$SetupIss+'" '+$AdditionalPackageArguments).Trim()
      $recorded=Invoke-NativeProcess $Installer $recordArguments $false $false 900
      $result.InstallerExitCode=$recorded.ExitCode
      if($recorded.TimedOut){throw 'InstallShield recording exceeded the 15-minute timeout.'}
      if($recorded.ExitCode -notin @(0,3010)){throw ('InstallShield recording returned exit code '+$recorded.ExitCode+'.')}
      if(-not (Test-InstallShieldResponse $SetupIss)){throw 'InstallShield did not create a valid setup.iss response file.'}
      $SilentInstallArguments=('/s /f1"'+$SetupIss+'" '+$AdditionalPackageArguments).Trim()
      $result.DiscoveryMethod='Recorded InstallShield response file + uninstall registry'
      for($i=0;$i -lt 12 -and -not $primary;$i++){
        Start-Sleep 3; $new=@(Get-UninstallSnapshot | Where-Object {$_.Key -notin $beforeKeys}); $primary=Select-Primary $new
      }
    } elseif($SilentOnly){
      Set-AnalysisHeartbeat 'strategy-discovery-start'
      $probeCandidates=@(Get-UnattendedProbeCandidates)
      if($InstallerKind -eq 'Msi'){$probeCandidates=@(Get-MsiInstallCandidates)}
      $result.SilentStrategyCandidates=@($probeCandidates | ForEach-Object {[PSCustomObject]@{Name=$_.Name;Score=$_.Score;File=$_.File;Arguments=$_.Arguments;Reason=$_.Reason}})
      if($probeCandidates.Count -eq 0){throw 'NO SILENT STRATEGY: Strategy Discovery Engine could not generate a safe unattended hypothesis.'}
      $selectedProbe=$null
      foreach($candidate in $probeCandidates){
        # Do not credit a partial installation from a rejected probe to the next strategy.
        if(@(Get-UninstallSnapshot | Where-Object {$_.Key -notin $beforeKeys}).Count -gt 0){throw 'Candidate exploration stopped: a rejected probe changed installed application state. A fresh Sandbox is required.'}
        Write-Checkpoint ('Strategy probe: '+$candidate.Name)
        Set-AnalysisHeartbeat ('strategy-probe-'+$candidate.Name)
        $attempt=[ordered]@{Source=$candidate.Reason;StartedAt=(Get-Date).ToString('o');CompletedAt=$null;Name=$candidate.Name;Score=$candidate.Score;Command=if($candidate.Kind -eq 'Msi'){'msiexec.exe /i "'+$candidate.File+'" '+$candidate.Arguments}else{'"'+$candidate.File+'" '+$candidate.Arguments};Outcome='Testing';ExitCode=$null;UiDetected=$false;VisibleWindows=@();UiDiagnostics=@();ApplicationDetected=$false}
        try{$ri=Invoke-InstallCandidate $candidate $null}catch{if($script:NetFx3Terminal){throw};$attempt.Outcome='Rejected: execution error - '+$_.Exception.Message;$attempt.CompletedAt=(Get-Date).ToString('o');$result.SilentStrategyAttempts+=@([PSCustomObject]$attempt);continue}
        $attempt.ExitCode=$ri.ExitCode;$attempt.UiDetected=$ri.UiDetected;$attempt.VisibleWindows=@($ri.VisibleWindows);$attempt.UiDiagnostics=@($ri.UiDiagnostics);$result.UiDiagnostics+=@($ri.UiDiagnostics)
        if($ri.ExitCode -eq -1073741515){$attempt.Outcome='PREREQUISITE REQUIRED: executable loader reported a missing DLL (0xC0000135).';$attempt.CompletedAt=(Get-Date).ToString('o');$result.SilentStrategyAttempts+=@([PSCustomObject]$attempt);throw $attempt.Outcome}
        if($ri.TimedOut){$attempt.Outcome='Rejected: timeout / possible prerequisite or interaction';$attempt.CompletedAt=(Get-Date).ToString('o');$result.SilentStrategyAttempts+=@([PSCustomObject]$attempt);continue}
        if($ri.UiDetected){$attempt.Outcome='Rejected: visible installer UI detected';$attempt.CompletedAt=(Get-Date).ToString('o');$result.SilentStrategyAttempts+=@([PSCustomObject]$attempt);continue}
        if($ri.ExitCode -notin @(0,3010,1641)){$attempt.Outcome="Rejected: exit code "+$ri.ExitCode;$attempt.CompletedAt=(Get-Date).ToString('o');$result.SilentStrategyAttempts+=@([PSCustomObject]$attempt);continue}
        if($ri.ExitCode -eq 1641){$attempt.Outcome='Rejected: immediate reboot requested';$attempt.CompletedAt=(Get-Date).ToString('o');$result.SilentStrategyAttempts+=@([PSCustomObject]$attempt);continue}
        Start-Sleep 4
        $after=@(Get-UninstallSnapshot);$new=@($after | Where-Object {$_.Key -notin $beforeKeys});$candidatePrimary=Select-Primary $new
        if(-not $candidatePrimary -and $InstallerKind -eq 'Squirrel'){$candidatePrimary=Find-SquirrelApplication}
        $attempt.ApplicationDetected=($null -ne $candidatePrimary)
        if($ri.ExitCode -notin @(0,3010)){$attempt.Outcome='Rejected: exit code '+$ri.ExitCode;$attempt.CompletedAt=(Get-Date).ToString('o');$result.SilentStrategyAttempts+=@([PSCustomObject]$attempt);continue}
        if(-not $candidatePrimary){$attempt.Outcome='Rejected: application identity not detected';$attempt.CompletedAt=(Get-Date).ToString('o');$result.SilentStrategyAttempts+=@([PSCustomObject]$attempt);continue}
        $attempt.Outcome='Validated';$attempt.CompletedAt=(Get-Date).ToString('o');$result.SilentStrategyAttempts+=@([PSCustomObject]$attempt);$selectedProbe=$candidate;$primary=$candidatePrimary;$result.InstallerExitCode=$ri.ExitCode;break
      }
      if(-not $selectedProbe){
        # v0.12.7: first-generation probes can reveal a vendor bootstrapper's extracted payload even
        # when the probe itself is rejected for UI/exit status. Turn those artifacts into a second
        # generation of MSI/setup candidates instead of giving up on an unfamiliar product.
        $discoveredAfterProbes=@(Get-NewInstallerFiles)
        $result.DiscoveredInstallerFiles=@($discoveredAfterProbes)
        $secondGen=@(Get-SecondGenerationCandidates $discoveredAfterProbes)
        foreach($candidate in $secondGen){
          if(@(Get-UninstallSnapshot | Where-Object {$_.Key -notin $beforeKeys}).Count -gt 0){throw 'Second-generation exploration stopped: a rejected probe changed installed application state. A fresh Sandbox is required.'}
          $result.SilentStrategyCandidates+=@([PSCustomObject]@{Name=$candidate.Name;Score=$candidate.Score;File=$candidate.File;Arguments=$candidate.Arguments;Reason=$candidate.Reason})
          Set-AnalysisHeartbeat ('strategy-second-generation-'+$candidate.Name)
          $attempt=[ordered]@{Source=$candidate.Reason;StartedAt=(Get-Date).ToString('o');CompletedAt=$null;Name=$candidate.Name;Score=$candidate.Score;Command=if($candidate.Kind -eq 'Msi'){'msiexec.exe /i "'+$candidate.File+'" '+$candidate.Arguments}else{'"'+$candidate.File+'" '+$candidate.Arguments};Outcome='Testing';ExitCode=$null;UiDetected=$false;VisibleWindows=@();UiDiagnostics=@();ApplicationDetected=$false}
          try{$ri=Invoke-InstallCandidate $candidate $null}catch{if($script:NetFx3Terminal){throw};$attempt.Outcome='Rejected: execution error - '+$_.Exception.Message;$attempt.CompletedAt=(Get-Date).ToString('o');$result.SilentStrategyAttempts+=@([PSCustomObject]$attempt);continue}
          $attempt.ExitCode=$ri.ExitCode;$attempt.UiDetected=$ri.UiDetected;$attempt.VisibleWindows=@($ri.VisibleWindows);$attempt.UiDiagnostics=@($ri.UiDiagnostics);$result.UiDiagnostics+=@($ri.UiDiagnostics)
          if($ri.ExitCode -eq -1073741515){$attempt.Outcome='PREREQUISITE REQUIRED: executable loader reported a missing DLL (0xC0000135).';$attempt.CompletedAt=(Get-Date).ToString('o');$result.SilentStrategyAttempts+=@([PSCustomObject]$attempt);throw $attempt.Outcome}
          if($ri.TimedOut){$attempt.Outcome='Rejected: timeout';$attempt.CompletedAt=(Get-Date).ToString('o');$result.SilentStrategyAttempts+=@([PSCustomObject]$attempt);continue}
          if($ri.UiDetected){$attempt.Outcome='Rejected: visible installer UI detected';$attempt.CompletedAt=(Get-Date).ToString('o');$result.SilentStrategyAttempts+=@([PSCustomObject]$attempt);continue}
          Start-Sleep 4
          $after=@(Get-UninstallSnapshot);$new=@($after | Where-Object {$_.Key -notin $beforeKeys});$candidatePrimary=Select-Primary $new
          $attempt.ApplicationDetected=($null -ne $candidatePrimary)
          if($ri.ExitCode -notin @(0,3010) -or -not $candidatePrimary){$attempt.Outcome=if($ri.ExitCode -notin @(0,3010)){'Rejected: exit code '+$ri.ExitCode}else{'Rejected: application identity not detected'};$attempt.CompletedAt=(Get-Date).ToString('o');$result.SilentStrategyAttempts+=@([PSCustomObject]$attempt);continue}
          $attempt.Outcome='Validated';$attempt.CompletedAt=(Get-Date).ToString('o');$result.SilentStrategyAttempts+=@([PSCustomObject]$attempt);$selectedProbe=$candidate;$primary=$candidatePrimary;$result.InstallerExitCode=$ri.ExitCode;break
        }
      }
      if(-not $selectedProbe){
        if($InstallerKind -eq 'Msi'){
          $detail=''
          try {
            foreach($line in @(Get-Content 'C:\InstallerOutput\msi-install.log' -Tail 4000 -ErrorAction Stop)){
              if($line -match 'Product: .*? -- (.+)$' -and $matches[1] -notmatch '^(Installation|Configuration) (failed|completed)'){$detail=$matches[1];break}
            }
          } catch {}
          $prefix=if($detail -match '(?i)transform|instanceid'){'PACKAGE CONFIGURATION REQUIRED: '}else{'INSTALL FAILED: '}
          throw ($prefix+'MSI returned '+(($result.SilentStrategyAttempts | Select-Object -Last 1).ExitCode)+'. '+$detail+' See msi-install.log.')
        }
        throw 'NO SILENT STRATEGY: First- and second-generation unattended hypotheses were tested, but none produced a validated installed application without visible UI.'
      }
      $result.SelectedSilentStrategy=$selectedProbe.Name;$result.SilentInstallCommand=if($selectedProbe.Kind -eq 'Msi'){'msiexec.exe /i "'+$selectedProbe.File+'" '+$selectedProbe.Arguments}else{'"'+$selectedProbe.File+'" '+$selectedProbe.Arguments};$SilentInstallArguments=$selectedProbe.Arguments;$EffectiveSilentInstaller=$selectedProbe.File
      $result.InitialInstallValidated=$true
      if($result.InstallerExitCode -eq 3010){$result.RebootRequired=$true}
    } elseif($InstallerKind -in @('Unknown','Bootstrapper')){
      $p=Start-Process -FilePath $Installer -PassThru
      $activity=Watch-Bootstrapper $p.Id $beforeKeys
      $result.BootstrapperProcesses=@($activity.Processes); $result.DiscoveredInstallerFiles=@($activity.Files); $primary=$activity.Primary; $new=@($activity.NewEntries)
      try {$p.Refresh(); if($p.HasExited){$result.InstallerExitCode=$p.ExitCode}else{$result.InstallerExitCode=-2}} catch {$result.InstallerExitCode=-2}
      $isClickToRun=Test-ClickToRun $result.BootstrapperProcesses $primary
      if($isClickToRun){
        $DeploymentMechanism='Microsoft Click-to-Run'
        $DeploymentSource=$Installer
        $IdentitySource='Office uninstall registry / Click-to-Run registration'
        $result.DeploymentMechanism=$DeploymentMechanism; $result.DeploymentSource=$DeploymentSource; $result.IdentitySource=$IdentitySource
        $result.DiscoveryMethod='Microsoft Click-to-Run + uninstall registry'
        # Office Click-to-Run integration MSIs are implementation components, not standalone deployment packages.
        # Keep the original bootstrapper as the deployment source and do not promote C2RInt*.msi.
      }
      # Prefer a real silent bootstrapper child observed during the successful install.
      # This avoids incorrectly promoting vendor cache MSIs (for example Adobe AcroPro.msi)
      # that may be transient or unusable as standalone deployment sources.
      $observedSilent=if($isClickToRun){$null}else{Get-ObservedSilentChild $result.BootstrapperProcesses}
      if($observedSilent){
        # The observed child proves the vendor's unattended argument grammar, but the child may
        # be ephemeral or a post-install cache executable. Reapply those arguments to the original
        # deployment source and validate that source instead of depending on the child path.
        $EffectiveSilentInstaller=$Installer; $DeploymentSource=$Installer; $SilentInstallArguments=$observedSilent.Arguments
        $result.DeploymentSource=$Installer; $result.BaseSilentArguments=$SilentInstallArguments; $result.CombinedSilentArguments=$SilentInstallArguments
        $result.SilentInstallCommand=('"'+$Installer+'" '+$SilentInstallArguments).Trim()
        $result.DiscoveryMethod='Observed silent bootstrapper arguments + original deployment source + uninstall registry'
      } elseif(-not $isClickToRun) {
        $safeRoots=@($env:TEMP,$env:LOCALAPPDATA,$env:ProgramData) | Where-Object {$_}
        $childMsi=@($result.DiscoveredInstallerFiles | Where-Object {
          $candidate=$_; $candidate -like '*.msi' -and (Test-Path $candidate) -and (@($safeRoots | Where-Object {$candidate.StartsWith($_,[StringComparison]::OrdinalIgnoreCase)}).Count -gt 0)
        } | Select-Object -First 1)
        if($childMsi.Count -gt 0){
          $EffectiveSilentInstaller=$childMsi[0]; $DiscoveredInstallerKind='Msi'; $SilentInstallArguments='/qn /norestart'
          $result.BaseSilentArguments='/qn /norestart'; $result.CombinedSilentArguments='/qn /norestart'
          $result.SilentInstallCommand=('msiexec.exe /i `"'+$EffectiveSilentInstaller+'`" /qn /norestart')
        }
      }
      if(-not $primary){
        $state=if($activity.TimedOut){'timed out while installer activity was still being observed'}else{'became idle'}
        throw ('Bootstrapper/unknown installer '+$state+' without an identifiable installed application. Relevant processes: '+@($result.BootstrapperProcesses).Count+'; candidate downloaded/extracted installer files: '+@($result.DiscoveredInstallerFiles).Count+'.')
      }
    } else {
      $p=Start-Process -FilePath $Installer -PassThru
      $finished=$false; $waitDeadline=(Get-Date).AddMinutes(10)
      while((Get-Date) -lt $waitDeadline){ Set-AnalysisHeartbeat 'initial-installer-wait'; if($p.WaitForExit(1000)){$finished=$true;break} }
      $result.InstallerExitCode=if($finished){$p.ExitCode}else{-2}
      for($i=0;$i -lt 12 -and -not $primary;$i++){
        Start-Sleep 3; $after=@(Get-UninstallSnapshot); $new=@($after | Where-Object {$_.Key -notin $beforeKeys}); $primary=Select-Primary $new
        if(-not $primary -and $InstallerKind -eq 'Squirrel'){$primary=Find-SquirrelApplication}
      }
    }
    $result.NewUninstallEntries=$new
    Set-InstalledComponentEvidence
    if(-not $primary){ throw 'Installer completed, but no primary application could be identified after registry and installer-specific discovery.' }
    if($primary.Key -like 'FILE::*' -and @($result.NewUninstallEntries).Count -eq 0){$result.NewUninstallEntries=@($primary)}
    $result.PrimaryKey=$primary.Key; $result.DiscoverySucceeded=$true; if([string]::IsNullOrWhiteSpace($result.IdentitySource)){$result.IdentitySource='Uninstall registry'}; if([string]::IsNullOrWhiteSpace($result.DeploymentSource)){$result.DeploymentSource=$EffectiveSilentInstaller}; if([string]::IsNullOrWhiteSpace($result.DeploymentMechanism)){$result.DeploymentMechanism=if($DiscoveredInstallerKind -eq 'Msi'){'MSI'}elseif($InstallerKind -in @('Unknown','Bootstrapper')){'Bootstrapper'}else{$InstallerKind}}; if([string]::IsNullOrWhiteSpace($result.DiscoveryMethod)){$result.DiscoveryMethod=if($DiscoveredInstallerKind -eq 'Msi'){'Bootstrapper child MSI + uninstall registry'}elseif($primary.Key -like 'FILE::*'){'Squirrel LocalAppData filesystem'}else{'Uninstall registry'}}

    # v0.11.38: preserve Adobe's COMPLETE cached setup directory before uninstall. The
    # prior single-file setup.exe copy returned exit 2, suggesting setup.exe expects adjacent
    # cached payload/context. This remains validation-only and does not replace DeploymentSource.
    try {
      $adobeSetup=@($result.DiscoveredInstallerFiles | Where-Object { $_ -match '(?i)\\Adobe\\Acrobat\\Setup\\.*\\setup\.exe$' -and (Test-Path $_) } | Select-Object -First 1)
      if($adobeSetup.Count -gt 0){
        $sourceSetupDir=Split-Path -Parent $adobeSetup[0]
        $stageRoot=Join-Path $env:TEMP 'InstallerAnalyzer-StagedVendor'
        $StagedVendorSetupDirectory=Join-Path $stageRoot 'AdobeSetupCache'
        Remove-Item -LiteralPath $StagedVendorSetupDirectory -Recurse -Force -ErrorAction SilentlyContinue
        New-Item -ItemType Directory -Path $StagedVendorSetupDirectory -Force | Out-Null
        Copy-Item -Path (Join-Path $sourceSetupDir '*') -Destination $StagedVendorSetupDirectory -Recurse -Force -ErrorAction Stop
        $StagedVendorSetup=Join-Path $StagedVendorSetupDirectory 'setup.exe'
        if(-not (Test-Path $StagedVendorSetup)){ throw 'Staged Adobe setup directory did not contain setup.exe.' }
      }
    } catch { $StagedVendorSetup=$null; $StagedVendorSetupDirectory=$null }

    # Checkpoint/debug helpers are initialized before Strategy Discovery in v0.12.7.
    $result.InitialInstallValidated=$true
    Initialize-DetectionEvidence $primary $before
    Write-Checkpoint 'Discovery complete'

    Write-Checkpoint 'Build uninstall candidate'
    $initialUninstallDone=$false
    $uninstallCommand=$primary.QuietUninstallString
    if([string]::IsNullOrWhiteSpace($uninstallCommand)){$uninstallCommand=Get-MsiUninstallCommand $primary; if($uninstallCommand){$result.UninstallCandidate=$uninstallCommand;$result.UninstallValidationMethod='MSI ProductCode /x /qn /norestart'}}
    if([string]::IsNullOrWhiteSpace($uninstallCommand) -and $InstallerKind -eq 'InnoSetup'){$uninstallCommand=Get-InnoUninstallCommand $primary; if($uninstallCommand){$result.UninstallCandidate=$uninstallCommand;$result.UninstallValidationMethod='Inno Setup silent uninstaller'}}
    if([string]::IsNullOrWhiteSpace($uninstallCommand) -and $InstallerKind -eq 'Nsis' -and $primary.UninstallString){$uninstallCommand=$primary.UninstallString + ' /S'; $result.UninstallCandidate=$uninstallCommand; $result.UninstallValidationMethod='NSIS /S candidate'}
    elseif([string]::IsNullOrWhiteSpace($uninstallCommand) -and $InstallerKind -eq 'Squirrel' -and $primary.UninstallString){$uninstallCommand=$primary.UninstallString; $result.UninstallCandidate=$uninstallCommand; $result.UninstallValidationMethod='Squirrel Update.exe --uninstall candidate'}
    elseif(-not [string]::IsNullOrWhiteSpace($uninstallCommand) -and $result.UninstallValidationMethod -eq 'Discovery only'){$result.UninstallValidationMethod='QuietUninstallString + detected silent install strategy'}
    if($RecordResponses -and [string]::IsNullOrWhiteSpace($uninstallCommand)){
      $RecordedUninstallParts=Split-Command $primary.UninstallString
      if(-not $RecordedUninstallParts){throw 'No registered uninstall command is available for response recording.'}
      Write-Checkpoint 'Record InstallShield uninstall response file'
      $result.UninstallRecordingAttempted=$true
      $recordArgs=($RecordedUninstallParts[1]+' /r /f1"'+$UninstallIss+'"').Trim()
      $recorded=Invoke-NativeProcess $RecordedUninstallParts[0] $recordArgs $false $false 900
      $result.RecordedUninstallExitCode=$recorded.ExitCode; $result.InitialUninstallExitCode=$recorded.ExitCode
      $result.UninstallResponseFileCreated=Test-InstallShieldResponse $UninstallIss
      if($recorded.TimedOut){throw 'InstallShield uninstall recording exceeded the 15-minute timeout.'}
      if($recorded.ExitCode -notin @(0,3010)){throw ('InstallShield uninstall recording returned exit code '+$recorded.ExitCode+'.')}
      if(-not $result.UninstallResponseFileCreated){throw 'InstallShield uninstall recording did not create a valid uninstall.iss.'}
      if(-not (Wait-ApplicationAbsent $primary 'Initial')){throw 'Application remained detected after recorded uninstall.'}
      $uninstallCommand=('"'+$RecordedUninstallParts[0]+'" '+$RecordedUninstallParts[1]+' /s /f1"'+$UninstallIss+'"').Trim()
      $result.UninstallCandidate=$uninstallCommand; $result.UninstallValidationMethod='Recorded InstallShield uninstall response file'
      $result.InitialUninstallValidated=$true; $result.CleanBaselineVerified=$true; $initialUninstallDone=$true
    }
    if([string]::IsNullOrWhiteSpace($uninstallCommand)){
      foreach($proposal in @(Get-SilentUninstallCandidates $primary)){
        Write-Checkpoint 'Discover initial silent uninstall strategy'
        $parts=Split-Command $proposal; if(-not $parts){continue}
        try {$trial=Invoke-NativeProcess $parts[0] $parts[1] $true $true 120}catch{continue}
        $result.UiDiagnostics+=@($trial.UiDiagnostics)
        Write-DebugEvent 'Initial uninstall hypothesis result' ([PSCustomObject]@{Command=$proposal;ExitCode=$trial.ExitCode;UiDetected=$trial.UiDetected})
        Start-Sleep 3
        if((Test-ProcessResultSuccess $trial) -and (Wait-ApplicationAbsent $primary 'Initial')){
          $uninstallCommand=$proposal; $result.UninstallCandidate=$proposal; $result.UninstallValidationMethod='Sandbox-discovered silent uninstall'; $result.InitialUninstallExitCode=$trial.ExitCode; $result.InitialUninstallValidated=$true; $result.CleanBaselineVerified=$true; $initialUninstallDone=$true; break
        }
        if(-not (Test-Detected $primary)){throw 'An unvalidated uninstall strategy changed application state. A fresh Sandbox is required.'}
      }
    }
    Write-Checkpoint 'Uninstall candidate ready'

    if($result.DeploymentMechanism -eq 'Microsoft Click-to-Run' -and [string]::IsNullOrWhiteSpace($uninstallCommand)) {$result.ValidationError='Microsoft Click-to-Run deployment was identified successfully. Internal Office MSI files were intentionally not promoted as deployment packages. A safe unattended Click-to-Run uninstall/reinstall strategy was not inferred automatically, so lifecycle validation was not attempted.'}
    elseif([string]::IsNullOrWhiteSpace($uninstallCommand)) {$result.ValidationError='Discovery succeeded, but no safe silent uninstall method or installer-family candidate is available. Lifecycle validation was not attempted.'}
    else {
      if(-not $initialUninstallDone){
      Write-Checkpoint 'Pre-uninstall detection'
      $preUninstallDetected=Test-Detected $primary
      Write-Checkpoint ('Pre-uninstall detection complete: '+$preUninstallDetected)
      $parts=Split-Command $uninstallCommand; if(-not $parts){throw 'Could not parse silent uninstall command.'}
      Write-Checkpoint 'Silent uninstall starting'
      if(-not $preUninstallDetected){throw 'Initial uninstall cannot be validated: the primary application was already absent.'}
      # Monitor UI and heartbeat while waiting. The Windows Installer client exits independently
      # of its long-lived service descendants, so only its own exit is authoritative for MSI.
      $initialExecution=$null
      for($initialAttempt=1;$initialAttempt -le 4;$initialAttempt++){
        $executionArguments=Get-UninstallExecutionArguments $parts[0] $parts[1] 'initial'
        Write-Checkpoint ('Initial silent uninstall attempt '+$initialAttempt+'/4')
        $initialExecution=Invoke-NativeProcess $parts[0] $executionArguments $true $true 300
        $result.UiDiagnostics+=@($initialExecution.UiDiagnostics)
        $result.InitialUninstallExitCode=$initialExecution.ExitCode
        Write-DebugEvent 'Initial uninstall result' ([PSCustomObject]@{ExitCode=$initialExecution.ExitCode;RawExitCode=$initialExecution.RawExitCode;UiDetected=$initialExecution.UiDetected;TimedOut=$initialExecution.TimedOut})
        if($initialExecution.ExitCode -ne 1618 -or $initialExecution.UiDetected -or $initialAttempt -eq 4){break}
        Write-Checkpoint 'Windows Installer busy (1618); waiting before initial-uninstall retry'
        for($busyWait=0;$busyWait -lt 15;$busyWait++){Set-AnalysisHeartbeat 'initial-uninstall-busy-wait';Start-Sleep 1}
      }
      if($initialExecution.TimedOut){throw 'Initial silent uninstall exceeded the 5-minute command timeout. See msi-uninstall-initial.log when available.'}
      if($initialExecution.UiDetected){
        $result['MsiRemovalUiActions']=@(Get-MsiRemovalUiActions $EffectiveSilentInstaller)
        throw ('Initial uninstall displayed interactive UI: '+($initialExecution.VisibleWindows -join '; '))
      }
      if(-not (Test-ProcessResultSuccess $initialExecution)){throw ('Initial silent uninstall returned exit code '+$initialExecution.ExitCode+'. See msi-uninstall-initial.log when available.')}
      $result.RebootRequired=($result.RebootRequired -or $initialExecution.ExitCode -eq 3010)
      if(-not (Wait-ApplicationAbsent $primary 'Initial')){throw 'Application remained detected after the bounded initial-uninstall absence verification.'}
      $result.InitialUninstallValidated=$true; $result.CleanBaselineVerified=$true
      Write-Checkpoint 'Initial uninstall verified absent'
      }

      Write-Checkpoint 'Build silent install candidates'
      $candidates=if($RecordResponses){@((New-InstallCandidate 'Recorded InstallShield response file' $Installer $SilentInstallArguments 'Exe' 100 'Response file recorded during this Sandbox lifecycle; replay must pass unattended validation.'))}elseif($SilentOnly -and $selectedProbe){@($selectedProbe)}else{@(Get-SilentInstallCandidates $observedSilent $result.DiscoveredInstallerFiles)}
      $result.SilentStrategyCandidates=@($candidates | ForEach-Object {[PSCustomObject]@{Name=$_.Name;Score=$_.Score;File=$_.File;Arguments=$_.Arguments;Reason=$_.Reason}})
      Write-Checkpoint ('Silent install candidates ready: '+$candidates.Count)
      if($candidates.Count -eq 0){throw 'Discovery succeeded, but no credible silent-install strategy candidates were available.'}
      # v0.11.38: candidate validation is a small, deterministic state machine.
      # Process execution returns first; evaluation/cleanup happens afterward. A failed
      # candidate is a validation result, not an analyzer exception.
      $current=$null; $selected=$null
      foreach($candidate in $candidates){
        Write-Checkpoint ('Candidate state: Execute / '+$candidate.Name)
        $attempt=[ordered]@{Source=$candidate.Reason;StartedAt=(Get-Date).ToString('o');CompletedAt=$null;Name=$candidate.Name;Score=$candidate.Score;Command=if($candidate.Kind -eq 'Msi'){'msiexec.exe /i "'+$candidate.File+'" '+$candidate.Arguments}else{'"'+$candidate.File+'" '+$candidate.Arguments};Outcome='Testing';ExitCode=$null;UiDetected=$false;VisibleWindows=@();UiDiagnostics=@();ApplicationDetected=$false}
        $ri=$null
        try {
          if($RecordResponses){
            $replayLog='C:\InstallerOutput\iss-install-replay.log'
            Remove-Item -LiteralPath $replayLog -Force -ErrorAction SilentlyContinue
            $ri=Invoke-NativeProcess $candidate.File ($candidate.Arguments+' /f2"'+$replayLog+'"') $true $true 600 $primary $true
            if(-not (Test-InstallShieldReplayLog $replayLog)){throw 'InstallShield reinstall replay did not produce exactly one successful ResultCode=0.'}
          }else{$ri=Invoke-InstallCandidate $candidate $primary}
        }
        catch {
          if($script:NetFx3Terminal){throw}
          $attempt.Outcome='Rejected: execution error: '+$_.Exception.Message
          $attempt.CompletedAt=(Get-Date).ToString('o');$result.SilentStrategyAttempts+=@([PSCustomObject]$attempt)
          Write-Checkpoint ('Candidate state: Rejected execution error / '+$candidate.Name)
          continue
        }

        # Record the minimum durable attempt FIRST. Diagnostics are deliberately copied only
        # after the attempt is safely present in the checkpoint/result object.
        $attempt.ExitCode=$ri.ExitCode
        $attempt.UiDetected=[bool]$ri.UiDetected
        foreach($vw in @($ri.VisibleWindows)){ if($null -ne $vw){$attempt.VisibleWindows += [string]$vw} }
        $attempt.CompletedAt=(Get-Date).ToString('o');$result.SilentStrategyAttempts+=@([PSCustomObject]$attempt)
        $attemptIndex=$result.SilentStrategyAttempts.Count-1
        Write-Checkpoint ('Candidate state: Evaluate / '+$candidate.Name+' / exit '+$ri.ExitCode)

        if($ri.UiDetected){
          $result.SilentStrategyAttempts[$attemptIndex].Outcome='Rejected: visible installer UI detected'
          Write-Checkpoint ('Candidate state: Cleanup visible UI / '+$candidate.Name)
          Start-Sleep 2
          $partial=$null; try{$partial=Find-Reinstalled $primary}catch{}
          $result.SilentStrategyAttempts[$attemptIndex].ApplicationDetected=($null -ne $partial)
          if($partial){
            $cleanup=$partial.QuietUninstallString; if([string]::IsNullOrWhiteSpace($cleanup)){$cleanup=Get-MsiUninstallCommand $partial}
            if($cleanup){
              $cp=Split-Command $cleanup
              if($cp){
                $cu=Invoke-NativeProcess $cp[0] $cp[1] $true $true 60
                Start-Sleep 4
              }
            }
          }
          if(Test-Detected $primary){
            $result.ValidationError='Candidate exploration stopped because a rejected visible-UI strategy changed system state and cleanup did not restore a clean baseline.'
            Write-Checkpoint ('Candidate state: Unsafe baseline / '+$candidate.Name)
            break
          }
          Write-Checkpoint ('Candidate state: Next / '+$candidate.Name)
          continue
        }

        # Non-success exit codes are terminal for this candidate. Do one bounded state check,
        # record the failure, restore the baseline if necessary, then move on immediately.
        if($ri.ExitCode -notin @(0,3010)){
          $partial=$null; try{$partial=Find-Reinstalled $primary}catch{}
          $result.SilentStrategyAttempts[$attemptIndex].ApplicationDetected=($null -ne $partial)
          $result.SilentStrategyAttempts[$attemptIndex].Outcome='Rejected: exit code '+$ri.ExitCode
          Write-Checkpoint ('Candidate state: Rejected exit code / '+$candidate.Name)
          if($partial){
            $cleanup=$partial.QuietUninstallString; if([string]::IsNullOrWhiteSpace($cleanup)){$cleanup=Get-MsiUninstallCommand $partial}
            if($cleanup){$cp=Split-Command $cleanup;if($cp){$cu=Invoke-NativeProcess $cp[0] $cp[1] $true $true 60;Start-Sleep 4}}
          }
          if(Test-Detected $primary){
            $result.ValidationError='Candidate exploration stopped because a failed strategy changed system state and cleanup did not restore a clean baseline.'
            Write-Checkpoint ('Candidate state: Unsafe baseline / '+$candidate.Name)
            break
          }
          Write-Checkpoint ('Candidate state: Next / '+$candidate.Name)
          continue
        }

        Write-Checkpoint ('Candidate state: Detect / '+$candidate.Name)
        $current=$null
        for($i=0;$i -lt 12 -and -not $current;$i++){
          Start-Sleep 3
          try{$current=Find-Reinstalled $primary}catch{$current=$null}
          if(($i % 3) -eq 2){Write-Checkpoint ('Candidate state: Detect '+($i+1)+'/12 / '+$candidate.Name)}
        }
        $result.SilentStrategyAttempts[$attemptIndex].ApplicationDetected=($null -ne $current)
        if($current){
          $result.SilentStrategyAttempts[$attemptIndex].Outcome='Validated'
          $selected=$candidate
          Write-Checkpoint ('Candidate state: Validated / '+$candidate.Name)
          break
        }

        $result.SilentStrategyAttempts[$attemptIndex].Outcome='Rejected: application not detected'
        Write-Checkpoint ('Candidate state: Rejected not detected / '+$candidate.Name)
        Write-Checkpoint ('Candidate state: Next / '+$candidate.Name)
      }
      if(-not $selected){$result.SilentReinstallUiDetected=[bool](@($result.SilentStrategyAttempts | Where-Object {$_.UiDetected}).Count -gt 0);$result.SilentReinstallVisibleWindows=@($result.SilentStrategyAttempts | ForEach-Object {$_.VisibleWindows} | Where-Object {$_} | Select-Object -Unique);throw 'No candidate silent-install strategy passed unattended validation.'}
      $result.SelectedSilentStrategy=$selected.Name; $EffectiveSilentInstaller=$selected.File; $SilentInstallArguments=$selected.Arguments; $DiscoveredInstallerKind=if($selected.Kind -eq 'Msi'){'Msi'}else{$DiscoveredInstallerKind}
      $result.SilentInstallCommand=if($selected.Kind -eq 'Msi'){('msiexec.exe /i `"'+$selected.File+'`" '+$selected.Arguments).Trim()}else{('"'+$selected.File+'" '+$selected.Arguments).Trim()}
      $result.BaseSilentArguments=$SilentInstallArguments; $result.CombinedSilentArguments=$SilentInstallArguments;
      $result.RebootRequired=($result.RebootRequired -or $ri.ExitCode -eq 3010); $result.SilentReinstallExitCode=$ri.ExitCode; $result.SilentInstallStdOut=''; $result.SilentInstallStdErr=''; $result.SilentReinstallUiDetected=$false; $result.SilentReinstallVisibleWindows=@(); $result.SilentReinstallValidated=$true

      $finalCandidates=if($RecordResponses -and $result.UninstallResponseFileCreated){
        $finalParts=Split-Command $current.UninstallString
        if(-not $finalParts){throw 'Reinstalled application has no registered uninstall command for response replay.'}
        @(('"'+$finalParts[0]+'" '+$finalParts[1]+' /s /f1"'+$UninstallIss+'"').Trim())
      }else{@(Get-SilentUninstallCandidates $current)}
      if($finalCandidates.Count -eq 0){throw 'Reinstalled application was detected, but no silent uninstall command could be produced.'}
      $finalCommand=$finalCandidates[0]
      $parts2=Split-Command $finalCommand; if(-not $parts2){throw 'Could not parse final silent uninstall command.'}
      # Adobe and other MSI-backed installers can report the application before the
      # Windows Installer transaction has completely settled. Exit 1618 is therefore a
      # retryable busy state, not a terminal lifecycle failure.
      Write-Checkpoint 'Waiting for installer activity to settle before final uninstall'
      Start-Sleep 10
      if(-not (Test-Detected $current)){throw 'Final uninstall cannot be validated: the reinstalled application was already absent.'}
      $u2=$null
      $uninstallCandidateIndex=0
      foreach($candidateCommand in $finalCandidates){
        $uninstallCandidateIndex++
        $parts2=Split-Command $candidateCommand; if(-not $parts2){continue}
        Write-Checkpoint ('Final uninstall strategy '+$uninstallCandidateIndex+'/'+$finalCandidates.Count)
        for($finalAttempt=1;$finalAttempt -le 12;$finalAttempt++){
          Write-Checkpoint ('Final silent uninstall attempt '+$finalAttempt+'/12')
          $executionArguments=Get-UninstallExecutionArguments $parts2[0] $parts2[1] 'final'
          if($RecordResponses -and $result.UninstallResponseFileCreated){
            $replayLog='C:\InstallerOutput\iss-uninstall-replay.log'
            Remove-Item -LiteralPath $replayLog -Force -ErrorAction SilentlyContinue
            $executionArguments+=' /f2"'+$replayLog+'"'
          }
          $u2=Invoke-NativeProcess $parts2[0] $executionArguments $true $true 300
          if($RecordResponses -and $result.UninstallResponseFileCreated -and -not (Test-InstallShieldReplayLog $replayLog)){throw 'InstallShield uninstall replay did not produce exactly one successful ResultCode=0.'}
          $result.UiDiagnostics+=@($u2.UiDiagnostics)
          $result.SilentUninstallExitCode=$u2.ExitCode
          $result.RebootRequired=($result.RebootRequired -or $u2.ExitCode -eq 3010)
          $result.SilentUninstallRawExitCode=$u2.RawExitCode
          $result.SilentUninstallUiDetected=$u2.UiDetected
          $result.SilentUninstallVisibleWindows=@($u2.VisibleWindows)
          Write-DebugEvent 'Final uninstall result' ([PSCustomObject]@{Strategy=$candidateCommand;Attempt=$finalAttempt;ExitCode=$u2.ExitCode;UiDetected=$u2.UiDetected;VisibleWindows=@($u2.VisibleWindows)})
          if($u2.ExitCode -ne 1618){break}
          Write-Checkpoint ('Windows Installer busy (1618); waiting before retry '+$finalAttempt+'/12')
          Start-Sleep 15
        }
        if(Test-ProcessResultSuccess $u2){$finalCommand=$candidateCommand;break}
        if(-not (Test-Detected $current)){$finalCommand=$candidateCommand;break}
      }
      Write-Checkpoint ('Final silent uninstall returned: '+$u2.ExitCode)
      $result.UninstallCandidate=$finalCommand
      if($u2.UiDetected){
        $result['MsiRemovalUiActions']=@(Get-MsiRemovalUiActions $EffectiveSilentInstaller)
        $result.ValidationError='Final silent uninstall displayed interactive UI: '+(($u2.VisibleWindows -join '; '))
      } elseif($u2.ExitCode -eq 1618){
        $result.ValidationError='Windows Installer remained busy (1618) after bounded final-uninstall retries.'
      } elseif($u2.ExitCode -notin @(0,3010)){
        $result.ValidationError='Final silent uninstall returned exit code '+$u2.ExitCode+'.'
      } else {
        Write-Checkpoint 'Final absence verification 0/20'
        $result.PostUninstallDetected=$true
        for($absencePoll=1;$absencePoll -le 20;$absencePoll++){
          Start-Sleep 3
          $result.PostUninstallDetected=Test-Detected $current
          Write-Checkpoint ('Final absence verification '+$absencePoll+'/20: detected='+$result.PostUninstallDetected)
          if(-not $result.PostUninstallDetected){Complete-RoadmapRemovalEvidence;break}
        }
        $result.SilentUninstallValidated=(-not $result.PostUninstallDetected)
        if(-not $result.SilentUninstallValidated){$result.ValidationError='Final uninstall returned success, but the application remained detected after the bounded 60-second absence verification.'}
      }
    }
    }
} catch {
  $result.ValidationError=$_.Exception.Message
  # Preserve the identity left by a rejected/partial attempt without turning it into proof.
  try {
    $result.NewUninstallEntries=@(Get-UninstallSnapshot | Where-Object {$_.Key -notin $beforeKeys})
    $partialPrimary=Select-Primary $result.NewUninstallEntries
    if($partialPrimary){$result.PrimaryKey=$partialPrimary.Key}
  } catch {}
  try { Write-DebugEvent 'Unhandled analysis exception' ([PSCustomObject]@{Type=$_.Exception.GetType().FullName;Message=$_.Exception.Message;ScriptStackTrace=$_.ScriptStackTrace;Position=[string]$_.InvocationInfo.PositionMessage}); Write-DebugProcessSnapshot 'Unhandled analysis exception' } catch {}
}
try { Write-DebugEvent 'Analysis finalizing' ([PSCustomObject]@{ValidationError=$result.ValidationError;SilentReinstallValidated=$result.SilentReinstallValidated;SilentUninstallExitCode=$result.SilentUninstallExitCode;SilentUninstallValidated=$result.SilentUninstallValidated;PostUninstallDetected=$result.PostUninstallDetected}) } catch {}
# v0.11.45: the validated lifecycle is the terminal Sandbox-side state. Do not run
# watchdog teardown, registry enumeration, or other optional cleanup on this execution thread:
# v0.11.44 proved that optional cleanup can hang after a completely successful deployment test.
# The host already owns completion/output handoff and Sandbox teardown.
Stop-PayloadTrace
Complete-AppControlEvidence
$result['LifecycleValidated']=[bool](Test-LifecycleEvidence $result)
$result.WorkflowStage='Generate final analysis'; $result.WorkflowStageUpdatedAt=(Get-Date).ToString('o')
Set-AnalysisHeartbeat 'final-result-commit-start'
Write-Result $result
Set-AnalysisHeartbeat 'final-result-committed'
Set-Content -Path 'C:\InstallerOutput\analysis-complete.flag' -Value (Get-Date).ToString('o') -Encoding ASCII
Set-AnalysisHeartbeat 'analysis-complete-flag-written'
try { Write-DebugEvent 'Analysis result committed' ([PSCustomObject]@{Analysis=$Analysis;CompleteFlag='C:\InstallerOutput\analysis-complete.flag'}) } catch {}

$result.WorkflowStage='Analysis complete'; $result.WorkflowStageUpdatedAt=(Get-Date).ToString('o')
Write-Result $result
Set-AnalysisHeartbeat 'analysis-complete'
try { Write-DebugEvent 'Analysis complete; optional cleanup delegated to Sandbox teardown' ([PSCustomObject]@{SilentReinstallValidated=$result.SilentReinstallValidated;SilentUninstallValidated=$result.SilentUninstallValidated;PostUninstallDetected=$result.PostUninstallDetected}) } catch {}
""";
        var encodedMsiMetadata = Convert.ToBase64String(Encoding.UTF8.GetBytes(System.Text.Json.JsonSerializer.Serialize(msiMetadata)));
        var values = new Dictionary<string, string>
        {
            ["__INSTALLER__"] = escaped, ["__KIND__"] = kindName, ["__BASE_ARGS__"] = baseSilent,
            ["__ADDITIONAL_ARGS__"] = additional, ["__BLOCK_MCAFEE__"] = blockMcAfee,
            ["__RECORD_RESPONSES__"] = recordResponses ? "$true" : "$false",
            ["__SILENT_ONLY__"] = silentOnlyValue, ["__ROADMAP_HELPERS__"] = RoadmapEvidenceScript.Replace("__MSI_METADATA__", encodedMsiMetadata) + Environment.NewLine + DetailedDetectionEvidenceScript + Environment.NewLine + RuntimeEnvironmentEvidenceScript + Environment.NewLine + NetFx3ProvisioningScript + Environment.NewLine + MsiIdentityEvidenceScript + Environment.NewLine + PrerequisiteFileEvidenceScript + Environment.NewLine + PrerequisiteServiceEvidenceScript + Environment.NewLine + DllEvidenceScript + Environment.NewLine + AppControlEvidenceScript + Environment.NewLine + PayloadTraceEvidenceScript.Replace("__TRACE_WORKER_B64__", Convert.ToBase64String(Encoding.UTF8.GetBytes(PayloadTraceWorkerScript))),
            ["__NETFX_EVIDENCE__"] = Convert.ToBase64String(Encoding.UTF8.GetBytes(netFxRequirement)), ["__MSI_METADATA__"] = encodedMsiMetadata
        };
        // One pass prevents token-shaped installer names/arguments being substituted as code.
        return System.Text.RegularExpressions.Regex.Replace(script, "__(?:INSTALLER|KIND|BASE_ARGS|ADDITIONAL_ARGS|BLOCK_MCAFEE|SILENT_ONLY|RECORD_RESPONSES|ROADMAP_HELPERS|MSI_METADATA|NETFX_EVIDENCE)__", match => values[match.Value]);
    }

    private static string BuildWsb(string input, string output)
    {
        string X(string value) => SecurityElement.Escape(value) ?? value;
        return "<Configuration>\r\n" +
               // Installer lifecycle guests use WARP; no host graphics/security policy is changed.
               "  <vGPU>Disable</vGPU>\r\n" +
               "  <MappedFolders>\r\n" +
               "    <MappedFolder>\r\n" +
               $"      <HostFolder>{X(input)}</HostFolder>\r\n" +
               "      <SandboxFolder>C:\\InstallerInput</SandboxFolder>\r\n" +
               "      <ReadOnly>true</ReadOnly>\r\n" +
               "    </MappedFolder>\r\n" +
               "    <MappedFolder>\r\n" +
               $"      <HostFolder>{X(output)}</HostFolder>\r\n" +
               "      <SandboxFolder>C:\\InstallerOutput</SandboxFolder>\r\n" +
               "      <ReadOnly>false</ReadOnly>\r\n" +
               "    </MappedFolder>\r\n" +
               "  </MappedFolders>\r\n" +
               "  <ClipboardRedirection>Enable</ClipboardRedirection>\r\n" +
               "  <Networking>Default</Networking>\r\n" +
               "  <LogonCommand>\r\n" +
               "    <Command>powershell.exe -NoProfile -ExecutionPolicy Bypass -File C:\\InstallerInput\\Start-Analysis.ps1</Command>\r\n" +
               "  </LogonCommand>\r\n" +
               "</Configuration>\r\n";
    }

    private const string GuestBootstrapScript = """
$ErrorActionPreference='Stop'
try {
  [ordered]@{Stage='Guest bootstrap started';At=[DateTimeOffset]::UtcNow.ToString('o')} | ConvertTo-Json | Set-Content -LiteralPath 'C:\InstallerOutput\sandbox-guest-startup.json' -Encoding UTF8
  & 'C:\InstallerInput\Record-Iss.ps1'
} catch {
  try { ($_ | Out-String) | Set-Content -LiteralPath 'C:\InstallerOutput\sandbox-guest-startup-error.txt' -Encoding UTF8 } catch {}
  exit 1
}
""";

    private static string BuildRecorderScript(string installerName, bool blockBundledMcAfee, string additionalPackageArguments = "")
        => BuildDiscoveryScriptCore(installerName, InstallerKind.InstallShield, "", additionalPackageArguments,
            blockBundledMcAfee, false, new MsiMetadata(), recordResponses: true);
}

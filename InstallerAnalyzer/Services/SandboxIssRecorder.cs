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
    public TimeSpan OverallTimeout { get; init; } = TimeSpan.FromMinutes(30);
}

public static partial class SandboxIssRecorder
{
    private const string LegacyProjectProduct = "Microsoft Office Project Professional 2007";
    private const string LegacyProjectMsiCode = "{90120000-003B-0000-0000-0000000FF1CE}";

    private static bool IsLegacyProjectMedia(string setup)
    {
        if (!Path.GetFileName(setup).Equals("setup.exe", StringComparison.OrdinalIgnoreCase)) return false;
        var version = FileVersionInfo.GetVersionInfo(setup);
        if (version.FileMajorPart != 12 && version.ProductMajorPart != 12) return false;
        if (!string.Equals(version.CompanyName, "Microsoft Corporation", StringComparison.OrdinalIgnoreCase)) return false;
        var msi = Path.Combine(Path.GetDirectoryName(setup)!, "PrjPro.WW", "PrjProWW.msi");
        if (!File.Exists(msi)) return false;
        var metadata = MsiMetadataService.Read(msi);
        return string.Equals(metadata.ProductName, LegacyProjectProduct, StringComparison.OrdinalIgnoreCase) &&
            string.Equals(metadata.Manufacturer, "Microsoft Corporation", StringComparison.OrdinalIgnoreCase) &&
            string.Equals(metadata.ProductCode, LegacyProjectMsiCode, StringComparison.OrdinalIgnoreCase);
    }

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

    public static SandboxIssSession Start(string installerPath, InstallerKind kind, bool requiresIss, string baseSilentArguments, string additionalPackageArguments, bool blockBundledMcAfee, bool silentOnly = false, bool prepareNetFx3 = false, bool installerCompatibility = false, InstallerArchive? archive = null)
        => StartCore(installerPath, kind, requiresIss, baseSilentArguments, additionalPackageArguments, blockBundledMcAfee, silentOnly, prepareNetFx3, installerCompatibility, archive, null);

    internal static SandboxIssSession StartReplay(string installerPath, InstallerArchive? archive, RecordedSandboxReplay replay,
        bool blockBundledMcAfee, bool prepareNetFx3, bool installerCompatibility)
    {
        replay.VerifySource(installerPath, archive);
        return StartCore(installerPath, InstallerKind.InstallShield, true, "", replay.Proof.AdditionalPackageArguments ?? "",
            blockBundledMcAfee, false, prepareNetFx3 || replay.Proof.NetFx3Provisioning?.RuntimeVerified == true, installerCompatibility, archive, replay);
    }

    private static SandboxIssSession StartCore(string installerPath, InstallerKind kind, bool requiresIss, string baseSilentArguments, string additionalPackageArguments, bool blockBundledMcAfee, bool silentOnly, bool prepareNetFx3, bool installerCompatibility, InstallerArchive? archive, RecordedSandboxReplay? replay)
    {
        if (!File.Exists(installerPath)) throw new FileNotFoundException("Installer not found.", installerPath);
        if (silentOnly && requiresIss)
            throw new InvalidOperationException("NO SILENT STRATEGY: This package requires a recorded response file. Run Full Analysis to record it before unattended testing.");
        if (!IsSandboxAvailable()) throw new InvalidOperationException("Windows Sandbox was not found. Enable 'Windows Sandbox' in Windows Features, then restart Windows.");

        var root = Path.Combine(Path.GetTempPath(), "InstallerAnalyzer", "ISS-" + Guid.NewGuid().ToString("N"));
        var input = Path.Combine(root, "Input");
        var output = Path.Combine(root, "Output");
        Directory.CreateDirectory(input);
        Directory.CreateDirectory(output);

        var installerName = Path.GetFileName(installerPath);
        string copiedInstaller;
        try
        {
            copiedInstaller = archive is null ? Path.Combine(input, installerName) : archive.Stage(Path.Combine(input, "Archive"));
        }
        catch
        {
            try { Directory.Delete(root, recursive: true); } catch (IOException) { } catch (UnauthorizedAccessException) { }
            throw;
        }
        if (archive is null) File.Copy(installerPath, copiedInstaller, true);
        var legacyProject = archive is not null && IsLegacyProjectMedia(copiedInstaller);
        if (legacyProject) { kind = InstallerKind.Bootstrapper; requiresIss = false; }
        if (archive is null && kind == InstallerKind.Msi && MsixDependencyService.Hash(copiedInstaller) == VirtualBoxReducedProfile.MsiHash)
        {
            VirtualBoxReducedProfile.Stage(installerPath, copiedInstaller);
            File.WriteAllText(Path.Combine(input, "virtualbox-reduced-profile.txt"), VirtualBoxReducedProfile.Arguments, new UTF8Encoding(false));
        }
        if (kind == InstallerKind.Msix)
        {
            var identity = InstallerDetector.ReadMsixIdentity(copiedInstaller)?.Attribute("Name")?.Value;
            if (string.IsNullOrWhiteSpace(identity))
                throw new InvalidOperationException("MSIX/AppX manifest is missing the package identity.");
            File.WriteAllText(Path.Combine(input, "msix-identity.txt"), identity, new UTF8Encoding(false));
            var dependencies = MsixDependencyService.Find(installerPath)
                .Select(path => new MsixDependency(Path.GetFileName(path), MsixDependencyService.Hash(path))).ToArray();
            MsixDependencyService.CopyValidated(installerPath, copiedInstaller, dependencies);
        }
        File.WriteAllText(Path.Combine(input, "pe-dependencies.json"), System.Text.Json.JsonSerializer.Serialize(PeDependencyService.Read(copiedInstaller)), new UTF8Encoding(false));

        var ps1 = Path.Combine(input, "Record-Iss.ps1");
        if (replay is not null)
        {
            File.WriteAllBytes(Path.Combine(input, "replay-setup.iss"), replay.Setup);
            File.WriteAllBytes(Path.Combine(input, "replay-uninstall.iss"), replay.Uninstall);
            File.WriteAllText(Path.Combine(input, "replay-recording.json"), System.Text.Json.JsonSerializer.Serialize(new
            {
                replay.RegistryKey, replay.Proof.InstallerSha256, replay.Proof.InitialUninstallExitCode,
                replay.Proof.UninstallCandidate
            }));
        }
        using (var source = typeof(SandboxIssRecorder).Assembly.GetManifestResourceStream("InstallerAnalyzer.PayloadTraceReducer.cs")!)
        using (var target = File.Create(Path.Combine(input, "PayloadTraceReducer.cs"))) source.CopyTo(target);
        var metadata = kind == InstallerKind.Msi ? MsiMetadataService.Read(copiedInstaller) : new MsiMetadata();
        if (archive is null && File.Exists(installerPath + ".config") && new FileInfo(installerPath + ".config").Length <= 65536)
            File.Copy(installerPath + ".config", copiedInstaller + ".config", true);
        var netFxRequirement = NetFx3RequirementService.Detect(copiedInstaller, metadata, prepareNetFx3);
        var requiredPrimaryProduct = "";
        if (Path.GetExtension(copiedInstaller).Equals(".exe", StringComparison.OrdinalIgnoreCase))
        {
            var version = FileVersionInfo.GetVersionInfo(copiedInstaller);
            if (legacyProject)
                requiredPrimaryProduct = LegacyProjectProduct;
            else if (AdobeReaderInstaller.IsOfflinePackage(copiedInstaller, version))
                requiredPrimaryProduct = AdobeReaderInstaller.DesktopProduct;
            else if (BentleyBootstrapperService.Inspect(copiedInstaller, version.CompanyName ?? "") is not null)
                requiredPrimaryProduct = version.ProductName ?? "";
        }
        ComponentDeploymentPlan? componentPlan = null;
        if (archive is null && requiredPrimaryProduct.Equals("gINT", StringComparison.OrdinalIgnoreCase))
        {
            componentPlan = GintDeploymentPlanService.TryStage(copiedInstaller, Path.Combine(input, "Payload"));
            if (componentPlan is not null)
            {
                metadata = MsiMetadataService.Read(Path.Combine(input, "Payload", "gINT.msi"));
                netFxRequirement = "gINT component recipe requires .NET Framework 3.5.";
                File.WriteAllText(Path.Combine(input, "component-prerequisites.ps1"), GintDeploymentPlanService.SandboxScript(componentPlan), new UTF8Encoding(false));
            }
        }
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
            recordResponses: requiresIss, netFxRequirement: netFxRequirement, requiredPrimaryProduct: requiredPrimaryProduct, installerCompatibility: installerCompatibility, componentPlan: componentPlan, archive: archive), new UTF8Encoding(false));

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
            RequiresIss = requiresIss,
            OverallTimeout = TimeSpan.FromMinutes(60)
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

    private static string BuildDiscoveryScriptCore(string installerName, InstallerKind kind, string baseSilentArguments, string additionalPackageArguments, bool blockBundledMcAfee, bool silentOnly, MsiMetadata msiMetadata, bool recordResponses = false, string netFxRequirement = "", string requiredPrimaryProduct = "", bool installerCompatibility = false, ComponentDeploymentPlan? componentPlan = null, InstallerArchive? archive = null)
    {
        var escaped = archive is null ? installerName.Replace("'", "''") : "";
        var kindName = kind.ToString().Replace("'", "''");
        var baseSilent = (baseSilentArguments ?? string.Empty).Replace("'", "''");
        var additional = (additionalPackageArguments ?? string.Empty).Replace("'", "''");
        var blockMcAfee = blockBundledMcAfee ? "$true" : "$false";
        var silentOnlyValue = silentOnly ? "$true" : "$false";
        var script = """
$ErrorActionPreference = 'Stop'
$Installer = 'C:\InstallerInput\__INSTALLER__'
$ArchiveEntry = [Text.Encoding]::UTF8.GetString([Convert]::FromBase64String('__ARCHIVE_ENTRY__'))
$ArchiveSha256 = '__ARCHIVE_HASH__'
if ($ArchiveEntry) { $Installer = Join-Path 'C:\InstallerArchive' $ArchiveEntry }
$Analysis = 'C:\InstallerOutput\install-analysis.json'
$Heartbeat = 'C:\InstallerOutput\analysis-heartbeat.txt'
function Set-AnalysisHeartbeat([string]$stage='activity') { try { ((Get-Date).ToString('o')+'|'+$stage) | Add-Content $Heartbeat -Encoding ASCII } catch {} }
Set-AnalysisHeartbeat 'analysis-start'
$BaseSilentArguments = '__BASE_ARGS__'
$AdditionalPackageArguments = '__ADDITIONAL_ARGS__'
$SilentInstallArguments = (@($BaseSilentArguments,$AdditionalPackageArguments) | Where-Object { -not [string]::IsNullOrWhiteSpace($_) }) -join ' '
$InstallerKind = '__KIND__'
$VirtualBoxProfileFile = 'C:\InstallerInput\virtualbox-reduced-profile.txt'
$IsVirtualBoxReducedProfile = $InstallerKind -eq 'Msi' -and (Test-Path -LiteralPath $VirtualBoxProfileFile -PathType Leaf)
$VirtualBoxLocalMsi = $null
$IsWebView2Installer = $InstallerKind -eq 'Bootstrapper' -and
    [IO.Path]::GetFileName($Installer) -match '^MicrosoftEdgeWebView2(?:Setup|RuntimeInstaller(?:X64|X86|ARM64))\.exe$'
$RequiredPrimaryProduct = [Text.Encoding]::UTF8.GetString([Convert]::FromBase64String('__REQUIRED_PRIMARY__'))
$LegacyProjectName = 'Microsoft Office Project Professional 2007'
$IsLegacyProject = [bool]$ArchiveEntry -and $RequiredPrimaryProduct -eq $LegacyProjectName
$ProjectProductCode = '{90120000-003B-0000-0000-0000000FF1CE}'
$ProjectConfig = 'C:\InstallerOutput\project2007-silent.xml'
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
        [PSCustomObject]@{ Key=$_.PSPath; DisplayName=$_.DisplayName; DisplayVersion=$_.DisplayVersion; Publisher=$_.Publisher; InstallLocation=$_.InstallLocation; UninstallString=$_.UninstallString; QuietUninstallString=$_.QuietUninstallString; WindowsInstaller=$_.WindowsInstaller; ProductCode=if ($_.WindowsInstaller -eq 1 -and $_.PSChildName -match '^\{[0-9A-Fa-f-]+\}$') {$_.PSChildName}else{$null} }
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
function Test-ProjectRegistration($entry) {
    return $entry.DisplayName -eq $LegacyProjectName -and $entry.Publisher -eq 'Microsoft Corporation' -and
        $entry.Key -match '\\Uninstall\\PRJPRO$'
}
function Test-ProjectMsi($entry) {
    return $entry.WindowsInstaller -eq 1 -and $entry.Publisher -eq 'Microsoft Corporation' -and
        $entry.ProductCode -eq $ProjectProductCode
}
function Find-ProjectFromArchiveDiscovery($entries) {
    if(-not $ArchiveEntry -or [IO.Path]::GetFileName($Installer) -ne 'setup.exe'){return $null}
    if(-not @($entries | Where-Object {Test-ProjectMsi $_}).Count){return $null}
    return $entries | Where-Object {Test-ProjectRegistration $_} | Select-Object -First 1
}
function Initialize-LegacyProject {
    $script:IsLegacyProject=$true
    $result['ExpectedPrimaryProduct']=$LegacyProjectName
    '__PROJECT_CONFIG__' |
      Set-Content -LiteralPath $ProjectConfig -Encoding UTF8
    if($SilentInstallArguments -notmatch '^/config\s+(?:"[^"]+"|[^\s"]+)$'){
      $script:SilentInstallArguments='/config "'+$ProjectConfig+'"'
      $result.BaseSilentArguments=$SilentInstallArguments
      $result.AdditionalPackageArguments=''
      $result.CombinedSilentArguments=$SilentInstallArguments
    }
    $result.DeploymentMechanism='Microsoft Office 2007 MSI suite'
    $result.IdentitySource='Project setup registration and product MSI'
    $result.DiscoveryMethod='Office 12 Setup + Project suite and MSI registrations'
}
function Select-Primary($entries) {
    $installerName = [IO.Path]::GetFileName($Installer)
    $stem = [IO.Path]::GetFileNameWithoutExtension($installerName).ToLowerInvariant() -replace '(setup|installer|install)','' -replace '[^a-z0-9]',''
    $best=$null; $bestScore=[int]::MinValue
    foreach($e in $entries){
        if($IsVirtualBoxReducedProfile){
          if($e.WindowsInstaller -ne 1 -or $e.ProductCode -ne $script:MsiStaticMetadata.ProductCode){continue}
        } elseif($IsWebView2Installer){
          if($e.DisplayName -ne 'Microsoft Edge WebView2 Runtime' -or $e.Publisher -ne 'Microsoft Corporation'){continue}
        } elseif($IsCetMsi){
          if($e.WindowsInstaller -ne 1 -or -not $e.ProductCode -or $e.Publisher -ne 'Configura Sverige AB' -or
              $e.DisplayName -notmatch '^(?:Configura )?CET(?:\s|$)'){continue}
        } elseif($RequiredPrimaryProduct -eq 'Adobe Acrobat'){
          # The Reader core AppX entry is a component of the desktop MSI installation.
          if($e.WindowsInstaller -ne 1 -or $e.ProductCode -notmatch '^\{AC76BA86-[0-9A-F]{4}-[0-9A-F]{4}-[0-9A-F]{4}-[0-9A-F]{12}\}$' -or
              $e.DisplayName -notmatch '^Adobe Acrobat(?:\s|$)' -or $e.Publisher -notmatch '^Adobe(?:\s|$)'){continue}
        } elseif($IsLegacyProject){
          if(-not (Test-ProjectRegistration $e)){continue}
        } elseif(-not [string]::IsNullOrWhiteSpace($RequiredPrimaryProduct)){
          $pattern='(?i)(?:^|[^a-z0-9])'+[regex]::Escape($RequiredPrimaryProduct.Trim())+'(?:$|[^a-z0-9])'
          if([string]$e.DisplayName -notmatch $pattern -or [string]$e.Publisher -notmatch '(?i)^Bentley Systems'){continue}
        }
        $name=([string]$e.DisplayName).ToLowerInvariant() -replace '[^a-z0-9]',''; $score=0
        if([string]::IsNullOrWhiteSpace($name) -or [string]::IsNullOrWhiteSpace([string]$e.Key)){continue}
        if($stem -and ($name.Contains($stem) -or $stem.Contains($name))){$score+=70}
        if($InstallerKind -eq 'WixBurn' -and $e.WindowsInstaller -ne 1){
          # Burn registers the original bundle EXE under Package Cache alongside its child MSIs.
          $command=Split-Command ([string]$e.QuietUninstallString)
          if($command -and [IO.Path]::GetFileName($command[0]) -eq $installerName -and
             $command[0] -match '\\Package Cache\\' -and $command[1] -match '(?:^|\s)[/-]uninstall(?:\s|$)'){$score+=150}
        }
        if($e.InstallLocation){$score+=15}; if($e.UninstallString){$score+=10}; if($e.QuietUninstallString){$score+=15}; if($e.DisplayVersion){$score+=5}
        if(-not $IsWebView2Installer -and $name -match 'microsoftvisualc|redistributable|runtime|netframework|webview2'){$score-=50}
        if($score -gt $bestScore){$best=$e;$bestScore=$score}
    }
    if($bestScore -lt 0){return $null}
    if($RecordResponses -and $best.ProductCode){
      $wrapperSuffix='\InstallShield_'+$best.ProductCode
      $cachedSetup='(?i)\\InstallShield Installation Information\\'+[regex]::Escape($best.ProductCode)+'\\setup\.exe"\s'
      $wrapper=$entries | Where-Object {
        ([string]$_.Key).EndsWith($wrapperSuffix,[StringComparison]::OrdinalIgnoreCase) -and
        $_.DisplayName -eq $best.DisplayName -and $_.Publisher -eq $best.Publisher -and
        $_.UninstallString -match $cachedSetup -and
        $_.UninstallString -match '(?i)(?:^|\s)[/-]removeonly(?:\s|$)'
      } | Select-Object -First 1
      if($wrapper){return $wrapper}
    }
    return $best
}
function Assert-BootstrapperDiscoveryComplete($activity) {
    if($activity.TimedOut -and -not $activity.MainMsiStarted -and -not [string]::IsNullOrWhiteSpace($RequiredPrimaryProduct) -and @($activity.ActiveProcesses | Where-Object {$_ -match '(?i)^Setup_CONNECTIONClient'}).Count){throw ('BOOTSTRAPPER TIMEOUT: CONNECTION Client setup did not return control before the timeout; '+$RequiredPrimaryProduct+' main MSI had not started. Review any captured prerequisite setup logs. No lifecycle removal was started.')}
    if($null -ne $activity.MainMsiFailure){
      $failure=$activity.MainMsiFailure
      $detail=if($failure.VbScriptUnavailable){' Windows Installer reported error 2738 (VBScript runtime unavailable for a custom action).'}else{''}
      throw ('INSTALL FAILED: '+$RequiredPrimaryProduct+' main MSI returned '+$failure.ExitCode+'.'+$detail+' See '+$failure.Log+'. Product registration does not validate this installation.')
    }
    if($activity.EndedWithoutPrimary){throw ('INSTALLER CHAIN EXITED: Setup and its observed descendants exited without registering '+$RequiredPrimaryProduct+'. See bootstrapper-process-exits.json and prerequisite logs for the observed exit codes.')}
    if($activity.TimedOut -and $activity.PrerequisiteTimedOut){throw 'PREREQUISITE TIMEOUT: Tracked prerequisite setup was still running when its wait expired. No lifecycle removal was started.'}
    if($activity.TimedOut){throw ('BOOTSTRAPPER TIMEOUT: Installer activity did not finish within the discovery budget. Expected application: '+$RequiredPrimaryProduct+'. Prerequisite entries are retained as diagnostics; lifecycle removal was not started. Finish the main installer in a fresh Sandbox.')}
    if(-not [string]::IsNullOrWhiteSpace($RequiredPrimaryProduct) -and $null -eq $activity.Primary){throw ('PRIMARY APPLICATION NOT FOUND: Expected '+$RequiredPrimaryProduct+' was not registered. Only prerequisites or unrelated entries were observed; lifecycle removal was not started.')}
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
    if($IsLegacyProject -and (Test-ProjectRegistration $primary)){
      if(@(Get-UninstallSnapshot | Where-Object {(Test-ProjectRegistration $_) -or (Test-ProjectMsi $_)}).Count){return $true}
      return [bool]($primary.InstallLocation -and (Test-Path -LiteralPath (Join-Path $primary.InstallLocation 'Office12\WINPROJ.EXE') -PathType Leaf))
    }
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
    if($IsLegacyProject -and (Test-ProjectRegistration $primary)){
      if(-not @($snapshot | Where-Object {Test-ProjectMsi $_}).Count){return $null}
      return $snapshot | Where-Object {Test-ProjectRegistration $_} | Select-Object -First 1
    }
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
  [DllImport("user32.dll")] static extern bool IsWindowEnabled(IntPtr hWnd);
  [StructLayout(LayoutKind.Sequential)] struct WindowRect { public int Left, Top, Right, Bottom; }
  [DllImport("user32.dll")] static extern bool GetWindowRect(IntPtr hWnd, out WindowRect rect);
  [DllImport("user32.dll")] static extern IntPtr MonitorFromRect(ref WindowRect rect, uint flags);
  public static bool IsPresentedWindow(long window) {
    var handle=new IntPtr(window); WindowRect rect;
    return IsWindowVisible(handle) && GetWindowRect(handle,out rect) &&
      rect.Right>rect.Left && rect.Bottom>rect.Top && MonitorFromRect(ref rect,0)!=IntPtr.Zero;
  }
  public static string WindowPresentation(long window) {
    WindowRect rect; if(!GetWindowRect(new IntPtr(window),out rect)) return "Bounds unavailable";
    return rect.Left+","+rect.Top+","+rect.Right+","+rect.Bottom+"; onMonitor="+(MonitorFromRect(ref rect,0)!=IntPtr.Zero);
  }
  [DllImport("user32.dll")] static extern uint GetWindowThreadProcessId(IntPtr hWnd, out uint processId);
  [DllImport("user32.dll", CharSet=CharSet.Unicode)] static extern int GetWindowText(IntPtr hWnd, StringBuilder text, int count);
  [DllImport("user32.dll")] static extern bool EnumChildWindows(IntPtr hWnd, EnumWindowsProc callback, IntPtr lParam);
  [DllImport("user32.dll", CharSet=CharSet.Unicode)] static extern int GetClassName(IntPtr hWnd, StringBuilder text, int count);
  [DllImport("user32.dll", CharSet=CharSet.Unicode, SetLastError=true)] static extern IntPtr SendMessageTimeout(IntPtr hWnd, uint message, UIntPtr count, StringBuilder text, uint flags, uint timeout, out UIntPtr result);
  [DllImport("user32.dll", EntryPoint="GetWindowLongW")] static extern int GetWindowStyle(IntPtr hWnd, int index);
  public static bool IsProgressOnlyWindow(long window, int expectedPid) {
    var handle=new IntPtr(window); uint owner; GetWindowThreadProcessId(handle,out owner);
    if(owner!=(uint)expectedPid) return false;
    bool progress=false, interactive=false;
    int visited=0;
    EnumChildWindows(handle,(child,state)=>{
      if(++visited>96){interactive=true;return false;}
      uint pid; GetWindowThreadProcessId(child,out pid);
      if(pid!=owner || !IsWindowVisible(child)) return true;
      var kind=new StringBuilder(128); GetClassName(child,kind,kind.Capacity);
      var name=kind.ToString();
      if(name.Equals("msctls_progress32",StringComparison.OrdinalIgnoreCase) ||
        name.StartsWith("WindowsForms10.msctls_progress32.",StringComparison.OrdinalIgnoreCase)){progress=true;return true;}
      if(!IsWindowEnabled(child)) return true;
      if(name.Equals("Button",StringComparison.OrdinalIgnoreCase) || name.StartsWith("WindowsForms10.BUTTON",StringComparison.OrdinalIgnoreCase)){
        var label=new StringBuilder(128); UIntPtr copied;
        if(SendMessageTimeout(child,13,new UIntPtr((uint)label.Capacity),label,34,75,out copied)!=IntPtr.Zero &&
          label.ToString().Replace("&","").Trim().Equals("Cancel",StringComparison.OrdinalIgnoreCase)) return true;
        interactive=true;return false;
      }
      if(name.IndexOf("edit",StringComparison.OrdinalIgnoreCase)>=0 || name.IndexOf("listbox",StringComparison.OrdinalIgnoreCase)>=0 ||
        name.IndexOf("combobox",StringComparison.OrdinalIgnoreCase)>=0){interactive=true;return false;}
      return true;
    },IntPtr.Zero);
    return progress && !interactive;
  }
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
    EnumWindows((h, l) => { uint pid; GetWindowThreadProcessId(h, out pid); if(ids.Contains((int)pid) && IsPresentedWindow(h.ToInt64())) { var b=new StringBuilder(512); GetWindowText(h,b,b.Capacity); var t=b.ToString().Trim(); found.Add(h.ToInt64()+"|"+((int)pid)+"|"+(t.Length==0?"<untitled visible window>":t)); } return true; }, IntPtr.Zero);
    return found.ToArray();
  }
  public static string[] DesktopWindows(bool includeOffscreen=false) {
    var found = new List<string>();
    EnumWindows((h, l) => { if(!(includeOffscreen ? IsWindowVisible(h) : IsPresentedWindow(h.ToInt64()))) return true; uint pid; GetWindowThreadProcessId(h, out pid); var b=new StringBuilder(512); GetWindowText(h,b,b.Capacity); var t=b.ToString().Trim(); if(t.Length>0) found.Add(h.ToInt64()+"|"+((int)pid)+"|"+t); return true; }, IntPtr.Zero);
    return found.ToArray();
  }
}
'@
}
function Get-InstallerProcessBirth($process,[datetime]$fallback) {
    try {return $process.StartTime.ToUniversalTime()} catch {return $fallback.ToUniversalTime()}
}
function Expand-TrackedProcessTree($all,[System.Collections.Generic.HashSet[int]]$tracked,[hashtable]$births) {
    $current=@{}
    foreach($x in $all){
      if($x.CreationDate){$current[[int]$x.ProcessId]=([datetime]$x.CreationDate).ToUniversalTime()}
    }
    $changed=$true
    while($changed){
      $changed=$false
      foreach($x in $all){
        $id=[int]$x.ProcessId; $parent=[int]$x.ParentProcessId
        if(-not $current.ContainsKey($id) -or $tracked.Contains($id) -or -not $births.ContainsKey($parent)){continue}
        $created=$current[$id]
        if($created -lt $births[$parent]){continue}
        # A PID can be recycled while children of its former owner are still running.
        if($current.ContainsKey($parent) -and $current[$parent] -gt $births[$parent].AddMilliseconds(1) -and $created -ge $current[$parent]){continue}
        [void]$tracked.Add($id); $births[$id]=$created; $changed=$true
      }
    }
    return @($all | Where-Object {
      $id=[int]$_.ProcessId
      -not $tracked.Contains($id) -or ($current.ContainsKey($id) -and [math]::Abs(($current[$id]-$births[$id]).TotalMilliseconds) -le 1)
    })
}
function Add-InstallShieldHandoff($processes,[System.Collections.Generic.HashSet[int]]$tracked,[hashtable]$births,[string]$source,[datetime]$launchTime) {
    $sourceDirectory=[IO.Path]::GetDirectoryName($source).TrimEnd('\')+'\'
    $tempDirectory=[IO.Path]::GetTempPath().TrimEnd('\')+'\'
    foreach($process in $processes){
      $id=[int]$process.ProcessId
      if($tracked.Contains($id) -or -not $process.CreationDate -or $process.Name -ne 'setup.exe' -or
         -not ([string]$process.ExecutablePath).StartsWith($tempDirectory,[StringComparison]::OrdinalIgnoreCase)){continue}
      $created=([datetime]$process.CreationDate).ToUniversalTime()
      if($created -lt $launchTime -or $process.CommandLine -notmatch '(?i)(?:^|\s)/IS_temp(?:\s|$)' -or
         $process.CommandLine -notmatch '(?i)(?:^|\s)/q"([^"]+)"(?:\s|$)'){continue}
      # InstallShield's temporary setup can outlive a short-lived intermediate launcher.
      try{$original=[IO.Path]::GetFullPath($Matches[1])}catch{continue}
      if(-not $original.StartsWith($sourceDirectory,[StringComparison]::OrdinalIgnoreCase) -or
         [IO.Path]::GetFileName($original) -ne 'setup.exe'){continue}
      [void]$tracked.Add($id); $births[$id]=$created
      Write-DebugEvent 'Tracked InstallShield temporary setup handoff' ([PSCustomObject]@{ProcessId=$id;Source=$original})
    }
}
function Update-TrackedProcessTree([System.Collections.Generic.HashSet[int]]$tracked,[hashtable]$births,[string]$handoffSource='', [datetime]$launchTime=[datetime]::MinValue) {
    $processes=@(Get-CimInstance Win32_Process -ErrorAction SilentlyContinue)
    if($handoffSource){Add-InstallShieldHandoff $processes $tracked $births $handoffSource $launchTime}
    $all=@(Expand-TrackedProcessTree $processes $tracked $births)
    Observe-InstallerTree $all $tracked
    return $all
}
function Test-InitialInstallerActivity($processes,$tracked,[int]$rootPid,[string]$sourceDirectory) {
    foreach($process in $processes){
      $id=[int]$process.ProcessId
      if($id -eq $rootPid -or -not $tracked.Contains($id)){continue}
      if($process.Name -match '^msiexec(?:\.exe)?$' -and $process.CommandLine -match '(?i)(?:^|\s)(?:/V|-Embedding)(?:\s|$)'){continue}
      if($process.Name -match '^(?:msiexec|setup|install)'){return $true}
      # Staged InstallShield media can hand off through a launcher such as demo32.exe.
      if($sourceDirectory -and ([string]$process.ExecutablePath).StartsWith($sourceDirectory,[StringComparison]::OrdinalIgnoreCase)){return $true}
    }
    return $false
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
function Stop-TrackedProcessTree([System.Collections.Generic.HashSet[int]]$tracked,[hashtable]$births,[int]$MaxSeconds=30) {
    # v0.11.38: cleanup is explicitly bounded. A rejected candidate must never strand the
    # lifecycle before the next strategy can start.
    Set-AnalysisHeartbeat 'candidate-cleanup-tree-start'
    $deadline=(Get-Date).AddSeconds([Math]::Max(5,$MaxSeconds))
    do {
      $alive=0
      $null=Update-TrackedProcessTree $tracked $births
      foreach($id in @(Get-TrackedProcessIds $tracked)){
        $p=Get-Process -Id $id -ErrorAction SilentlyContinue
        if($null -eq $p){continue}
        try {
          # Hold the handle while checking birth time and terminating this exact process.
          $null=$p.Handle
          if(-not $p.HasExited -and [math]::Abs(($p.StartTime.ToUniversalTime()-$births[$id]).TotalMilliseconds) -le 1){
            $alive++
            $p.Kill()
          }
        }catch{}finally{$p.Dispose()}
      }
      if($alive -eq 0){Set-AnalysisHeartbeat 'candidate-cleanup-tree-complete';return $true}
      Set-AnalysisHeartbeat ('candidate-cleanup-waiting-'+$alive)
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
function Stop-RejectedInstaller([System.Collections.Generic.HashSet[int]]$tracked,[hashtable]$births) {
    Set-AnalysisHeartbeat 'candidate-ui-reject-stop-owner-start'
    $stopped=Stop-TrackedProcessTree $tracked $births 30
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
function Invoke-NativeProcess([string]$file,[string]$arguments,[bool]$MonitorUi=$false,[bool]$AbortOnUi=$false,[int]$MaxSeconds=0,$DetectionTarget=$null,[bool]$CompleteWhenDetected=$false,[bool]$WatchInstallPrerequisites=$false,[bool]$AllowProgressWindow=$false) {
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
    if ($ArchiveEntry) {
      if ($file.StartsWith('C:\InstallerArchive\', [StringComparison]::OrdinalIgnoreCase)) {
        $psi.WorkingDirectory = Split-Path -Parent $file
      } elseif ($arguments.IndexOf($Installer, [StringComparison]::OrdinalIgnoreCase) -ge 0) {
        $psi.WorkingDirectory = Split-Path -Parent $Installer
      }
    }
    if($CompleteWhenDetected){Write-Checkpoint ($launchPhase+' launch: ProcessStartInfo ready')}
    $proc = New-Object System.Diagnostics.Process; $proc.StartInfo = $psi
    if($CompleteWhenDetected){Write-Checkpoint ($launchPhase+' launch: calling Process.Start')}
    $launchTime=(Get-Date).ToUniversalTime()
    $handoffSource=if($ArchiveEntry -and $InstallerKind -eq 'InstallShield' -and $file -eq $Installer){$Installer}else{''}
    [void]$proc.Start()
    if($CompleteWhenDetected){Write-Checkpoint ($launchPhase+' launch: Process.Start returned PID '+$proc.Id)}
    $tracked=New-Object 'System.Collections.Generic.HashSet[int]'; [void]$tracked.Add([int]$proc.Id)
    $births=@{}; $births[[int]$proc.Id]=Get-InstallerProcessBirth $proc $launchTime
    $ui=New-Object 'System.Collections.Generic.HashSet[string]'; $aborted=$false
    $uiDiagnostics=New-Object 'System.Collections.Generic.List[object]'
    $lastUiDiagnostic=[DateTime]::MinValue
    $unexpectedSince=@{}
    $rootExit=$null
    $lastHandoffActivity=$null
    $startedAt=Get-Date; $completedByDetection=$false; $timedOut=$false
    $clock=@{Deadline=$startedAt.AddSeconds($MaxSeconds);Limit=$startedAt.AddMinutes(50);ApplicationSeconds=$MaxSeconds;Waiting=$false;Seen=$false}
    while($true){
      Set-AnalysisHeartbeat 'native-process-monitor'
      try{$all=Update-TrackedProcessTree $tracked $births $handoffSource $launchTime}catch{$all=@()}
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
          $progressWindows=@{}
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
            if($AllowProgressWindow -and $tracked.Contains($w.Pid) -and [InstallerAnalyzerWindowProbe]::IsProgressOnlyWindow([long]$w.Hwnd,$w.Pid)){
              $progressWindows[$w.Hwnd]=$true
              $unexpectedSince.Remove($key)
              continue
            }
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
                Stop-RejectedInstaller $tracked $births
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
            if(-not [InstallerAnalyzerWindowProbe]::IsPresentedWindow($gp.MainWindowHandle.ToInt64())){continue}
            $pw=[PSCustomObject]@{Hwnd=$gp.MainWindowHandle.ToString();Pid=[int]$gp.Id;Title=[string]$gp.MainWindowTitle}
            if(Test-IgnoredDesktopWindow $pw){continue}
            if($CompleteWhenDetected -and $gp.Id -ne $proc.Id -and (Test-InstalledApplicationProcess $gp.Id $installedWindowTarget $file)){continue}
            $pkey=('PID:'+ $gp.Id + ':' + $gp.MainWindowHandle)
            if($AllowProgressWindow -and $tracked.Contains($pw.Pid) -and ($progressWindows.ContainsKey($pw.Hwnd) -or
              [InstallerAnalyzerWindowProbe]::IsProgressOnlyWindow([long]$pw.Hwnd,$pw.Pid))){
              $unexpectedSince.Remove($pkey)
              continue
            }
            if(-not $unexpectedSince.ContainsKey($pkey)){$unexpectedSince[$pkey]=Get-Date;continue}
            if($InstallerKind -eq 'InnoSetup' -and $gp.MainWindowTitle -eq 'Setup'){continue}
            $processUiPersistenceMs=500
            if($CompleteWhenDetected -and $proc.HasExited -and $proc.ExitCode -eq 0){$processUiPersistenceMs=3000}
            if(((Get-Date)-$unexpectedSince[$pkey]).TotalMilliseconds -ge $processUiPersistenceMs){
              $desc=($gp.Id.ToString()+' :: '+$gp.ProcessName+' :: '+$gp.MainWindowTitle)
              Record-InstallerUiEvidence $pw $tracked
              [void]$ui.Add($desc)
              if($AbortOnUi){$aborted=$true;Stop-RejectedInstaller $tracked $births;break}
            }
          }
          if($aborted){break}
        } catch {}
      }
      try{$proc.Refresh()}catch{}
      if($proc.HasExited -and $null -eq $rootExit){$lastHandoffActivity=Get-Date;try{$rootExit=$proc.ExitCode}catch{$rootExit=-2}}
      # v0.11.38: a bootstrapper may leave normal application/helper descendants alive forever.
      # During reinstall validation, keep waiting for the installer exit code while ignoring
      # only application processes confirmed beneath its registered installation directory.
      # Registration can precede the end of the install transaction. Retain the real root
      # process exit code; only exclude a proven installed application's launched processes.
      if($WatchInstallPrerequisites -or $CompleteWhenDetected){
        $prerequisite=Find-TrackedPrerequisite $all $tracked $proc.Id
        Update-InstallWait $clock $prerequisite (Get-Date)
      }
      if($MaxSeconds -gt 0 -and (Get-Date) -ge $clock.Deadline){$timedOut=$true;break}
      # Bootstrapper parents often exit after handing work to a child. Keep watching every PID
      # already discovered until the entire tracked tree is gone.
      $trackedIds=@(Get-TrackedProcessIds $tracked)
      $alive=@($all | Where-Object {[int]$_.ProcessId -in $trackedIds})
      if($CompleteWhenDetected -and $null -ne $installedWindowTarget -and $proc.HasExited){
        $alive=@($alive | Where-Object {-not (Test-InstalledApplicationProcess ([int]$_.ProcessId) $installedWindowTarget $file)})
      }
      if($handoffSource -and $alive.Count -gt 0){$lastHandoffActivity=Get-Date}
      $handoffPending=$handoffSource -and $lastHandoffActivity -and ((Get-Date)-$lastHandoffActivity).TotalSeconds -lt 5
      if($proc.HasExited -and -not $clock.Waiting -and -not $handoffPending -and ($alive.Count -eq 0 -or (Test-MsiClientCommand $file))){break}
      Start-Sleep -Milliseconds 150
    }
    if($completedByDetection -or $timedOut){try{Stop-TrackedProcessTree $tracked $births}catch{}}
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
    return (($text -match '(?im)^\[InstallShield Silent\]\s*$' -and $text -match '(?im)^File=Response File\s*$' -and $text -match '(?im)^Count=[1-9][0-9]*\s*$') -or
      $text -match '__ISS_DIALOG_SEQUENCE__')
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
function Test-VirtualBoxDriverState([string]$phase,[bool]$installed) {
    if(-not $IsVirtualBoxReducedProfile){return}
    $drivers=@(Get-CimInstance Win32_SystemDriver -ErrorAction Stop | Where-Object Name -like 'VBox*' | Select-Object Name,State,StartMode)
    $network=@(netcfg.exe -s n | Select-String -Pattern 'VBox|VirtualBox' | ForEach-Object Line)
    if($LASTEXITCODE -ne 0){throw 'Could not inspect VirtualBox network bindings.'}
    $packages=@(Get-WindowsDriver -Online -ErrorAction Stop | Where-Object {
      $_.ProviderName -match '^Oracle' -and [IO.Path]::GetFileName($_.OriginalFileName) -match '^VBox'
    } | Select-Object Driver,OriginalFileName,ProviderName)
    Add-Content -LiteralPath 'C:\InstallerOutput\virtualbox-driver-evidence.jsonl' -Value (
      [PSCustomObject]@{Phase=$phase;Drivers=$drivers;Bindings=$network;DriverPackages=$packages} | ConvertTo-Json -Depth 4 -Compress)
    if($installed){
      $running=@($drivers | Where-Object State -eq 'Running' | ForEach-Object Name)
      if('VBoxSup' -notin $running -or 'VBoxUSBMon' -notin $running -or 'VBoxNetLwf' -notin $running -or
         'VBoxNetAdp' -in $drivers.Name -or -not ($network -match 'oracle_vboxnetlwf')){
        throw "VirtualBox did not establish the expected core, USB and bridge driver state during $phase."
      }
    }elseif($drivers.Count -or $network.Count -or $packages.Count){
      throw "VirtualBox driver or network traces remain during $phase."
    }
}
function Get-MsiInstallCandidates {
    $base=if([string]::IsNullOrWhiteSpace($SilentInstallArguments)){'/qn /norestart'}else{$SilentInstallArguments}
    if($IsVirtualBoxReducedProfile){
      return (New-InstallCandidate 'VirtualBox core, USB and bridge' $Installer $base 'Msi' 100 'Pinned Oracle x64 MSI and cabinet with the VM-tested feature set.')
    }
    if($IsCetMsi){
      # Configura's unattended install guide uses the version ID and an embedded instance transform.
      if($base -notmatch '(?i)\bCET_VERSIONID\s*='){
        $versionId='64-bit'
        if([IO.Path]::GetFileNameWithoutExtension($Installer) -match '#([A-Za-z0-9_.-]{1,80})$'){$versionId=$matches[1]}
        $base+=' CET_VERSIONID='+$versionId
      }
      if($base -notmatch '(?i)\bTRANSFORMS\s*='){$base+=' TRANSFORMS=:InstanceId01'}
      return (New-InstallCandidate 'Configura CET instance strategy' $Installer $base 'Msi' 100 'Vendor-documented unattended installation for a clean CET instance.')
    }
    $items=@(New-InstallCandidate 'Known MSI strategy' $Installer $base 'Msi' 100 'Preferred Windows Installer quiet strategy with verbose logging.')
    if($base -notmatch '(?i)\bTRANSFORMS\s*='){
      foreach($name in @(Get-MsiEmbeddedInstanceTransforms $Installer | Sort-Object | Select-Object -First 3)){
        $items+=New-InstallCandidate ('Embedded MSI instance transform: '+$name) $Installer ($base+' TRANSFORMS=":'+$name+'" MSINEWINSTANCE=1') 'Msi' 85 'Instance transform discovered in the package storage table; must pass a complete clean Sandbox lifecycle.'
      }
    }
    return $items
}
function Get-SilentInstallCandidates($observedSilent,$files) {
    if($IsLegacyProject){
      return New-InstallCandidate 'Project 2007 Setup with silent configuration' $Installer $SilentInstallArguments 'Exe' 100 'Uses the original Office 12 setup and the Project configuration.'
    }
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
    if($IsLegacyProject){return Get-SilentInstallCandidates $null @()}
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
    if($candidate.Kind -eq 'Msi'){
      $msiLog='C:\InstallerOutput\msi-install.log'
      if($IsVirtualBoxReducedProfile){
        return Invoke-NativeProcess 'msiexec.exe' (('/i "'+$VirtualBoxLocalMsi+'" '+$candidate.Arguments+' /L*v! "'+$msiLog+'"').Trim()) $true $true 120 $detectionTarget $false
      }
      return Invoke-NativeProcess 'msiexec.exe' (("/i `"$($candidate.File)`" " + $candidate.Arguments + " /L*v `"$msiLog`"").Trim()) $true $true 600 $detectionTarget $true
    }
    # Bound each reinstall candidate to ten minutes and stop as soon as the expected application
    # is detected. This prevents Adobe/other bootstrappers from hanging on normal descendants.
    return Invoke-NativeProcess $candidate.File $candidate.Arguments $true $true 600 $detectionTarget (-not $IsLegacyProject)
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
function Normalize-QSetupUninstallCommand([string]$command) {
    if($InstallerKind -ne 'QSetup' -or [string]::IsNullOrWhiteSpace($command)){return $command}
    $parts=Split-Command $command
    if(-not $parts){return $command}
    # QSetup /silent can still display its removal wizard. Preserve vendor arguments
    # and add /Hide even when the registry labels the command QuietUninstallString.
    if([string]$parts[1] -notmatch '(?i)(^|\s)/hide(\s|$)'){return ($command.TrimEnd()+' /Hide')}
    return $command
}
function Get-InnoUninstallCommand([string]$command) {
    if($InstallerKind -ne 'InnoSetup'){return $null}
    $parts=Split-Command $command
    if(-not $parts -or [IO.Path]::GetFileName($parts[0]) -notmatch '^unins\d*\.exe$'){return $null}
    # Keep quoted argument values intact when replacing Inno's progress-window switch.
    $arguments=[regex]::Matches([string]$parts[1], '(?:[^\s"]+|"[^"]*")+') |
        ForEach-Object Value |
        Where-Object {$_ -notmatch '^/(SILENT|VERYSILENT|SUPPRESSMSGBOXES|NORESTART)$'}
    return ((@('"'+$parts[0]+'"') + @($arguments) + @('/VERYSILENT','/SUPPRESSMSGBOXES','/NORESTART')) -join ' ')
}
function Get-SilentUninstallCandidates($entry) {
    if($IsLegacyProject -and (Test-ProjectRegistration $entry)){
      return ('"'+$Installer+'" /uninstall PRJPRO /config "'+$ProjectConfig+'"')
    }
    if($entry.Key -like 'APPX::*' -and -not [string]::IsNullOrWhiteSpace([string]$entry.QuietUninstallString)){return @([string]$entry.QuietUninstallString)}
    $list=New-Object 'System.Collections.Generic.List[string]'
    $quiet=[string]$entry.QuietUninstallString
    $inno=Get-InnoUninstallCommand $quiet
    if($inno){$list.Add($inno)}
    elseif(-not [string]::IsNullOrWhiteSpace($quiet)){$list.Add((Normalize-QSetupUninstallCommand $quiet))}
    $msi=Get-MsiUninstallCommand $entry; if($msi){$list.Add($msi)}
    if(-not [string]::IsNullOrWhiteSpace([string]$entry.UninstallString)){
      $u=[string]$entry.UninstallString
      $inno=Get-InnoUninstallCommand $u
      if($inno){$list.Add($inno)}
      $sp=Split-Command $u
      if($sp -and -not $inno){
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
    if($entry.WindowsInstaller -eq 1 -and $entry.ProductCode){
      $command="msiexec.exe /x $($entry.ProductCode) /qn /norestart"
      if($CetHasDataPrompt -and $entry.Publisher -eq 'Configura Sverige AB' -and $entry.DisplayName -match '^(?:Configura )?CET(?:\s|$)'){
        # Skip the package's Clear User Data action so unattended removal preserves user data.
        $command+=' USED_DATA_ALREADY_REMOVED=1'
      }
      return $command
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
    if($IsLegacyProject){return $false}
    if($primary -and (([string]$primary.UninstallString) -match '(?i)OfficeClickToRun\.exe' -or ([string]$primary.QuietUninstallString) -match '(?i)OfficeClickToRun\.exe')){ return $true }
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
function Find-BootstrapperMainMsi($processes,$tracked,[string]$product) {
    if([string]::IsNullOrWhiteSpace($product)){return $null}
    foreach($process in $processes){
      if(-not $tracked.Contains([int]$process.ProcessId) -or $process.Name -notmatch '(?i)^msiexec(?:\.exe)?$'){continue}
      if([string]$process.CommandLine -match '(?i)(?:^|\s)/(?:i|package)\s*(?:"(?<msi>[^"]+\.msi)"|(?<msi>[^\s"]+\.msi))(?=\s|$)'){
        if([IO.Path]::GetFileNameWithoutExtension($matches['msi']) -ieq $product){return $process}
      }
    }
    return $null
}
function Find-TrackedPrerequisite($processes,$tracked,[int]$rootPid) {
    # Use recognizable prerequisite package names on owned descendants only.
    $runtime='(?:vc[0-9]*redist|vc_redist|dotnetfx|ndp\d|(?:dotnet|windowsdesktop|aspnetcore)-runtime-|MicrosoftEdgeWebView2RuntimeInstaller|AccessDatabaseEngine|dxsetup|Setup_CONNECTIONClient)'
    $sqlSetupPath='(?i)\\(?:SQL20\d{2}(?:x(?:64|86))?|Microsoft SQL Server\\\d+\\Setup Bootstrap\\SQL20\d{2})(?:\\x(?:64|86))?\\(?:setup|ScenarioEngine)\.exe$'
    foreach($process in $processes){
      if($process.ProcessId -eq $rootPid -or -not $tracked.Contains([int]$process.ProcessId)){continue}
      if($process.Name -match ('(?i)^'+$runtime+'[\w.-]*\.exe$')){return $process}
      if($process.Name -match '(?i)^msiexec(?:\.exe)?$' -and $process.CommandLine -match ('(?i)(?:^|\s)/(?:i|package)\s*(?:"[^"]*[\\/]|[^\s"]*[\\/]|"?)'+$runtime+'[\w.-]*\.msi(?:"|\s|$)')){return $process}
      # SQL Server can hand off from setup.exe to ScenarioEngine.exe after a runtime installer exits.
      if($process.ExecutablePath -match $sqlSetupPath -and
         $process.CommandLine -match '(?i)(?:^|\s)(?:"/ACTION=Install"|/ACTION=(?:"Install"|Install))(?:\s|$)'){return $process}
    }
}
function Update-InstallWait($clock,$prerequisite,[datetime]$now) {
    if($prerequisite -and -not $clock.Waiting){
      $clock.Waiting=$true
      $clock.Seen=$true
      $clock.Deadline=$now.AddMinutes(15)
      Write-Checkpoint ('Waiting for prerequisite setup: '+$prerequisite.Name+'; application timer is paused')
    }elseif(-not $prerequisite -and $clock.Waiting){
      $clock.Waiting=$false
      $clock.Deadline=$now.AddSeconds($clock.ApplicationSeconds)
      Write-Checkpoint 'Prerequisite setup processes exited; waiting for the application installer'
    }
    if($clock.Deadline -gt $clock.Limit){$clock.Deadline=$clock.Limit}
}
function Save-BootstrapperLogSnapshot([string]$log,[string]$output,[string]$name) {
    $source=$null;$destination=$null
    try {
      $source=[IO.File]::Open($log,[IO.FileMode]::Open,[IO.FileAccess]::Read,([IO.FileShare]::ReadWrite -bor [IO.FileShare]::Delete))
      if($source.Length -eq 0){return $null}
      $unicode=$source.ReadByte() -eq 255 -and $source.ReadByte() -eq 254
      [long]$offset=[Math]::Max(0,$source.Length-4194304);if($unicode -and $offset%2){$offset++}
      $source.Position=$offset;$destination=[IO.File]::Create((Join-Path $output $name))
      if($unicode -and $offset -gt 0){$destination.WriteByte(255);$destination.WriteByte(254)}
      $buffer=New-Object byte[] 65536;[long]$remaining=[Math]::Min(4194304,$source.Length-$offset)
      while($remaining -gt 0){$read=$source.Read($buffer,0,[int][Math]::Min($buffer.Length,$remaining));if($read -eq 0){break};$destination.Write($buffer,0,$read);$remaining-=$read}
      return [PSCustomObject]@{Source=$log;File=$name;Truncated=($offset -gt 0)}
    } finally {if($destination){$destination.Dispose()};if($source){$source.Dispose()}}
}
function Save-BootstrapperMsiLogs([string[]]$files,[string]$product,[string]$output,[string]$tempRoot) {
    if([string]::IsNullOrWhiteSpace($product)){return @()}
    $allowed=[IO.Path]::GetFullPath($tempRoot).TrimEnd('\')+'\'
    $saved=@();$seen=@{}
    foreach($file in $files){
      try {
        $full=[IO.Path]::GetFullPath($file)
        if(-not $full.StartsWith($allowed,[StringComparison]::OrdinalIgnoreCase) -or [IO.Path]::GetExtension($full) -ine '.msi' -or [IO.Path]::GetFileNameWithoutExtension($full) -ine $product){continue}
        $directory=[IO.Path]::GetDirectoryName($full);$parent=[IO.Path]::GetDirectoryName($directory)
        foreach($folder in @($directory,$parent)){
          if(-not $folder){continue}
          $log=[IO.Path]::GetFullPath((Join-Path $folder ($product+'SetupLog.txt')))
          if(-not $log.StartsWith($allowed,[StringComparison]::OrdinalIgnoreCase) -or $seen.ContainsKey($log) -or -not [IO.File]::Exists($log)){continue}
          $seen[$log]=$true;$snapshot=Save-BootstrapperLogSnapshot $log $output ('bootstrapper-main-msi-log-'+($saved.Count+1)+'.txt')
          if($null -ne $snapshot){$saved+=@($snapshot)}
        }
      } catch {Write-DebugEvent 'Bootstrapper MSI log snapshot unavailable' ([PSCustomObject]@{Detail=$_.Exception.Message})}
    }
    return $saved
}
function Get-BootstrapperMainMsiStatus($snapshots,[string]$output,[string]$product) {
    if([string]::IsNullOrWhiteSpace($product)){return}
    $productPattern='(?i)(?:^|[^a-z0-9])'+[regex]::Escape($product.Trim())+'(?:$|[^a-z0-9])'
    $success=$null
    foreach($snapshot in $snapshots){
      try{
        $log=[IO.File]::ReadAllText((Join-Path $output $snapshot.File))
        $terminal=$null
        $vbScriptUnavailable=$false
        foreach($line in ($log -split '\r?\n')){
          if($line -match '(?i)\berror code is 2738\b'){$vbScriptUnavailable=$true}
          if($line -match '(?i)Product Name:\s*(?<product>.*?)\.\s+Product Version:.*Installation success or error status:\s*(?<status>\d{1,5})\.?\s*$'){
            $loggedProduct=$Matches.product
            $status=[int]$Matches.status
            if($loggedProduct -match $productPattern){
              $terminal=[PSCustomObject]@{ExitCode=$status;Log=$snapshot.File;VbScriptUnavailable=$vbScriptUnavailable}
            }
            $vbScriptUnavailable=$false
          }
        }
        if($null -ne $terminal){
          if($terminal.ExitCode -notin @(0,1641,3010)){return $terminal}
          if($null -eq $success -or $terminal.ExitCode -ne 0){$success=$terminal}
        }
      }catch{Write-DebugEvent 'Main MSI status could not be read' ([PSCustomObject]@{Detail=$_.Exception.Message})}
    }
    return $success
}
function Get-BootstrapperSettleDeadline($status,$primary,[bool]$settling,[bool]$prerequisiteActive,[datetime]$deadline) {
    if(-not $settling -and -not $prerequisiteActive -and $primary -and $null -ne $status -and $status.ExitCode -eq 0){
      return $deadline.AddSeconds(60)
    }
}
function Update-BootstrapperExitEvidence($processes,$tracked,$handles,$exits) {
    foreach($process in $processes){
      $id=[int]$process.ProcessId
      if(-not $tracked.Contains($id) -or $handles.ContainsKey($id) -or $handles.Count -ge 128){continue}
      $entry=[ordered]@{ProcessId=$id;Name=[string]$process.Name;ParentProcessId=[int]$process.ParentProcessId;ObservedAt=(Get-Date).ToString('o');Status='Running';ExitCode=$null;ExitedAt=$null}
      $handle=$null
      try {
        $handle=[Diagnostics.Process]::GetProcessById($id)
        $null=$handle.Handle
      }catch{
        if($handle){$handle.Dispose();$handle=$null}
        $entry.Status='Exit code unavailable'
      }
      $handles[$id]=[PSCustomObject]@{Process=$handle;Evidence=$entry}
      [void]$exits.Add($entry)
    }
    foreach($record in $handles.Values){
      if($null -eq $record.Process -or $record.Evidence.Status -ne 'Running'){continue}
      try {
        if($record.Process.HasExited){
          $record.Evidence.ExitCode=$record.Process.ExitCode
          $record.Evidence.ExitedAt=$record.Process.ExitTime.ToString('o')
          $record.Evidence.Status='Exited'
        }
      }catch{$record.Evidence.Status='Exit code unavailable'}
    }
}
function Save-BootstrapperPrerequisiteLogs([bool]$observedConnection,[string]$product,[string]$output,[string]$tempRoot,[datetime]$since,[bool]$observedVisualCpp=$false) {
    if((-not $observedConnection -and -not $observedVisualCpp) -or [string]::IsNullOrWhiteSpace($product)){return @()}
    $saved=@()
    # Bentley documents CONNECTION_Client*.log in the root of the user's temp directory.
    # Application/authentication logs under LocalAppData are deliberately outside this scope.
    $logs=@(Get-ChildItem -LiteralPath $tempRoot -File -ErrorAction SilentlyContinue | Where-Object {
      $_.LastWriteTimeUtc -ge $since.ToUniversalTime() -and -not ($_.Attributes -band [IO.FileAttributes]::ReparsePoint) -and (
        ($observedConnection -and $_.Name -match '(?i)^(?:CONNECTION_Client|Setup_CONNECTIONClient).*\.log$') -or
        ($observedVisualCpp -and $_.Name -match '(?i)^(?:dd_vcredist|dd_vc_redist|vc_redist|vcredist)[a-z0-9_.-]*\.(?:log|txt)$')
      )
    } | Sort-Object LastWriteTimeUtc -Descending | Select-Object -First 8)
    foreach($file in $logs){
      try {$snapshot=Save-BootstrapperLogSnapshot $file.FullName $output ('bootstrapper-prerequisite-log-'+($saved.Count+1)+'.txt');if($null -ne $snapshot){$saved+=@($snapshot)}}
      catch {Write-DebugEvent 'Bootstrapper prerequisite log snapshot unavailable' ([PSCustomObject]@{Detail=$_.Exception.Message})}
    }
    return $saved
}
function Test-BootstrapperChainExited($processes,$tracked,$handles,[int]$rootPid) {
    if(-not $handles.ContainsKey($rootPid) -or $handles[$rootPid].Evidence.Status -ne 'Exited'){return $false}
    foreach($process in $processes){
      if(-not $tracked.Contains([int]$process.ProcessId)){continue}
      if($process.Name -match '(?i)^msiexec(?:\.exe)?$' -and ([string]$process.CommandLine) -match '(?i)(?:^|\s)(?:/V|-Embedding)(?:\s|$)'){continue}
      return $false
    }
    return $true
}
function Watch-Bootstrapper([int]$RootPid,[string[]]$BeforeKeys) {
    $tracked = New-Object 'System.Collections.Generic.HashSet[int]'; [void]$tracked.Add($RootPid)
    $seen = New-Object 'System.Collections.Generic.HashSet[int]'
    $processLog = New-Object 'System.Collections.Generic.List[string]'
    $imageLog = New-Object 'System.Collections.Generic.HashSet[string]' ([StringComparer]::OrdinalIgnoreCase)
    $fileLog = New-Object 'System.Collections.Generic.HashSet[string]'
    $primary=$null; $new=@(); $quietSince=$null; $discoveryStarted=Get-Date
    $clock=@{Deadline=$discoveryStarted.AddMinutes(15);Limit=$discoveryStarted.AddMinutes(50);ApplicationSeconds=900;Waiting=$false;Seen=$false}
    $mainStageStarted=$false;$connectionStageSeen=$false;$settling=$false;$settled=$false;$visualCppSeen=$false;$endedWithoutPrimary=$false
    $processHandles=@{}
    $exitEvidence=New-Object 'System.Collections.Generic.List[object]' 
    $infra='^(msiexec|OfficeClickToRun|OfficeC2RClient|setup|installer|install|update|Reader_en_install)'
    $postInstall='^(Acrobat|AdobeCollabSync|ShowAppPickerForPDF|msedge|msedgewebview2|explorer|SSScheduler|mc-webview-cnt|identity_helper)$'
    try {
    while($true){
      if((Get-Date) -ge $clock.Deadline){
        if(-not $mainStageStarted -or $settling -or $clock.Waiting){break}
        $settleLogs=@(Save-BootstrapperMsiLogs @(Get-StringSetItems $fileLog) $RequiredPrimaryProduct 'C:\InstallerOutput' $env:TEMP)
        $status=Get-BootstrapperMainMsiStatus $settleLogs 'C:\InstallerOutput' $RequiredPrimaryProduct
        $settleDeadline=Get-BootstrapperSettleDeadline $status $primary $settling $clock.Waiting $clock.Deadline
        if($null -eq $settleDeadline -or (Get-Date) -ge $settleDeadline){break}
        $settling=$true
        $clock.Deadline=$settleDeadline
        Write-Checkpoint ('Main MSI reported success: '+$RequiredPrimaryProduct+'; waiting for setup activity to settle')
      }
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
      Update-BootstrapperExitEvidence $all $tracked $processHandles $exitEvidence
      if(@($all | Where-Object {$tracked.Contains([int]$_.ProcessId) -and $_.Name -match '(?i)^(?:vc[0-9]*redist|vc_redist)'}).Count){$visualCppSeen=$true}
      if(-not $connectionStageSeen -and @($all | Where-Object {$tracked.Contains([int]$_.ProcessId) -and $_.Name -match '(?i)^Setup_CONNECTIONClient'}).Count){
        $connectionStageSeen=$true
      }
      $prerequisite=Find-TrackedPrerequisite $all $tracked $RootPid
      if(-not $settling){Update-InstallWait $clock $prerequisite (Get-Date)}
      if(-not $mainStageStarted -and -not $clock.Waiting){
        $mainMsi=Find-BootstrapperMainMsi $all $tracked $RequiredPrimaryProduct
        if($null -ne $mainMsi){
          $mainStageStarted=$true;$mainStarted=Get-Date
          $maximum=if($clock.Seen){$clock.Limit}else{$discoveryStarted.AddMinutes(30)}
          $clock.Deadline=if($mainStarted.AddMinutes(15) -lt $maximum){$mainStarted.AddMinutes(15)}else{$maximum}
          $result['BootstrapperMainMsi']=[ordered]@{ProcessId=$mainMsi.ProcessId;StartedAt=$mainStarted.ToString('o');Deadline=$clock.Deadline.ToString('o');Product=$RequiredPrimaryProduct}
          Write-Checkpoint ('Main MSI started: '+$RequiredPrimaryProduct+'; waiting for setup and product registration')
        }
      }
      foreach($proc in $all){
        if($proc.ProcessId -in $BeforeProcessIds){continue}
        if($tracked.Contains([int]$proc.ProcessId) -and $imageLog.Count -lt 32 -and -not [string]::IsNullOrWhiteSpace([string]$proc.ExecutablePath)){if($imageLog.Add([string]$proc.ExecutablePath)){$result['BootstrapperObservedImages']=@(Get-StringSetItems $imageLog)}}
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
        # Windows Installer service/COM hosts can outlive the completed client transaction.
        if($_.Name -match '(?i)^msiexec(?:\.exe)?$' -and ([string]$_.CommandLine) -match '(?i)(?:^|\s)(?:/V|-Embedding)(?:\s|$)'){return $false}
        if($_.Name -match '^OfficeClickToRun' -and ([string]$_.CommandLine) -match '(?i)\s/service(?:\s|$)'){return $false}
        return $true
      })
      $chainExited=Test-BootstrapperChainExited $all $tracked $processHandles $RootPid
      $idle=if($primary){-not $clock.Waiting -and -not $prerequisite -and $active.Count -eq 0}else{$chainExited}
      if($idle){
        if(-not $quietSince){$quietSince=Get-Date}
        if(((Get-Date)-$quietSince).TotalSeconds -ge 24){
          $endedWithoutPrimary=$null -eq $primary
          $settled=$true
          break
        }
      }else{$quietSince=$null}
      Start-Sleep 3
    }
    Update-BootstrapperExitEvidence @() $tracked $processHandles $exitEvidence
    $result['BootstrapperProcessExits']=@(Get-ObjectListItems $exitEvidence)
    $result.BootstrapperProcessExits | ConvertTo-Json -Depth 4 | Set-Content 'C:\InstallerOutput\bootstrapper-process-exits.json' -Encoding UTF8
    $result['BootstrapperObservedImages']=@(Get-StringSetItems $imageLog)
    $snapshots=@(Save-BootstrapperMsiLogs @(Get-StringSetItems $fileLog) $RequiredPrimaryProduct 'C:\InstallerOutput' $env:TEMP)
    $result['BootstrapperMsiLogSnapshots']=$snapshots
    $status=Get-BootstrapperMainMsiStatus $snapshots 'C:\InstallerOutput' $RequiredPrimaryProduct
    $mainMsiFailure=if($null -ne $status -and $status.ExitCode -notin @(0,1641,3010)){$status}
    $result['BootstrapperPrerequisiteLogSnapshots']=@(Save-BootstrapperPrerequisiteLogs $connectionStageSeen $RequiredPrimaryProduct 'C:\InstallerOutput' $env:TEMP $discoveryStarted $visualCppSeen)
    $result['BootstrapperPrerequisiteLogStatus']=if(-not $connectionStageSeen -and -not $visualCppSeen){'Setup not observed'}elseif(@($result.BootstrapperPrerequisiteLogSnapshots).Count -eq 0){'No readable current prerequisite installation logs captured from guest TEMP'}else{'Captured'}
    $activeNames=@($active | ForEach-Object {$_.Name} | Sort-Object -Unique);$result['BootstrapperActiveProcesses']=$activeNames
    return [PSCustomObject]@{Processes=@($processLog);Files=@($fileLog);Primary=$primary;NewEntries=@($new);TimedOut=(-not $settled);EndedWithoutPrimary=$endedWithoutPrimary;PrerequisiteTimedOut=$clock.Waiting;MainMsiFailure=$mainMsiFailure;MainMsiStarted=$mainStageStarted;ActiveProcesses=$activeNames}
    } finally {
      foreach($record in $processHandles.Values){if($record.Process){$record.Process.Dispose()}}
    }
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

$IsCetMsi=$InstallerKind -eq 'Msi' -and $script:MsiStaticMetadata.Manufacturer -eq 'Configura Sverige AB' -and
    $script:MsiStaticMetadata.UpgradeCode -eq '{0D00DF52-730E-4251-A536-B53F18318375}' -and
    $script:MsiStaticMetadata.ProductName -match '^CET(?:\s|$)'
$CetHasDataPrompt=$false
if($IsCetMsi){
    $SilentOnly=$true
    $CetHasDataPrompt=@(Get-MsiRemovalUiActions $Installer | Where-Object {
      $_.Action -eq 'CETShowClearUserDataDialogOnUninstall' -and $_.Condition -eq 'REMOVE AND NOT USED_DATA_ALREADY_REMOVED=1'
    }).Count -gt 0
}

$result=[ordered]@{ ValidationSchemaVersion=3; EvidenceCollectionComplete=$false; UiTextEvidence=@(); RuntimeEnvironment=@(); PrerequisiteProbes=@(); PrerequisiteFiles=@(); DetectionStrategies=@(); Components=@(); ProcessTree=@(); NetworkActivity=@(); NewRebootIndicators=@(); PostRebootValidated=$false; InitialInstallValidated=$false; InitialUninstallValidated=$false; InitialUninstallExitCode=$null; CleanBaselineVerified=$false; RebootRequired=$false; SessionId=([guid]::NewGuid().ToString()); InstallerSha256=$null; Installer=[IO.Path]::GetFileName($Installer); InstallerExitCode=-1; CapturedAt=(Get-Date).ToString('o'); NewUninstallEntries=@(); PrimaryKey=$null; UninstallValidationMethod='Discovery only'; UninstallRecordingAttempted=$false; UninstallResponseFileCreated=$false; RecordedUninstallExitCode=$null; BaseSilentArguments=$BaseSilentArguments; AdditionalPackageArguments=$AdditionalPackageArguments; CombinedSilentArguments=$SilentInstallArguments; SilentInstallCommand=('"'+$Installer+'" '+$SilentInstallArguments).Trim(); SilentInstallStdOut=$null; SilentInstallStdErr=$null; SilentReinstallExitCode=$null; SilentReinstallValidated=$false; SilentReinstallUiDetected=$false; SilentReinstallVisibleWindows=@(); SilentUninstallExitCode=$null; SilentUninstallRawExitCode=$null; SilentUninstallUiDetected=$false; SilentUninstallVisibleWindows=@(); UiDiagnostics=@(); SilentStrategyCandidates=@(); SilentStrategyAttempts=@(); SelectedSilentStrategy=$null; PostUninstallDetected=$null; SilentUninstallValidated=$false; DiscoverySucceeded=$false; DiscoveryMethod=$null; DeploymentMechanism=$null; DeploymentSource=$Installer; IdentitySource=$null; UninstallCandidate=$null; ValidationError=$null; BootstrapperProcesses=@(); DiscoveredInstallerFiles=@(); BlockedBundledSoftware=@(); BlockedBundledSoftwareVerifiedAbsent=$null; WorkflowStage='Initial installation / discovery'; WorkflowStageUpdatedAt=(Get-Date).ToString('o'); WorkflowStageHistory=@() }
# v0.12.7: Strategy Discovery can execute candidates before the later lifecycle section is reached.
# Keep checkpoint/debug helpers available from the start of analysis so Invoke-InstallCandidate and
# Invoke-NativeProcess can safely report progress in Silent Only mode.
$result['ExpectedPrimaryProduct']=$RequiredPrimaryProduct
$result['AnalyzerVersion']='__ANALYZER_VERSION__'
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
    Ensure-SandboxInstallerCompatibility __SANDBOX_COMPATIBILITY__
    $script:NativeMsiBaselineState=Get-NativeMsiProductState ([string]$script:MsiStaticMetadata.ProductCode)
    $result['MsiProductStateBefore']=$script:NativeMsiBaselineState
    if ($ArchiveEntry) {
      Write-Checkpoint 'Staging installer ZIP folders'
      Copy-Item -LiteralPath 'C:\InstallerInput\Archive' -Destination 'C:\InstallerArchive' -Recurse -Force
      $result['InstallerArchiveEntry'] = $ArchiveEntry
      $result['InstallerArchiveSha256'] = $ArchiveSha256
    }
    if($IsLegacyProject){Initialize-LegacyProject}
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
    $netFxEvidence=[Text.Encoding]::UTF8.GetString([Convert]::FromBase64String('__NETFX_EVIDENCE__'))
    $script:UseGintPrerequisites=$RequiredPrimaryProduct -eq 'gINT' -and -not [string]::IsNullOrWhiteSpace($netFxEvidence)
    if($script:UseGintPrerequisites){Ensure-GintWindowsCatalog;Ensure-GintVbScript}
    Ensure-NetFx3 $netFxEvidence
    if($IsVirtualBoxReducedProfile){
      $result.DeploymentMechanism='VirtualBox 7.2.22 core, USB and bridged networking'
      $SilentInstallArguments=(Get-Content -LiteralPath $VirtualBoxProfileFile -Raw).Trim()
      $result.CombinedSilentArguments=$SilentInstallArguments
      $SilentOnly=$true
      Write-Checkpoint 'VirtualBox: verifying clean driver baseline'
      Test-VirtualBoxDriverState 'Before install' $false
      $local=Join-Path $env:TEMP ('IA-VirtualBox-'+[guid]::NewGuid().ToString('N'))
      New-Item -ItemType Directory -Path $local | Out-Null
      Copy-Item -LiteralPath $Installer,(Join-Path ($Installer+'.dependencies') 'common.cab'),(Join-Path ($Installer+'.dependencies') 'vc_redist.x64.exe') -Destination $local
      $VirtualBoxLocalMsi=Join-Path $local ([IO.Path]::GetFileName($Installer))
      Write-Checkpoint 'VirtualBox: preparing Microsoft Visual C++ x64 prerequisite'
      $vc=Invoke-NativeProcess (Join-Path $local 'vc_redist.x64.exe') '/install /quiet /norestart /log C:\InstallerOutput\virtualbox-vc-redist.log' $true $true 120
      if($vc.UiDetected -or $vc.TimedOut -or $vc.ExitCode -notin @(0,1638)){
        throw ('PREREQUISITE REQUIRED: VirtualBox Visual C++ x64 setup returned '+$vc.ExitCode+'. See virtualbox-vc-redist.log.')
      }
      $runtime=@(foreach($view in @('Registry64','Registry32')){
        $value=Read-RuntimeRegistry 'LocalMachine' $view 'SOFTWARE\Microsoft\VisualStudio\14.0\VC\Runtimes\x64' @('Installed')
        if($value.Available -and $value.Values['Installed'] -eq 1){$value}
      })
      if(-not $runtime.Count){throw 'PREREQUISITE REQUIRED: VirtualBox Visual C++ x64 registration was not found after setup.'}
    }
    $componentEncoded='__COMPONENT_PLAN__'
    if(-not [string]::IsNullOrWhiteSpace($componentEncoded)){
      $plan=[Text.Encoding]::UTF8.GetString([Convert]::FromBase64String($componentEncoded))|ConvertFrom-Json
      if($plan.SourceSha256 -ne $result.InstallerSha256){throw 'Component recipe source binding failed.'}
      Write-Checkpoint 'gINT: validating component prerequisites'
      . 'C:\InstallerInput\component-prerequisites.ps1'
      $result['ComponentDeployment']=$plan
      if($script:IAGintReboot){$result.RebootRequired=$true}
      $Installer='C:\InstallerInput\Payload\gINT.msi';$EffectiveSilentInstaller=$Installer
      $InstallerKind='Msi';$DiscoveredInstallerKind='Msi';$RecordResponses=$false;$SilentOnly=$true
      $SilentInstallArguments='/qn /norestart';$BaseSilentArguments=$SilentInstallArguments
      $result.DeploymentMechanism='Component recipe';$result.DeploymentSource='gINT.msi'
    }
    Start-PayloadTrace
    $replayPath='C:\InstallerInput\replay-recording.json'
    if(Test-Path -LiteralPath $replayPath -PathType Leaf){
      $recording=Get-Content -LiteralPath $replayPath -Raw | ConvertFrom-Json
      if($recording.InstallerSha256 -ne $result.InstallerSha256){throw 'Replay installer hash differs from the recorded installer.'}
      Copy-Item -LiteralPath 'C:\InstallerInput\replay-setup.iss' -Destination $SetupIss
      Copy-Item -LiteralPath 'C:\InstallerInput\replay-uninstall.iss' -Destination $UninstallIss
      if(-not (Test-InstallShieldResponse $SetupIss) -or -not (Test-InstallShieldResponse $UninstallIss)){throw 'Replay requires two valid InstallShield response files.'}
      $before=@(Get-UninstallSnapshot); $beforeKeys=@($before | ForEach-Object {$_.Key})
      if($recording.RegistryKey -in $beforeKeys){throw 'The recorded application is already present in the replay baseline.'}
      $result.InitialInstallValidated=$true
      $result.InitialUninstallValidated=$true
      $result.InitialUninstallExitCode=$recording.InitialUninstallExitCode
      $result.CleanBaselineVerified=$true
      $result.UninstallResponseFileCreated=$true
      $result.DiscoveryMethod='Recorded InstallShield response files replayed in a fresh Sandbox'
      $result.DeploymentMechanism='InstallShield'
      $result.IdentitySource='Uninstall registry'
      $SilentInstallArguments=('/s /f1"'+$SetupIss+'" '+$AdditionalPackageArguments).Trim()
      $result.BaseSilentArguments=$SilentInstallArguments
      $result.CombinedSilentArguments=$SilentInstallArguments
      $result.SilentInstallCommand=('"'+$Installer+'" '+$SilentInstallArguments)
      Write-Checkpoint 'Replay recorded install in fresh Sandbox'
      $installLog='C:\InstallerOutput\iss-install-replay.log'
      $install=Invoke-NativeProcess $Installer ($SilentInstallArguments+' /f2"'+$installLog+'"') $true $true 1200 ([PSCustomObject]@{Key=$recording.RegistryKey}) $true -AllowProgressWindow $true
      $result.InstallerExitCode=$install.ExitCode
      $result.SilentReinstallExitCode=$install.ExitCode
      $result.SilentReinstallUiDetected=$install.UiDetected
      $result.SilentReinstallVisibleWindows=@($install.VisibleWindows)
      $result.UiDiagnostics+=@($install.UiDiagnostics)
      if($install.UiDetected){throw ('Recorded install displayed installer UI: '+($install.VisibleWindows -join '; '))}
      if(-not (Test-ProcessResultSuccess $install) -or -not (Test-InstallShieldReplayLog $installLog)){
        throw 'Recorded silent install failed in the fresh Sandbox. See iss-install-replay.log when available.'
      }
      $new=@(Get-UninstallSnapshot | Where-Object {$_.Key -notin $beforeKeys})
      $primary=$new | Where-Object Key -eq $recording.RegistryKey | Select-Object -First 1
      if(-not $primary){throw 'Silent install did not register the application from the original recording.'}
      $result.NewUninstallEntries=$new
      $result.PrimaryKey=$primary.Key
      $result.DiscoverySucceeded=$true
      $result.SilentReinstallValidated=$true
      $result.SelectedSilentStrategy='Recorded InstallShield response file'
      Set-InstalledComponentEvidence
      Initialize-DetectionEvidence $primary $before
      $parts=Split-Command $primary.UninstallString
      if(-not $parts){throw 'Replayed application has no registered uninstall command.'}
      $arguments=($parts[1]+' /s /f1"'+$UninstallIss+'"').Trim()
      $command=('"'+$parts[0]+'" '+$arguments).Trim()
      if($command -ine $recording.UninstallCandidate){throw 'The registered uninstaller differs from the original recording.'}
      $result.UninstallCandidate=$command
      $result.UninstallValidationMethod='Recorded InstallShield uninstall response file'
      Write-Checkpoint 'Replay recorded uninstall in fresh Sandbox'
      $uninstallLog='C:\InstallerOutput\iss-uninstall-replay.log'
      $uninstall=Invoke-NativeProcess $parts[0] ($arguments+' /f2"'+$uninstallLog+'"') $true $true 900 -AllowProgressWindow $true
      $result.SilentUninstallExitCode=$uninstall.ExitCode
      $result.SilentUninstallUiDetected=$uninstall.UiDetected
      $result.SilentUninstallVisibleWindows=@($uninstall.VisibleWindows)
      $result.UiDiagnostics+=@($uninstall.UiDiagnostics)
      if($uninstall.UiDetected){throw ('Recorded uninstall displayed installer UI: '+($uninstall.VisibleWindows -join '; '))}
      if(-not (Test-ProcessResultSuccess $uninstall) -or -not (Test-InstallShieldReplayLog $uninstallLog)){
        throw 'Recorded silent uninstall failed in the fresh Sandbox. See iss-uninstall-replay.log when available.'
      }
      $result.PostUninstallDetected=-not (Wait-ApplicationAbsent $primary 'Final')
      if($result.PostUninstallDetected){throw 'The recorded application remained registered after removal.'}
      Complete-RoadmapRemovalEvidence
      $result.SilentUninstallValidated=$true
    } elseif($InstallerKind -eq 'Msix'){
      $packageName=(Get-Content -LiteralPath 'C:\InstallerInput\msix-identity.txt' -Raw).Trim()
      if($packageName -notmatch '^[A-Za-z0-9.-]+$'){throw 'Invalid MSIX/AppX package identity.'}
      if(Get-AppxPackage -Name $packageName -PackageTypeFilter Main){throw 'MSIX/AppX target is already present in the baseline. A clean guest is required for lifecycle validation.'}
      $parameters=@{Path=$Installer;ErrorAction='Stop'}
      $dependencyFolder=$Installer+'.dependencies'
      if(Test-Path -LiteralPath $dependencyFolder -PathType Container){
        $dependencies=@(Get-ChildItem -LiteralPath $dependencyFolder -File | Where-Object Extension -in @('.appx','.msix','.appxbundle','.msixbundle'))
        if($dependencies.Count){
          $parameters.DependencyPath=@($dependencies | ForEach-Object FullName)
          $result['MsixDependencies']=@($dependencies | ForEach-Object {
            [PSCustomObject]@{FileName=$_.Name;Sha256=(Get-FileHash -LiteralPath $_.FullName -Algorithm SHA256).Hash}
          })
        }
      }
      try { Add-AppxPackage @parameters; $result.InstallerExitCode=0 } catch { throw "MSIX/AppX installation failed: $($_.Exception.Message)" }
      Start-Sleep 4
      $pkg=Get-AppxPackage -Name $packageName -PackageTypeFilter Main | Select-Object -First 1
      if(-not $pkg){throw 'MSIX/AppX package installation completed, but no newly installed package could be identified.'}
      $primary=[PSCustomObject]@{Key=('APPX::'+$pkg.PackageFullName);DisplayName=$pkg.Name;DisplayVersion=$pkg.Version.ToString();Publisher=$pkg.Publisher;InstallLocation=$pkg.InstallLocation;UninstallString=('Remove-AppxPackage -Package '+$pkg.PackageFullName);QuietUninstallString=$null;WindowsInstaller=$null;ProductCode=$pkg.PackageFullName}
      $result.NewUninstallEntries=@($primary); $result.PrimaryKey=$primary.Key; $result.DiscoverySucceeded=$true; $result.DiscoveryMethod='MSIX/AppX package registration'; $result.UninstallValidationMethod='Remove-AppxPackage'; $result.UninstallCandidate=$primary.UninstallString
      Set-InstalledComponentEvidence
      Initialize-DetectionEvidence $primary @()
      Remove-AppxPackage -Package $pkg.PackageFullName -ErrorAction Stop; Start-Sleep 3
      if(Get-AppxPackage -PackageTypeFilter Main,Bundle | Where-Object {$_.PackageFullName -eq $pkg.PackageFullName}){throw 'MSIX/AppX package remained detected after silent uninstall.'}
      $result.InitialInstallValidated=$true; $result.InitialUninstallExitCode=0; $result.InitialUninstallValidated=$true; $result.CleanBaselineVerified=$true
      try { Add-AppxPackage @parameters; $result.SilentReinstallExitCode=0 } catch { $result.SilentReinstallExitCode=1; throw "MSIX/AppX silent reinstall failed: $($_.Exception.Message)" }
      Start-Sleep 3; $current=Get-AppxPackage -Name $packageName -PackageTypeFilter Main | Where-Object PackageFullName -eq $pkg.PackageFullName | Select-Object -First 1
      $result.SilentReinstallValidated=($null -ne $current)
      if(-not $current){throw 'MSIX/AppX package was not detected after reinstall.'}
      Remove-AppxPackage -Package $current.PackageFullName -ErrorAction Stop; $result.SilentUninstallExitCode=0; Start-Sleep 3
      $result.PostUninstallDetected=[bool](Get-AppxPackage | Where-Object {$_.Name -eq $pkg.Name})
      Complete-RoadmapRemovalEvidence
      $result.SilentUninstallValidated=-not $result.PostUninstallDetected
      if(-not $result.SilentUninstallValidated){$result.ValidationError='MSIX/AppX final removal verification did not pass.'}
    } else {
    $before=@(Get-UninstallSnapshot); $beforeKeys=@($before | ForEach-Object {$_.Key})
    if($IsLegacyProject -and @($before | Where-Object {(Test-ProjectRegistration $_) -or (Test-ProjectMsi $_)}).Count){
      throw 'Project Professional 2007 is already present. A clean Sandbox is required.'
    }
    $primary=$null; $new=@(); $p=$null
    if($RecordResponses){
      Write-Checkpoint 'Record InstallShield installation response file'
      $recordArguments=('/r /f1"'+$SetupIss+'" '+$AdditionalPackageArguments).Trim()
      $recorded=Invoke-NativeProcess $Installer $recordArguments $false $false 900 -WatchInstallPrerequisites $true
      $result.InstallerExitCode=$recorded.ExitCode
      if($recorded.TimedOut){throw 'InstallShield recording exceeded its watchdog window.'}
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
      if($IsWebView2Installer){
        if(@($result.RuntimeEnvironment | Where-Object {$_.Name -eq 'WebView2 Runtime' -and $_.State -eq 'Registered Evergreen Runtime'}).Count){
          throw 'Microsoft Edge WebView2 Runtime is already registered in the baseline. A clean guest is required for lifecycle validation.'
        }
        $probeCandidates=@((New-InstallCandidate 'Microsoft WebView2 unattended setup' $Installer '/silent /install' 'Exe' 100 'Microsoft documents /silent /install for both Evergreen installer types.'))
      }
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
        if($IsVirtualBoxReducedProfile){
          $lastAttempt=$result.SilentStrategyAttempts | Select-Object -Last 1
          $result.InstallerExitCode=$lastAttempt.ExitCode
          throw ('INSTALL FAILED: VirtualBox reduced profile did not validate. '+$lastAttempt.Outcome+' See msi-install.log and app-control-evidence.json.')
        }
        if($IsWebView2Installer){
          $lastAttempt=$result.SilentStrategyAttempts | Select-Object -Last 1
          if($null -ne $lastAttempt.ExitCode -and $lastAttempt.ExitCode -notin @(0,3010)){
            $result.InstallerExitCode=$lastAttempt.ExitCode
            $exitHex='0x{0:X8}' -f [int]$lastAttempt.ExitCode
            $updateLogs=@("$env:ProgramData\Microsoft\EdgeUpdate\Log\MicrosoftEdgeUpdate.log","$env:LOCALAPPDATA\Microsoft\EdgeUpdate\Log\MicrosoftEdgeUpdate.log")
            $updateFailure=@(foreach($log in $updateLogs){
              if(Test-Path -LiteralPath $log){
                Get-Content -LiteralPath $log -Tail 400 -ErrorAction SilentlyContinue |
                  Where-Object {$_ -match 'InstallApp returned.*F3017226-FE2A-4295-8BDF-00C3A9A7E4C5' -and $_ -like ('*'+$exitHex+'*')} |
                  Select-Object -Last 1
              }
            })
            if($updateFailure.Count){$updateFailure | Set-Content 'C:\InstallerOutput\webview2-updater-error.txt' -Encoding UTF8}
            $detail=if($updateFailure -match "couldn't create a temporary directory"){' Edge Update could not create a temporary directory.'}else{''}
            throw ('INSTALL FAILED: Microsoft Edge WebView2 Runtime setup returned '+$exitHex+' using /silent /install.'+$detail)
          }
          throw ('Microsoft Edge WebView2 Runtime did not validate with /silent /install. '+$lastAttempt.Outcome)
        }
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
      $result.SelectedSilentStrategy=$selectedProbe.Name;$result.SilentInstallCommand=if($selectedProbe.Kind -eq 'Msi'){'msiexec.exe /i "'+$selectedProbe.File+'" '+$selectedProbe.Arguments}else{'"'+$selectedProbe.File+'" '+$selectedProbe.Arguments};$SilentInstallArguments=$selectedProbe.Arguments;$EffectiveSilentInstaller=$selectedProbe.File; if($ArchiveEntry){$result.DeploymentSource=$EffectiveSilentInstaller}
      $result.InitialInstallValidated=$true
      if($result.InstallerExitCode -eq 3010){$result.RebootRequired=$true}
    } elseif($InstallerKind -in @('Unknown','Bootstrapper')){
      $launchOptions = @{}
      if ($ArchiveEntry) { $launchOptions.WorkingDirectory = Split-Path -Parent $Installer }
      $p=Start-Process -FilePath $Installer -PassThru @launchOptions
      $null=$p.Handle
      $activity=Watch-Bootstrapper $p.Id $beforeKeys
      $result.BootstrapperProcesses=@($activity.Processes); $result.DiscoveredInstallerFiles=@($activity.Files); $primary=$activity.Primary; $new=@($activity.NewEntries); $result.NewUninstallEntries=$new
      Assert-BootstrapperDiscoveryComplete $activity
      try {$p.Refresh(); if($p.HasExited){$result.InstallerExitCode=$p.ExitCode}else{$result.InstallerExitCode=-2}} catch {$result.InstallerExitCode=-2}
      if(-not $IsLegacyProject){
        $project=Find-ProjectFromArchiveDiscovery $new
        if($project){
          if(@($before | Where-Object {(Test-ProjectRegistration $_) -or (Test-ProjectMsi $_)}).Count){
            throw 'Project Professional 2007 was already present before setup. No removal was started.'
          }
          Initialize-LegacyProject
          $primary=$project
        } elseif($ArchiveEntry -and [IO.Path]::GetFileName($Installer) -eq 'setup.exe' -and
            @($new | Where-Object {(Test-ProjectRegistration $_) -or (Test-ProjectMsi $_)}).Count){
          throw 'Project setup registered only part of the expected product. No removal was started.'
        }
      }
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
      $observedSilent=if($isClickToRun -or $IsLegacyProject){$null}else{Get-ObservedSilentChild $result.BootstrapperProcesses}
      if($observedSilent){
        # The observed child proves the vendor's unattended argument grammar, but the child may
        # be ephemeral or a post-install cache executable. Reapply those arguments to the original
        # deployment source and validate that source instead of depending on the child path.
        $EffectiveSilentInstaller=$Installer; $DeploymentSource=$Installer; $SilentInstallArguments=$observedSilent.Arguments
        $result.DeploymentSource=$Installer; $result.BaseSilentArguments=$SilentInstallArguments; $result.CombinedSilentArguments=$SilentInstallArguments
        $result.SilentInstallCommand=('"'+$Installer+'" '+$SilentInstallArguments).Trim()
        $result.DiscoveryMethod='Observed silent bootstrapper arguments + original deployment source + uninstall registry'
      } elseif(-not $isClickToRun -and -not $IsLegacyProject) {
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
      $launchTime=(Get-Date).ToUniversalTime()
      $handoffSource=if($ArchiveEntry -and $InstallerKind -eq 'InstallShield'){$Installer}else{''}
      $handoffDirectory=if($handoffSource){[IO.Path]::GetDirectoryName($handoffSource)+'\'}else{''}
      $launchOptions = @{}
      if ($ArchiveEntry) { $launchOptions.WorkingDirectory = Split-Path -Parent $Installer }
      $p=Start-Process -FilePath $Installer -PassThru @launchOptions
      $tracked=New-Object 'System.Collections.Generic.HashSet[int]'; [void]$tracked.Add($p.Id)
      $births=@{}; $births[[int]$p.Id]=Get-InstallerProcessBirth $p $launchTime
      $started=Get-Date
      $clock=@{Deadline=$started.AddMinutes(10);Limit=$started.AddMinutes(50);ApplicationSeconds=600;Waiting=$false;Seen=$false}
      $finished=$false
      $lastHandoffActivity=$null
      $waitingForHandoff=$false
      while((Get-Date) -lt $clock.Deadline){
        Set-AnalysisHeartbeat 'initial-installer-wait'
        $all=Update-TrackedProcessTree $tracked $births $handoffSource $launchTime
        $prerequisite=Find-TrackedPrerequisite $all $tracked $p.Id
        Update-InstallWait $clock $prerequisite (Get-Date)
        if($p.HasExited -and -not $clock.Waiting){
          $active=Test-InitialInstallerActivity $all $tracked $p.Id $handoffDirectory
          if($active -or -not $lastHandoffActivity){$lastHandoffActivity=Get-Date}
          $handoffPending=$handoffSource -and ((Get-Date)-$lastHandoffActivity).TotalSeconds -lt 5
          if(-not $active -and -not $handoffPending){$finished=$true;break}
          if($active -and -not $waitingForHandoff){
            Write-Checkpoint 'Waiting for installer handoff to finish'
            $waitingForHandoff=$true
          }
        }
        Start-Sleep -Seconds 1
      }
      if(-not $finished){
        $visible=@()
        try {
          $visible=@((Get-DesktopWindowSnapshot).Values | Where-Object {
            $tracked.Contains([int]$_.Pid) -and -not (Test-IgnoredDesktopWindow $_)
          })
          foreach($window in $visible){Record-InstallerUiEvidence $window $tracked}
          Write-DebugEvent 'Installer windows at watchdog timeout' @($visible | ForEach-Object {
            [PSCustomObject]@{ProcessId=$_.Pid;Title=$_.Title}
          })
        }catch{}
        if($visible.Count -gt 0){
          throw 'INSTALL TIMEOUT: Setup still had a visible installer window. Check the Sandbox desktop for a prompt during the next run.'
        }
        throw 'INSTALL TIMEOUT: Setup did not complete within its watchdog window.'
      }
      $result.InstallerExitCode=$p.ExitCode
      for($i=0;$i -lt 12 -and -not $primary;$i++){
        Start-Sleep 3; $after=@(Get-UninstallSnapshot); $new=@($after | Where-Object {$_.Key -notin $beforeKeys}); $primary=Select-Primary $new
        if(-not $primary -and $InstallerKind -eq 'Squirrel'){$primary=Find-SquirrelApplication}
      }
    }
    $result.NewUninstallEntries=$new
    Set-InstalledComponentEvidence
    if(-not $primary){ throw 'Installer completed, but no primary application could be identified after registry and installer-specific discovery.' }
    if($IsLegacyProject -and ($result.InstallerExitCode -notin @(0,3010) -or -not @($new | Where-Object {Test-ProjectMsi $_}).Count)){
      throw 'Project 2007 setup did not successfully register both the Project suite and its product MSI. No removal was started.'
    }
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
    Test-VirtualBoxDriverState 'Initial install' $true
    Write-Checkpoint 'Discovery complete'

    Write-Checkpoint 'Build uninstall candidate'
    $initialUninstallDone=$false
    $uninstallCommand=if($IsLegacyProject){
      $result.UninstallValidationMethod='Project 2007 Setup /uninstall PRJPRO'
      Get-SilentUninstallCandidates $primary
    }else{Get-InnoUninstallCommand ([string]$primary.QuietUninstallString)}
    if(-not $uninstallCommand){$uninstallCommand=Normalize-QSetupUninstallCommand ([string]$primary.QuietUninstallString)}
    if([string]::IsNullOrWhiteSpace($uninstallCommand)){$uninstallCommand=Get-MsiUninstallCommand $primary; if($uninstallCommand){$result.UninstallCandidate=$uninstallCommand;$result.UninstallValidationMethod='MSI ProductCode /x /qn /norestart'}}
    if([string]::IsNullOrWhiteSpace($uninstallCommand)){$uninstallCommand=Get-InnoUninstallCommand ([string]$primary.UninstallString); if($uninstallCommand){$result.UninstallCandidate=$uninstallCommand;$result.UninstallValidationMethod='Inno Setup silent uninstaller'}}
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
        $uninstallTimeout=if([IO.Path]::GetFileName($parts[0]) -in @('msiexec','msiexec.exe')){900}else{300}
        $initialExecution=Invoke-NativeProcess $parts[0] $executionArguments $true $true $uninstallTimeout
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
      Test-VirtualBoxDriverState 'Initial uninstall' $false
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
      $result.BaseSilentArguments=$SilentInstallArguments; $result.CombinedSilentArguments=$SilentInstallArguments; if($ArchiveEntry){$result.DeploymentSource=$EffectiveSilentInstaller}
      Test-VirtualBoxDriverState 'Reinstall' $true
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
          # MSI can spend several minutes removing shared assemblies after reinstall.
          $uninstallTimeout=if([IO.Path]::GetFileName($parts2[0]) -in @('msiexec','msiexec.exe')){900}else{300}
          $u2=Invoke-NativeProcess $parts2[0] $executionArguments $true $true $uninstallTimeout
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
          if(-not $result.PostUninstallDetected){
            Test-VirtualBoxDriverState 'Final uninstall' $false
            if($IsVirtualBoxReducedProfile){$result['VirtualBoxDriverCleanupVerified']=$true}
            Complete-RoadmapRemovalEvidence
            break
          }
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
            ["__ANALYZER_VERSION__"] = UpdateService.CurrentDisplayVersion.Replace("'", "''"),
            ["__PROJECT_CONFIG__"] = Project2007Deployment.Configuration.Replace("'", "''"),
            ["__ARCHIVE_ENTRY__"] = archive is null ? "" : Convert.ToBase64String(Encoding.UTF8.GetBytes(archive.Entry)),
            ["__ARCHIVE_HASH__"] = archive?.Sha256 ?? "",
            ["__ADDITIONAL_ARGS__"] = additional, ["__BLOCK_MCAFEE__"] = blockMcAfee,
            ["__SANDBOX_COMPATIBILITY__"] = installerCompatibility ? "$true" : "$false",
            ["__COMPONENT_PLAN__"] = componentPlan is null ? "" : Convert.ToBase64String(System.Text.Json.JsonSerializer.SerializeToUtf8Bytes(componentPlan)),
            ["__RECORD_RESPONSES__"] = recordResponses ? "$true" : "$false",
            ["__ISS_DIALOG_SEQUENCE__"] = InstallShieldResponseFormat.HeaderlessDialogSequence,
            ["__SILENT_ONLY__"] = silentOnlyValue, ["__ROADMAP_HELPERS__"] = RoadmapEvidenceScript.Replace("__MSI_METADATA__", encodedMsiMetadata) + Environment.NewLine + DetailedDetectionEvidenceScript + Environment.NewLine + RuntimeEnvironmentEvidenceScript + Environment.NewLine + NetFx3ProvisioningScript + Environment.NewLine + GintPrerequisiteScript + Environment.NewLine + SandboxCompatibilityScript + Environment.NewLine + MsiIdentityEvidenceScript + Environment.NewLine + PrerequisiteFileEvidenceScript + Environment.NewLine + PrerequisiteServiceEvidenceScript + Environment.NewLine + DllEvidenceScript + Environment.NewLine + AppControlEvidenceScript + Environment.NewLine + PayloadTraceEvidenceScript.Replace("__TRACE_WORKER_B64__", Convert.ToBase64String(Encoding.UTF8.GetBytes(PayloadTraceWorkerScript))),
            ["__REQUIRED_PRIMARY__"] = Convert.ToBase64String(Encoding.UTF8.GetBytes(requiredPrimaryProduct)), ["__NETFX_EVIDENCE__"] = Convert.ToBase64String(Encoding.UTF8.GetBytes(netFxRequirement)), ["__MSI_METADATA__"] = encodedMsiMetadata
        };
        // One pass prevents token-shaped installer names/arguments being substituted as code.
        return System.Text.RegularExpressions.Regex.Replace(script, "__(?:INSTALLER|ANALYZER_VERSION|PROJECT_CONFIG|ARCHIVE_ENTRY|ARCHIVE_HASH|KIND|BASE_ARGS|ADDITIONAL_ARGS|BLOCK_MCAFEE|SILENT_ONLY|RECORD_RESPONSES|ISS_DIALOG_SEQUENCE|ROADMAP_HELPERS|MSI_METADATA|NETFX_EVIDENCE|REQUIRED_PRIMARY|SANDBOX_COMPATIBILITY|COMPONENT_PLAN)__", match => values[match.Value]);
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

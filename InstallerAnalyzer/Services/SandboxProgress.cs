using System.IO;
using System.Text.Json;

namespace InstallerAnalyzer.Services;

internal sealed class SandboxProgress
{
    public string Phase { get; set; } = "";
    public string? Prerequisite { get; set; }
    public bool ApplicationTimerPaused { get; set; }
    public DateTimeOffset CapturedAt { get; set; }
    public double? RemainingSeconds { get; set; }
    public double? PhaseElapsedSeconds { get; set; }

    internal static SandboxProgress? Read(SandboxIssSession session)
    {
        var path = Path.Combine(session.OutputFolder, "analysis-progress.json");
        if (!File.Exists(path)) return null;
        try
        {
            return JsonSerializer.Deserialize<SandboxProgress>(AnalysisArtifactReader.ReadText(path, 32768),
                new JsonSerializerOptions { PropertyNameCaseInsensitive = true });
        }
        catch (Exception ex) when (ex is IOException or UnauthorizedAccessException or JsonException) { return null; }
    }

    internal string Describe(DateTimeOffset now)
    {
        var age = Math.Max(0, (now - CapturedAt).TotalSeconds);
        if (age > 15) return Phase + " · Waiting for a fresh progress report";
        var elapsed = PhaseElapsedSeconds is >= 0 and < 86400 ? " · " + Duration(PhaseElapsedSeconds.Value + age) + " elapsed" : "";
        var remaining = RemainingSeconds is >= 0 and < 86400 ? " · " + Duration(Math.Max(0, RemainingSeconds.Value - age)) + " remaining" : "";
        return Phase + elapsed + remaining;
    }

    internal string PauseDescription => ApplicationTimerPaused
        ? "Application timer paused while " + (string.IsNullOrWhiteSpace(Prerequisite) ? "a prerequisite installs." : Prerequisite + " installs.")
        : "";
    internal static string Duration(double seconds) => TimeSpan.FromSeconds(Math.Clamp(seconds, 0, 86400)).ToString(@"hh\:mm\:ss");
}

public static partial class SandboxIssRecorder
{
    private const string LiveProgressScript = """
$script:ProgressWrittenAt=[datetime]::MinValue
$script:ProgressSignature=''
function Write-TimerProgress([string]$phase,$clock,$prerequisite=$null) {
  try {
    $now=Get-Date
    $name=if($prerequisite){[string]$prerequisite.Name}else{''}
    $signature=$phase+'|'+[string]$clock.Waiting+'|'+$name
    if($clock.ProgressSignature -ne $signature){$clock.ProgressSignature=$signature;$clock.ProgressStartedAt=$now}
    if($script:ProgressSignature -eq $signature -and ($now-$script:ProgressWrittenAt).TotalSeconds -lt 1){return}
    $script:ProgressSignature=$signature;$script:ProgressWrittenAt=$now
    $remaining=[Math]::Max(0,($clock.Deadline-$now).TotalSeconds)
    Write-JsonAtomic 'C:\InstallerOutput\analysis-progress.json' ([ordered]@{
      Phase=if($clock.Waiting){'Prerequisite setup'}else{$phase}
      Prerequisite=$name;ApplicationTimerPaused=[bool]$clock.Waiting
      CapturedAt=([DateTimeOffset]::Now.ToString('o'))
      RemainingSeconds=$remaining;PhaseElapsedSeconds=[Math]::Max(0,($now-$clock.ProgressStartedAt).TotalSeconds)
    })
  }catch{}
}
function Write-PhaseProgress([string]$phase) {
  try {
    $script:ProgressSignature=''
    Write-JsonAtomic 'C:\InstallerOutput\analysis-progress.json' ([ordered]@{
      Phase=$phase;Prerequisite='';ApplicationTimerPaused=$false
      CapturedAt=([DateTimeOffset]::Now.ToString('o'));RemainingSeconds=$null;PhaseElapsedSeconds=0
    })
  }catch{}
}
""";
}

using System.ComponentModel;
using System.Text.Json;

namespace InstallerAnalyzer.Services;

public sealed record TimeoutDefinition(string Key, string Label, int DefaultSeconds, int MinimumSeconds, int MaximumSeconds, int StepSeconds);

public sealed class TimeoutSettings
{
    public bool Enabled { get; set; }
    public Dictionary<string, int> Seconds { get; set; } = new();
    public static TimeoutSettings Current { get; set; } = new();
    public static IReadOnlyList<TimeoutDefinition> Definitions { get; } = new TimeoutDefinition[]
    {
        new("Startup", "Sandbox startup", 180, 30, 900, 15),
        new("StartupRetry", "Startup retry pause", 5, 1, 60, 1),
        new("Session", "Entire Sandbox session", 3600, 300, 14400, 60),
        new("Inactivity", "Sandbox inactivity", 720, 60, 3600, 30),
        new("Discovery", "Standard installer discovery", 600, 60, 7200, 60),
        new("Bootstrapper", "Bootstrapper discovery", 900, 60, 7200, 60),
        new("Operation", "Installation operation ceiling", 3000, 300, 10800, 60),
        new("Prerequisite", "Prerequisite wait", 900, 60, 7200, 60),
        new("MainMsi", "Bootstrapper main MSI", 900, 60, 7200, 60),
        new("MainMsiCeiling", "Main MSI handoff ceiling", 1800, 300, 10800, 60),
        new("Settle", "Bootstrapper settling", 60, 5, 300, 5),
        new("SilentInstall", "Silent install candidate", 600, 60, 7200, 60),
        new("Odis", "Autodesk ODIS installation", 3000, 300, 10800, 60),
        new("RecordInstall", "InstallShield install recording", 900, 60, 7200, 60),
        new("ReplayInstall", "InstallShield replay install", 1200, 60, 7200, 60),
        new("RecordUninstall", "InstallShield uninstall recording", 900, 60, 7200, 60),
        new("Uninstall", "Executable uninstall", 300, 30, 3600, 30),
        new("MsiUninstall", "MSI / ODIS uninstall", 900, 60, 7200, 60),
        new("UninstallProbe", "Uninstall candidate", 120, 15, 900, 15),
        new("ProcessCleanup", "Process cleanup", 30, 5, 300, 5),
        new("Absence", "Removal verification", 60, 15, 600, 3),
        new("NetFxQuery", "NET 3.5 query / verification", 30, 10, 300, 5),
        new("NetFxDownload", "NET 3.5 source download", 150, 30, 900, 15),
        new("NetFxRequest", "NET 3.5 download request / read", 15, 5, 120, 5),
        new("NetFxInstall", "NET 3.5 package staging / enabling", 600, 60, 3600, 60),
        new("GintStep", "gINT deployment step", 600, 60, 3600, 60),
        new("GintTotal", "gINT deployment total", 1800, 300, 10800, 60),
        new("Datto", "Datto job recommendation", 1200, 60, 14400, 60),
        new("DattoGint", "Datto gINT job recommendation", 2400, 300, 14400, 60),
        new("Ai", "AI assistant request", 180, 15, 900, 15),
        new("UpdateRequest", "Update HTTP request", 20, 5, 300, 5),
        new("UpdateDownload", "Update download / verification", 600, 60, 3600, 60),
        new("Signature", "Installer signature inspection", 12, 5, 120, 1),
    };

    public int GetSeconds(string key)
    {
        var definition = Definitions.First(d => d.Key == key);
        return Enabled && Seconds is not null && Seconds.TryGetValue(key, out var value)
            ? Math.Clamp(value, definition.MinimumSeconds, definition.MaximumSeconds)
            : definition.DefaultSeconds;
    }

    public TimeSpan Duration(string key) => TimeSpan.FromSeconds(GetSeconds(key));
    public TimeoutSettings Snapshot() => new()
    {
        Enabled = Enabled,
        Seconds = Definitions.ToDictionary(d => d.Key, d => GetSeconds(d.Key))
    };
    internal string ToJson() => JsonSerializer.Serialize(Definitions.ToDictionary(d => d.Key, d => GetSeconds(d.Key)));
}

public sealed class TimeoutSettingRow : INotifyPropertyChanged
{
    public TimeoutDefinition Definition { get; }
    private double _seconds;
    public TimeoutSettingRow(TimeoutDefinition definition, int seconds) { Definition = definition; _seconds = seconds; }
    public double Seconds
    {
        get => _seconds;
        set
        {
            var bounded = Math.Clamp(Math.Round(value), Definition.MinimumSeconds, Definition.MaximumSeconds);
            if (_seconds == bounded) return;
            _seconds = bounded;
            PropertyChanged?.Invoke(this, new PropertyChangedEventArgs(nameof(Seconds)));
            PropertyChanged?.Invoke(this, new PropertyChangedEventArgs(nameof(Display)));
        }
    }
    public string Display => Seconds >= 60
        ? $"{(int)Seconds / 60} min" + ((int)Seconds % 60 == 0 ? "" : $" {(int)Seconds % 60} sec")
        : $"{(int)Seconds} sec";
    public event PropertyChangedEventHandler? PropertyChanged;
}

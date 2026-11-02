using System.IO;
using System.Xml.Linq;
using InstallerAnalyzer.Models;
using InstallerAnalyzer.Services;

internal static class PayloadTraceChecks
{
    public sealed class FakeRecord(string xml) : IDisposable
    {
        public bool Disposed { get; private set; }
        public string ToXml() => xml;
        public void Dispose() => Disposed = true;
    }
    public sealed class FakeReader(params FakeRecord[] records)
    {
        private int index;
        public FakeRecord? ReadEvent() => index < records.Length ? records[index++] : null;
    }
    private const string Birth = "2026-10-28T10:00:00.0000000Z";
    private const string FileProvider = "Microsoft-Windows-Kernel-File";
    private const string ProcessProvider = "Microsoft-Windows-Kernel-Process";
    private static string Event(string provider, int id, int tick, params (string Key, string Value)[] fields)
    {
        XNamespace ns = "http://schemas.microsoft.com/win/2004/08/events/event";
        return new XElement(ns + "Event", new XElement(ns + "System", new XElement(ns + "Provider", new XAttribute("Name", provider)),
            new XElement(ns + "EventID", id), new XElement(ns + "TimeCreated", new XAttribute("SystemTime", DateTimeOffset.Parse(Birth).AddMilliseconds(tick).ToString("o"))),
            new XElement(ns + "Execution", new XAttribute("ProcessID", 999), new XAttribute("ThreadID", 999))),
            new XElement(ns + "EventData", fields.Select(f => new XElement(ns + "Data", new XAttribute("Name", f.Key), f.Value)))).ToString();
    }
    private static PayloadTraceReducer Ready()
    {
        var r = new PayloadTraceReducer(); r.AddDrive(@"\Device\HarddiskVolume2", "C:"); r.AddScope(42, Birth, "setup.exe");
        r.Add(Event(ProcessProvider, 1, 0, ("ProcessID", "42"), ("CreateTime", Birth)));
        r.Add(Event(ProcessProvider, 3, 1, ("ProcessID", "42"), ("ThreadID", "43")));
        return r;
    }
    private static void Open(PayloadTraceReducer r, int tick = 2, string path = @"\Device\HarddiskVolume2\Temp\payload.msi", string thread = "43") =>
        r.Add(Event(FileProvider, 12, tick, ("IssuingThreadId", thread), ("FileObject", "0x123"), ("FileName", path), ("Irp", "0x999")));
    private static void Write(PayloadTraceReducer r, int tick = 3, string thread = "43") =>
        r.Add(Event(FileProvider, 16, tick, ("IssuingThreadId", thread), ("FileObject", "0x123"), ("Irp", "0x456"), ("IOSize", "0x10")));
    private static void Complete(PayloadTraceReducer r, int tick = 4, string status = "0", string bytes = "0x10") =>
        r.Add(Event(FileProvider, 24, tick, ("Irp", "0x456"), ("Status", status), ("ExtraInformation", bytes)));
    public static void Run(string root, Action<bool, string> check)
    {
        var r = Ready(); Open(r); Write(r);
        check(r.Result.Files.Count == 0, "Write requests alone do not establish completed payload writes");
        Complete(r);
        check(r.Result.Files.Single().Path == @"C:\Temp\payload.msi" && r.Result.Files[0].ProcessId == 42 && r.Result.Files[0].Bytes == 16,
            "Kernel open, issuing thread, process lifetime and successful completion establish a file writer");
        check(r.Result.Files[0].ProcessId != 999, "Worker-thread event header PID does not override the issuing thread owner");
        r = Ready(); Open(r); Write(r); Complete(r, status: "0xc0000022");
        check(r.Result.Files.Count == 0, "Failed file operations do not become completed writes");
        r = Ready(); Open(r); Write(r); Complete(r, bytes: "0x11");
        check(r.Result.Files.Count == 0, "Completion byte count cannot exceed the requested write size");
        r = Ready(); Open(r); Write(r); Complete(r, tick: 40000);
        check(r.Result.Files.Count == 0, "Expired IRP correlations are rejected");
        r = Ready(); Open(r); Write(r, thread: "99"); Complete(r);
        check(r.Result.Files.Count == 0, "Unknown issuing threads remain unattributed");
        r = Ready(); Open(r); r.Add(Event(ProcessProvider, 1, 3, ("ProcessID", "42"), ("CreateTime", DateTimeOffset.Parse(Birth).AddMilliseconds(3).ToString("o")))); Write(r, 4); Complete(r, 5);
        check(r.Result.Files.Count == 0, "Reused PIDs cannot inherit an earlier installer process scope");
        r = Ready(); Open(r); r.Add(Event(ProcessProvider, 4, 3, ("ProcessID", "42"), ("ThreadID", "43"))); Write(r, 4); Complete(r, 5);
        check(r.Result.Files.Count == 0, "Terminated thread identity is not reused for file attribution");
        r = Ready(); Open(r); Open(r, 3, thread: "99"); Write(r, 4); Complete(r, 5);
        check(r.Result.Files.Count == 0, "File-object reuse by an unscoped opener invalidates prior attribution");
        r = Ready(); Open(r); Write(r); r.Add(Event(FileProvider, 12, 4, ("Irp", "0x456"))); Complete(r, 5);
        check(r.Result.Files.Count == 0, "An IRP reused for another operation cannot complete an old write");
        r = Ready(); Open(r); r.Add(Event(FileProvider, 14, 3, ("FileObject", "0x123"))); Write(r, 4); Complete(r, 5);
        check(r.Result.Files.Count == 0, "File cleanup invalidates its file-object path mapping");
        foreach (var path in new[] { @"\Device\HarddiskVolume99\Temp\payload.msi", @"C:\InstallerInput\source.msi", @"C:\Temp\secret.txt", @"\\server\share\payload.msi", @"C:\Temp\..\payload.msi" })
        {
            r = Ready(); Open(r, path: path); Write(r); Complete(r);
            check(r.Result.Files.Count == 0, "Trace filters exclude unsafe or irrelevant path: " + path);
        }
        r = Ready(); Open(r); Write(r); Complete(r, 2);
        check(r.Result.Files.Count == 0 && r.Result.Status.Contains("Out-of-order"), "Out-of-order trace records clear stale correlation state");
        r.Add("<!DOCTYPE Event [<!ENTITY x 'expanded'>]><Event>&x;</Event>");
        check(r.Result.Status.Contains("Malformed"), "Trace XML forbids DTD and entity expansion");
        r = Ready(); Open(r); Write(r); Complete(r);
        var proof = new InstallAnalysis { PayloadTrace = r.Result, ProcessTree = [new() { ProcessId = 42, CreatedAt = Birth, Name = "setup.exe" }] };
        proof.NetworkActivity.Add(new() { ProcessId = 42, ProcessCreatedAt = Birth, Evidence = "Established TCP connection" });
        IntelligenceReportService.Enrich(proof, null, null);
        check(proof.Intelligence.Payloads.Single().Writes.Count == 1 && proof.Intelligence.Payloads[0].Executed is null,
            "Trace-only temporary payloads retain their writer without fabricated execution");
        check(proof.Intelligence.Payloads[0].NetworkActiveWriterProcessIds.SequenceEqual(new[] { 42 }) && proof.Intelligence.Payloads[0].Evidence.Contains("download is not established"),
            "Network-active writers are candidates without fabricated download success");
        check(proof.Intelligence.Edges.Any(e => e.Relationship == "Completed file write (kernel trace)"), "Relationship graph carries measured writer attribution");
        proof.NetworkActivity[0].ProcessCreatedAt = DateTimeOffset.Parse(Birth).AddMinutes(1).ToString("o");
        IntelligenceReportService.Enrich(proof, null, null);
        check(proof.Intelligence.Payloads[0].NetworkActiveWriterProcessIds.Count == 0, "Connections from another PID lifetime cannot attach to a file writer");
        var folder = Path.Combine(root, "trace-artifacts"); Directory.CreateDirectory(folder);
        IntelligenceReportService.WriteArtifacts(proof, null, folder);
        check(File.ReadAllText(Path.Combine(folder, "payload-file-activity.json")).Contains("Write completed"), "Filtered trace evidence is retained in normalized diagnostic artifacts");
        var complete = new InstallAnalysis { ValidationSchemaVersion = 3, EvidenceCollectionComplete = true,
            CapturedAt = DateTimeOffset.UtcNow.ToString("o"), DiscoverySucceeded = true, PrimaryKey = "fixture",
            NewUninstallEntries = [new() { Key = "fixture", DisplayName = "Fixture" }],
            InitialInstallValidated = true, InitialUninstallValidated = true, InitialUninstallExitCode = 0, CleanBaselineVerified = true,
            SilentReinstallValidated = true, SilentReinstallExitCode = 0, SilentUninstallValidated = true, SilentUninstallExitCode = 0, PostUninstallDetected = false,
            PayloadTrace = new() { Status = "Unavailable" } };
        check(LifecycleValidationService.IsComplete(complete), "Unavailable optional tracing does not invalidate an independently completed lifecycle");
        complete.EvidenceCollectionComplete = false;
        check(!LifecycleValidationService.IsComplete(complete), "Writer evidence cannot bypass final evidence-completion gating");
        var record = new FakeRecord(Event(ProcessProvider, 1, 0, ("ProcessID", "42"), ("CreateTime", Birth)));
        var reader = new FakeReader(record); var checkpoints = 0; r = new PayloadTraceReducer();
        r.Read(reader, 1000, 10, () => checkpoints++);
        check(record.Disposed && r.Result.EventsRead == 1 && checkpoints == 1, "Bounded native reader loop disposes event records and commits a final checkpoint");
        record = new FakeRecord("<Event />"); r = new PayloadTraceReducer(); r.Read(new FakeReader(record), 1000, 1, null!);
        check(record.Disposed && r.Result.Status.Contains("Event limit"), "Native trace reader enforces its event budget");
        record = new FakeRecord("<Event />"); r = new PayloadTraceReducer(); r.Read(new FakeReader(record), 0, 10, null!);
        check(!record.Disposed && r.Result.EventsRead == 0 && r.Result.Status.Contains("time limit"), "Native trace reader stops before consuming records once its time budget expires");
        var sharedPath = Path.Combine(root, "shared-checkpoint.json");
        File.WriteAllText(sharedPath, "{\"stage\":\"writing\"}");
        using (var writer = new FileStream(sharedPath, FileMode.Open, FileAccess.ReadWrite, FileShare.ReadWrite | FileShare.Delete))
            check(AnalysisArtifactReader.ReadText(sharedPath).Contains("writing"), "Analysis reads succeed while the guest retains a write-sharing handle");
        using (var locked = new FileStream(sharedPath, FileMode.Open, FileAccess.ReadWrite, FileShare.None))
        {
            var clock = System.Diagnostics.Stopwatch.StartNew(); var denied = false;
            try { AnalysisArtifactReader.ReadText(sharedPath); } catch (IOException) { denied = true; }
            check(denied && clock.Elapsed < TimeSpan.FromSeconds(1), "Exclusively locked analysis reads fail within a bounded retry budget");
        }
        var oversized = false;
        try { AnalysisArtifactReader.ReadText(sharedPath, 4); } catch (InvalidDataException) { oversized = true; }
        check(oversized, "Growing or oversized analysis text cannot exceed the reader character budget");
    }
}

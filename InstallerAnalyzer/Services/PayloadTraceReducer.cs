// Also compiled by Windows PowerShell inside Sandbox. Keep this source compatible with C# 5.
#nullable disable
using System;
using System.Collections.Generic;
using System.Globalization;
using System.IO;
using System.Linq;
using System.Xml.Linq;

namespace InstallerAnalyzer.Models
{
    public sealed class BitsFileMapping
    {
        public string JobId { get; set; }
        public int ProcessId { get; set; }
        public string ProcessCreatedAt { get; set; }
        public string Process { get; set; }
        public string Path { get; set; }
        public string RequestedOrigin { get; set; }
        public string ObservedAt { get; set; }
        public string Evidence { get; set; }
        public string CompletionStatus { get; set; }
    }
    public sealed class BitsDownloadEvidence
    {
        public string JobId { get; set; }
        public int ProcessId { get; set; }
        public string ProcessCreatedAt { get; set; }
        public string Process { get; set; }
        public string Path { get; set; }
        public string RequestedOrigin { get; set; }
        public string TransferredObservedAt { get; set; }
        public string CompletionObservedAt { get; set; }
        public long BytesReported { get; set; }
        public string FileSnapshotStatus { get; set; }
        public string FileObservedAt { get; set; }
        public string Sha256 { get; set; }
        public string Evidence { get; set; }
    }
    public sealed class PayloadFileActivity
    {
        public int ProcessId { get; set; }
        public string ProcessCreatedAt { get; set; }
        public string Process { get; set; }
        public string Path { get; set; }
        public string Operation { get; set; }
        public string ObservedAt { get; set; }
        public long Bytes { get; set; }
        public string Evidence { get; set; }
    }
    public sealed class PayloadTraceCapture
    {
        public string Status { get; set; }
        public string Limitation { get; set; }
        public int EventsRead { get; set; }
        public List<PayloadFileActivity> Files { get; set; }
        public List<BitsFileMapping> BitsMappings { get; set; }
        public List<BitsDownloadEvidence> BitsDownloads { get; set; }
        public string BitsObservationStatus { get; set; }
        public int BitsSampleAttempts { get; set; }
        public int BitsTransferredSamples { get; set; }
        public int BitsCompletionSignals { get; set; }
        public PayloadTraceCapture()
        {
            Status = "Not collected"; Limitation = "Missing events never establish absence of file activity.";
            Files = new List<PayloadFileActivity>();
            BitsMappings = new List<BitsFileMapping>();
            BitsDownloads = new List<BitsDownloadEvidence>();
            BitsObservationStatus = "No read-only job samples collected; missing evidence does not establish absence.";
        }
    }
}

namespace InstallerAnalyzer.Services
{
    using InstallerAnalyzer.Models;

    // Consumes manifest events and read-only job samples as data. No file access, job mutation or code evaluation.
    public sealed class PayloadTraceReducer
    {
        private sealed class Owner
        {
            public int Pid; public DateTime Birth; public string Name;
            public string Key { get { return Pid + "|" + Birth.Ticks; } }
        }
        private sealed class OpenFile { public Owner Owner; public string Path; }
        private sealed class PendingWrite { public OpenFile File; public DateTime Time; public long Requested; }
        private sealed class BitsSample { public string Path, RemoteKey; public DateTime Time; public long Bytes; }
        private sealed class BitsBinding { public BitsFileMapping Mapping; public string RemoteKey, Owner; public DateTime Time; }
        private sealed class BitsComplete { public DateTime Time; public long Bytes, Count; public string Owner; }
        private readonly Dictionary<string, BitsSample> bitsSamples = new Dictionary<string, BitsSample>();
        private readonly Dictionary<string, string> bitsSampleReasons = new Dictionary<string, string>();
        private readonly Dictionary<string, BitsBinding> bitsBindings = new Dictionary<string, BitsBinding>();
        private readonly Dictionary<string, BitsComplete> bitsComplete = new Dictionary<string, BitsComplete>();
        private readonly Dictionary<string, string> bitsSignatures = new Dictionary<string, string>();
        private readonly HashSet<string> bitsInvalid = new HashSet<string>();
        private bool bitsOrderInvalid;
        private readonly Dictionary<int, List<Owner>> seeds = new Dictionary<int, List<Owner>>();
        private readonly Dictionary<int, Owner> active = new Dictionary<int, Owner>();
        private readonly Dictionary<int, Owner> threads = new Dictionary<int, Owner>();
        private readonly Dictionary<string, OpenFile> files = new Dictionary<string, OpenFile>();
        private readonly Dictionary<string, PendingWrite> writes = new Dictionary<string, PendingWrite>();
        private readonly Dictionary<string, string> drives = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase);
        private readonly HashSet<string> seen = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
        private DateTime previous;
        public PayloadTraceCapture Result { get; private set; }
        public PayloadTraceReducer() { Result = new PayloadTraceCapture(); Result.Status = "Collected; coverage may be incomplete"; }
        public void AddDrive(string device, string drive) { drives[device.TrimEnd('\\')] = drive.TrimEnd('\\'); }
        public void AddScope(int pid, string birth, string name)
        {
            DateTime created;
            if (!DateTime.TryParse(birth, CultureInfo.InvariantCulture, DateTimeStyles.RoundtripKind, out created)) return;
            List<Owner> list;
            if (!seeds.TryGetValue(pid, out list)) { list = new List<Owner>(); seeds.Add(pid, list); }
            list.Add(new Owner { Pid = pid, Birth = created.ToUniversalTime(), Name = name });
        }
        private static string Value(Dictionary<string, string> data, string name)
        { string value; return data.TryGetValue(name, out value) ? value : ""; }
        private static long Number(string value)
        {
            long result;
            if (value.StartsWith("0x", StringComparison.OrdinalIgnoreCase))
                return long.TryParse(value.Substring(2), NumberStyles.HexNumber, CultureInfo.InvariantCulture, out result) ? result : -1;
            return long.TryParse(value, NumberStyles.Integer, CultureInfo.InvariantCulture, out result) ? result : -1;
        }
        private static string RemoteKey(Uri remote)
        {
            using (var sha = System.Security.Cryptography.SHA256.Create())
                return BitConverter.ToString(sha.ComputeHash(System.Text.Encoding.UTF8.GetBytes(remote.AbsoluteUri)));
        }
        private void InvalidateBits(string key)
        {
            if (bitsInvalid.Count >= 1024) { bitsOrderInvalid = true; Result.BitsObservationStatus = "BITS evidence key limit reached; completion attribution withheld."; return; }
            bitsInvalid.Add(key);
        }
        public void ObserveBits(string jobId, string direction, string state, string path, string remoteName,
            string total, string transferred, int fileCount, bool filesComplete, string observedAt)
        {
            Result.BitsSampleAttempts++;
            Guid id; Uri remote; DateTime time;
            if (!Guid.TryParse(jobId, out id) || id == Guid.Empty) return;
            var key = id.ToString("D");
            if (bitsSampleReasons.Count < 256) bitsSampleReasons[key] = "No complete transferred sample.";
            if (bitsSamples.Count >= 256 && !bitsSamples.ContainsKey(key)) { InvalidateBits(key); return; }
            if (direction != "Download" || fileCount > 1 || state == "Cancelled") { InvalidateBits(key); return; }
            if (fileCount != 1) return;
            path = LocalPath(path);
            if (path == null || !Uri.TryCreate(remoteName, UriKind.Absolute, out remote) || (remote.Scheme != "http" && remote.Scheme != "https")) { if(bitsSampleReasons.ContainsKey(key)) bitsSampleReasons[key]="Unsupported local path or source URI."; return; }
            var bytes = Number(total); var completed = Number(transferred);
            if (!DateTime.TryParse(observedAt, CultureInfo.InvariantCulture, DateTimeStyles.RoundtripKind, out time)) { if(bitsSampleReasons.ContainsKey(key)) bitsSampleReasons[key]="Invalid sample timestamp."; return; }
            var signature = RemoteKey(remote); BitsSample prior;
            if (bitsSamples.TryGetValue(key, out prior) && (!string.Equals(prior.Path,path,StringComparison.OrdinalIgnoreCase) || prior.RemoteKey != signature || prior.Bytes != bytes)) InvalidateBits(key);
            if (state != "Transferred" || !filesComplete || bytes < 0 || completed != bytes) { if(bitsSampleReasons.ContainsKey(key)) bitsSampleReasons[key]="State="+state+"; complete file counts="+filesComplete+"; known byte count="+(bytes>=0)+"; byte counts equal="+(completed==bytes)+"."; return; }
            if (prior == null) bitsSamples[key] = new BitsSample { Path = path, RemoteKey = signature, Bytes = bytes, Time = time.ToUniversalTime() };
        }
        public void FinishBits()
        {
            Result.BitsDownloads.Clear();
            Result.BitsTransferredSamples = bitsSamples.Count; Result.BitsCompletionSignals = bitsComplete.Count;
            foreach (var mapping in Result.BitsMappings) mapping.CompletionStatus = "Completion not established; missing or incomplete evidence.";
            if (bitsOrderInvalid) { foreach (var mapping in Result.BitsMappings) mapping.CompletionStatus = "Event ordering or evidence limit prevents completion attribution."; return; }
            foreach (var pair in bitsBindings.Take(64))
            {
                BitsSample sample; BitsComplete complete; var binding = pair.Value; var mapping = binding.Mapping;
                if (bitsInvalid.Contains(pair.Key)) { mapping.CompletionStatus = "Conflicting mapping, cancellation, ownership change or unsupported job shape."; continue; }
                if (!bitsSamples.TryGetValue(pair.Key, out sample)) { string reason; mapping.CompletionStatus = "No eligible read-only Download/Transferred file sample observed. " + (bitsSampleReasons.TryGetValue(pair.Key,out reason)?reason:""); continue; }
                if (!bitsComplete.TryGetValue(pair.Key, out complete)) { mapping.CompletionStatus = "No matching service completion signal observed."; continue; }
                if (
                    !string.Equals(sample.Path,mapping.Path,StringComparison.OrdinalIgnoreCase) || sample.RemoteKey != binding.RemoteKey || sample.Bytes != complete.Bytes || complete.Count != 1 ||
                    string.IsNullOrEmpty(binding.Owner) || !string.Equals(binding.Owner, complete.Owner, StringComparison.OrdinalIgnoreCase) ||
                    sample.Time < binding.Time || sample.Time > complete.Time || complete.Time < binding.Time) { mapping.CompletionStatus = "Source/path/owner/byte counts or observation timing did not match."; continue; }
                mapping.CompletionStatus = "BITS download completion reported; local snapshot and content identity remain separate.";
                Result.BitsDownloads.Add(new BitsDownloadEvidence { JobId = pair.Key, ProcessId = mapping.ProcessId, ProcessCreatedAt = mapping.ProcessCreatedAt,
                    Process = mapping.Process, Path = mapping.Path, RequestedOrigin = mapping.RequestedOrigin, TransferredObservedAt = sample.Time.ToString("o"),
                    CompletionObservedAt = complete.Time.ToString("o"), BytesReported = complete.Bytes, FileSnapshotStatus = "Not measured",
                    Evidence = "Read-only single-file Download job observed Transferred with complete job byte/file counts; matching BITS event 16403 client lifetime/source/local mapping and event 4 owner/count/bytes completion. Requested origin only; redirects and network-to-file content integrity are not established. A later fingerprint describes only the locked local file snapshot." });
            }
        }
        private string LocalPath(string path)
        {
            foreach (var pair in drives.OrderByDescending(p => p.Key.Length))
                if (path.StartsWith(pair.Key + "\\", StringComparison.OrdinalIgnoreCase)) { path = pair.Value + path.Substring(pair.Key.Length); break; }
            if (path.Length < 4 || path[1] != ':' || path[2] != '\\' || !char.IsLetter(path[0]) || path.Substring(2).Contains(":")) return null;
            if (path.IndexOfAny(new[] { '*', '?', '\0' }) >= 0 || path.Split('\\').Any(p => p == ".." || p == ".")) return null;
            if (path.StartsWith(@"C:\InstallerInput\", StringComparison.OrdinalIgnoreCase) || path.StartsWith(@"C:\InstallerOutput\", StringComparison.OrdinalIgnoreCase) || path.StartsWith(@"C:\InstallerTrace\", StringComparison.OrdinalIgnoreCase)) return null;
            var extension = Path.GetExtension(path).ToLowerInvariant();
            return new[] { ".exe", ".msi", ".msix", ".msp", ".appx", ".msixbundle", ".appxbundle", ".cab", ".zip", ".7z", ".iss", ".rsp", ".response", ".config", ".ini" }.Contains(extension) ? path : null;
        }
        public void Add(string xml)
        {
            if (Result.EventsRead++ >= 300000) { Result.Status = "Event limit reached; partial"; return; }
            if (xml.Length > 65536) { Result.Status = "Oversized event skipped; partial"; return; }
            try
            {
                var settings = new System.Xml.XmlReaderSettings { DtdProcessing = System.Xml.DtdProcessing.Prohibit, XmlResolver = null, MaxCharactersInDocument = 65536 };
                using (var input = new StringReader(xml))
                using (var reader = System.Xml.XmlReader.Create(input, settings)) Reduce(XElement.Load(reader));
            }
            catch (Exception ex)
            {
                if (!(ex is System.Xml.XmlException || ex is FormatException || ex is ArgumentException || ex is OverflowException)) throw;
                Result.Status = "Malformed event skipped; partial";
            }
        }
        // Reflection keeps this source usable both in .NET 8 and in Windows PowerShell's
        // framework EventLogReader without another dependency. The tight loop avoids a
        // PowerShell pipeline invocation for every machine-wide trace record.
        public void Read(object reader, int milliseconds, int maxEvents, Action checkpoint)
        {
            var read = reader.GetType().GetMethod("ReadEvent", Type.EmptyTypes);
            if (read == null) throw new ArgumentException("Event reader has no parameterless ReadEvent method.");
            System.Reflection.MethodInfo toXml = null;
            var watch = System.Diagnostics.Stopwatch.StartNew();
            var count = 0;
            try
            {
                while (count < maxEvents && Result.EventsRead < 300000)
                {
                    if (watch.ElapsedMilliseconds >= milliseconds) { Result.Status = "Parse time limit; partial"; return; }
                    var record = read.Invoke(reader, null);
                    if (record == null) return;
                    try
                    {
                        if (toXml == null) toXml = record.GetType().GetMethod("ToXml", Type.EmptyTypes);
                        if (toXml == null) throw new ArgumentException("Event record has no ToXml method.");
                        Add((string)toXml.Invoke(record, null)); count++;
                    }
                    finally { var disposable = record as IDisposable; if (disposable != null) disposable.Dispose(); }
                    if (count % 5000 == 0 && checkpoint != null) checkpoint();
                }
                Result.Status = "Event limit reached; partial";
            }
            finally { if (checkpoint != null) checkpoint(); }
        }
        private void Reduce(XElement root)
        {
            var ns = root.Name.Namespace;
            var system = root.Element(ns + "System"); if (system == null) return;
            var provider = system.Element(ns + "Provider"); if (provider == null) return;
            var name = (string)provider.Attribute("Name");
            var id = (int?)system.Element(ns + "EventID") ?? -1;
            var timeNode = system.Element(ns + "TimeCreated"); if (timeNode == null) return;
            DateTime time;
            if (!DateTime.TryParse((string)timeNode.Attribute("SystemTime"), CultureInfo.InvariantCulture, DateTimeStyles.RoundtripKind, out time)) return;
            time = time.ToUniversalTime();
            if (time < previous) { files.Clear(); writes.Clear(); threads.Clear(); active.Clear(); bitsOrderInvalid = true; Result.Status = "Out-of-order events; partial"; }
            previous = time;
            var data = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase);
            var payload = root.Element(ns + "EventData");
            if (payload != null) foreach (var field in payload.Elements(ns + "Data")) { var key = (string)field.Attribute("Name"); if (key != null) data[key] = field.Value; }
            if (name == "Microsoft-Windows-Kernel-Process")
            {
                var pid = (int)Number(Value(data, "ProcessID")); Owner owner;
                if (id == 1)
                {
                    active.Remove(pid); // Never allow PID reuse to inherit scope.
                    DateTime birth;
                    if (!DateTime.TryParse(Value(data, "CreateTime"), CultureInfo.InvariantCulture, DateTimeStyles.RoundtripKind, out birth)) return;
                    birth = birth.ToUniversalTime(); List<Owner> candidates;
                    if (!seeds.TryGetValue(pid, out candidates)) return;
                    var matching = candidates.Where(s => Math.Abs((s.Birth - birth).Ticks) <= TimeSpan.TicksPerMillisecond).ToArray();
                    if (matching.Length != 1) return;
                    owner = new Owner { Pid = pid, Birth = birth, Name = matching[0].Name };
                    active[pid] = owner;
                }
                else if (id == 2) active.Remove(pid);
                else if (id == 3 || id == 4)
                {
                    var tid = (int)Number(Value(data, "ThreadID")); threads.Remove(tid);
                    if (id == 3 && active.TryGetValue(pid, out owner)) threads[tid] = owner;
                }
                return;
            }
            if (name == "Microsoft-Windows-Bits-Client")
            {
                Guid bitsId;
                if (id == 4 || id == 5 || id == 16388)
                {
                    var rawId = id == 16388 ? Value(data, "Id") : Value(data, "jobId");
                    if (!Guid.TryParse(rawId, out bitsId)) return;
                    var jobKey = bitsId.ToString("D");
                    if (id != 4) { InvalidateBits(jobKey); return; }
                    if (bitsComplete.ContainsKey(jobKey)) { InvalidateBits(jobKey); return; }
                    if (bitsComplete.Count < 256) bitsComplete[jobKey] = new BitsComplete { Time = time, Bytes = Number(Value(data, "bytesTransferred")), Count = Number(Value(data, "fileCount")), Owner = Value(data, "jobOwner") };
                    return;
                }
                // Event 16403 exposes the requested remote/local mapping and client PID.
                // It does not expose direction, success, redirected origin or content identity.
                if (id != 16403 || Result.BitsMappings.Count >= 256) return;
                Owner owner; Guid job; Uri remote;
                var pid = Number(Value(data, "processId"));
                var path = LocalPath(Value(data, "LocalName"));
                if (path == null ||
                    !Guid.TryParse(Value(data, "jobId"), out job) || job == Guid.Empty ||
                    !Uri.TryCreate(Value(data, "RemoteName"), UriKind.Absolute, out remote) ||
                    (remote.Scheme != "http" && remote.Scheme != "https")) return;
                var origin = remote.GetLeftPart(UriPartial.Authority);
                // GetLeftPart can include credentials. Reconstruct from safe origin components.
                origin = new UriBuilder(remote.Scheme, remote.Host, remote.IsDefaultPort ? -1 : remote.Port).Uri.GetLeftPart(UriPartial.Authority);
                var jobKeyMapping = job.ToString("D"); var remoteKey = RemoteKey(remote);
                var bindingSignature = path.ToUpperInvariant() + "|" + remoteKey; string priorSignature;
                if (bitsSignatures.TryGetValue(jobKeyMapping, out priorSignature) && priorSignature != bindingSignature) InvalidateBits(jobKeyMapping);
                if (bitsSignatures.Count < 256) bitsSignatures[jobKeyMapping] = bindingSignature;
                else if (!bitsSignatures.ContainsKey(jobKeyMapping)) InvalidateBits(jobKeyMapping);
                if (Number(Value(data,"fileCount")) != 1) InvalidateBits(jobKeyMapping);
                if (pid <= 0 || pid > int.MaxValue || !active.TryGetValue((int)pid,out owner)) return;
                var key = "bits|" + job + "|" + owner.Key + "|" + path + "|" + origin;
                if (!seen.Add(key)) return;
                Result.BitsMappings.Add(new BitsFileMapping { JobId = job.ToString("D"), ProcessId = owner.Pid,
                    ProcessCreatedAt = owner.Birth.ToString("o"), Process = owner.Name, Path = path, RequestedOrigin = origin,
                    ObservedAt = time.ToString("o"), Evidence = "BITS event 16403 requested remote/local mapping; client PID matched to an observed active process lifetime. URL path, credentials and query omitted. Transfer direction, completion, redirect origin and current file bytes are not established." });
                if (bitsBindings.ContainsKey(jobKeyMapping)) InvalidateBits(jobKeyMapping);
                else bitsBindings[jobKeyMapping] = new BitsBinding { Mapping = Result.BitsMappings[Result.BitsMappings.Count - 1], RemoteKey = remoteKey, Owner = Value(data,"jobOwner"), Time = time };
                return;
            }
            if (name != "Microsoft-Windows-Kernel-File") return;
            var objectKey = Value(data, "FileObject");
            if (id != 16 && id != 24) writes.Remove(Value(data, "Irp"));
            if (id == 12 || id == 30)
            {
                files.Remove(objectKey); // Includes unscoped opens and pointer reuse.
                var issuer = Issuer(system, ns, data);
                var path = LocalPath(Value(data, "FileName"));
                if (issuer != null && path != null && objectKey.Length > 0 && files.Count < 4096)
                    files[objectKey] = new OpenFile { Owner = issuer, Path = path };
            }
            else if (id == 13 || id == 14) files.Remove(objectKey);
            else if (id == 16)
            {
                var irp = Value(data, "Irp"); writes.Remove(irp);
                OpenFile opened; var issuer = Issuer(system, ns, data);
                if (issuer == null || !files.TryGetValue(objectKey, out opened) || issuer.Key != opened.Owner.Key || irp.Length == 0) return;
                var size = Number(Value(data, "IOSize"));
                if (size > 0 && writes.Count < 4096) writes[irp] = new PendingWrite { File = opened, Time = time, Requested = size };
            }
            else if (id == 24)
            {
                var irp = Value(data, "Irp"); PendingWrite pending;
                if (!writes.TryGetValue(irp, out pending)) return;
                writes.Remove(irp);
                var bytes = Number(Value(data, "ExtraInformation"));
                Owner current;
                if (Number(Value(data, "Status")) != 0 || bytes <= 0 || bytes > pending.Requested || (time - pending.Time).TotalSeconds > 30 ||
                    !active.TryGetValue(pending.File.Owner.Pid, out current) || current.Key != pending.File.Owner.Key) return;
                var key = current.Key + "|" + pending.File.Path;
                if (!seen.Add(key) || Result.Files.Count >= 256) return;
                Result.Files.Add(new PayloadFileActivity { ProcessId = current.Pid, ProcessCreatedAt = current.Birth.ToString("o"), Process = current.Name,
                    Path = pending.File.Path, Operation = "Write completed", Bytes = bytes, ObservedAt = time.ToString("o"),
                    Evidence = "Kernel file open/write/completion correlated by file object and IRP; issuing thread mapped to observed process lifetime. First completed write only; not total file size or download proof." });
            }
        }
        private Owner Issuer(XElement system, XNamespace ns, Dictionary<string, string> data)
        {
            var tid = Number(Value(data, "IssuingThreadId"));
            if (tid < 0) tid = Number(Value(data, "ThreadId"));
            Owner owner, current;
            if (tid <= 0 || !threads.TryGetValue((int)tid, out owner) || !active.TryGetValue(owner.Pid, out current) || current.Key != owner.Key) return null;
            return owner;
        }
    }

    // Called inside the disposable guest after reduction; never executes a payload or changes a BITS job.
    public static class BitsDownloadFingerprint
    {
        public static void Capture(PayloadTraceCapture capture)
        {
            var watch = System.Diagnostics.Stopwatch.StartNew(); long total = 0; var count = 0;
            foreach (var download in capture.BitsDownloads)
            {
                download.Sha256 = null; download.FileObservedAt = null;
                download.FileSnapshotStatus = "Unavailable or unsafe local file; transfer content identity remains unverified";
                if (++count > 8 || watch.ElapsedMilliseconds >= 3000 || download.BytesReported < 0 || download.BytesReported > 64L * 1024 * 1024 || total + download.BytesReported > 128L * 1024 * 1024)
                { download.FileSnapshotStatus = "File snapshot budget exceeded; not measured"; continue; }
                try
                {
                    var path = download.Path;
                    if (!SafePath(path)) continue;
                    using (var file = new FileStream(path, FileMode.Open, FileAccess.Read, FileShare.Read, 65536, FileOptions.SequentialScan))
                    {
                        if (file.Length != download.BytesReported) { download.FileSnapshotStatus = "Local length differs from service-reported transfer bytes; not fingerprinted"; continue; }
                        total += file.Length;
                        using (var sha = System.Security.Cryptography.SHA256.Create())
                        {
                            var buffer = new byte[65536]; int read; long measured = 0; var timedOut = false;
                            while ((read = file.Read(buffer, 0, buffer.Length)) > 0)
                            {
                                if (watch.ElapsedMilliseconds >= 3000) { timedOut = true; break; }
                                sha.TransformBlock(buffer, 0, read, buffer, 0); measured += read;
                            }
                            if (timedOut || measured != download.BytesReported) { download.FileSnapshotStatus = "File snapshot read budget exceeded or incomplete; no digest retained"; continue; }
                            sha.TransformFinalBlock(new byte[0], 0, 0);
                            download.Sha256 = BitConverter.ToString(sha.Hash).Replace("-", "");
                            download.FileObservedAt = DateTime.UtcNow.ToString("o");
                            download.FileSnapshotStatus = "Locked local snapshot measured; network-to-file content identity unverified";
                        }
                    }
                }
                catch (Exception ex)
                {
                    if (!(ex is IOException || ex is UnauthorizedAccessException || ex is ArgumentException || ex is NotSupportedException || ex is System.Security.SecurityException)) throw;
                }
            }
        }
        private static bool SafePath(string path)
        {
            if (string.IsNullOrEmpty(path) || path.Length > 1024 || !System.Text.RegularExpressions.Regex.IsMatch(path,@"\A[A-Za-z]:\\") || path.Substring(2).Contains(":")) return false;
            if (!string.Equals(Path.GetFullPath(path),path,StringComparison.OrdinalIgnoreCase)) return false;
            if (path.StartsWith(@"C:\InstallerInput\",StringComparison.OrdinalIgnoreCase) || path.StartsWith(@"C:\InstallerOutput\",StringComparison.OrdinalIgnoreCase) || path.StartsWith(@"C:\InstallerTrace\",StringComparison.OrdinalIgnoreCase)) return false;
            if (!new[] { ".exe", ".msi", ".msp", ".msix", ".appx", ".msixbundle", ".appxbundle", ".cab", ".zip", ".7z" }.Contains(Path.GetExtension(path).ToLowerInvariant())) return false;
            if (new DriveInfo(Path.GetPathRoot(path)).DriveType != DriveType.Fixed) return false;
            var parts = path.Substring(3).Split('\\');
            if (parts.Length > 64 || parts.Any(p => p.Length == 0 || p.EndsWith(".") || p.EndsWith(" ") || p.Any(c => char.IsControl(c)) ||
                System.Text.RegularExpressions.Regex.IsMatch(p,@"\A(?:CON|PRN|AUX|NUL|COM[1-9]|LPT[1-9]|CLOCK\$)(?:\.|\z)",System.Text.RegularExpressions.RegexOptions.IgnoreCase))) return false;
            var current = path;
            while (!string.IsNullOrEmpty(current))
            {
                if ((File.GetAttributes(current) & FileAttributes.ReparsePoint) != 0) return false;
                current = Path.GetDirectoryName(current);
            }
            return true;
        }
    }
}

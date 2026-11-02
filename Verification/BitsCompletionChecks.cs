using System.IO;
using System.IO.Compression;
using System.Security.Cryptography;
using System.Xml.Linq;
using InstallerAnalyzer.Models;
using InstallerAnalyzer.Services;

internal static class BitsCompletionChecks
{
    private const string Birth="2026-10-29T10:00:00Z", Job="099f807e-cb8a-454f-a1df-0a26b4a69cb1", Owner="fixture-owner";
    private const string Remote="https://user:fixture-secret@example.org/private/payload.msi?token=fixture-secret";
    private static string Time(int tick)=>DateTimeOffset.Parse(Birth).AddMilliseconds(tick).ToString("o");
    private static string Event(string provider,int id,int tick,params (string,string)[] fields)
    {
        XNamespace ns="http://schemas.microsoft.com/win/2004/08/events/event";
        return new XElement(ns+"Event",new XElement(ns+"System",new XElement(ns+"Provider",new XAttribute("Name",provider)),new XElement(ns+"EventID",id),
            new XElement(ns+"TimeCreated",new XAttribute("SystemTime",Time(tick)))),new XElement(ns+"EventData",fields.Select(f=>new XElement(ns+"Data",new XAttribute("Name",f.Item1),f.Item2)))).ToString();
    }
    private static PayloadTraceReducer Ready(string path=@"C:\Temp\payload.msi")
    {
        var r=new PayloadTraceReducer();r.AddScope(42,Birth,"setup.exe");r.Add(Event("Microsoft-Windows-Kernel-Process",1,0,("ProcessID","42"),("CreateTime",Birth)));
        r.Add(Event("Microsoft-Windows-Bits-Client",16403,1,("processId","42"),("jobId",Job),("jobOwner",Owner),("fileCount","1"),("RemoteName",Remote),("LocalName",path)));return r;
    }
    private static void Sample(PayloadTraceReducer r,string path=@"C:\Temp\payload.msi",string direction="Download",string state="Transferred",string remote=Remote,string total="24",string bytes="24",int count=1,int tick=2,bool complete=true) =>
        r.ObserveBits(Job,direction,state,path,remote,total,bytes,count,complete,Time(tick));
    private static void Complete(PayloadTraceReducer r,string bytes="24",string count="1",string owner=Owner,int tick=3)=>
        r.Add(Event("Microsoft-Windows-Bits-Client",4,tick,("jobId",Job),("jobOwner",owner),("fileCount",count),("bytesTransferred",bytes)));
    public static void Run(string root,Action<bool,string> check)
    {
        var r=Ready();Sample(r);Complete(r);r.FinishBits();
        check(r.Result.BitsDownloads.Single().BytesReported==24 && r.Result.BitsDownloads[0].RequestedOrigin=="https://example.org","BITS completion joins explicit download direction, complete progress, mapping and service completion bytes");
        check(!System.Text.Json.JsonSerializer.Serialize(r.Result).Contains("fixture-secret") && r.Result.BitsDownloads[0].Evidence.Contains("integrity"),"Completed-transfer evidence omits URI secrets and retains the content-integrity boundary");
        var noSample=Ready();Complete(noSample);noSample.FinishBits();check(noSample.Result.BitsDownloads.Count==0,"A completion event without a sampled Download/Transferred state remains unverified");
        var noEvent=Ready();Sample(noEvent);noEvent.FinishBits();check(noEvent.Result.BitsDownloads.Count==0,"Transferred state without a service completion signal remains unverified");
        foreach(var state in new[]{"Queued","Connecting","Transferring","Error","TransientError","Suspended"})
        {var x=Ready();Sample(x,state:state);Complete(x);x.FinishBits();check(x.Result.BitsDownloads.Count==0,"Incomplete or failed job state cannot establish completion: "+state);}
        var upload=Ready();Sample(upload,direction:"Upload");Complete(upload);upload.FinishBits();check(upload.Result.BitsDownloads.Count==0,"Uploads cannot become download evidence");
        var wrongRemote=Ready();Sample(wrongRemote,remote:"https://example.org/other/file?token=other");Complete(wrongRemote);wrongRemote.FinishBits();check(wrongRemote.Result.BitsDownloads.Count==0,"Same-origin URLs with different paths/query cannot substitute for the mapped source");
        var wrongPath=Ready();Sample(wrongPath,path:@"C:\Temp\other.msi");Complete(wrongPath);wrongPath.FinishBits();check(wrongPath.Result.BitsDownloads.Count==0,"A different local destination cannot acquire download evidence");
        foreach(var bytes in new[]{"22","18446744073709551615","-1"})
        {var x=Ready();Sample(x);Complete(x,bytes:bytes);x.FinishBits();check(x.Result.BitsDownloads.Count==0,"Unknown/mismatched completion byte count remains unverified: "+bytes);}
        var partial=Ready();Sample(partial,bytes:"22");Complete(partial);partial.FinishBits();check(partial.Result.BitsDownloads.Count==0,"Partial file progress cannot establish completion");
        var flag=Ready();Sample(flag,complete:false);Complete(flag);flag.FinishBits();check(flag.Result.BitsDownloads.Count==0,"Complete native job file counts are required");
        var multi=Ready();Sample(multi,count:2);Complete(multi,count:"2");multi.FinishBits();check(multi.Result.BitsDownloads.Count==0,"Unsupported multi-file jobs remain unverified");
        var owner=Ready();Sample(owner);Complete(owner,owner:"different-owner");owner.FinishBits();check(owner.Result.BitsDownloads.Count==0,"A different job owner cannot inherit transfer attribution");
        foreach(var id in new[]{5,16388})
        {var x=Ready();Sample(x);x.Add(Event("Microsoft-Windows-Bits-Client",id,3,(id==5?"jobId":"Id",Job)));Complete(x,tick:4);x.FinishBits();check(x.Result.BitsDownloads.Count==0,"Cancellation/ownership change invalidates completion attribution: "+id);}
        var late=Ready();Sample(late,tick:4);Complete(late);late.FinishBits();check(late.Result.BitsDownloads.Count==0,"Samples taken after the completion event are not backdated");
        var exited=Ready();Sample(exited);exited.Add(Event("Microsoft-Windows-Kernel-Process",2,3,("ProcessID","42")));Complete(exited,tick:4);exited.FinishBits();check(exited.Result.BitsDownloads.Count==1,"A service may finish after the observed mapping client exits without inventing a new process identity");
        var changed=Ready();Sample(changed);Sample(changed,remote:"https://example.org/changed");Complete(changed);changed.FinishBits();check(changed.Result.BitsDownloads.Count==0,"Observed job source changes invalidate prior transfer attribution");
        var order=Ready();Sample(order);Complete(order);order.Add(Event("Microsoft-Windows-Kernel-Process",2,2,("ProcessID","42")));order.FinishBits();check(order.Result.BitsDownloads.Count==0,"Out-of-order event streams withhold completed-download attribution");
        var folder=Path.Combine(root,"download-fingerprints");Directory.CreateDirectory(folder);var path=Path.Combine(folder,"payload.msi");File.WriteAllText(path,"inert BITS fixture bytes");
        var file=Ready(path);Sample(file,path);Complete(file);file.FinishBits();BitsDownloadFingerprint.Capture(file.Result);
        check(file.Result.BitsDownloads[0].Sha256==Convert.ToHexString(SHA256.HashData(File.ReadAllBytes(path))) && file.Result.BitsDownloads[0].FileSnapshotStatus.Contains("identity unverified"),"Locked post-completion local file snapshot retains a digest without claiming network content identity");
        using(var locked=new FileStream(path,FileMode.Open,FileAccess.Read,FileShare.None))
        {BitsDownloadFingerprint.Capture(file.Result);check(file.Result.BitsDownloads[0].Sha256 is null,"An unavailable file lock cannot produce a fingerprint");}
        File.WriteAllBytes(path,new byte[24]);BitsDownloadFingerprint.Capture(file.Result);
        check(file.Result.BitsDownloads[0].Sha256==Convert.ToHexString(SHA256.HashData(new byte[24])) && file.Result.BitsDownloads[0].FileSnapshotStatus.Contains("identity unverified"),"Same-size replacement is measured as current local bytes without a network-content integrity claim");
        File.WriteAllText(path,"changed length");BitsDownloadFingerprint.Capture(file.Result);check(file.Result.BitsDownloads[0].Sha256 is null && file.Result.BitsDownloads[0].FileSnapshotStatus.Contains("length differs"),"A changed local file length does not masquerade as matching transfer bytes");
        File.Delete(path);BitsDownloadFingerprint.Capture(file.Result);check(file.Result.BitsDownloads[0].Sha256 is null,"Deleted temporary downloads retain completion evidence without fabricated file identity");
        var budget=new PayloadTraceCapture {BitsDownloads=[new(){Path=path,BytesReported=64L*1024*1024+1}]};BitsDownloadFingerprint.Capture(budget);check(budget.BitsDownloads[0].Sha256 is null && budget.BitsDownloads[0].FileSnapshotStatus.Contains("budget"),"File fingerprint size budget is enforced before reading");
        var proof=new InstallAnalysis {PayloadTrace=file.Result,ProcessTree=[new(){ProcessId=42,CreatedAt=Birth,Name="setup.exe"}]};IntelligenceReportService.Enrich(proof,null,null);IntelligenceReportService.WriteArtifacts(proof,null,folder);
        check(proof.Intelligence.Payloads.Single().Downloads.Count==1 && proof.Intelligence.Payloads[0].Executed is null && proof.Intelligence.Edges.Any(e=>e.Relationship=="BITS download completion reported"),"Completed temporary downloads enter the payload graph without fabricated execution");
        check(File.Exists(Path.Combine(folder,"bits-download-evidence.json")) && IntelligenceReportService.Generate(null,proof).Contains("BITS download completion reported"),"Completed-download evidence survives artifacts and readable reports");
        var zip=Path.Combine(root,"bits-completion-diagnostics.zip");DiagnosticBundleService.Export(zip,[new(){Installer="Fixture.exe",ArtifactFolder=folder}]);
        using var archive=ZipFile.OpenRead(zip);check(archive.Entries.Any(e=>e.FullName.EndsWith("bits-download-evidence.json")),"Diagnostic export retains completed-download evidence");
    }
}

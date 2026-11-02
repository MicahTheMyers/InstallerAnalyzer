using System.IO;
using System.Xml.Linq;
using InstallerAnalyzer.Models;
using InstallerAnalyzer.Services;

internal static class BitsMappingChecks
{
    public static void Run(string root, Action<bool,string> check)
    {
        const string birth="2026-10-29T10:00:00Z";
        const string job="099f807e-cb8a-454f-a1df-0a26b4a69cb1";
        string Event(string provider,int id,int tick,params (string,string)[] fields)
        {
            XNamespace ns="http://schemas.microsoft.com/win/2004/08/events/event";
            return new XElement(ns+"Event",new XElement(ns+"System",new XElement(ns+"Provider",new XAttribute("Name",provider)),new XElement(ns+"EventID",id),
                new XElement(ns+"TimeCreated",new XAttribute("SystemTime",DateTimeOffset.Parse(birth).AddMilliseconds(tick).ToString("o")))),
                new XElement(ns+"EventData",fields.Select(f=>new XElement(ns+"Data",new XAttribute("Name",f.Item1),f.Item2)))).ToString();
        }
        PayloadTraceReducer Ready()
        {
            var r=new PayloadTraceReducer(); r.AddScope(42,birth,"setup.exe");
            r.Add(Event("Microsoft-Windows-Kernel-Process",1,0,("ProcessID","42"),("CreateTime",birth)));return r;
        }
        void Map(PayloadTraceReducer r,string remote="https://user:secret@example.org/private/file?token=secret",string local=@"C:\Temp\payload.msi",string pid="42",int tick=1) =>
            r.Add(Event("Microsoft-Windows-Bits-Client",16403,tick,("jobId",job),("processId",pid),("RemoteName",remote),("LocalName",local)));
        var reducer=Ready();Map(reducer);
        var mapping=reducer.Result.BitsMappings.Single();
        check(mapping.RequestedOrigin=="https://example.org" && mapping.Path==@"C:\Temp\payload.msi" && mapping.ProcessId==42,"BITS mapping joins requested source, local payload and active installer lifetime");
        check(!System.Text.Json.JsonSerializer.Serialize(mapping).Contains("secret") && !mapping.RequestedOrigin.Contains("private"),"BITS report omits URI credentials, query and path");
        check(mapping.Evidence.Contains("completion") && reducer.Result.Files.Count==0,"BITS mapping does not fabricate a completed write or download");
        Map(reducer,tick:2);check(reducer.Result.BitsMappings.Count==1,"Repeated BITS mappings are deduplicated");
        foreach(var remote in new[]{"file:///C:/payload.msi","ftp://example.org/file","not a URI"})
        { var r=Ready();Map(r,remote:remote);check(r.Result.BitsMappings.Count==0,"Unsupported BITS remote reference remains unreported: "+remote); }
        foreach(var path in new[]{@"\\server\payload.msi",@"C:\InstallerInput\payload.msi",@"C:\Temp\..\payload.msi",@"C:\Temp\secret.txt"})
        { var r=Ready();Map(r,local:path);check(r.Result.BitsMappings.Count==0,"BITS mapping filters unsafe or irrelevant local path: "+path); }
        var unknown=Ready();Map(unknown,pid:"99");check(unknown.Result.BitsMappings.Count==0,"Unscoped BITS clients do not inherit installer attribution");
        var reuse=Ready();reuse.Add(Event("Microsoft-Windows-Kernel-Process",1,3,("ProcessID","42"),("CreateTime",DateTimeOffset.Parse(birth).AddMilliseconds(3).ToString("o"))));Map(reuse,tick:4);
        check(reuse.Result.BitsMappings.Count==0,"BITS PID reuse cannot inherit the previous installer lifetime");
        var exited=Ready();exited.Add(Event("Microsoft-Windows-Kernel-Process",2,1,("ProcessID","42")));Map(exited,tick:2);
        check(exited.Result.BitsMappings.Count==0,"BITS records after the client exits stay unattributed");
        var folder=Path.Combine(root,"bits-mapping-artifacts");Directory.CreateDirectory(folder);
        var proof=new InstallAnalysis {PayloadTrace=reducer.Result};IntelligenceReportService.Enrich(proof,null,null);IntelligenceReportService.WriteArtifacts(proof,null,folder);
        check(File.ReadAllText(Path.Combine(folder,"bits-file-mappings.json")).Contains("https://example.org") && IntelligenceReportService.Generate(null,proof).Contains("BITS requested source mapping"),"BITS mappings survive normalized artifacts and the human-readable report");
    }
}

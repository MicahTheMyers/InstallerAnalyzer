using System.Reflection;
using InstallerAnalyzer;
using InstallerAnalyzer.Models;

internal static class BentleyTargetUiChecks
{
    public static void Run(MainWindow window, Action<bool,string> check)
    {
        var field=typeof(MainWindow).GetField("_installAnalysis",BindingFlags.Instance|BindingFlags.NonPublic)!;
        var choose=typeof(MainWindow).GetMethod("ChooseBestEntry",BindingFlags.Instance|BindingFlags.NonPublic)!;
        var status=typeof(MainWindow).GetProperty("CompletedSandboxStatus",BindingFlags.Instance|BindingFlags.NonPublic)!;
        var previous=field.GetValue(window);
        try
        {
            var proof=new InstallAnalysis{ExpectedPrimaryProduct="gINT",ValidationError="Main application missing"};field.SetValue(window,proof);
            var client=new UninstallEntry{Key="client",DisplayName="CONNECTION Client",Publisher="Bentley Systems, Incorporated",InstallLocation="C:\\Client",UninstallString="client.exe"};
            check(choose.Invoke(window,new object[]{new List<UninstallEntry>{client}}) is null,"UI does not promote CONNECTION Client when expected gINT is absent");
            var product=new UninstallEntry{Key="gint",DisplayName="gINT CONNECT Edition",Publisher="Bentley Systems, Incorporated"};
            check(ReferenceEquals(choose.Invoke(window,new object[]{new List<UninstallEntry>{client,product}}),product),"UI selects expected gINT instead of richer prerequisite entry");
            var exact=new UninstallEntry{Key="validated",DisplayName="gINT CONNECT Edition",Publisher="Bentley Systems, Incorporated"};proof.PrimaryKey=exact.Key;
            check(ReferenceEquals(choose.Invoke(window,new object[]{new List<UninstallEntry>{product,exact}}),exact),"UI preserves guest primary identity when multiple product entries exist");
            check((string)status.GetValue(window)! =="Analysis failed","Completed run with validation error is labeled failed");
            proof.ValidationError=null;
            check((string)status.GetValue(window)! =="Analysis finished — validation incomplete","Output capture alone is not labeled validated success");
        }
        finally{field.SetValue(window,previous);}
    }
}

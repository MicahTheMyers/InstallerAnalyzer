using System.IO;
using System.Reflection;
using System.Windows;
using System.Windows.Controls;
using System.Windows.Threading;
using InstallerAnalyzer;
using InstallerAnalyzer.Models;
using InstallerAnalyzer.Services;

internal static class RegressionInteractionChecks
{
    public static void Run(MainWindow window, string root, Action<bool,string> check)
    {
        var settle=DateTime.UtcNow.AddMilliseconds(200); PumpUntil(()=>DateTime.UtcNow>=settle);
        T Field<T>(string name) => (T)typeof(MainWindow).GetField(name, BindingFlags.Instance | BindingFlags.NonPublic | BindingFlags.Public)!.GetValue(window)!;
        void Set(string name, object value) => typeof(MainWindow).GetField(name, BindingFlags.Instance | BindingFlags.NonPublic)!.SetValue(window,value);
        void Invoke(string name, params object?[] args) => typeof(MainWindow).GetMethod(name, BindingFlags.Instance | BindingFlags.NonPublic)!.Invoke(window,args);
        var history = new RegressionHistoryService(Path.Combine(root,"ui-test-mode","RunHistory"));
        var folder = Path.Combine(root,"ui-test-mode","TestInstallers"); Directory.CreateDirectory(folder);
        var installer = Path.Combine(folder,"same-name.exe"); File.WriteAllText(installer,"inert original fixture bytes");
        var originalHash = RegressionHistoryService.HashFile(installer);
        var run = new RegressionRun { Completed=DateTimeOffset.UtcNow, Mode="SilentOnlyUnattended", Tests=[new() { Installer="same-name.exe",InstallerSha256=originalHash,Result="FAIL",Failure=new() {Owner="Sandbox",Category=FailureCategory.SandboxStartupFailure} }] };
        history.Save(run); Set("_legacyHistoryImported",true);
        Invoke("RefreshRunHistory",run.Id);
        Invoke("SetRegressionBaseline_Click",new Button(),new RoutedEventArgs());
        check(history.BaselineId()==run.Id,"WPF baseline action persists the displayed completed run");
        Invoke("ClearRegressionBaseline_Click",new Button(),new RoutedEventArgs());
        check(history.BaselineId() is null && history.Load().Any(r=>r.Id==run.Id),"WPF clear-baseline action preserves saved history");
        var stopped = new RegressionRun {Completed=DateTimeOffset.UtcNow,Stopped=true}; history.Save(stopped);
        Invoke("RefreshRunHistory",stopped.Id); Invoke("SetRegressionBaseline_Click",new Button(),new RoutedEventArgs());
        check(history.BaselineId() is null,"WPF refuses to save a stopped run as a baseline");
        Invoke("RefreshRunHistory",run.Id);
        File.WriteAllText(installer,"replaced inert fixture bytes");
        foreach(var action in new[]{"Failed","Infrastructure","Unknown"})
        {
            Field<TextBlock>("RegressionHistoryStatus").Text="pending";
            Invoke("Retest_Click",new Button {Tag=action},new RoutedEventArgs());
            PumpUntil(()=>!Field<bool>("_preparingRetest"));
            check(Field<TextBlock>("RegressionHistoryStatus").Text.Contains("No matching installer bytes") && !Field<bool>("_testModeRunning"),"WPF "+action+" retest rejects same-name files with replaced bytes");
        }
        // Hashing yields to the dispatcher. Change selection before its continuation resumes.
        File.WriteAllText(installer,"inert original fixture bytes");
        Invoke("Retest_Click",new Button {Tag="Failed"},new RoutedEventArgs());
        Field<ComboBox>("RegressionCurrentRunBox").SelectedItem=null;
        PumpUntil(()=>!Field<bool>("_preparingRetest"));
        check(!Field<bool>("_testModeRunning") && Field<TextBlock>("RegressionHistoryStatus").Text.Contains("preparation cancelled"),"WPF cancels a prepared retest if the displayed run changes while hashing");
        Invoke("RefreshRunHistory",run.Id); Set("_analysisBusy",true);
        try
        {
            Field<TextBlock>("RegressionHistoryStatus").Text="busy sentinel";
            Invoke("Retest_Click",new Button {Tag="Failed"},new RoutedEventArgs());
            check(!Field<bool>("_preparingRetest") && Field<TextBlock>("RegressionHistoryStatus").Text=="busy sentinel","WPF retest respects an active analysis operation");
        }
        finally { Set("_analysisBusy",false); }
        File.Delete(installer);
    }
    private static void PumpUntil(Func<bool> complete)
    {
        var frame=new DispatcherFrame(); var deadline=DateTime.UtcNow.AddSeconds(15);
        var timer=new DispatcherTimer(DispatcherPriority.Background) {Interval=TimeSpan.FromMilliseconds(10)};
        timer.Tick+=(_,_)=>{if(complete() || DateTime.UtcNow>deadline) frame.Continue=false;};
        timer.Start(); Dispatcher.PushFrame(frame); timer.Stop();
        if(!complete()) throw new TimeoutException("Retest UI did not complete.");
    }
}

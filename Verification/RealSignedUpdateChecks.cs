using System.Diagnostics;
using System.IO;
using System.Net;
using System.Net.Http;
using System.Reflection;
using System.Security.Cryptography;
using InstallerAnalyzer.Services;

internal static class RealSignedUpdateChecks
{
    private sealed class PayloadHandler(byte[] payload) : HttpMessageHandler
    {
        protected override Task<HttpResponseMessage> SendAsync(HttpRequestMessage request, CancellationToken token)
        {
            if (request.RequestUri?.AbsoluteUri != Origin) throw new InvalidOperationException("Unexpected fixture request URI.");
            return Task.FromResult(new HttpResponseMessage(HttpStatusCode.OK) { Content = new ByteArrayContent(payload) });
        }
    }
    private const string Origin = "https://github.com/MicahTheMyers/InstallerAnalyzer/releases/download/v99.0.0.0/InstallerAnalyzer-Setup.exe";
    public static int Run(string root, string payloadPath)
    {
        try { RunAsync(root, payloadPath).GetAwaiter().GetResult(); return 0; }
        catch (Exception ex) { Console.Error.WriteLine(ex); File.WriteAllText(Path.Combine(root, "signed-handoff-error.txt"), ex.ToString()); return 1; }
    }
    public static int RunUntrusted(string root)
    {
        try
        {
            var identity = InstallerIdentityService.Inspect(Environment.ProcessPath!);
            if (identity.SignatureStatus is not ("NotTrusted" or "UnknownError") || identity.SignerThumbprint != File.ReadAllText(@"C:\SigningFixture\expected-test-thumbprint.txt")) throw new Exception("Fixture must have its actual embedded test signature and no trusted chain.");
            var method = typeof(UpdateService).GetMethod("RunningPublisher", BindingFlags.Static | BindingFlags.NonPublic)!;
            using var http = new HttpClient(new PayloadHandler(Array.Empty<byte>()));
            var service = new UpdateService(http, () => (string)method.Invoke(null, null)!, InstallerIdentityService.Inspect,
                _ => throw new Exception("Untrusted publisher must never launch an updater."), Path.Combine(root, "staging"));
            var rejected = false;
            var update = new UpdateInfo(new Version(99, 0, 0, 0), "v99.0.0.0", "Guest untrusted-chain fixture", "", new(UpdateService.InstallerAssetName, Origin, "sha256:" + new string('0', 64)));
            try { using var unused = service.DownloadInstallerAsync(update).GetAwaiter().GetResult(); }
            catch (TargetInvocationException ex) when (ex.InnerException is InvalidOperationException) { rejected = true; }
            if (!rejected || Directory.Exists(Path.Combine(root, "staging"))) throw new Exception("Real untrusted publisher was not rejected before staging/transport.");
            Console.WriteLine("PASS real signed PE with an untrusted certificate chain is rejected by production publisher verification before transport, staging or launch");
            File.WriteAllText(Path.Combine(root, "PASS.txt"), "Real untrusted-signature rejection passed; no certificate trust store was changed.");
            return 0;
        }
        catch (Exception ex) { Console.Error.WriteLine(ex); return 1; }
    }
    private static async Task RunAsync(string root, string payloadPath)
    {
        var pinMethod = typeof(UpdateService).GetMethod("RunningPublisher", BindingFlags.Static | BindingFlags.NonPublic)!;
        string RealPublisher() => (string)pinMethod.Invoke(null, null)!;
        var pin = RealPublisher();
        var identity = InstallerIdentityService.Inspect(payloadPath);
        if (!identity.SignatureValid || identity.SignerThumbprint != pin) throw new Exception("Real signature chain/publisher check failed for the test setup.");
        Console.WriteLine("PASS production running-publisher and Authenticode checks trust the isolated test certificate");
        var bytes = File.ReadAllBytes(payloadPath); var launches = 0;
        using var http = new HttpClient(new PayloadHandler(bytes));
        var service = new UpdateService(http, RealPublisher, InstallerIdentityService.Inspect, info =>
        {
            using var process = Process.Start(info) ?? throw new Exception("Inert setup launch failed.");
            if (!process.WaitForExit(10000)) { process.Kill(true); throw new TimeoutException("Inert setup did not exit."); }
            if (process.ExitCode != 0) throw new Exception("Inert setup returned failure.");
            launches++;
        }, Path.Combine(root, "staging"));
        UpdateInfo Info(byte[] data) => new(new Version(99, 0, 0, 0), "v99.0.0.0", "Isolated signed fixture", "", new(UpdateService.InstallerAssetName, Origin, "sha256:" + Convert.ToHexString(SHA256.HashData(data))));
        using (var update = await service.DownloadInstallerAsync(Info(bytes)))
        {
            await service.LaunchInstallerAsync(update);
            var refused = false;
            try { await service.LaunchInstallerAsync(update); } catch (InvalidOperationException) { refused = true; }
            if (!refused) throw new Exception("A second launch was not rejected.");
        }
        if (launches != 1 || !File.Exists(@"C:\InstallerOutput\signed-handoff-launched.txt")) throw new Exception("Real signed setup launch marker missing.");
        Console.WriteLine("PASS real signed PE digest/product/version verification, locked staging and single inert setup handoff");
        var otherPath = Path.Combine(Path.GetDirectoryName(payloadPath)!, "OtherPublisher-Setup.exe");
        var otherIdentity = InstallerIdentityService.Inspect(otherPath);
        if (!otherIdentity.SignatureValid || otherIdentity.SignerThumbprint == pin) throw new Exception("Different-publisher fixture did not have its own valid trusted signature.");
        var other = File.ReadAllBytes(otherPath); using var otherHttp = new HttpClient(new PayloadHandler(other));
        var rejected = false;
        var wrong = new UpdateService(otherHttp, RealPublisher, InstallerIdentityService.Inspect, _ => throw new Exception("Wrong-publisher setup must never launch."), Path.Combine(root, "wrong-publisher"));
        try { using var unused = await wrong.DownloadInstallerAsync(Info(other)); } catch (InvalidDataException) { rejected = true; }
        if (!rejected) throw new Exception("Valid different-publisher setup was accepted.");
        Console.WriteLine("PASS real trusted different-certificate setup is rejected by the publisher pin");
        File.WriteAllText(Path.Combine(root, "PASS.txt"), "Real Authenticode and launch fixture passed with guest-only test certificates and stubbed transport; no public release trust asserted.");
    }
}

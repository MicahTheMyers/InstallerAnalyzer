using System.IO;
using System.Net;
using System.Net.Http;
using System.Net.Http.Headers;
using System.Net.Http.Json;
using System.Net.Security;
using System.Security.Cryptography;
using InstallerAnalyzer.CatalogSync;

namespace InstallerAnalyzer.Services;

internal sealed class OnlineCatalogClient : IDisposable
{
    private readonly HttpClient _http;
    private readonly CatalogSessionStore _sessionStore;
    private readonly ECDsa _signer = ECDsa.Create();
    private string? _token;
    private long _revision;

    public OnlineCatalogClient(string server, string publicKeyPem, string? tlsFingerprint = null)
    {
        if (!Uri.TryCreate(server, UriKind.Absolute, out var address) ||
            !(address.Scheme == "https" || address.Scheme == "http" && address.Host == "127.0.0.1") ||
            address.UserInfo.Length != 0 || address.Query.Length != 0 || address.Fragment.Length != 0)
            throw new InvalidOperationException("Set an HTTPS catalog address and a trusted public signing key.");
        var handler = new HttpClientHandler { AllowAutoRedirect = false };
        if (!string.IsNullOrEmpty(tlsFingerprint))
        {
            if (address.Scheme != "https" || tlsFingerprint.Length != 64 || !tlsFingerprint.All(Uri.IsHexDigit))
                throw new InvalidOperationException("Set a SHA-256 TLS certificate fingerprint for the HTTPS catalog address.");
            var expected = Convert.FromHexString(tlsFingerprint);
            handler.ServerCertificateCustomValidationCallback = (_, certificate, _, errors) =>
                certificate is not null && (errors & ~SslPolicyErrors.RemoteCertificateChainErrors) == SslPolicyErrors.None &&
                certificate.NotBefore.ToUniversalTime() <= DateTime.UtcNow && certificate.NotAfter.ToUniversalTime() > DateTime.UtcNow &&
                CryptographicOperations.FixedTimeEquals(expected, SHA256.HashData(certificate.RawData));
        }
        try { _signer.ImportFromPem(publicKeyPem); }
        catch { handler.Dispose(); _signer.Dispose(); throw; }
        _http = new HttpClient(handler)
        {
            BaseAddress = new Uri(address.AbsoluteUri.TrimEnd('/') + "/api/catalog/v1/"),
            Timeout = TimeSpan.FromSeconds(20),
            MaxResponseContentBufferSize = 4 * 1024 * 1024
        };
        _sessionStore = new CatalogSessionStore(_http.BaseAddress, tlsFingerprint);
    }

    public Task<DeviceSignIn> Start(CancellationToken ct) => Read<DeviceSignIn>(HttpMethod.Post, "sign-in/start", null, ct);
    public async Task<SignInResult> Poll(string id, CancellationToken ct)
    {
        var reply = await Read<SignInResult>(HttpMethod.Post, "sign-in/poll", new PollSignIn(id), ct);
        if (reply.Account is not null && reply.Token is { Length: 64 }) _token = reply.Token;
        return reply;
    }
    public async Task<CatalogSession?> RestoreSession(CancellationToken ct)
    {
        _token = _sessionStore.Load();
        if (_token is null) return null;
        try { return await Read<CatalogSession>(HttpMethod.Get, "session", null, ct); }
        catch (HttpRequestException ex) when (ex.StatusCode == HttpStatusCode.Unauthorized)
        {
            ForgetSession();
            _token = null;
            return null;
        }
        catch
        {
            _token = null;
            throw;
        }
    }

    public void RememberSession() => _sessionStore.Save(_token ?? throw new InvalidOperationException("Sign in before saving a catalog session."));
    public void ForgetSession() => _sessionStore.Clear(_token);
    public async Task<CatalogSnapshot> Sync(CancellationToken ct)
    {
        var snapshot = (await Read<SignedSnapshot>(HttpMethod.Get, "snapshot?includeUnsigned=true", null, ct)).Verify(_signer, DateTimeOffset.UtcNow, _revision);
        _revision = snapshot.Revision;
        return snapshot;
    }
    public Task<RecipeSubmission> Submit(RecipeInput recipe, CancellationToken ct) => Read<RecipeSubmission>(HttpMethod.Post, "submissions", recipe, ct);
    public Task<Member[]> Members(CancellationToken ct) => Read<Member[]>(HttpMethod.Get, "admin/members", null, ct);
    public Task<RecipeSubmission[]> Submissions(CancellationToken ct) => Read<RecipeSubmission[]>(HttpMethod.Get, "admin/submissions", null, ct);
    public Task<Member> Invite(string login, CancellationToken ct) => Read<Member>(HttpMethod.Post, "admin/members", new InviteRequest(login), ct);
    public Task Remove(long id, CancellationToken ct) => Write(HttpMethod.Delete, $"admin/members/{id}", ct);
    public Task Decide(Guid id, string decision, CancellationToken ct) => Write(HttpMethod.Post, $"admin/submissions/{id:D}/{decision}", ct);
    public async Task SignOut(CancellationToken ct)
    {
        try
        {
            try { ForgetSession(); }
            finally { if (_token is not null) await Write(HttpMethod.Post, "sign-out", ct); }
        }
        finally { _token = null; }
    }

    private async Task<T> Read<T>(HttpMethod method, string path, object? body, CancellationToken ct)
    {
        using var response = await Send(method, path, body, ct);
        return await response.Content.ReadFromJsonAsync<T>(ct) ?? throw new InvalidDataException("Catalog server sent an empty reply.");
    }

    private async Task Write(HttpMethod method, string path, CancellationToken ct)
    {
        using var response = await Send(method, path, null, ct);
    }

    private async Task<HttpResponseMessage> Send(HttpMethod method, string path, object? body, CancellationToken ct)
    {
        using var request = new HttpRequestMessage(method, path);
        if (_token is not null) request.Headers.Authorization = new AuthenticationHeaderValue("Bearer", _token);
        if (body is not null) request.Content = JsonContent.Create(body, body.GetType());
        var response = await _http.SendAsync(request, ct);
        if (response.IsSuccessStatusCode) return response;
        var status = response.StatusCode;
        response.Dispose();
        throw new HttpRequestException(status switch
        {
            HttpStatusCode.Forbidden => "This GitHub account does not have permission. Ask the catalog maintainer for access.",
            HttpStatusCode.Unauthorized => "Sign-in was declined or your session ended. Sign in again.",
            HttpStatusCode.NotFound => "The requested account or sign-in could not be found.",
            HttpStatusCode.Conflict => "This recipe already exists or its review status changed. Refresh and try again.",
            HttpStatusCode.TooManyRequests => "The catalog limit was reached. Wait and try again or contact the maintainer.",
            _ => $"The catalog server returned HTTP {(int)status}."
        }, null, status);
    }

    public void Dispose() { _http.Dispose(); _signer.Dispose(); }
}

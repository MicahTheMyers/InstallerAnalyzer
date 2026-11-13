using System.IO;
using System.Security.Cryptography;
using System.Text.Json;
using System.Text.RegularExpressions;

namespace InstallerAnalyzer.CatalogSync;

public sealed record DeviceSignIn(string Id, string UserCode, int Interval, int ExpiresIn);
public sealed record PollSignIn(string Id);
public sealed record CatalogAccount(long Id, string Login, bool Maintainer);
public sealed record CatalogSession(CatalogAccount Account, DateTimeOffset ExpiresAt);
public sealed record SignInResult(string? Token, CatalogAccount? Account, int RetryAfter = 0, DateTimeOffset? ExpiresAt = null);
public sealed record InviteRequest(string Login);
public sealed record Member(long Id, string Login);
public sealed record RecipeInput(string Product, string Version, string Publisher, string VendorPage,
    string Sha256, string SignerThumbprint, Guid ProductCode)
{
    public bool IsValid() =>
        ValidText(Product, 120) && ValidText(Version, 60) && ValidText(Publisher, 120) &&
        Sha256 is { Length: 64 } && Sha256.All(Uri.IsHexDigit) &&
        (SignerThumbprint is "" || SignerThumbprint is { Length: 40 } && SignerThumbprint.All(Uri.IsHexDigit)) &&
        ProductCode != Guid.Empty &&
        VendorPage is { Length: <= 500 } && Uri.TryCreate(VendorPage, UriKind.Absolute, out var uri) &&
        uri.Scheme == Uri.UriSchemeHttps && uri.HostNameType == UriHostNameType.Dns &&
        !uri.IsLoopback && uri.IsDefaultPort && uri.UserInfo.Length == 0 && uri.Query.Length == 0 && uri.Fragment.Length == 0;

    private static bool ValidText(string? value, int limit) => !string.IsNullOrWhiteSpace(value) &&
        value.Length <= limit && value.All(c => !char.IsControl(c) &&
            char.GetUnicodeCategory(c) != System.Globalization.UnicodeCategory.Format);
}

public sealed record RecipeSubmission(Guid Id, long SubmittedBy, RecipeInput Recipe, string Status,
    string? SubmittedByLogin = null, DateTimeOffset? SubmittedAt = null);
public sealed record CatalogSnapshot(long Revision, DateTimeOffset Issued, DateTimeOffset Expires, RecipeInput[] Recipes);
public sealed record SignedSnapshot(string Payload, string Signature)
{
    public static SignedSnapshot Create(CatalogSnapshot snapshot, ECDsa key)
    {
        var bytes = JsonSerializer.SerializeToUtf8Bytes(snapshot);
        return new(Convert.ToBase64String(bytes), Convert.ToBase64String(key.SignData(bytes, HashAlgorithmName.SHA256)));
    }

    public CatalogSnapshot Verify(ECDsa key, DateTimeOffset now, long minimumRevision)
    {
        var bytes = Convert.FromBase64String(Payload);
        if (!key.VerifyData(bytes, Convert.FromBase64String(Signature), HashAlgorithmName.SHA256))
            throw new CryptographicException("Catalog signature did not match the configured signing key.");
        var snapshot = JsonSerializer.Deserialize<CatalogSnapshot>(bytes);
        if (snapshot is null || snapshot.Revision < minimumRevision || snapshot.Expires <= now ||
            snapshot.Issued > now.AddMinutes(1) || snapshot.Expires <= snapshot.Issued ||
            snapshot.Expires - snapshot.Issued > TimeSpan.FromMinutes(5) ||
            snapshot.Recipes is not { Length: <= 500 } || snapshot.Recipes.Any(r => r is null || !r.IsValid()))
            throw new InvalidDataException("Catalog snapshot is stale or invalid.");
        return snapshot;
    }
}

public static partial class CatalogProtocol
{
    [GeneratedRegex(@"\A[A-Za-z0-9](?:[A-Za-z0-9-]{0,37}[A-Za-z0-9])?\z")]
    public static partial Regex GitHubLogin();
    public const string GitHubDevicePage = "https://github.com/login/device";
}

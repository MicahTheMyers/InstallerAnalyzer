using System.Diagnostics;
using System.IO;
using System.Net;
using System.Net.Http;
using System.Security.Cryptography;
using System.Windows;
using System.Windows.Automation;
using System.Windows.Controls;
using System.Windows.Controls.Primitives;
using System.Windows.Input;
using System.Windows.Media.Imaging;
using System.Windows.Threading;
using InstallerAnalyzer.CatalogSync;
using InstallerAnalyzer.Models;
using InstallerAnalyzer.Services;
using Microsoft.Win32;

namespace InstallerAnalyzer;

public partial class MainWindow
{
    private static readonly HttpClient GitHubAvatarClient = new(new HttpClientHandler { AllowAutoRedirect = false, UseCookies = false })
    {
        Timeout = TimeSpan.FromSeconds(5),
        MaxResponseContentBufferSize = 256 * 1024
    };

    private readonly CancellationTokenSource _catalogOnlineLifetime = new();
    private readonly DispatcherTimer _catalogOnlineTimer = new() { Interval = TimeSpan.FromSeconds(5) };
    private CancellationTokenSource? _catalogSignIn;
    private OnlineCatalogClient? _catalogClient;
    private CatalogAccount? _catalogAccount;
    private CatalogSnapshot? _catalogSnapshot;
    private DateTimeOffset _catalogAccountExpires;
    private bool _catalogOnlineBusy;

    private void InitializeOnlineCatalogAccount()
    {
        CatalogProfilePopup.CustomPopupPlacementCallback = (popup, target, _) =>
            [new CustomPopupPlacement(new Point(target.Width - popup.Width, target.Height + 8), PopupPrimaryAxis.Horizontal)];
        var (address, key, fingerprint) = GetCatalogConnection();
        if (string.IsNullOrWhiteSpace(address) || string.IsNullOrWhiteSpace(key))
            CatalogAccountStatus.Text = "Online Catalog needs a server address and trusted public key. Ask your catalog maintainer to set them up.";
        else
            Loaded += async (_, _) => await RestoreCatalogAccount(address, key, fingerprint);
        _catalogOnlineTimer.Tick += (_, _) =>
        {
            if (_catalogOnlineBusy) return;
            if (_catalogAccount is not null && _catalogAccountExpires <= DateTimeOffset.UtcNow)
            {
                ResetCatalogAccount();
                CatalogAccountStatus.Text = "Your catalog session expired. Sign in again.";
            }
            else if (_catalogSnapshot is { } snapshot && snapshot.Expires <= DateTimeOffset.UtcNow)
            {
                ClearApprovedCatalog();
                CatalogApprovedStatus.Text = "The approved list expired. Refresh it to continue.";
            }
        };
        Closed += (_, _) =>
        {
            _catalogOnlineTimer.Stop();
            _catalogOnlineLifetime.Cancel();
            _catalogClient?.Dispose();
            _catalogOnlineLifetime.Dispose();
        };
    }

    private Task RestoreCatalogAccount(string address, string key, string? fingerprint) =>
        RunCatalogOperation(CatalogAccountStatus, async ct =>
        {
            if (_catalogAccount is not null) return;
            var client = new OnlineCatalogClient(address, key, fingerprint);
            try
            {
                var session = await client.RestoreSession(ct);
                ct.ThrowIfCancellationRequested();
                if (session is null) return;
                SetCatalogAccount(session.Account, session.ExpiresAt);
                _catalogClient = client;
            }
            catch (Exception ex) when (!ct.IsCancellationRequested && ex is HttpRequestException or OperationCanceledException)
            {
                CatalogAccountStatus.Text = "Could not restore your catalog sign-in. Check the catalog connection and reopen Installer Analyzer.";
            }
            finally { if (!ReferenceEquals(_catalogClient, client)) client.Dispose(); }
        });

    private void SetCatalogAccount(CatalogAccount account, DateTimeOffset expiresAt)
    {
        _catalogAccount = account;
        _catalogAccountExpires = expiresAt;
        SetProfileButton(account.Login);
        if (account.Id > 0) _ = LoadProfileAvatarAsync(account, _catalogOnlineLifetime.Token);
        _catalogOnlineTimer.Start();
        CatalogAccountStatus.Text = account.Maintainer
            ? $"Signed in as {account.Login}. Open Admin Control Center to invite users or review sync requests."
            : $"Signed in as {account.Login}. Open Catalog to send a sync request.";
    }

    private void SetProfileButton(string? login)
    {
        CatalogProfileLabel.Text = login ?? "Profile";
        CatalogProfileButton.ToolTip = login ?? "Catalog profile";
        AutomationProperties.SetName(CatalogProfileButton, login is null ? "Profile" : $"Profile for {login}");
        CatalogProfileAvatarImage.ImageSource = null;
        CatalogProfileAvatar.Visibility = Visibility.Collapsed;
        CatalogProfileIcon.Visibility = Visibility.Visible;
    }

    private async Task LoadProfileAvatarAsync(CatalogAccount account, CancellationToken cancellationToken)
    {
        try
        {
            var url = FormattableString.Invariant($"https://avatars.githubusercontent.com/u/{account.Id}?s=64&v=4");
            var bytes = await GitHubAvatarClient.GetByteArrayAsync(url, cancellationToken);
            if (cancellationToken.IsCancellationRequested || !ReferenceEquals(account, _catalogAccount)) return;

            using var stream = new MemoryStream(bytes, writable: false);
            var avatar = new BitmapImage();
            avatar.BeginInit();
            avatar.StreamSource = stream;
            avatar.CacheOption = BitmapCacheOption.OnLoad;
            avatar.DecodePixelWidth = 64;
            avatar.EndInit();
            CatalogProfileAvatarImage.ImageSource = avatar;
            CatalogProfileAvatar.Visibility = Visibility.Visible;
            CatalogProfileIcon.Visibility = Visibility.Collapsed;
        }
        catch (Exception ex) when (ex is HttpRequestException or OperationCanceledException or IOException or FormatException or NotSupportedException)
        {
            // Keep the username and profile icon when the public avatar is unavailable.
        }
    }

    private void CatalogProfile_Click(object sender, RoutedEventArgs e) =>
        CatalogProfilePopup.IsOpen = !CatalogProfilePopup.IsOpen;

    private void CatalogProfile_Opened(object sender, EventArgs e)
    {
        if (CatalogDeviceCodeRow.Visibility == Visibility.Visible)
        {
            CatalogDeviceCode.Focus();
            CatalogDeviceCode.SelectAll();
        }
        else if (_catalogSignIn is not null)
            CatalogCancelSignInButton.Focus();
        else if (_catalogAccount is null)
            CatalogSignInButton.Focus();
        else
            CatalogSignOutButton.Focus();
    }

    private void CatalogProfile_PreviewKeyDown(object sender, KeyEventArgs e)
    {
        if (e.Key != Key.Escape) return;
        CatalogProfilePopup.IsOpen = false;
        CatalogProfileButton.Focus();
        e.Handled = true;
    }

    private static (string? Address, string? Key, string? Fingerprint) GetCatalogConnection()
    {
        var address = Environment.GetEnvironmentVariable("INSTALLER_ANALYZER_CATALOG_URL");
        var key = Environment.GetEnvironmentVariable("INSTALLER_ANALYZER_CATALOG_PUBLIC_KEY");
        var fingerprint = Environment.GetEnvironmentVariable("INSTALLER_ANALYZER_CATALOG_TLS_SHA256");
        if (address is not null || key is not null || fingerprint is not null)
            return ReadCatalogConnection(address, key, fingerprint);

        var folder = AppContext.BaseDirectory;
        var addressPath = Path.Combine(folder, "catalog-server.txt");
        var keyPath = Path.Combine(folder, "catalog-signing-public.pem");
        var fingerprintPath = Path.Combine(folder, "catalog-tls-sha256.txt");
        if (!File.Exists(addressPath) && !File.Exists(keyPath) && !File.Exists(fingerprintPath))
            return (ReadBuiltInCatalogFile("catalog-server.txt").Trim(), ReadBuiltInCatalogFile("catalog-signing-public.pem"), null);

        try
        {
            address = File.ReadAllText(addressPath).Trim();
            try { fingerprint = File.ReadAllText(fingerprintPath).Trim(); }
            catch (FileNotFoundException) { }
            if (fingerprint is null || fingerprint.Length == 64 && fingerprint.All(Uri.IsHexDigit))
                return ReadCatalogConnection(address, keyPath, fingerprint);
        }
        catch (IOException) { }
        catch (UnauthorizedAccessException) { }
        return (null, null, null);
    }

    private static (string? Address, string? Key, string? Fingerprint) ReadCatalogConnection(
        string? address, string? keyPath, string? fingerprint)
    {
        try { return (address, keyPath is null ? null : File.ReadAllText(keyPath), fingerprint); }
        catch (IOException) { return (address, null, fingerprint); }
        catch (UnauthorizedAccessException) { return (address, null, fingerprint); }
    }

    private static string ReadBuiltInCatalogFile(string name)
    {
        using var stream = typeof(MainWindow).Assembly.GetManifestResourceStream("InstallerAnalyzer." + name)
            ?? throw new InvalidOperationException("Missing built-in catalog configuration: " + name);
        using var reader = new StreamReader(stream);
        return reader.ReadToEnd();
    }

    private async Task RunCatalogOperation(TextBlock status, Func<CancellationToken, Task> operation, CancellationToken? cancellation = null)
    {
        if (_catalogOnlineBusy || _windowClosed) return;
        _catalogOnlineBusy = true;
        UpdateCatalogAccountControls();
        var ct = cancellation ?? _catalogOnlineLifetime.Token;
        try { await operation(ct); }
        catch (OperationCanceledException) when (ct.IsCancellationRequested)
        {
            if (!_windowClosed && cancellation.HasValue) status.Text = "Sign-in cancelled.";
        }
        catch (Exception ex) when (!_windowClosed)
        {
            if (ex is HttpRequestException { StatusCode: HttpStatusCode.Unauthorized } && _catalogAccount is not null)
            {
                ResetCatalogAccount();
                CatalogAccountStatus.Text = "Your catalog session ended. Sign in again.";
            }
            status.Text = ex.Message;
        }
        catch (Exception) when (_windowClosed) { }
        finally
        {
            _catalogOnlineBusy = false;
            if (!_windowClosed) UpdateCatalogAccountControls();
        }
    }

    private void UpdateCatalogAccountControls()
    {
        var signedIn = _catalogAccount is not null;
        var admin = _catalogAccount?.Maintainer == true;
        CatalogSignInButton.Visibility = signedIn ? Visibility.Collapsed : Visibility.Visible;
        CatalogSignInButton.IsEnabled = !_catalogOnlineBusy;
        CatalogSignOutButton.Visibility = signedIn ? Visibility.Visible : Visibility.Collapsed;
        CatalogSignOutButton.IsEnabled = !_catalogOnlineBusy;
        CatalogCancelSignInButton.Visibility = _catalogSignIn is null ? Visibility.Collapsed : Visibility.Visible;
        CatalogAdminNavButton.Visibility = admin ? Visibility.Visible : Visibility.Collapsed;
        CatalogAdminTabs.IsEnabled = CatalogAdminSyncButton.IsEnabled = CatalogAdminApprovedButton.IsEnabled = admin && !_catalogOnlineBusy;
        CatalogApprovedButton.Visibility = signedIn ? Visibility.Visible : Visibility.Collapsed;
        CatalogApprovedButton.IsEnabled = CatalogApprovedActions.IsEnabled = signedIn && !_catalogOnlineBusy;
        CatalogSyncPanel.Visibility = signedIn && !admin ? Visibility.Visible : Visibility.Collapsed;
        UpdateCatalogSyncSelection();
    }

    private void UpdateCatalogSyncSelection()
    {
        if (CatalogSyncHint is null || CatalogList is null) return;
        var row = CatalogList.SelectedItem as CatalogRecord;
        var reason = CatalogSyncBlockReason(row);
        CatalogSyncFields.IsEnabled = reason is null && !_catalogOnlineBusy;
        CatalogSyncHint.Text = reason is null
            ? $"Enter the official vendor page and click Sync to send {row!.Product} {row.Version} to the maintainer for review."
            : reason;
    }

    private static bool CatalogSyncEligible(CatalogRecord? row) => CatalogSyncBlockReason(row) is null;

    private static string? CatalogSyncBlockReason(CatalogRecord? row)
    {
        if (row is null) return "Select an installer to check if it can be synced.";
        if (row.Origin != "Local validated" || row.Validations <= 0) return "Complete local Sandbox validation before syncing this installer.";
        if (row.Family != "Msi" || row.ComponentDeployment is not null || row.Recording is not null)
            return "Catalog sync supports standalone MSI recipes.";
        if (row.SigningIdentity?.SignatureStatus is not ("Valid" or "NotSigned"))
            return $"{row.Product} has an invalid or unverified signature. Catalog sync accepts valid signatures and unsigned MSIs.";
        if (!Guid.TryParse(row.SigningIdentity.Msi.ProductCode, out var code) || code == Guid.Empty)
            return "This MSI is missing a valid product code. Retest the original installer before syncing.";
        if (!row.History.Any(h => h.InstallPassed && h.DetectionPassed && h.UninstallPassed && h.RemovalPassed &&
            h.InstallArguments.Trim().Equals("/qn /norestart", StringComparison.OrdinalIgnoreCase)))
            return "Catalog sync requires a full Sandbox pass using /qn /norestart.";
        return null;
    }

    private async void CatalogSignIn_Click(object sender, RoutedEventArgs e)
    {
        if (_catalogOnlineBusy || _catalogAccount is not null) return;
        var (address, key, fingerprint) = GetCatalogConnection();
        if (string.IsNullOrWhiteSpace(address) || string.IsNullOrWhiteSpace(key))
        {
            CatalogAccountStatus.Text = "Online Catalog needs a server address and trusted public key. Ask your catalog maintainer to set them up.";
            return;
        }
        using var signIn = CancellationTokenSource.CreateLinkedTokenSource(_catalogOnlineLifetime.Token);
        _catalogSignIn = signIn;
        try
        {
            await RunCatalogOperation(CatalogAccountStatus, async ct =>
            {
                CatalogAccountStatus.Text = "Requesting a GitHub sign-in code...";
                _catalogClient ??= new OnlineCatalogClient(address, key, fingerprint);
                DeviceSignIn start;
                try { start = await _catalogClient.Start(ct); }
                catch (OperationCanceledException ex) when (!ct.IsCancellationRequested)
                {
                    throw new TimeoutException("The catalog server did not respond. Check that you are on the same network as the catalog server and try again.", ex);
                }
                catch (HttpRequestException ex) when (ex.StatusCode is null)
                {
                    throw new InvalidOperationException("Could not connect securely to the catalog server. Check the network and try again.", ex);
                }
                if (start.Interval is < 1 or > 60 || start.ExpiresIn is < 1 or > 900 ||
                    start.UserCode is not { Length: > 0 and <= 24 } || start.Id is not { Length: 64 })
                    throw new InvalidOperationException("The server returned an invalid sign-in code.");
                CatalogDeviceCode.Text = start.UserCode;
                CatalogDeviceCodeRow.Visibility = Visibility.Visible;
                CatalogDeviceCode.Focus();
                CatalogDeviceCode.SelectAll();
                CatalogOpenGitHubButton.Visibility = Visibility.Visible;
                CatalogOpenGitHub_Click(this, e);
                var until = DateTimeOffset.UtcNow.AddSeconds(start.ExpiresIn);
                var delay = start.Interval;
                while (delay <= 900 && DateTimeOffset.UtcNow.AddSeconds(delay) < until)
                {
                    await Task.Delay(TimeSpan.FromSeconds(delay), ct);
                    var result = await _catalogClient.Poll(start.Id, ct);
                    ct.ThrowIfCancellationRequested();
                    if (result.Account is { } account && result.Token is { Length: 64 })
                    {
                        SetCatalogAccount(account, result.ExpiresAt ?? DateTimeOffset.UtcNow.AddMinutes(30));
                        try { _catalogClient.RememberSession(); }
                        catch (Exception ex) when (ex is IOException or UnauthorizedAccessException or CryptographicException)
                        {
                            CatalogAccountStatus.Text += " Windows could not save this sign-in for next time.";
                        }
                        return;
                    }
                    delay = Math.Max(1, result.RetryAfter);
                }
                throw new TimeoutException("The GitHub sign-in code expired. Try again.");
            }, signIn.Token);
        }
        finally
        {
            _catalogSignIn = null;
            if (!_windowClosed)
            {
                if (_catalogAccount is null)
                {
                    _catalogClient?.Dispose();
                    _catalogClient = null;
                }
                CatalogDeviceCode.Clear();
                CatalogDeviceCodeRow.Visibility = Visibility.Collapsed;
                CatalogOpenGitHubButton.Visibility = Visibility.Collapsed;
                UpdateCatalogAccountControls();
            }
        }
    }

    private void CatalogCancelSignIn_Click(object sender, RoutedEventArgs e) => _catalogSignIn?.Cancel();

    private void CatalogCopyDeviceCode_Click(object sender, RoutedEventArgs e)
    {
        if (CatalogDeviceCode.Text.Length == 0) return;
        try
        {
            Clipboard.SetText(CatalogDeviceCode.Text);
            CatalogAccountStatus.Text = "Code copied. Paste it on the GitHub device authorization page.";
        }
        catch (System.Runtime.InteropServices.ExternalException)
        {
            CatalogDeviceCode.Focus();
            CatalogDeviceCode.SelectAll();
            CatalogAccountStatus.Text = "The clipboard is busy. Try Copy again or press Ctrl+C to copy the selected code.";
        }
    }

    private void CatalogOpenGitHub_Click(object sender, RoutedEventArgs e)
    {
        CatalogAccountStatus.Text = $"Enter the code below at {CatalogProtocol.GitHubDevicePage}.";
        try { Process.Start(new ProcessStartInfo(CatalogProtocol.GitHubDevicePage) { UseShellExecute = true })?.Dispose(); }
        catch (System.ComponentModel.Win32Exception)
        {
            CatalogAccountStatus.Text = $"Open {CatalogProtocol.GitHubDevicePage} in your browser and enter the code below.";
        }
    }

    private async void CatalogSignOut_Click(object sender, RoutedEventArgs e) => await RunCatalogOperation(CatalogAccountStatus, async ct =>
    {
        try { if (_catalogClient is not null) await _catalogClient.SignOut(ct); }
        finally
        {
            if (!_windowClosed) ResetCatalogAccount();
        }
        CatalogAccountStatus.Text = "Signed out.";
    });

    private void ResetCatalogAccount()
    {
        _catalogAccount = null;
        SetProfileButton(null);
        _catalogOnlineTimer.Stop();
        try { _catalogClient?.ForgetSession(); }
        catch (Exception ex) when (ex is IOException or UnauthorizedAccessException) { }
        _catalogClient?.Dispose();
        _catalogClient = null;
        ClearApprovedCatalog();
        CatalogAdminRequests.ItemsSource = null;
        CatalogAdminMembers.ItemsSource = null;
        CatalogInviteLogin.Clear();
        CatalogAdminStatus.Text = "";
        CatalogReviewDetails.Text = "";
        CatalogRequestStatus.Text = "";
        CatalogVendorPage.Clear();
        if (CatalogAdminPage.Visibility == Visibility.Visible || CatalogApprovedPage.Visibility == Visibility.Visible)
            ShowPage(AboutPage);
        UpdateCatalogAccountControls();
    }

    private async void CatalogSyncRequest_Click(object sender, RoutedEventArgs e)
    {
        if (_catalogAccount is not { Maintainer: false } || _catalogClient is not { } client ||
            CatalogList.SelectedItem is not CatalogRecord row || !CatalogSyncEligible(row)) return;
        var recipe = new RecipeInput(row.Product, row.Version, row.Publisher, CatalogVendorPage.Text.Trim(),
            row.Sha256, row.SigningIdentity.SignatureValid ? row.SigningIdentity.SignerThumbprint : "",
            Guid.Parse(row.SigningIdentity.Msi.ProductCode));
        await RunCatalogOperation(CatalogRequestStatus, async ct =>
        {
            if (!recipe.IsValid())
                throw new InvalidOperationException("Enter the official HTTPS vendor page without a query or fragment. A complete MSI identity is required.");
            await client.Submit(recipe, ct);
            CatalogRequestStatus.Text = $"Sync request sent for {recipe.Product} {recipe.Version}. It’s pending maintainer review.";
            CatalogVendorPage.Clear();
        });
    }

    private async void CatalogAdminNav_Click(object sender, RoutedEventArgs e)
    {
        if (_catalogAccount?.Maintainer != true) return;
        ShowPage(CatalogAdminPage);
        await SyncCatalogAdmin();
    }

    private async void CatalogAdminSync_Click(object sender, RoutedEventArgs e) => await SyncCatalogAdmin();

    private async Task SyncCatalogAdmin()
    {
        if (_catalogAccount?.Maintainer != true || _catalogClient is not { } client) return;
        await RunCatalogOperation(CatalogAdminStatus, async ct =>
        {
            CatalogAdminStatus.Text = "Checking for sync requests...";
            var pending = await RefreshCatalogAdmin(client, ct);
            var count = await RefreshApprovedCatalog(client, ct);
            CatalogAdminStatus.Text = $"{pending} pending sync request(s). {count} approved recipe(s).";
        });
    }

    private async Task<int> RefreshCatalogAdmin(OnlineCatalogClient client, CancellationToken ct)
    {
        var members = await client.Members(ct);
        var requests = await client.Submissions(ct);
        CatalogAdminMembers.ItemsSource = members.OrderBy(m => m.Login, StringComparer.OrdinalIgnoreCase).ToList();
        CatalogAdminRequests.ItemsSource = requests.OrderByDescending(r => r.Status == "Pending")
            .ThenByDescending(r => r.SubmittedAt).ToList();
        return requests.Count(r => r.Status == "Pending");
    }

    private async void CatalogInvite_Click(object sender, RoutedEventArgs e)
    {
        if (_catalogAccount?.Maintainer != true || _catalogClient is not { } client) return;
        await RunCatalogOperation(CatalogAdminStatus, async ct =>
        {
            var login = CatalogInviteLogin.Text.Trim();
            if (!CatalogProtocol.GitHubLogin().IsMatch(login)) throw new InvalidOperationException("Enter a GitHub username.");
            var member = await client.Invite(login, ct);
            CatalogInviteLogin.Clear();
            await RefreshCatalogAdmin(client, ct);
            CatalogAdminStatus.Text = $"{member.Login} can now sign in from Profile.";
        });
    }

    private async void CatalogRemoveMember_Click(object sender, RoutedEventArgs e)
    {
        if (_catalogAccount?.Maintainer != true || _catalogClient is not { } client ||
            CatalogAdminMembers.SelectedItem is not Member member ||
            MessageBox.Show(this, $"Remove catalog access for {member.Login}?", "Remove user", MessageBoxButton.YesNo,
                MessageBoxImage.Question, MessageBoxResult.No) != MessageBoxResult.Yes) return;
        await RunCatalogOperation(CatalogAdminStatus, async ct =>
        {
            await client.Remove(member.Id, ct);
            await RefreshCatalogAdmin(client, ct);
            CatalogAdminStatus.Text = $"Removed catalog access for {member.Login}.";
        });
    }

    private void CatalogReviewSelection_Changed(object sender, SelectionChangedEventArgs e)
    {
        CatalogReviewDetails.Text = CatalogAdminRequests.SelectedItem is RecipeSubmission request
            ? $"{request.Recipe.Product} {request.Recipe.Version} • {request.Status}\n" +
              $"Submitted by: {request.SubmittedByLogin ?? request.SubmittedBy.ToString()} (GitHub ID {request.SubmittedBy})\n" +
              $"Submitted: {request.SubmittedAt?.ToLocalTime().ToString("g") ?? "Unavailable"}\n" +
              $"Publisher: {request.Recipe.Publisher}\nVendor page: {request.Recipe.VendorPage}\n" +
              $"SHA-256: {request.Recipe.Sha256}\n" +
              (request.Recipe.SignerThumbprint.Length == 0 ? "Signature: Unsigned\n" : $"Signer thumbprint: {request.Recipe.SignerThumbprint}\n") +
              $"MSI product code: {request.Recipe.ProductCode:B}"
            : "Select a sync request to view its details.";
    }

    private async void CatalogReview_Click(object sender, RoutedEventArgs e)
    {
        if (_catalogAccount?.Maintainer != true || _catalogClient is not { } client ||
            sender is not Button { Tag: string action } || CatalogAdminRequests.SelectedItem is not RecipeSubmission request) return;
        if (action == "revoke" ? request.Status != "Published" : request.Status != "Pending")
        {
            CatalogAdminStatus.Text = "Approve or reject a pending request. Revoke an already published recipe.";
            return;
        }
        var message = action == "publish"
            ? $"Approve and publish {request.Recipe.Product} {request.Recipe.Version}? Confirm that you independently verified the installer and tested the recipe."
            : $"Confirm {action} for {request.Recipe.Product} {request.Recipe.Version}.";
        if (MessageBox.Show(this, message, "Review sync request", MessageBoxButton.YesNo, MessageBoxImage.Question, MessageBoxResult.No) != MessageBoxResult.Yes) return;
        await RunCatalogOperation(CatalogAdminStatus, async ct =>
        {
            await client.Decide(request.Id, action, ct);
            ClearApprovedCatalog();
            await RefreshCatalogAdmin(client, ct);
            CatalogAdminStatus.Text = "Review decision saved.";
        });
    }

    private async void CatalogApproved_Click(object sender, RoutedEventArgs e)
    {
        if (_catalogAccount is null) return;
        ShowPage(CatalogApprovedPage);
        await LoadApprovedCatalog();
    }

    private async void CatalogApprovedRefresh_Click(object sender, RoutedEventArgs e) => await LoadApprovedCatalog();

    private async Task LoadApprovedCatalog()
    {
        if (_catalogAccount is null || _catalogClient is not { } client) return;
        await RunCatalogOperation(CatalogApprovedStatus, async ct =>
        {
            var count = await RefreshApprovedCatalog(client, ct);
            CatalogApprovedStatus.Text = $"{count} approved recipe(s). Verify your local MSI before running fresh Sandbox validation.";
        });
    }

    private async Task<int> RefreshApprovedCatalog(OnlineCatalogClient client, CancellationToken ct)
    {
        ClearApprovedCatalog();
        _catalogSnapshot = await client.Sync(ct);
        CatalogApprovedList.ItemsSource = _catalogSnapshot.Recipes;
        return _catalogSnapshot.Recipes.Length;
    }

    private void ClearApprovedCatalog()
    {
        _catalogSnapshot = null;
        CatalogApprovedList.ItemsSource = null;
    }

    private async void CatalogVerify_Click(object sender, RoutedEventArgs e)
    {
        if (_catalogAccount is null || _catalogClient is not { } client ||
            _catalogSnapshot is null || CatalogApprovedList.SelectedItem is not RecipeInput recipe) return;
        var picker = new OpenFileDialog { Filter = "Windows Installer (*.msi)|*.msi", Title = "Select your copy of the MSI" };
        if (picker.ShowDialog(this) != true) return;
        await RunCatalogOperation(CatalogApprovedStatus, async ct =>
        {
            await RefreshApprovedCatalog(client, ct);
            if (_catalogSnapshot is not { } snapshot || !snapshot.Recipes.Contains(recipe))
                throw new InvalidOperationException("The selected recipe is no longer approved.");
            var identity = await Task.Run(() => new InstallerDetector().Analyze(picker.FileName).Identity, ct);
            ct.ThrowIfCancellationRequested();
            var signatureMatches = recipe.SignerThumbprint.Length == 0
                ? identity.SignatureStatus == "NotSigned"
                : identity.SignatureValid && recipe.SignerThumbprint.Equals(identity.SignerThumbprint, StringComparison.OrdinalIgnoreCase);
            if (!signatureMatches || !recipe.Sha256.Equals(identity.Sha256, StringComparison.OrdinalIgnoreCase) ||
                !Guid.TryParse(identity.Msi.ProductCode, out var productCode) || productCode != recipe.ProductCode)
                throw new InvalidOperationException("The MSI does not match the approved file hash, signature status or signer, and product code.");
            CatalogApprovedStatus.Text = "The MSI matches. Open it in Analyze and run a fresh Sandbox validation before deployment.";
        });
    }
}

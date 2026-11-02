using System.IO;
using System.Text.Json;
using System.Text.RegularExpressions;
using InstallerAnalyzer.Models;
using Microsoft.Data.Sqlite;

namespace InstallerAnalyzer.Services;

public static partial class InstallerCatalogService
{
    private static readonly JsonSerializerOptions CatalogJson = new() { WriteIndented = true };
    private static void EnsureRoadmapSchema(SqliteConnection db)
    {
        using var command = db.CreateCommand();
        command.CommandText = """
            CREATE TABLE IF NOT EXISTS CatalogMetadata (Sha256 TEXT PRIMARY KEY, RecordJson TEXT NOT NULL);
            CREATE TABLE IF NOT EXISTS CatalogValidations (Sha256 TEXT NOT NULL, ProofId TEXT NOT NULL, RecordJson TEXT NOT NULL, PRIMARY KEY(Sha256,ProofId));
            CREATE TABLE IF NOT EXISTS ImportedCandidates (Sha256 TEXT PRIMARY KEY, RecordJson TEXT NOT NULL);
            """;
        command.ExecuteNonQuery();
    }

    private static void RememberDetails(SqliteConnection db, SqliteTransaction transaction, AnalysisResult installer,
        InstallAnalysis proof, string hash, string arguments, string source, string proofId)
    {
        var primary = proof.NewUninstallEntries.First(e => e.Key == proof.PrimaryKey);
        using var command = db.CreateCommand();
        command.Transaction = transaction;
        command.CommandText = "SELECT RecordJson FROM CatalogMetadata WHERE Sha256=$hash";
        command.Parameters.AddWithValue("$hash", hash);
        var previous = command.ExecuteScalar() as string;
        var detail = previous is null ? new CatalogRecord() : JsonSerializer.Deserialize<CatalogRecord>(previous) ?? new();
        var now = DateTimeOffset.UtcNow.ToString("O");
        detail.Sha256 = hash; detail.Product = primary.DisplayName ?? installer.ProductName;
        detail.ProductFamily = installer.ProductName; detail.Version = primary.DisplayVersion ?? installer.FileVersion;
        detail.Publisher = primary.Publisher ?? installer.CompanyName; detail.Architecture = installer.Architecture;
        detail.Family = installer.Kind.ToString(); detail.InstallArguments = arguments;
        detail.DeploymentSource = installer.FileName; detail.DeploymentMechanism = proof.DeploymentMechanism ?? installer.Kind.ToString();
        detail.ApplicationIdentity = proof.PrimaryKey ?? ""; detail.LocalInstallerPath = installer.FilePath;
        detail.SigningIdentity = installer.Identity; detail.Origin = "Local validated";
        detail.RebootRequired = proof.RebootRequired; detail.PostRebootValidated = proof.PostRebootValidated;
        detail.Detection = proof.DetectionStrategies.Where(d => d.Validated).OrderByDescending(d => d.Rank).FirstOrDefault();
        detail.UninstallType = primary.Key?.StartsWith("APPX::", StringComparison.Ordinal) == true ? "MsixPackageIdentity" :
            !string.IsNullOrWhiteSpace(primary.ProductCode) ? "MsiProductCode" : "ValidatedVendorCommand";
        detail.UninstallIdentity = detail.UninstallType == "ValidatedVendorCommand" ? primary.Key ?? "" : primary.ProductCode ?? "";
        if (detail.FirstValidatedUtc.Length == 0) detail.FirstValidatedUtc = now;
        detail.LastValidatedUtc = now;
        // The canonical strategy stores data, not an executable script or Sandbox path.
        command.CommandText = "INSERT INTO CatalogMetadata VALUES($hash,$json) ON CONFLICT(Sha256) DO UPDATE SET RecordJson=excluded.RecordJson";
        command.Parameters.AddWithValue("$json", JsonSerializer.Serialize(detail, CatalogJson)); command.ExecuteNonQuery();
        var history = new CatalogValidation
        {
            ProofId = proofId, TimestampUtc = now, AnalyzerVersion = typeof(InstallerCatalogService).Assembly.GetName().Version?.ToString() ?? "",
            InstallerSha256 = hash, Source = source, StrategyType = detail.Family, InstallArguments = arguments,
            InstallPassed = LifecycleValidationService.InstallPassed(proof), DetectionPassed = detail.Detection?.Validated == true,
            UninstallPassed = LifecycleValidationService.UninstallPassed(proof), RemovalPassed = proof.PostUninstallDetected == false,
            Confidence = installer.Confidence,
            DurationSeconds = DateTimeOffset.TryParse(proof.WorkflowStageHistory.FirstOrDefault()?.At, out var start) &&
                DateTimeOffset.TryParse(proof.CapturedAt, out var finish) ? Math.Max(0, (finish - start).TotalSeconds) : null
        };
        command.CommandText = "INSERT OR IGNORE INTO CatalogValidations VALUES($hash,$proof,$json)";
        command.Parameters["$json"].Value = JsonSerializer.Serialize(history, CatalogJson);
        command.Parameters.AddWithValue("$proof", proofId); command.ExecuteNonQuery();
        command.CommandText = "DELETE FROM ImportedCandidates WHERE Sha256=$hash"; command.ExecuteNonQuery();
    }

    public static List<CatalogRecord> ReadCatalog(bool includeImported = true)
    {
        using var db = Open();
        return ReadCatalog(db, includeImported);
    }

    private static List<CatalogRecord> ReadCatalog(SqliteConnection db, bool includeImported)
    {
        using var cmd = db.CreateCommand();
        cmd.CommandText = "SELECT Sha256,Product,Version,Publisher,Architecture,Family,Arguments,ProductCode,DetectionKey,DeploymentMechanism,IdentitySource,Validations,LastValidatedUtc FROM ValidatedInstallers";
        var rows = new List<CatalogRecord>();
        using (var reader = cmd.ExecuteReader())
            while (reader.Read()) rows.Add(new()
            {
                Sha256 = reader.GetString(0), Product = reader.GetString(1), Version = reader.GetString(2), Publisher = reader.GetString(3),
                Architecture = reader.GetString(4), Family = reader.GetString(5), InstallArguments = reader.GetString(6),
                UninstallIdentity = reader.IsDBNull(7) ? "" : reader.GetString(7), ApplicationIdentity = reader.IsDBNull(8) ? "" : reader.GetString(8),
                DeploymentMechanism = reader.IsDBNull(9) ? "" : reader.GetString(9), Validations = reader.GetInt32(11), LastValidatedUtc = reader.GetString(12)
            });
        var tables = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
        cmd.CommandText = "SELECT name FROM sqlite_master WHERE type='table'";
        using (var reader = cmd.ExecuteReader()) while (reader.Read()) tables.Add(reader.GetString(0));
        foreach (var row in rows)
        {
            cmd.Parameters.Clear(); cmd.Parameters.AddWithValue("$hash", row.Sha256);
            if (tables.Contains("CatalogMetadata"))
            {
                cmd.CommandText = "SELECT RecordJson FROM CatalogMetadata WHERE Sha256=$hash";
                if (cmd.ExecuteScalar() is string json)
                {
                    var metadata = JsonSerializer.Deserialize<CatalogRecord>(json);
                    if (metadata is not null)
                    {
                        // Keep authoritative row counters and strategy; metadata enriches them.
                        row.ProductFamily = metadata.ProductFamily; row.SigningIdentity = metadata.SigningIdentity;
                        row.DeploymentSource = metadata.DeploymentSource; row.LocalInstallerPath = metadata.LocalInstallerPath;
                        row.Detection = metadata.Detection; row.UninstallType = metadata.UninstallType;
                        row.UninstallIdentity = metadata.UninstallIdentity; row.RebootRequired = metadata.RebootRequired;
                        row.PostRebootValidated = metadata.PostRebootValidated;
                        row.FirstValidatedUtc = metadata.FirstValidatedUtc; row.Failures = metadata.Failures;
                    }
                }
            }
            if (tables.Contains("CatalogValidations"))
            {
                cmd.CommandText = "SELECT RecordJson FROM CatalogValidations WHERE Sha256=$hash";
                using var reader = cmd.ExecuteReader();
                while (reader.Read()) if (JsonSerializer.Deserialize<CatalogValidation>(reader.GetString(0)) is { } entry) row.History.Add(entry);
            }
        }
        if (includeImported && tables.Contains("ImportedCandidates"))
        {
            cmd.Parameters.Clear(); cmd.CommandText = "SELECT RecordJson FROM ImportedCandidates";
            using var reader = cmd.ExecuteReader();
            while (reader.Read()) if (JsonSerializer.Deserialize<CatalogRecord>(reader.GetString(0)) is { } item) rows.Add(item);
        }
        return rows.OrderBy(r => r.Product, StringComparer.OrdinalIgnoreCase).ToList();
    }

    public static bool ApplyBestMatch(AnalysisResult result) => ApplyBestMatchCore(result, null);

    private static bool ApplyBestMatchCore(AnalysisResult result, string? snapshotHash)
    {
        if (ApplyExactMatchCore(result, snapshotHash)) return true;
        try
        {
            var identity = result.Identity;
            var records = ReadCatalog();
            var related = records.Where(r => r.Origin == "Local validated" && result.Kind != InstallerKind.Unknown &&
                identity.SignatureValid && r.SigningIdentity.SignatureValid && identity.SignerThumbprint.Length > 0 &&
                string.Equals(identity.SignerThumbprint, r.SigningIdentity.SignerThumbprint, StringComparison.OrdinalIgnoreCase) &&
                RelatedProductIdentity(result, r) &&
                result.Kind.ToString() == r.Family && result.Architecture != "Unknown" && result.Architecture == r.Architecture)
                .OrderByDescending(r => r.LastValidatedUtc).FirstOrDefault();
            var imported = records.FirstOrDefault(r => r.Origin == "Imported candidate" && identity.Sha256.Equals(r.Sha256, StringComparison.OrdinalIgnoreCase));
            var candidate = related ?? imported;
            if (candidate is null || !SafeArguments(candidate.InstallArguments)) return false;
            result.SuggestedArguments = candidate.InstallArguments;
            if (related is null) result.Kind = Enum.Parse<InstallerKind>(candidate.Family);
            result.CatalogMatch = related is null ? "Imported candidate — not locally validated" : "Related signed product — candidate only";
            result.Evidence.Add(result.CatalogMatch + ". Fresh complete Sandbox validation is required; no validation status is inherited.");
            return true;
        }
        catch (Exception ex) { result.Evidence.Add("Catalog candidates unavailable: " + ex.Message); return false; }
    }

    private static bool SafeArguments(string value) => value.Length <= 4096 && value.IndexOfAny(['\r', '\n', '\0', '`', '$']) < 0;

    private static bool RelatedProductIdentity(AnalysisResult result, CatalogRecord record)
    {
        var currentCode = result.Identity.Msi.UpgradeCode; var previousCode = record.SigningIdentity.Msi.UpgradeCode;
        if (result.Kind == InstallerKind.Msi && Guid.TryParse(currentCode, out var current) && current != Guid.Empty && Guid.TryParse(previousCode, out var previous) && previous != Guid.Empty)
            return current == previous; // A conflicting stable product identity defeats a matching display name.
        return !string.IsNullOrWhiteSpace(result.ProductName) && string.Equals(result.ProductName.Trim(), record.ProductFamily.Trim(), StringComparison.OrdinalIgnoreCase);
    }

    public static void ExportCatalog(string path)
    {
        if (Path.GetFullPath(path).Equals(Path.GetFullPath(DatabasePath), StringComparison.OrdinalIgnoreCase))
            throw new InvalidOperationException("Choose an export file separate from the active database.");
        var entries = ReadCatalog();
        foreach (var record in entries)
        {
            record.LocalInstallerPath = ""; // Not portable and not needed in shared catalogs.
            record.History = record.History.OrderBy(h => h.TimestampUtc).ToList();
        }
        File.WriteAllText(path, JsonSerializer.Serialize(new CatalogTransfer { Entries = entries }, CatalogJson));
    }

    public static CatalogImportResult ImportCatalog(string path)
    {
        if (new FileInfo(path).Length > 20 * 1024 * 1024) throw new InvalidDataException("Catalog exceeds the 20 MB import limit.");
        var transfer = JsonSerializer.Deserialize<CatalogTransfer>(File.ReadAllText(path)) ?? throw new InvalidDataException("Empty catalog.");
        return MergeCandidates(transfer);
    }

    private static CatalogImportResult MergeCandidates(CatalogTransfer transfer)
    {
        if (transfer.SchemaVersion != 1 || transfer.Entries is null || transfer.Entries.Count > 5000)
            throw new InvalidDataException("Unsupported catalog schema or entry count.");
        foreach (var item in transfer.Entries)
            if (item is null || !Regex.IsMatch(item.Sha256 ?? "", "^[a-fA-F0-9]{64}$") ||
                !Enum.TryParse<InstallerKind>(item.Family, out var family) || !Enum.IsDefined(family) ||
                item.InstallArguments is null || !SafeArguments(item.InstallArguments) || string.IsNullOrWhiteSpace(item.Product) ||
                item.SigningIdentity is null || item.SigningIdentity.Msi is null || item.History is null || item.History.Any(h => h is null))
                throw new InvalidDataException("Catalog contains an invalid identity or non-structured strategy.");
        using var db = Open(); using var transaction = db.BeginTransaction();
        int imported = 0, preserved = 0;
        foreach (var item in transfer.Entries)
        {
            item.Sha256 = item.Sha256.ToUpperInvariant();
            using var cmd = db.CreateCommand(); cmd.Transaction = transaction;
            cmd.Parameters.AddWithValue("$hash", item.Sha256);
            cmd.CommandText = "SELECT COUNT(*) FROM ValidatedInstallers WHERE Sha256=$hash";
            if (Convert.ToInt32(cmd.ExecuteScalar()) > 0) { preserved++; continue; }
            cmd.CommandText = "SELECT RecordJson FROM ImportedCandidates WHERE Sha256=$hash";
            if (cmd.ExecuteScalar() is string previous)
            {
                var old = JsonSerializer.Deserialize<CatalogRecord>(previous)!;
                if (string.CompareOrdinal(old.LastValidatedUtc, item.LastValidatedUtc) >= 0) { preserved++; continue; }
            }
            item.Origin = "Imported candidate"; item.LocalInstallerPath = ""; item.Validations = 0;
            // Foreign history is useful evidence, but cannot claim a local validation.
            foreach (var history in item.History) history.Source = "Imported / unverified";
            cmd.CommandText = "INSERT INTO ImportedCandidates VALUES($hash,$json) ON CONFLICT(Sha256) DO UPDATE SET RecordJson=excluded.RecordJson";
            cmd.Parameters.AddWithValue("$json", JsonSerializer.Serialize(item, CatalogJson)); cmd.ExecuteNonQuery(); imported++;
        }
        transaction.Commit(); return new(imported, preserved);
    }

    public static void BackupCatalog(string path)
    {
        if (Path.GetFullPath(path).Equals(Path.GetFullPath(DatabasePath), StringComparison.OrdinalIgnoreCase))
            throw new InvalidOperationException("Choose a separate backup file.");
        using var source = Open();
        using var destination = new SqliteConnection(new SqliteConnectionStringBuilder { DataSource = path }.ToString());
        destination.Open(); source.BackupDatabase(destination);
    }

    public static CatalogImportResult RestoreCatalog(string path)
    {
        if (new FileInfo(path).Length > 100 * 1024 * 1024) throw new InvalidDataException("Backup exceeds the 100 MB restore limit.");
        using var backup = new SqliteConnection(new SqliteConnectionStringBuilder { DataSource = path, Mode = SqliteOpenMode.ReadOnly, Pooling = false }.ToString());
        backup.Open(); using var command = backup.CreateCommand(); command.CommandText = "PRAGMA quick_check";
        if (!string.Equals(command.ExecuteScalar()?.ToString(), "ok", StringComparison.Ordinal)) throw new InvalidDataException("Backup integrity check failed.");
        // Restore merges candidates. Existing local proof and newer strategies are preserved.
        return MergeCandidates(new CatalogTransfer { Entries = ReadCatalog(backup, true) });
    }

    public static void RemoveEntry(string hash)
    {
        using var db = Open(); using var transaction = db.BeginTransaction();
        foreach (var table in new[] { "ValidatedInstallers", "CatalogMetadata", "CatalogValidations", "ImportedCandidates" })
        {
            using var command = db.CreateCommand(); command.Transaction = transaction;
            command.CommandText = "DELETE FROM " + table + " WHERE Sha256=$hash";
            command.Parameters.AddWithValue("$hash", hash); command.ExecuteNonQuery();
        }
        transaction.Commit();
    }

    public static void RecordFailure(string hash)
    {
        using var db = Open(); using var transaction = db.BeginTransaction(); using var cmd = db.CreateCommand(); cmd.Transaction = transaction;
        cmd.CommandText = "SELECT RecordJson FROM CatalogMetadata WHERE Sha256=$hash"; cmd.Parameters.AddWithValue("$hash", hash);
        if (cmd.ExecuteScalar() is not string json) return;
        var detail = JsonSerializer.Deserialize<CatalogRecord>(json)!; detail.Failures++;
        cmd.CommandText = "UPDATE CatalogMetadata SET RecordJson=$json WHERE Sha256=$hash";
        cmd.Parameters.AddWithValue("$json", JsonSerializer.Serialize(detail, CatalogJson)); cmd.ExecuteNonQuery(); transaction.Commit();
    }
}

using System.IO;
using System.Security.Cryptography;
using Microsoft.Data.Sqlite;
using InstallerAnalyzer.Models;

namespace InstallerAnalyzer.Services;

// A catalog hit supplies a candidate, never a substitute for fresh Sandbox proof.
public static partial class InstallerCatalogService
{
    internal static string? TestDatabasePath;
    private static readonly System.Runtime.CompilerServices.ConditionalWeakTable<InstallAnalysis, object> Recorded = new();
    public static string DatabasePath => TestDatabasePath ?? Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData), "InstallerAnalyzer", "InstallerCatalog.db");
    private static SqliteConnection Open()
    {
        Directory.CreateDirectory(Path.GetDirectoryName(DatabasePath)!);
        var db = new SqliteConnection(new SqliteConnectionStringBuilder { DataSource = DatabasePath }.ToString());
        db.Open();
        using var cmd = db.CreateCommand();
        cmd.CommandText = """
            CREATE TABLE IF NOT EXISTS ValidatedInstallers (
                Sha256 TEXT PRIMARY KEY, Product TEXT NOT NULL, Version TEXT NOT NULL,
                Publisher TEXT NOT NULL, Architecture TEXT NOT NULL, Family TEXT NOT NULL,
                Arguments TEXT NOT NULL, ProductCode TEXT, DetectionKey TEXT,
                UninstallCommand TEXT, DeploymentMechanism TEXT, IdentitySource TEXT,
                Validations INTEGER NOT NULL DEFAULT 1, LastValidatedUtc TEXT NOT NULL, LastProof TEXT NOT NULL);
            """;
        cmd.ExecuteNonQuery();
        cmd.CommandText = "SELECT COUNT(*) FROM pragma_table_info('ValidatedInstallers') WHERE name='LastProof'";
        if (Convert.ToInt32(cmd.ExecuteScalar()) == 0)
        {
            cmd.CommandText = "ALTER TABLE ValidatedInstallers ADD COLUMN LastProof TEXT NOT NULL DEFAULT ''";
            cmd.ExecuteNonQuery();
        }
        EnsureRoadmapSchema(db);
        return db;
    }
    private static string Hash(string path)
    {
        using var file = File.OpenRead(path);
        return Convert.ToHexString(SHA256.HashData(file));
    }
    public static List<CatalogItem> ReadEntries()
    {
        using var db = Open();
        using var cmd = db.CreateCommand();
        cmd.CommandText = "SELECT Product,Version,Publisher,Family,Arguments,Validations,LastValidatedUtc,Sha256 FROM ValidatedInstallers ORDER BY LastValidatedUtc DESC";
        using var reader = cmd.ExecuteReader();
        var rows = new List<CatalogItem>();
        while (reader.Read()) rows.Add(new(reader.GetString(0),reader.GetString(1),reader.GetString(2),reader.GetString(3),reader.GetString(4),reader.GetInt32(5),reader.GetString(6),reader.GetString(7)));
        return rows;
    }
    public static AnalysisResult AnalyzeWithCatalog(string path, InstallerDetector detector)
        => AnalyzeWithCatalogSnapshot(path, detector.Analyze);

    internal static AnalysisResult AnalyzeWithCatalogSnapshot(string path, Func<string, AnalysisResult> inspect)
    {
        path = Path.GetFullPath(path);
        // Keep writers and replacements out while inspection and catalog matching share
        // this operation's hash. Independent callers still hash the current file afresh.
        using var snapshot = new FileStream(path, FileMode.Open, FileAccess.Read, FileShare.Read);
        var result = inspect(path);
        if (!Path.GetFullPath(result.FilePath).Equals(path, StringComparison.OrdinalIgnoreCase))
            throw new InvalidDataException("Inspection identity belongs to a different installer.");
        if (result.Identity.Sha256.Length != 64 || !result.Identity.Sha256.All(Uri.IsHexDigit))
            throw new InvalidDataException("Inspection did not produce a valid installer identity.");
        ApplyBestMatchCore(result, result.Identity.Sha256);
        return result;
    }

    public static bool ApplyExactMatch(AnalysisResult result) => ApplyExactMatchCore(result, null);

    private static bool ApplyExactMatchCore(AnalysisResult result, string? snapshotHash)
    {
        try
        {
            using var db = Open();
            using var cmd = db.CreateCommand();
            cmd.CommandText = "SELECT Arguments,Family,Product,Version,Publisher,Architecture FROM ValidatedInstallers WHERE Sha256=$hash";
            cmd.Parameters.AddWithValue("$hash", snapshotHash ?? Hash(result.FilePath));
            using var row = cmd.ExecuteReader();
            if (!row.Read() || !Enum.TryParse<InstallerKind>(row.GetString(1), out var family) || !Enum.IsDefined(family)) return false;
            result.SuggestedArguments = row.GetString(0);
            result.Kind = family;
            result.NeedsIss = false;
            if (!string.IsNullOrWhiteSpace(row.GetString(2))) result.ProductName = row.GetString(2);
            if (!string.IsNullOrWhiteSpace(row.GetString(3))) result.FileVersion = row.GetString(3);
            if (!string.IsNullOrWhiteSpace(row.GetString(4))) result.CompanyName = row.GetString(4);
            if (!string.IsNullOrWhiteSpace(row.GetString(5))) result.Architecture = row.GetString(5);
            result.Evidence.Add("Local catalog: exact SHA-256 previously passed silent install, uninstall and removal. Fresh Sandbox validation still required.");
            result.CatalogMatch = "Exact validated installer";
            return true;
        }
        catch (Exception ex) { result.Evidence.Add("Local catalog unavailable: " + ex.Message); return false; }
    }
    public static bool Remember(AnalysisResult installer, InstallAnalysis? proof, string source = "Analyze")
    {
        if (proof is not null && Recorded.TryGetValue(proof, out _)) return false;
        if (!LifecycleValidationService.IsComplete(proof) || installer.NeedsIss) return false;
        // IsComplete guarantees non-null, identity and clean lifecycle evidence.
        if (proof is null) return false;
        // Extracted payloads and response files need their own packaged-source model. Never replay
        // a child command against the original bootstrapper merely because that lifecycle passed.
        var selected = proof.SilentStrategyCandidates.FirstOrDefault(c => c.Name == proof.SelectedSilentStrategy);
        var file = selected?.File ?? proof.DeploymentSource;
        if (string.IsNullOrWhiteSpace(file) ||
            !(file.Equals(Path.Combine("C:\\InstallerInput", installer.FileName), StringComparison.OrdinalIgnoreCase) ||
              file.Equals(installer.FilePath, StringComparison.OrdinalIgnoreCase))) return false;
        var arguments = selected?.Arguments ?? proof.CombinedSilentArguments;
        if ((string.IsNullOrWhiteSpace(arguments) && installer.Kind != InstallerKind.Msix) ||
            (arguments?.Contains("C:\\Installer", StringComparison.OrdinalIgnoreCase) ?? false)) return false;
        arguments ??= "";
        var primary = proof.NewUninstallEntries.FirstOrDefault(e => e.Key == proof.PrimaryKey);
        if (primary is null) return false;
        var packageHash = Hash(installer.FilePath);
        if (!string.IsNullOrWhiteSpace(proof.InstallerSha256) && !packageHash.Equals(proof.InstallerSha256, StringComparison.OrdinalIgnoreCase)) return false;
        var proofId = proof.SessionId ?? proof.WorkflowStageHistory.FirstOrDefault()?.At ?? proof.CapturedAt;
        using var db = Open();
        using var transaction = db.BeginTransaction();
        using var cmd = db.CreateCommand();
        cmd.Transaction = transaction;
        cmd.CommandText = "SELECT COUNT(*) FROM CatalogValidations WHERE Sha256=$seenHash AND ProofId=$seenProof";
        cmd.Parameters.AddWithValue("$seenHash", packageHash);
        cmd.Parameters.AddWithValue("$seenProof", proofId ?? proof.CapturedAt!);
        if (Convert.ToInt32(cmd.ExecuteScalar()) > 0) return false;
        cmd.Parameters.Clear();
        cmd.CommandText = """
            INSERT INTO ValidatedInstallers
            (Sha256,Product,Version,Publisher,Architecture,Family,Arguments,ProductCode,DetectionKey,UninstallCommand,DeploymentMechanism,IdentitySource,LastValidatedUtc,LastProof)
            VALUES ($hash,$product,$version,$publisher,$arch,$family,$args,$code,$key,$uninstall,$mechanism,$identity,$at,$proof)
            ON CONFLICT(Sha256) DO UPDATE SET Arguments=excluded.Arguments,
            Product=excluded.Product,Version=excluded.Version,Publisher=excluded.Publisher,
            Architecture=excluded.Architecture,Family=excluded.Family,ProductCode=excluded.ProductCode,
            DetectionKey=excluded.DetectionKey,DeploymentMechanism=excluded.DeploymentMechanism,IdentitySource=excluded.IdentitySource,
            UninstallCommand=excluded.UninstallCommand, Validations=Validations+1,LastValidatedUtc=excluded.LastValidatedUtc,LastProof=excluded.LastProof
            WHERE LastProof <> excluded.LastProof;
            """;
        foreach (var pair in new Dictionary<string,string?> {
            ["$hash"]=packageHash, ["$product"]=primary.DisplayName, ["$version"]=primary.DisplayVersion,
            ["$publisher"]=primary.Publisher, ["$arch"]=installer.Architecture, ["$family"]=installer.Kind.ToString(),
            ["$args"]=arguments, ["$code"]=primary.ProductCode, ["$key"]=primary.Key,
            ["$uninstall"]=proof.UninstallCandidate, ["$mechanism"]=proof.DeploymentMechanism,
            ["$identity"]=proof.IdentitySource, ["$at"]=DateTime.UtcNow.ToString("O"), ["$proof"]=proofId })
            cmd.Parameters.AddWithValue(pair.Key, pair.Value ?? "");
        var written = cmd.ExecuteNonQuery();
        if (written > 0) RememberDetails(db, transaction, installer, proof, packageHash, arguments, source, proofId ?? proof.CapturedAt!);
        transaction.Commit();
        Recorded.GetValue(proof, _ => new object());
        return written > 0;
    }
}
public sealed record CatalogItem(string Product, string Version, string Publisher, string Family, string Arguments, int Validations, string LastValidatedUtc, string Sha256);

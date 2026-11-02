namespace InstallerAnalyzer.Models;
public sealed class MsiConditionObservation
{
    public string Condition { get; set; } = "";
    public string Description { get; set; } = "";
    public bool? Result { get; set; }
    public List<string> UnresolvedSymbols { get; set; } = new();
    public string Scope { get; set; } = "Observed initial product state; no MSI action sequence or runtime property changes simulated";
    public string Explanation { get; set; } = "";
}

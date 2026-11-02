using InstallerAnalyzer.Models;
using InstallerAnalyzer.Services;

internal static class MsiConditionChecks
{
    public static void Run(string root, Action<bool,string> check)
    {
        var values = new Dictionary<string,string?>(StringComparer.Ordinal) { ["Installed"] = null, ["ZERO"] = "0", ["NAME"] = "Example", ["%Path"] = "observed", ["QUOTE"] = "x\" OR 1 OR \"y" };
        bool? Eval(string expression) => MsiConditionEvaluator.Evaluate(expression, values).Result;
        foreach (var (expression, expected) in new (string,bool)[] { ("1",true),("0",false),("-1",true),("NOT 0",true),("1 AND 0 OR 1",true),("1 OR 0 AND 0",true),("(1 OR 0) AND 0",false),("1 XOR 1",false),("1 EQV 1",true),("0 IMP 0",true),("1 IMP 0",false),("1 OR 0 XOR 1",false),("10 < 2",false),("\"A\" ~= \"a\"",true),("\"Abc\" ~>< \"B\"",true),("\"abc\" << \"a\"",true),("\"abc\" >> \"c\"",true),("5 >< 1",true),("65536 << 1",true),("65537 >> 1",true),("\"bad\" = 1",false),("\"bad\" <> 1",true) })
        {
            check(Eval(expression) == expected, "Condition follows documented literal semantics: " + expression);
        }
        check(Eval("NOT Installed") == true && Eval("Installed") == false, "Explicit absent product state supplies an unset Installed property");
        check(Eval("ZERO") == true && Eval("ZERO = 0") == true, "Nonempty property zero is true but compares numerically when requested");
        check(Eval("\"+1\" = 1") == false && Eval("\"01\" = 1") == false && Eval("\"-0\" = 0") == false, "String-to-integer comparisons require MSI's canonical decimal form");
        check(Eval("\"Z\" < \"a\"") == true && Eval("-65536 << 65535") == false, "String ordering and signed high-word extraction match the native oracle");
        check(Eval("\"Ä\" ~= \"ä\"") is null, "Unverified non-ASCII case folding stays unknown");
        check(Eval("Installed OR UNKNOWN") is null && Eval("NOT Installed OR UNKNOWN") == true, "Unknown observations retain conservative three-valued Boolean behavior");
        check(Eval("UNKNOWN AND 0") == false && Eval("UNKNOWN OR 1") == true, "Known Boolean operands can resolve otherwise unknown expressions");
        check(Eval("NAME = \"Example\"") == true && Eval("name = \"Example\"") is null, "MSI property identifiers remain case sensitive");
        check(Eval("%PATH = \"observed\"") == true, "Explicit environment observations use case-insensitive names");
        check(Eval("?Component = 3") is null && Eval("&Feature = 3") is null, "Unobserved component/feature action state is not invented");
        check(Eval("QUOTE = \"x\"") == false, "Observed quotes remain data and cannot inject Boolean operators");
        foreach (var invalid in new[] { "1 OR", "1; 0", "(1", "1 + 1", "2147483648", new string('(', 100)+"1"+new string(')',100), new string('x',4097) })
            check(Eval(invalid) is null, "Malformed/unsupported/over-budget condition remains unknown");
        var unknown = MsiConditionEvaluator.Evaluate("UNOBSERVED OR NotSeen", values);
        check(unknown.UnresolvedSymbols.SequenceEqual(new[] { "NotSeen", "UNOBSERVED" }), "Unknown symbol names are retained without raw observed property values");
        var proof = new InstallAnalysis { MsiProductStateBefore = -1 };
        var installer = new AnalysisResult(); installer.Identity.Msi.LaunchConditions.Add(new() { Condition="NOT Installed", Description="First install condition" });
        IntelligenceReportService.Enrich(proof, installer, null);
        check(proof.MsiConditions.Single().Result == true && proof.Intelligence.Prerequisites.Single().Status == "Declared; not evaluated", "Scoped observed condition evaluation never substitutes for actual launch-sequence acceptance");
    }
}

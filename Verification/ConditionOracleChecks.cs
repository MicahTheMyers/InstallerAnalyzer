using System.IO;
using System.Runtime.InteropServices;
using InstallerAnalyzer.Services;

internal static class ConditionOracleChecks
{
    [DllImport("msi.dll", EntryPoint="MsiOpenPackageExW", CharSet=CharSet.Unicode)] private static extern uint Open(string path, uint options, out uint session);
    [DllImport("msi.dll", EntryPoint="MsiSetPropertyW", CharSet=CharSet.Unicode)] private static extern uint Set(uint session,string name,string value);
    [DllImport("msi.dll", EntryPoint="MsiEvaluateConditionW", CharSet=CharSet.Unicode)] private static extern int Evaluate(uint session,string expression);
    [DllImport("msi.dll", EntryPoint="MsiCloseHandle")] private static extern uint Close(uint session);
    public static int Run(string root, string fixture)
    {
        uint session=0;
        try
        {
            if (Open(fixture, 1, out session) != 0) throw new Exception("Authored empty condition package could not be opened.");
            var values = new Dictionary<string,string?> { ["Installed"] = null, ["ZERO"] = "0", ["NAME"] = "Example", ["QUOTE"] = "x\" OR 1 OR \"y" };
            foreach(var entry in values) if(Set(session,entry.Key,entry.Value??"")!=0) throw new Exception("Cannot populate authored oracle context.");
            var conditions = new[] { "1", "0", "-1", "NOT 0", "1 AND 0 OR 1", "1 OR 0 AND 0", "(1 OR 0) AND 0", "1 XOR 1", "1 EQV 1", "0 IMP 0", "1 IMP 0", "1 OR 0 XOR 1", "0 EQV 0 IMP 1", "10 < 2", "\"10\" < \"2\"", "\"Z\" < \"a\"", "\"A\" ~= \"a\"", "\"Abc\" ~>< \"B\"", "\"abc\" << \"a\"", "\"abc\" >> \"c\"", "5 >< 1", "65536 << 1", "65537 >> 1", "\"bad\" = 1", "\"bad\" <> 1", "\"0\"", "\"\"", "NOT Installed", "ZERO", "ZERO = 0", "NAME = \"Example\"", "QUOTE = \"x\"", "NOT NOT 1", "-65536 << 65535" };
            conditions=conditions.Concat(new[] { "\" 1\"=1", "\"1 \"=1", "\"+1\"=1", "\"01\"=1", "\"0x10\"=16", "\"-0\"=0", "\"\"=0", "\"2147483648\"<>1", "\"Z\"~<\"a\"", "\"foo\"~><\"FOO\"" }).ToArray();
            var failures=new List<string>();
            foreach(var condition in conditions)
            {
                var expected=Evaluate(session,condition);var actual=MsiConditionEvaluator.Evaluate(condition,values).Result;
                var matches=expected is 0 or 1 ? actual==(expected==1) : actual is null;
                Console.WriteLine((matches?"PASS ":"FAIL ")+condition+" native="+expected+" observed="+(actual?.ToString()??"Unknown"));
                if(!matches) failures.Add(condition);
            }
            if(failures.Count>0) throw new Exception("Native oracle mismatches: "+string.Join("; ",failures));
            File.WriteAllText(Path.Combine(root,"PASS.txt"),conditions.Length+" condition results match the Windows Installer engine in an authored data-only guest context; no MSI action invoked.");
            return 0;
        }
        catch(Exception ex){Console.Error.WriteLine(ex);return 1;}
        finally{if(session!=0)Close(session);}
    }
}

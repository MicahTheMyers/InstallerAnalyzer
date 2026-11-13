using System.Text.RegularExpressions;

namespace InstallerAnalyzer.Services;

internal static class InstallShieldResponseFormat
{
    // Some InstallScript recorders emit the product's dialog sequence without an INI header.
    internal const string HeaderlessDialogSequence =
        @"(?im)^\[(?<product>\{[0-9a-f]{8}-(?:[0-9a-f]{4}-){3}[0-9a-f]{12}\})-DlgOrder\][ \t]*\r?$\n" +
        @"(?=[^\[]*?^Count=[1-9][0-9]*[ \t]*\r?$)[^\[]*?^Dlg0=(?<dialog>\k<product>-[\w.-]+)[ \t]*\r?$" +
        @"[\s\S]*?^\[\k<dialog>\][ \t]*\r?$";

    internal static bool HasHeaderlessDialogSequence(string text) => Regex.IsMatch(text, HeaderlessDialogSequence);
}

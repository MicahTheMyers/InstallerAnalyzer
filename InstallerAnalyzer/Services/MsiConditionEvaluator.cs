using System.Globalization;
using System.Text.RegularExpressions;
using InstallerAnalyzer.Models;

namespace InstallerAnalyzer.Services;

// Evaluates supplied observations only. Missing bindings mean unknown, not an empty MSI property.
// No package, installation session or action is opened; observed values are never parsed as condition code.
public static class MsiConditionEvaluator
{
    public static MsiConditionObservation Evaluate(string condition, IReadOnlyDictionary<string, string?> values)
    {
        var result = new MsiConditionObservation { Condition = condition };
        try
        {
            if (string.IsNullOrWhiteSpace(condition) || condition.Length > 4096) throw new FormatException("Empty or oversized condition.");
            var parser = new Parser(condition, values);
            result.Result = parser.Parse(); result.UnresolvedSymbols = parser.Unknown.OrderBy(s => s, StringComparer.Ordinal).ToList();
            result.Explanation = result.Result is null ? "Unresolved observation or unsupported comparison; no outcome inferred." : "Evaluated against supplied observations only; MSI actions and later property changes are not simulated.";
        }
        catch (Exception ex) when (ex is FormatException or DllNotFoundException or EntryPointNotFoundException or RegexMatchTimeoutException)
        { result.Result = null; result.Explanation = ex.Message; }
        return result;
    }
    private sealed record Value(string? Text, bool Number, bool Known);
    private sealed class Parser
    {
        private readonly List<string> tokens = new();
        private readonly Dictionary<string, string?> values;
        private int position, depth;
        public HashSet<string> Unknown { get; } = new(StringComparer.Ordinal);
        private static readonly Regex Token = new("\\G\\s*(\"[^\"]*\"|-?[0-9]+|[%$?!&]?[A-Za-z_][A-Za-z0-9_.]*|~?(?:><|<<|>>|<>|<=|>=|=|<|>)|[()])", RegexOptions.CultureInvariant, TimeSpan.FromMilliseconds(100));
        public Parser(string input, IReadOnlyDictionary<string, string?> supplied)
        {
            values = new Dictionary<string, string?>(supplied, StringComparer.Ordinal);
            var offset = 0;
            while (offset < input.Length)
            {
                if (string.IsNullOrWhiteSpace(input[offset..])) break;
                var match = Token.Match(input, offset);
                if (!match.Success || match.Index != offset || tokens.Count >= 512) throw new FormatException("Unsupported condition syntax or token limit.");
                tokens.Add(match.Groups[1].Value); offset += match.Length;
            }
        }
        private string Peek => position < tokens.Count ? tokens[position] : "";
        private bool Take(string text) { if (!Peek.Equals(text, StringComparison.OrdinalIgnoreCase)) return false; position++; return true; }
        public bool? Parse()
        {
            var result = Logical(0);
            if (position != tokens.Count) throw new FormatException("Unexpected condition tokens.");
            return result;
        }
        private bool? Logical(int precedence)
        {
            if (++depth > 64) throw new FormatException("Condition nesting limit reached.");
            try
            {
                if (precedence == 5) return Unary();
                var op = new[] { "IMP", "EQV", "XOR", "OR", "AND" }[precedence];
                var left = Logical(precedence + 1);
                while (Take(op))
                {
                    var right = Logical(precedence + 1);
                    left = op switch
                    {
                        "AND" => And(left, right), "OR" => Or(left, right), "IMP" => Or(Not(left), right),
                        "XOR" => left.HasValue && right.HasValue ? left != right : null,
                        _ => left.HasValue && right.HasValue ? left == right : null
                    };
                }
                return left;
            }
            finally { depth--; }
        }
        private bool? Unary()
        {
            if (Take("NOT")) return Not(UnaryBounded());
            return Term();
        }
        private bool? UnaryBounded()
        {
            if (++depth > 64) throw new FormatException("Condition nesting limit reached.");
            try { return Unary(); } finally { depth--; }
        }
        private bool? Term()
        {
            if (Take("(")) { var result = Logical(0); if (!Take(")")) throw new FormatException("Unclosed condition group."); return result; }
            var left = Operand();
            if (Peek.Length > 0 && "~=<>".Contains(Peek[0]))
            {
                var op = tokens[position++]; var right = Operand();
                if (!left.Known || !right.Known) return null;
                return Compare(left, right, op);
            }
            if (!left.Known) return null;
            return left.Number ? int.Parse(left.Text!, CultureInfo.InvariantCulture) != 0 : !string.IsNullOrEmpty(left.Text);
        }
        private Value Operand()
        {
            if (position >= tokens.Count) throw new FormatException("Condition operand missing.");
            var token = tokens[position++];
            if (token.StartsWith('"')) return new(token[1..^1], false, true);
            if (int.TryParse(token, NumberStyles.AllowLeadingSign, CultureInfo.InvariantCulture, out var number)) return new(number.ToString(CultureInfo.InvariantCulture), true, true);
            if (!Regex.IsMatch(token, @"\A[%$?!&]?[A-Za-z_][A-Za-z0-9_.]*\z", RegexOptions.CultureInvariant) || new[] { "NOT", "AND", "OR", "XOR", "EQV", "IMP" }.Contains(token, StringComparer.OrdinalIgnoreCase)) throw new FormatException("Invalid condition operand.");
            if (token.StartsWith('%'))
            {
                var binding = values.FirstOrDefault(p => p.Key.StartsWith('%') && p.Key.Equals(token, StringComparison.OrdinalIgnoreCase));
                if (binding.Key is not null) return new(binding.Value ?? "", false, true);
            }
            else if (values.TryGetValue(token, out var text))
            {
                if ("$?!&".Contains(token[0]))
                {
                    if (int.TryParse(text, NumberStyles.AllowLeadingSign, CultureInfo.InvariantCulture, out var state)) return new(state.ToString(CultureInfo.InvariantCulture), true, true);
                }
                else return new(text ?? "", false, true);
            }
            Unknown.Add(token); return new(null, false, false);
        }
        private static bool? Compare(Value left, Value right, string op)
        {
            var insensitive = op.StartsWith('~'); op = op.TrimStart('~');
            if (left.Number || right.Number)
            {
                if (!CanonicalInteger(left, out var a) || !CanonicalInteger(right, out var b)) return op == "<>";
                return op switch { "=" => a == b, "<>" => a != b, "<" => a < b, ">" => a > b, "<=" => a <= b, ">=" => a >= b,
                    "><" => (a & b) != 0, "<<" => (a >> 16) == b, ">>" => (a & 65535) == b, _ => null };
            }
            if (left.Text!.Contains('\0') || right.Text!.Contains('\0')) return null;
            if (insensitive && (left.Text.Any(c => c > 127) || right.Text.Any(c => c > 127))) return null;
            var comparison = insensitive ? StringComparison.OrdinalIgnoreCase : StringComparison.Ordinal;
            if (op == "><") return left.Text.Contains(right.Text!, comparison);
            if (op == "<<") return left.Text.StartsWith(right.Text!, comparison);
            if (op == ">>") return left.Text.EndsWith(right.Text!, comparison);
            var order = string.Compare(left.Text, right.Text, comparison);
            return op switch { "=" => order == 0, "<>" => order != 0, "<" => order < 0, ">" => order > 0, "<=" => order <= 0, ">=" => order >= 0, _ => null };
        }
        private static bool CanonicalInteger(Value value, out int number) => int.TryParse(value.Text, NumberStyles.AllowLeadingSign, CultureInfo.InvariantCulture, out number) &&
            (value.Number || value.Text == number.ToString(CultureInfo.InvariantCulture));
        private static bool? Not(bool? value) => value.HasValue ? !value.Value : null;
        private static bool? And(bool? a, bool? b) => a == false || b == false ? false : a == true && b == true ? true : null;
        private static bool? Or(bool? a, bool? b) => a == true || b == true ? true : a == false && b == false ? false : null;
    }
}

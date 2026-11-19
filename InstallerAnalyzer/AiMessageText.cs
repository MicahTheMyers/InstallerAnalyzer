using System.ComponentModel;
using System.Diagnostics;
using System.Text.RegularExpressions;
using System.Windows;
using System.Windows.Controls;
using System.Windows.Documents;
using System.Windows.Navigation;
using InstallerAnalyzer.Services;

namespace InstallerAnalyzer;

public sealed class AiMessageText : TextBlock
{
    private static readonly Regex WebLinks = new(
        @"\[(?<label>[^\]\r\n]+)\]\((?:<(?<target>[^<>\s]+)>|(?<target>(?:[^\s()<>]|\([^\s()<>]*\))+))\)|(?<bare>https?://[^\s<>""']+)",
        RegexOptions.IgnoreCase | RegexOptions.CultureInvariant);

    public static readonly DependencyProperty MessageProperty = DependencyProperty.Register(
        nameof(Message), typeof(AiChatTurn), typeof(AiMessageText),
        new PropertyMetadata(null, (element, args) => ((AiMessageText)element).ShowMessage((AiChatTurn?)args.NewValue)));

    public AiChatTurn? Message
    {
        get => (AiChatTurn?)GetValue(MessageProperty);
        set => SetValue(MessageProperty, value);
    }

    private void ShowMessage(AiChatTurn? message)
    {
        Inlines.Clear();
        if (message is null) return;
        if (message.Role != "AI Assist")
        {
            Inlines.Add(new Run(message.Text));
            return;
        }

        var text = message.Text;
        var position = 0;
        foreach (Match match in WebLinks.Matches(text))
        {
            var markdown = match.Groups["target"].Success;
            var target = markdown ? match.Groups["target"].Value : TrimUrlPunctuation(match.Value);
            if (!TryWebUri(target, out var uri)) continue;
            Inlines.Add(new Run(text[position..match.Index]));
            var hyperlink = new Hyperlink(new Run(markdown ? match.Groups["label"].Value : target))
            {
                NavigateUri = uri,
                ToolTip = uri.AbsoluteUri
            };
            hyperlink.SetResourceReference(ForegroundProperty, "Link");
            hyperlink.RequestNavigate += OpenWebLink;
            Inlines.Add(hyperlink);
            position = match.Index + (markdown ? match.Length : target.Length);
        }
        Inlines.Add(new Run(text[position..]));
    }

    private static string TrimUrlPunctuation(string text)
    {
        var length = text.Length;
        var parentheses = text.Count(c => c == ')') - text.Count(c => c == '(');
        while (length > 0)
        {
            var character = text[length - 1];
            if (character == ')' && parentheses > 0) parentheses--;
            else if (character is not ('.' or ',' or ';' or ':' or '!' or '?' or ']' or '}' or '*' or (char)96)) break;
            length--;
        }
        return text[..length];
    }

    private static bool TryWebUri(string value, out Uri uri)
    {
        uri = null!;
        if (!Uri.TryCreate(value, UriKind.Absolute, out var parsed) || !parsed.IsWellFormedOriginalString() ||
            parsed.Scheme is not ("http" or "https") || parsed.Host.Length == 0 || parsed.UserInfo.Length != 0)
            return false;
        uri = parsed;
        return true;
    }

    private void OpenWebLink(object sender, RequestNavigateEventArgs e)
    {
        e.Handled = true;
        if (!TryWebUri(e.Uri.OriginalString, out var uri)) return;
        try { Process.Start(new ProcessStartInfo(uri.AbsoluteUri) { UseShellExecute = true }); }
        catch (Win32Exception) { MessageBox.Show("Windows could not open this link in the default browser.", "AI Assist"); }
    }
}

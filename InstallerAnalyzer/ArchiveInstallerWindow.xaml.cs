using System.Windows;

namespace InstallerAnalyzer;

internal partial class ArchiveInstallerWindow : Window
{
    public string? SelectedInstaller => (InstallerTree.SelectedItem as ArchiveNode)?.Entry;

    public ArchiveInstallerWindow(Window owner, string[] entries)
    {
        InitializeComponent();
        Owner = owner;
        Resources.MergedDictionaries.Add(owner.Resources);
        Width = Math.Min(Width, SystemParameters.WorkArea.Width);
        Height = Math.Min(Height, SystemParameters.WorkArea.Height);
        InstallerTree.SelectedItemChanged += (_, _) => AnalyzeButton.IsEnabled = SelectedInstaller is not null;
        AnalyzeButton.IsEnabled = false;
        InstallerTree.ItemsSource = BuildTree(entries);
        ContentRendered += (_, _) => InstallerTree.Focus();
    }

    private static List<ArchiveNode> BuildTree(string[] entries)
    {
        var root = new ArchiveNode("", null);
        var folders = new Dictionary<string, ArchiveNode>(StringComparer.OrdinalIgnoreCase) { [""] = root };
        foreach (var entry in entries)
        {
            var parts = entry.Split('\\');
            var parent = root;
            var path = "";
            for (var index = 0; index < parts.Length - 1; index++)
            {
                path += parts[index] + "\\";
                if (!folders.TryGetValue(path, out var folder))
                {
                    folder = new ArchiveNode(parts[index], null) { Expanded = entries.Length == 1 };
                    folders.Add(path, folder);
                    parent.Children.Add(folder);
                }
                parent = folder;
            }
            parent.Children.Add(new ArchiveNode(parts[^1], entry) { Selected = entries.Length == 1 });
        }

        foreach (var folder in folders.Values)
            folder.Children.Sort((left, right) =>
            {
                var byType = (left.Entry is not null).CompareTo(right.Entry is not null);
                return byType != 0 ? byType : StringComparer.OrdinalIgnoreCase.Compare(left.Name, right.Name);
            });
        return root.Children;
    }

    private sealed record ArchiveNode(string Name, string? Entry)
    {
        public List<ArchiveNode> Children { get; } = new();
        public bool Expanded { get; init; }
        public bool Selected { get; init; }
    }

    private void Analyze_Click(object sender, RoutedEventArgs e)
    {
        if (SelectedInstaller is not null) DialogResult = true;
    }

    private void Close_Click(object sender, RoutedEventArgs e) => Close();
}

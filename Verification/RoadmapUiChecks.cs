using System.IO;
using System.Reflection;
using System.Windows;
using System.Windows.Controls;
using System.Windows.Controls.Primitives;
using System.Windows.Input;
using System.Windows.Media;
using System.Windows.Media.Imaging;
using InstallerAnalyzer;

internal static class RoadmapUiChecks
{
    public static void Run(MainWindow window, string root, Action<bool, string> check)
    {
        var folder = Path.Combine(root, "ui-matrix"); Directory.CreateDirectory(folder);
        T Field<T>(string name) => (T)typeof(MainWindow).GetField(name, BindingFlags.Instance | BindingFlags.NonPublic | BindingFlags.Public)!.GetValue(window)!;
        var show = typeof(MainWindow).GetMethod("ShowPage", BindingFlags.NonPublic | BindingFlags.Instance)!;
        var content = (FrameworkElement)window.Content;
        var toggle = Field<ToggleButton>("SandboxToggle");
        var originalMode = toggle.IsChecked;
        var refresh = typeof(MainWindow).GetMethod("UpdateSandboxControls", BindingFlags.NonPublic | BindingFlags.Instance)!;
        foreach (var mode in new[] { false, true })
        {
            toggle.IsChecked = mode;
            refresh.Invoke(window, null);
            check(Field<Button>("RecordIssButton").Visibility == Visibility.Visible && Field<Button>("OpenIssButton").Visibility == Visibility.Visible,
                $"Analyze response-file buttons remain visible with Sandbox {(mode ? "on" : "off")}");
            check(!Field<Button>("RecordIssButton").IsEnabled,
                $"Changing Sandbox mode does not enable recording without an installer ({mode})");
        }
        toggle.IsChecked = originalMode;
        refresh.Invoke(window, null);
        show.Invoke(window, new object[] { Field<Grid>("TestModePage") });
        var outer = Field<ScrollViewer>("TestModeScroll");
        void Layout()
        {
            content.Measure(new Size(1060, 760));
            content.Arrange(new Rect(0, 0, 1060, 760));
            content.UpdateLayout();
        }
        foreach (var name in new[] { "TestQueueList", "TestResultsList" })
        {
            var list = Field<ListBox>(name);
            var source = list.ItemsSource;
            var height = list.Height;
            try
            {
                list.Height = 240;
                list.ItemsSource = Array.Empty<object>();
                Layout();
                var inner = FindScrollViewer(list)!;
                MouseWheelEventArgs Wheel(int delta)
                {
                    var args = new MouseWheelEventArgs(Mouse.PrimaryDevice, Environment.TickCount, delta)
                        { RoutedEvent = Mouse.PreviewMouseWheelEvent };
                    inner.RaiseEvent(args);
                    Layout();
                    return args;
                }
                outer.ScrollToTop(); Layout();
                var down = Wheel(-120);
                check(down.Handled && outer.VerticalOffset > 0, name + " empty list lets the page scroll down");
                var up = Wheel(120);
                check(up.Handled && outer.VerticalOffset == 0, name + " empty list lets the page scroll up");
                list.ItemsSource = Enumerable.Range(0, 80).Select(i => new ScrollFixture { FileName = "Fixture " + i }).ToArray();
                Layout();
                inner.ScrollToTop(); outer.ScrollToTop(); Layout();
                var within = Wheel(-120);
                check(inner.ScrollableHeight > 0 && !within.Handled && outer.VerticalOffset == 0,
                    name + " scrollable list retains wheel input within its range");
                inner.ScrollToBottom(); Layout();
                var edge = Wheel(-120);
                check(edge.Handled && outer.VerticalOffset > 0, name + " bottom edge passes downward scrolling to the page");
            }
            finally { list.ItemsSource = source; list.Height = height; Layout(); }
        }
        foreach (var theme in new[] { "Dark", "SuperDark", "Light", "Purple", "Hacker", "Custom" })
        {
            Field<RadioButton>(theme + "ThemeRadio").IsChecked = true;
            var text = ((SolidColorBrush)window.Resources["Text"]).Color;
            var background = ((SolidColorBrush)window.Resources["Bg"]).Color;
            var lighter = Math.Max(Luminance(text), Luminance(background)); var darker = Math.Min(Luminance(text), Luminance(background));
            check((lighter + .05) / (darker + .05) >= 4.5, theme + " default body text remains readable against the page background");
            foreach (var size in new[] { new Size(1060, 760), new Size(1240, 900), new Size(1600, 1000) })
                foreach (var pageName in new[] { "AnalyzePage", "TestModePage", "CatalogPage", "DattoPage" })
                {
                    var page = Field<Grid>(pageName); show.Invoke(window, new object[] { page });
                    content.Measure(size); content.Arrange(new Rect(new Point(), size)); content.UpdateLayout();
                    check(page.ActualWidth > 0 && page.ActualHeight > 0 && page.ActualWidth <= size.Width && page.ActualHeight <= size.Height,
                        $"{theme} {pageName} fits {size.Width} x {size.Height}");
                    if (pageName == "AnalyzePage")
                    {
                        var button = Field<Button>("InstallTabButton"); var panel = (Panel)button.Parent;
                        var buttons = panel.Children.OfType<Button>().ToArray();
                        check(buttons.All(b => b.ActualWidth > 0 && b.TranslatePoint(new Point(b.ActualWidth, 0), panel).X <= panel.ActualWidth + 1),
                            $"{theme} script controls remain reachable at {size.Width} x {size.Height}");
                    }
                    var bitmap = new RenderTargetBitmap((int)size.Width, (int)size.Height, 96, 96, PixelFormats.Pbgra32); bitmap.Render(content);
                    var png = new PngBitmapEncoder(); png.Frames.Add(BitmapFrame.Create(bitmap));
                    using var output = File.Create(Path.Combine(folder, $"{theme}-{pageName}-{size.Width}x{size.Height}.png")); png.Save(output);
                }
            show.Invoke(window, new object[] { Field<Grid>("SettingsPage") });
            var testNav = Field<Button>("TestModeNavButton");
            var testNavVisibility = testNav.Visibility;
            testNav.Visibility = Visibility.Visible;
            content.Measure(new Size(1240, 1100)); content.Arrange(new Rect(0, 0, 1240, 1100)); content.UpdateLayout();
            var appearance = new RenderTargetBitmap(1240, 1100, 96, 96, PixelFormats.Pbgra32); appearance.Render(content);
            var appearancePng = new PngBitmapEncoder(); appearancePng.Frames.Add(BitmapFrame.Create(appearance));
            using var appearanceOutput = File.Create(Path.Combine(folder, $"{theme}-SettingsPage.png")); appearancePng.Save(appearanceOutput);
            show.Invoke(window, new object[] { Field<Grid>("SandboxPage") });
            content.Measure(new Size(1240, 900)); content.Arrange(new Rect(0, 0, 1240, 900)); content.UpdateLayout();
            var sandbox = new RenderTargetBitmap(1240, 900, 96, 96, PixelFormats.Pbgra32); sandbox.Render(content);
            var sandboxPng = new PngBitmapEncoder(); sandboxPng.Frames.Add(BitmapFrame.Create(sandbox));
            using var sandboxOutput = File.Create(Path.Combine(folder, $"{theme}-SandboxPage.png")); sandboxPng.Save(sandboxOutput);
            var wasIntegrated = Field<RadioButton>("EmbeddedModeRadio").IsChecked == true;
            Field<RadioButton>("EmbeddedModeRadio").IsChecked = true;
            content.UpdateLayout();
            var integrated = new RenderTargetBitmap(1240, 900, 96, 96, PixelFormats.Pbgra32); integrated.Render(content);
            var integratedPng = new PngBitmapEncoder(); integratedPng.Frames.Add(BitmapFrame.Create(integrated));
            using var integratedOutput = File.Create(Path.Combine(folder, $"{theme}-SandboxPage-Integrated.png")); integratedPng.Save(integratedOutput);
            if (!wasIntegrated) Field<RadioButton>("SeparateModeRadio").IsChecked = true;
            var logoField = typeof(MainWindow).GetField("_logoPath", BindingFlags.NonPublic | BindingFlags.Instance)!;
            var originalLogo = logoField.GetValue(window);
            logoField.SetValue(window, Path.Combine(root, "logos", "native-logo.png"));
            typeof(MainWindow).GetMethod("LoadLogoPreview", BindingFlags.NonPublic | BindingFlags.Instance)!.Invoke(window, null);
            show.Invoke(window, new object[] { Field<Grid>("ImmyBotPage") });
            content.Measure(new Size(1240, 900)); content.Arrange(new Rect(0, 0, 1240, 900)); content.UpdateLayout();
            var immy = new RenderTargetBitmap(1240, 900, 96, 96, PixelFormats.Pbgra32); immy.Render(content);
            var immyPng = new PngBitmapEncoder(); immyPng.Frames.Add(BitmapFrame.Create(immy));
            using var immyOutput = File.Create(Path.Combine(folder, $"{theme}-ImmyBotPage.png")); immyPng.Save(immyOutput);
            logoField.SetValue(window, originalLogo);
            typeof(MainWindow).GetMethod("LoadLogoPreview", BindingFlags.NonPublic | BindingFlags.Instance)!.Invoke(window, null);
            testNav.Visibility = testNavVisibility;
        }
    }

    private static ScrollViewer? FindScrollViewer(DependencyObject parent)
    {
        if (parent is ScrollViewer scroll) return scroll;
        for (var i = 0; i < VisualTreeHelper.GetChildrenCount(parent); i++)
            if (FindScrollViewer(VisualTreeHelper.GetChild(parent, i)) is { } found) return found;
        return null;
    }

    private sealed class ScrollFixture
    {
        public string FileName { get; init; } = "";
        public string Status => "Ready";
        public string Path => "fixture";
        public bool Selected { get; set; }
    }

    private static double Luminance(Color color)
    {
        double Linear(byte component) { var x = component / 255.0; return x <= .04045 ? x / 12.92 : Math.Pow((x + .055) / 1.055, 2.4); }
        return .2126 * Linear(color.R) + .7152 * Linear(color.G) + .0722 * Linear(color.B);
    }
}

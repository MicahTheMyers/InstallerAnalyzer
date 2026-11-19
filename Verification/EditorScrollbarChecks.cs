using System.IO;
using System.Reflection;
using System.Windows;
using System.Windows.Controls;
using System.Windows.Controls.Primitives;
using System.Windows.Media;
using InstallerAnalyzer;

internal static class EditorScrollbarChecks
{
    public static void Run(MainWindow window, string root, Action<bool, string> check)
    {
        T Field<T>(string name) => (T)window.FindName(name);
        var editor = Field<TextBox>("SandboxScriptEditor");
        var original = editor.Text;
        var enabled = Field<ToggleButton>("UseEditedSandboxScript").IsChecked;
        var flags = BindingFlags.Instance | BindingFlags.NonPublic;
        var guard = typeof(MainWindow).GetField("_loadingSandboxScript", flags)!;
        var details = new List<string>();
        void Layout()
        {
            var content = (FrameworkElement)window.Content;
            content.Measure(new Size(1240, 900));
            content.Arrange(new Rect(0, 0, 1240, 900));
            content.UpdateLayout();
        }
        try
        {
            guard.SetValue(window, true);
            editor.Text = string.Join("\n", Enumerable.Range(0, 200).Select(i => $"# Line {i} " + new string('x', 240)));
            typeof(MainWindow).GetMethod("ShowPage", flags)!.Invoke(window, new object[] { Field<Grid>("AnalyzePage") });
            foreach (var theme in new[] { "DarkThemeRadio", "LightThemeRadio", "PurpleThemeRadio" })
            {
                Field<RadioButton>(theme).IsChecked = true;
                Layout();
                editor.ApplyTemplate();
                var view = (ScrollViewer)editor.Template.FindName("PART_ContentHost", editor);
                view.ApplyTemplate();
                Layout();
                var vertical = (ScrollBar)view.Template.FindName("PART_VerticalScrollBar", view);
                var horizontal = (ScrollBar)view.Template.FindName("PART_HorizontalScrollBar", view);
                var presenter = (ScrollContentPresenter)view.Template.FindName("PART_ScrollContentPresenter", view);
                var corner = (Border)view.Template.FindName("ScrollCorner", view);
                vertical.ApplyTemplate(); horizontal.ApplyTemplate();
                Layout();
                check(view.ScrollableWidth > 0 && view.ScrollableHeight > 0 &&
                      horizontal.Visibility == Visibility.Visible && vertical.Visibility == Visibility.Visible,
                    theme + " editor shows both bars for a long script");
                var vTrack = (Track)vertical.Template.FindName("PART_Track", vertical);
                var hTrack = (Track)horizontal.Template.FindName("PART_Track", horizontal);
                check(vertical.Template.FindName("ScrollTrack", vertical) is not null &&
                      horizontal.Template.FindName("ScrollTrack", horizontal) is not null &&
                      vTrack.IsDirectionReversed && !hTrack.IsDirectionReversed &&
                      hTrack.ValueFromDistance(20, 0) > 0 && vTrack.ValueFromDistance(0, 20) > 0,
                    theme + " editor uses themed bars with normal horizontal and vertical drag directions");
                var contentRect = new Rect(presenter.TranslatePoint(new Point(), view), presenter.RenderSize);
                var horizontalRect = new Rect(horizontal.TranslatePoint(new Point(), view), horizontal.RenderSize);
                var verticalRect = new Rect(vertical.TranslatePoint(new Point(), view), vertical.RenderSize);
                check(contentRect.Right <= verticalRect.Left + 1 && contentRect.Bottom <= horizontalRect.Top + 1 &&
                      horizontalRect.Right <= verticalRect.Left + 1 && verticalRect.Bottom <= horizontalRect.Top + 1,
                    theme + " scrollbar tracks and text viewport occupy separate space");
                check(((SolidColorBrush)corner.Background).Color == ((SolidColorBrush)window.Resources["ScrollTrackBg"]).Color,
                    theme + " scrollbar corner matches the active theme");
                view.ScrollToHorizontalOffset(0); view.ScrollToVerticalOffset(0); Layout();
                var left = hTrack.Thumb.TranslatePoint(new Point(), hTrack).X;
                var top = vTrack.Thumb.TranslatePoint(new Point(), vTrack).Y;
                ScrollBar.PageRightCommand.Execute(null, horizontal);
                ScrollBar.PageDownCommand.Execute(null, vertical);
                window.Dispatcher.Invoke(() => { }, System.Windows.Threading.DispatcherPriority.Background);
                Layout();
                check(view.HorizontalOffset > 0 && view.VerticalOffset > 0 &&
                      hTrack.Thumb.TranslatePoint(new Point(), hTrack).X > left &&
                      vTrack.Thumb.TranslatePoint(new Point(), vTrack).Y > top,
                    theme + " paging moves content and both thumbs in the expected directions");
                view.ScrollToRightEnd(); view.ScrollToBottom(); Layout();
                var hEnd = hTrack.Thumb.TranslatePoint(new Point(hTrack.Thumb.ActualWidth, 0), hTrack).X;
                var vEnd = vTrack.Thumb.TranslatePoint(new Point(0, vTrack.Thumb.ActualHeight), vTrack).Y;
                check(hEnd <= hTrack.ActualWidth + 1 && vEnd <= vTrack.ActualHeight + 1,
                    theme + " scrollbar thumbs stay inside the tracks at the end of the script");
                details.Add($"{theme}: viewport={contentRect}; horizontal={horizontalRect}; vertical={verticalRect}");
            }
            editor.Text = "# short script";
            Layout();
            var shortView = (ScrollViewer)editor.Template.FindName("PART_ContentHost", editor);
            check(shortView.ComputedHorizontalScrollBarVisibility == Visibility.Collapsed &&
                  shortView.ComputedVerticalScrollBarVisibility == Visibility.Collapsed,
                "A short script hides both unused scrollbar tracks");
            editor.Text = string.Join("\n", Enumerable.Range(0, 200).Select(i => "# " + i));
            Layout();
            check(shortView.ComputedVerticalScrollBarVisibility == Visibility.Visible &&
                  shortView.ComputedHorizontalScrollBarVisibility == Visibility.Collapsed,
                "A tall narrow script uses only the vertical scrollbar");
            File.WriteAllLines(Path.Combine(root, "editor-scrollbar-layout.txt"), details);
        }
        finally
        {
            editor.Text = original;
            Field<ToggleButton>("UseEditedSandboxScript").IsChecked = enabled;
            guard.SetValue(window, false);
            Field<RadioButton>("DarkThemeRadio").IsChecked = true;
        }
    }
}

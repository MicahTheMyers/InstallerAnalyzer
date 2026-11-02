using System.IO;
using System.Reflection;
using System.Runtime.InteropServices;
using System.Text.Json;
using System.Windows;
using System.Windows.Controls;
using System.Windows.Controls.Primitives;
using System.Windows.Interop;
using System.Windows.Threading;
using InstallerAnalyzer;

internal static class WindowBoundsChecks
{
    [StructLayout(LayoutKind.Sequential)] private struct Point { public int X, Y; }
    [StructLayout(LayoutKind.Sequential)] private struct Rect { public int Left, Top, Right, Bottom; }
    [StructLayout(LayoutKind.Sequential)] private struct MonitorInfo { public int Size; public Rect Monitor, Work; public uint Flags; }
    [StructLayout(LayoutKind.Sequential)] private struct MinMax { public Point Reserved, MaxSize, MaxPosition, MinTrackSize, MaxTrackSize; }
    [DllImport("user32.dll")] private static extern IntPtr MonitorFromWindow(IntPtr hwnd, uint flags);
    [DllImport("user32.dll", CharSet = CharSet.Unicode)] private static extern bool GetMonitorInfo(IntPtr monitor, ref MonitorInfo info);
    [DllImport("user32.dll")] private static extern bool GetWindowRect(IntPtr hwnd, out Rect rect);
    [DllImport("user32.dll")] private static extern IntPtr SendMessage(IntPtr hwnd, int message, IntPtr wParam, IntPtr lParam);

    public static void Run(MainWindow window, string root, Action<bool, string> check)
    {
        var flags = BindingFlags.Instance | BindingFlags.NonPublic | BindingFlags.Public;
        T Get<T>(string name) => (T)typeof(MainWindow).GetField(name, flags)!.GetValue(window)!;
        var updateToggle = Get<ToggleButton>("AutoUpdateToggle"); var oldUpdate = updateToggle.IsChecked;
        var width = window.Width; var height = window.Height; var left = window.Left; var top = window.Top;
        void Pump() => window.Dispatcher.Invoke(() => { }, DispatcherPriority.ApplicationIdle);
        try
        {
            updateToggle.IsChecked = false; // Do not issue an update request from this native window fixture.
            window.Show(); Pump();
            var hwnd = new WindowInteropHelper(window).Handle;
            var monitor = new MonitorInfo { Size = Marshal.SizeOf<MonitorInfo>() };
            check(GetMonitorInfo(MonitorFromWindow(hwnd, 2), ref monitor), "Native window monitor work area is available");
            window.WindowState = WindowState.Maximized; Pump(); window.UpdateLayout();
            check(GetWindowRect(hwnd, out var actual) && actual.Left == monitor.Work.Left && actual.Top == monitor.Work.Top && actual.Right == monitor.Work.Right && actual.Bottom == monitor.Work.Bottom, "Maximized native window exactly fits monitor work area");
            var footer = Get<TextBlock>("StatusText");
            var footerBottom = footer.PointToScreen(new System.Windows.Point(0, footer.ActualHeight));
            check(footerBottom.Y <= monitor.Work.Bottom && footerBottom.Y >= monitor.Work.Top && footer.ActualHeight > 0, "Maximized footer stays inside visible work area above taskbar");
            File.WriteAllText(Path.Combine(root, "window-bounds.json"), JsonSerializer.Serialize(new { Work = new[] { monitor.Work.Left, monitor.Work.Top, monitor.Work.Right, monitor.Work.Bottom }, Window = new[] { actual.Left, actual.Top, actual.Right, actual.Bottom }, FooterBottom = footerBottom.Y }));
            var memory = Marshal.AllocHGlobal(Marshal.SizeOf<MinMax>());
            try
            {
                Marshal.StructureToPtr(new MinMax(), memory, false); SendMessage(hwnd, 0x0024, IntPtr.Zero, memory);
                var info = Marshal.PtrToStructure<MinMax>(memory);
                var dpi = System.Windows.Media.VisualTreeHelper.GetDpi(window);
                check(info.MinTrackSize.X == Math.Min((int)Math.Ceiling(window.MinWidth * dpi.DpiScaleX), monitor.Work.Right - monitor.Work.Left) && info.MinTrackSize.Y == Math.Min((int)Math.Ceiling(window.MinHeight * dpi.DpiScaleY), monitor.Work.Bottom - monitor.Work.Top), "Native bounds preserve minimum window dimensions within work area");
            }
            finally { Marshal.FreeHGlobal(memory); }
            window.WindowState = WindowState.Normal; Pump();
            check(Math.Abs(window.Width - width) < 2 && Math.Abs(window.Height - height) < 2, "Restore retains normal window dimensions");
        }
        finally { window.WindowState = WindowState.Normal; window.Hide(); window.Width = width; window.Height = height; window.Left = left; window.Top = top; updateToggle.IsChecked = oldUpdate; }

        var nested = typeof(MainWindow).GetNestedTypes(BindingFlags.NonPublic);
        var nativeMonitor = nested.Single(t => t.Name == "BoundsMonitorInfo"); var nativeRect = nested.Single(t => t.Name == "BoundsRect"); var nativeMinMax = nested.Single(t => t.Name == "BoundsMinMaxInfo");
        object Rectangle(int l, int t, int r, int b)
        {
            var value = Activator.CreateInstance(nativeRect)!;
            foreach (var pair in new[] { ("Left", l), ("Top", t), ("Right", r), ("Bottom", b) }) nativeRect.GetField(pair.Item1)!.SetValue(value, pair.Item2);
            return value;
        }
        foreach (var edge in new[] { "bottom", "top", "left", "right" })
        {
            // Negative monitor origin and high-resolution pixel dimensions exercise secondary displays.
            var monitor = Activator.CreateInstance(nativeMonitor)!;
            nativeMonitor.GetField("Monitor")!.SetValue(monitor, Rectangle(-3840, -2160, 0, 0));
            var l = -3840 + (edge == "left" ? 96 : 0); var t = -2160 + (edge == "top" ? 96 : 0);
            var r = edge == "right" ? -96 : 0; var b = edge == "bottom" ? -96 : 0;
            nativeMonitor.GetField("Work")!.SetValue(monitor, Rectangle(l, t, r, b));
            var args = new[] { Activator.CreateInstance(nativeMinMax)!, monitor };
            typeof(MainWindow).GetMethod("ApplyMonitorWorkArea", BindingFlags.Static | BindingFlags.NonPublic)!.Invoke(null, args);
            var position = nativeMinMax.GetField("MaxPosition")!.GetValue(args[0])!; var size = nativeMinMax.GetField("MaxSize")!.GetValue(args[0])!;
            int X(object p) => (int)p.GetType().GetField("X")!.GetValue(p)!;
            int Y(object p) => (int)p.GetType().GetField("Y")!.GetValue(p)!;
            check(X(position) == l + 3840 && Y(position) == t + 2160 && X(size) == r - l && Y(size) == b - t, "Secondary monitor pixel bounds respect " + edge + " taskbar");
        }
    }
}

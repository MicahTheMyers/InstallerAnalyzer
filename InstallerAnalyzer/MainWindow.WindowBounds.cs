using System.Runtime.InteropServices;
using System.Windows;
using System.Windows.Interop;

namespace InstallerAnalyzer;

public partial class MainWindow
{
    private HwndSource? _boundsSource;

    private void InitializeWindowBounds()
    {
        SourceInitialized += (_, _) =>
        {
            _boundsSource = HwndSource.FromHwnd(new WindowInteropHelper(this).Handle);
            _boundsSource?.AddHook(WindowBoundsHook);
        };
        Closed += (_, _) => { _boundsSource?.RemoveHook(WindowBoundsHook); _boundsSource = null; };
    }

    private IntPtr WindowBoundsHook(IntPtr hwnd, int message, IntPtr wParam, IntPtr lParam, ref bool handled)
    {
        if (message != 0x0024 || lParam == IntPtr.Zero) return IntPtr.Zero; // WM_GETMINMAXINFO
        var monitor = new BoundsMonitorInfo { Size = Marshal.SizeOf<BoundsMonitorInfo>() };
        if (!GetMonitorInfo(MonitorFromWindow(hwnd, 2), ref monitor)) return IntPtr.Zero;
        var info = Marshal.PtrToStructure<BoundsMinMaxInfo>(lParam);
        var dpi = System.Windows.Media.VisualTreeHelper.GetDpi(this);
        info.MinTrackSize.X = Math.Max(info.MinTrackSize.X, (int)Math.Ceiling(MinWidth * dpi.DpiScaleX));
        info.MinTrackSize.Y = Math.Max(info.MinTrackSize.Y, (int)Math.Ceiling(MinHeight * dpi.DpiScaleY));
        ApplyMonitorWorkArea(ref info, monitor);
        Marshal.StructureToPtr(info, lParam, false);
        handled = true;
        return IntPtr.Zero;
    }

    // Both native rectangles are physical pixels. Using monitor-relative offsets avoids
    // primary-screen/DPI assumptions and includes taskbars docked to any screen edge.
    private static void ApplyMonitorWorkArea(ref BoundsMinMaxInfo info, BoundsMonitorInfo monitor)
    {
        var width = monitor.Work.Right - monitor.Work.Left;
        var height = monitor.Work.Bottom - monitor.Work.Top;
        info.MaxPosition = new BoundsPoint { X = monitor.Work.Left - monitor.Monitor.Left, Y = monitor.Work.Top - monitor.Monitor.Top };
        info.MaxSize = new BoundsPoint { X = width, Y = height };
        info.MinTrackSize.X = Math.Min(info.MinTrackSize.X, width);
        info.MinTrackSize.Y = Math.Min(info.MinTrackSize.Y, height);
    }

    [StructLayout(LayoutKind.Sequential)]
    private struct BoundsPoint { public int X, Y; }
    [StructLayout(LayoutKind.Sequential)]
    private struct BoundsRect { public int Left, Top, Right, Bottom; }
    [StructLayout(LayoutKind.Sequential)]
    private struct BoundsMonitorInfo { public int Size; public BoundsRect Monitor, Work; public uint Flags; }
    [StructLayout(LayoutKind.Sequential)]
    private struct BoundsMinMaxInfo { public BoundsPoint Reserved, MaxSize, MaxPosition, MinTrackSize, MaxTrackSize; }
    [DllImport("user32.dll")] private static extern IntPtr MonitorFromWindow(IntPtr hwnd, uint flags);
    [DllImport("user32.dll", CharSet = CharSet.Unicode)]
    [return: MarshalAs(UnmanagedType.Bool)] private static extern bool GetMonitorInfo(IntPtr monitor, ref BoundsMonitorInfo info);
}

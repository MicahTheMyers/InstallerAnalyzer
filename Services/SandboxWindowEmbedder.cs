using System.Diagnostics;
using System.Runtime.InteropServices;
using System.Text;

namespace InstallerAnalyzer.Services;

public static class SandboxWindowEmbedder
{
    private static long _originalStyle;
    private static IntPtr _embeddedChild = IntPtr.Zero;
    private const int GWL_STYLE = -16;
    private const long WS_CAPTION = 0x00C00000L;
    private const long WS_THICKFRAME = 0x00040000L;
    private const long WS_MINIMIZEBOX = 0x00020000L;
    private const long WS_MAXIMIZEBOX = 0x00010000L;
    private const long WS_SYSMENU = 0x00080000L;
    private const long WS_CHILD = 0x40000000L;
    private const long WS_POPUP = unchecked((long)0x80000000L);
    private const uint SWP_NOZORDER = 0x0004;
    private const uint SWP_FRAMECHANGED = 0x0020;
    private const int SW_RESTORE = 9;

    public static IntPtr FindSandboxWindow()
    {
        IntPtr found = IntPtr.Zero;
        EnumWindows((hWnd, _) =>
        {
            if (!IsWindowVisible(hWnd)) return true;
            var len = GetWindowTextLength(hWnd);
            if (len == 0) return true;
            var title = new StringBuilder(len + 1);
            GetWindowText(hWnd, title, title.Capacity);
            var text = title.ToString();
            if (!text.Contains("Windows Sandbox", StringComparison.OrdinalIgnoreCase)) return true;
            GetWindowThreadProcessId(hWnd, out var pid);
            try
            {
                var process = Process.GetProcessById((int)pid);
                if (process.ProcessName.Contains("WindowsSandbox", StringComparison.OrdinalIgnoreCase) ||
                    process.ProcessName.Contains("Sandbox", StringComparison.OrdinalIgnoreCase))
                {
                    found = hWnd;
                    return false;
                }
            }
            catch { }
            return true;
        }, IntPtr.Zero);
        return found;
    }

    public static bool Embed(IntPtr child, IntPtr parent, int width, int height)
    {
        if (child == IntPtr.Zero || parent == IntPtr.Zero) return false;
        ShowWindow(child, SW_RESTORE);
        var style = GetWindowLongPtr(child, GWL_STYLE).ToInt64();
        _originalStyle = style;
        _embeddedChild = child;
        // SetParent does NOT change WS_POPUP/WS_CHILD for us. Leaving the Sandbox
        // as a popup while parenting it into a WinForms host can produce a black surface.
        style &= ~(WS_CAPTION | WS_THICKFRAME | WS_MINIMIZEBOX | WS_MAXIMIZEBOX | WS_SYSMENU | WS_POPUP);
        style |= WS_CHILD;
        SetLastError(0);
        SetWindowLongPtr(child, GWL_STYLE, new IntPtr(style));
        var previousParent = SetParent(child, parent);
        if (previousParent == IntPtr.Zero && Marshal.GetLastWin32Error() != 0) return false;
        SetWindowPos(child, IntPtr.Zero, 0, 0, Math.Max(1, width), Math.Max(1, height), SWP_NOZORDER | SWP_FRAMECHANGED);
        ShowWindow(child, SW_RESTORE);
        RedrawWindow(child, IntPtr.Zero, IntPtr.Zero, RDW_INVALIDATE | RDW_ALLCHILDREN | RDW_UPDATENOW | RDW_FRAME);
        return true;
    }


    public static void Detach(IntPtr child)
    {
        if (child == IntPtr.Zero) return;
        SetParent(child, IntPtr.Zero);
        if (_embeddedChild == child && _originalStyle != 0)
            SetWindowLongPtr(child, GWL_STYLE, new IntPtr(_originalStyle));
        SetWindowPos(child, IntPtr.Zero, 80, 80, 1100, 760, SWP_NOZORDER | SWP_FRAMECHANGED);
        _embeddedChild = IntPtr.Zero;
        ShowWindow(child, SW_RESTORE);
    }

    public static void Resize(IntPtr child, int width, int height)
    {
        if (child != IntPtr.Zero) SetWindowPos(child, IntPtr.Zero, 0, 0, Math.Max(1, width), Math.Max(1, height), SWP_NOZORDER);
    }

    public static void BringToFront(IntPtr hWnd)
    {
        if (hWnd == IntPtr.Zero) return;
        ShowWindow(hWnd, SW_RESTORE);
        SetForegroundWindow(hWnd);
    }

    private delegate bool EnumWindowsProc(IntPtr hWnd, IntPtr lParam);
    [DllImport("user32.dll")] private static extern bool EnumWindows(EnumWindowsProc lpEnumFunc, IntPtr lParam);
    [DllImport("user32.dll")] private static extern bool IsWindowVisible(IntPtr hWnd);
    [DllImport("user32.dll", CharSet = CharSet.Unicode)] private static extern int GetWindowText(IntPtr hWnd, StringBuilder lpString, int nMaxCount);
    [DllImport("user32.dll")] private static extern int GetWindowTextLength(IntPtr hWnd);
    [DllImport("user32.dll")] private static extern uint GetWindowThreadProcessId(IntPtr hWnd, out uint processId);
    [DllImport("user32.dll", SetLastError = true)] private static extern IntPtr SetParent(IntPtr hWndChild, IntPtr hWndNewParent);
    [DllImport("user32.dll")] private static extern bool SetWindowPos(IntPtr hWnd, IntPtr hWndInsertAfter, int x, int y, int cx, int cy, uint flags);
    [DllImport("user32.dll")] private static extern bool SetForegroundWindow(IntPtr hWnd);
    [DllImport("user32.dll")] private static extern bool ShowWindow(IntPtr hWnd, int nCmdShow);
    [DllImport("kernel32.dll")] private static extern void SetLastError(uint dwErrCode);
    private const uint RDW_INVALIDATE = 0x0001;
    private const uint RDW_UPDATENOW = 0x0100;
    private const uint RDW_ALLCHILDREN = 0x0080;
    private const uint RDW_FRAME = 0x0400;
    [DllImport("user32.dll")] private static extern bool RedrawWindow(IntPtr hWnd, IntPtr lprcUpdate, IntPtr hrgnUpdate, uint flags);

    private static IntPtr GetWindowLongPtr(IntPtr hWnd, int nIndex) => IntPtr.Size == 8 ? GetWindowLongPtr64(hWnd, nIndex) : new IntPtr(GetWindowLong32(hWnd, nIndex));
    private static IntPtr SetWindowLongPtr(IntPtr hWnd, int nIndex, IntPtr value) => IntPtr.Size == 8 ? SetWindowLongPtr64(hWnd, nIndex, value) : new IntPtr(SetWindowLong32(hWnd, nIndex, value.ToInt32()));
    [DllImport("user32.dll", EntryPoint = "GetWindowLong")] private static extern int GetWindowLong32(IntPtr hWnd, int nIndex);
    [DllImport("user32.dll", EntryPoint = "GetWindowLongPtr")] private static extern IntPtr GetWindowLongPtr64(IntPtr hWnd, int nIndex);
    [DllImport("user32.dll", EntryPoint = "SetWindowLong")] private static extern int SetWindowLong32(IntPtr hWnd, int nIndex, int dwNewLong);
    [DllImport("user32.dll", EntryPoint = "SetWindowLongPtr")] private static extern IntPtr SetWindowLongPtr64(IntPtr hWnd, int nIndex, IntPtr dwNewLong);
}

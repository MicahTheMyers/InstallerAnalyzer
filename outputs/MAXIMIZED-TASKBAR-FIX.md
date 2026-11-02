# Maximized taskbar clipping fix — 0.12.10, 2026-10-30

The custom WindowChrome frame previously relied on default maximized sizing, which can place the window's layout beyond the visible work area. MainWindow now handles WM_GETMINMAXINFO using MonitorFromWindow and GetMonitorInfo for the current display. Maximum position is relative to that monitor; dimensions use its work area in native pixels, preserving taskbars on any edge without a fixed taskbar-height or primary-monitor assumption. Minimum resize dimensions retain their DPI-scaled constraints, capped to available space. Restore retains the normal window size. The native message hook is removed on close.

Release build: zero warnings/errors. All 549 .NET/WPF checks passed. Nine new checks include a real shown/maximized application window, exact native work-area bounds, footer visibility, minimum tracking dimensions and restore, plus synthetic negative-origin/high-resolution secondary-monitor cases for all four taskbar edges. Taskbar settings were unchanged. No live multi-monitor or mixed-DPI hardware acceptance is claimed. Existing 137 PowerShell checks remain applicable; guest scripts are unchanged and were not rerun.

See Taskbar-Work-Checks.txt; the verification result directory contains window-bounds.json for the actual native rectangles/footer position. The full roadmap remains open. No installers, signing or external release publication were performed.

Native API reference: https://learn.microsoft.com/en-us/windows/win32/api/winuser/ns-winuser-minmaxinfo

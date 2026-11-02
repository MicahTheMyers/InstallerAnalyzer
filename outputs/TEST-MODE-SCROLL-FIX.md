# Test Mode mouse-wheel scrolling

2026-10-30, based on 0.12.9. The Test Mode page now uses the shared preview mouse-wheel routing handler. The queue and overview list ScrollViewers previously consumed wheel input even without their own scrollable content. A list that can move in the requested direction keeps normal wheel input; an empty/non-scrollable list or a list at the requested edge passes movement to the outer page. The Analyze page uses the same direction-aware behavior.

493 .NET/WPF checks pass, including eight routed-wheel checks using the real Test Mode controls: empty-list page scrolling both directions, inner-list input retention and bottom-edge page handoff for each panel. No installer was executed. Build: zero warnings/errors. The preceding 137 PowerShell checks remain applicable; guest script source is unchanged. The preceding Analyze toggle fix is included. Full InstallShield recording acceptance remains open.

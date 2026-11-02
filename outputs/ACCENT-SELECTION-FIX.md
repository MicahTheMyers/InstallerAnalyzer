# Accent selection visibility

2026-10-30. All nine accent choices use the segmented radio template with an explicit checkmark, selected background and border. The shared checkmark uses the theme text brush rather than hard-coded white so it remains visible in light mode. Accent choices retain their existing radio grouping, saved settings and color behavior. No installer or security settings were changed.

Build: zero warnings/errors. Existing 493 .NET/WPF checks passed. Settings renders were generated for all six themes; Dark and Light were visually inspected with Blue selected. Earlier Analyze toggle and Test Mode scroll fixes are included. Prior 137 PowerShell checks remain applicable; guest scripts are unchanged. Source only, no new official release; live recording acceptance remains open.

Follow-up: Custom is now last in both the theme and accent choice groups; Gold precedes Custom. Custom theme uses the same segmented tile as the predefined themes. Color-picker actions sit beneath their respective choice groups. The current render was visually inspected and all 493 checks pass again; see Appearance-Order-Checks.txt.

# Sidebar icons and alignment

2026-10-30. Test Mode now uses a vector clipboard; Catalog uses a brown open cardboard box. All sidebar rows use identical 34-pixel icon columns, 24-pixel icon canvases and label margins. Other text-glyph icons were converted to vector paths, retaining the ImmyBot robot, for consistent sizing. The navigation button template now stretches its content instead of centering each variable-width icon/label group. Hover, pressed, disabled and keyboard focus visuals remain available.

Build: zero warnings/errors. All 493 .NET/WPF checks pass. Settings/sidebar previews were generated for six themes with Test Mode shown solely in the render fixture. Dark and Light renders were visually inspected: icon centers and label starts align, and both requested symbols are visible. Earlier toggle, wheel scrolling and accent selection fixes are included. Guest scripts are unchanged; prior 137 PowerShell checks remain applicable. No installer was launched and live recording acceptance remains open.

Follow-up: Catalog's brown filled icon was replaced with an open-box outline using the same theme text brush, 1.7-pixel rounded stroke and 24-pixel canvas as the other navigation icons. The aligned sidebar was visually inspected in the updated Settings render.

Settings follow-up: replaced the irregular outer shape with a symmetric six-tooth cog and circular center. It retains the shared outline brush, stroke weight and icon alignment. Updated Dark render visually inspected; 493 checks pass and the build has zero warnings/errors.

Sandbox follow-up: replaced the diamond with a Windows Sandbox-inspired isometric cube, preserving the common 24-pixel outline style and sidebar alignment. Updated Dark render visually inspected; all 493 checks pass, with zero build warnings/errors.

Reference correction: the user supplied the Windows Sandbox layered logo. Sandbox now uses a filled vector recreation of its upper folded chevron, separate center diamond and solid lower section, in the dynamic theme text brush. This supersedes the generic cube above. Updated rendered sidebar visually inspected; 493 checks pass with zero build warnings/errors.

ImmyBot reference correction: replaced the head-only robot with a friendly full-body outline matching the supplied reference: rounded head, small antenna, round eyes and smile, chest display, segmented side arms and separate feet. The dynamic theme brush and common 24-pixel alignment remain. Updated Dark render visually inspected; 493 checks pass with zero build warnings/errors.

Analyze card headings: replaced the faint Analysis text glyph with a 22-pixel vector of three sliders based on the supplied reference. Deployment settings now uses the same cog geometry as the sidebar Settings icon. Both headings use aligned icon/label rows and dynamic theme text brushes. Updated Analyze render visually inspected; 493 checks pass and the build has zero warnings/errors.

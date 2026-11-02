# Native application-logo quality

2026-10-30, development source based on 0.12.9.

ApplicationLogoService now reads the primary EXE/DLL icon group as data resources and selects its largest valid native frame, preferring higher bit depth on equal dimensions. LoadLibraryEx uses only LOAD_LIBRARY_AS_DATAFILE | LOAD_LIBRARY_AS_IMAGE_RESOURCE: no entry point or imported executable code runs. A standalone ICO similarly uses its largest native frame. Windows shell icons remain the fallback for MSI and files without usable embedded icons, but are saved at native size rather than stretched into a nominal 256-pixel image. This does not invent detail absent from the source or retrieve brand assets from the Internet.

Resource counts, frame byte sizes, directory offsets and PNG/DIB dimensions are bounded before decoding. Mapped resources and HICON handles are released. PNG output preserves the original native pixels and transparency. Existing same-name cached logos are regenerated when Re-extract is used or the installer is selected again.

The ImmyBot logo preview uses high-quality bitmap scaling, reports actual pixel dimensions and identifies small source images. Replace Image still supports a user-supplied high-resolution PNG; a generic/small MSI icon may require that option.

Validation: build with zero warnings/errors; 498 .NET/WPF checks passed, including real 256-pixel PE resource extraction, unchanged EXE bytes, multi-size ICO selection and rejection of malformed/oversized images. The ImmyBot page was rendered across six themes with the extracted native logo; Dark was visually inspected. No vendor executable was launched. Previous 137 PowerShell checks remain applicable; guest scripts are unchanged.

Primary format/API documentation:
https://learn.microsoft.com/en-us/windows/win32/menurc/about-icons
https://learn.microsoft.com/en-us/windows/win32/intl/loading-a-win32-pe-resource-module

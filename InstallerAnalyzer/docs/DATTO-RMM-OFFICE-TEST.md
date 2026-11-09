# Datto RMM office acceptance — 0.13.0-preview.1

This preview adds local component export. Real Datto RMM job acceptance is pending your office test. Public latest remains v0.12.10.

1. Extract the portable preview and run InstallerAnalyzer.exe on Windows x64. No .NET SDK is needed for the portable build.
2. Analyze a machine-wide EXE or MSI and complete its Sandbox install/remove/reinstall/remove lifecycle. Select its validated detection entry.
3. Open **Deployment**, choose **Datto RMM** from the target dropdown, review the previews, and choose **Export Component Kit**. Extract the resulting ZIP.
4. In Datto RMM, create an **Applications / Batch** component. Paste the complete contents of `Component.cmd` as its script.
5. Attach `DattoComponent.ps1`, `installer.exe` or `installer.msi`, and every response file from the kit. Preserve their filenames. The ZIP is a creation kit, not a native `.cpt` import file.
6. Add an input variable named `IAAction`, type **Selection**, with choices `Detect`, `Install`, `Uninstall`. Set its default to `Detect`.
7. Run as **LocalSystem** on a disposable managed Windows device. Allow 1200 seconds; increase this for a known slower installer. The launcher selects 64-bit Windows PowerShell 5.1. Follow your organization's script-signing policy. Add a warning post-condition matching `IA_REBOOT_REQUIRED=1`; the component does not reboot automatically.
8. Run this sequence, retaining the complete job output:

| Action | Expected result |
| --- | --- |
| Detect before installation | Exit 0, `IA_DETECTED=0` |
| Install | Exit 0, `IA_DETECTED=1` |
| Install again | Exit 0, installation skipped |
| Detect | Exit 0, `IA_DETECTED=1` |
| Uninstall | Exit 0, `IA_DETECTED=0` |
| Uninstall again | Exit 0, removal skipped |

Exit 1 or `IA_ERROR` indicates failure. Detect reports absence as a successful observation; it is not a Datto monitor script. A verified reboot-required result emits `IA_REBOOT_REQUIRED=1` and succeeds only after the expected installed/absent state is observed.

Supported initial scope: one original machine-wide EXE/MSI with completed lifecycle evidence, plus required recorded InstallShield responses. Per-user/MSIX installs, separate extracted payloads, external .NET 3.5 provisioning and MSI transform packages are blocked. No tenant credentials, API integration or automatic job submission are included. Review vendor arguments before sharing a kit; known credential switches are rejected.

Local acceptance: 606 .NET/WPF checks, 184 PowerShell checks and 11 source syntax checks passed. The actual Batch launcher and generated payload passed 18 checks in a fresh Sandbox as LocalSystem, including two real RSPile install/remove cycles, repeated-action skipping, missing/tampered payload rejection and literal MSI argument handling. These results do not establish Datto tenant acceptance.

Official setup references: [Create a component](https://rmm.datto.com/help/en/Content/3NEWUI/Automation/Components/CreateAComponent.htm), [Scripting](https://rmm.datto.com/help/en/Content/3NEWUI/Automation/Components/Scripting.htm), [Input variables](https://rmm.datto.com/help/en/Content/3NEWUI/Automation/Components/InputVariables.htm).

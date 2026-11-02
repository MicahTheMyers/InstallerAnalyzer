# Sandbox display investigation — 2026-10-29

Status: unresolved; administrator-assisted graphics diagnostic prepared.

Two obsolete viewers from the previous, already stopped recording tests were closed using their exact retained fixture paths. A fresh diagnostic Sandbox was launched visibly with software guest graphics and no installer or logon command. The guest reported an active WDAGUtilityAccount session, responding Explorer and DWM processes, and a healthy Microsoft Remote Display Adapter. Capturing both the original viewer and the explicitly connected viewer still returned black pixels with no guest controls. This establishes that a healthy guest can coexist with the capture/display problem; it does not prove that the physical monitor is black. The user cannot check the physical display right now.

The host RDP client event log reported an active connection and hardware memory for its frame buffer. Software guest graphics does not establish software decoding in the host viewer. Hardware decoding is a hypothesis, not a confirmed cause.

After stopping the owned guest, its viewers and the idle Sandbox application server, a fresh default-graphics Sandbox was started visibly. Its capture also remained black. Both diagnostic guests were stopped, their owned viewers closed, and the final Sandbox inventory was empty. No installer was run in these diagnostic sessions; no USB inputs were changed.

Microsoft documents software decoding as a diagnostic for suspected acceleration problems:
https://learn.microsoft.com/en-us/windows/client-management/mdm/policy-csp-admx-terminalserver#ts_client_disable_hardware_mode

Attempting to access that machine graphics policy for writing returned `Requested registry access is not allowed.` Its EnableHardwareMode value remains unset; no graphics workaround was applied. The existing key and absent value were saved in the diagnostic folder. No administrator prompt was triggered by the agent.

Prepared, PowerShell syntax-checked helpers:

- Verification/Apply-Sandbox-Display-Workaround.cmd: user launches and approves Windows elevation; saves the original value before applying DWORD EnableHardwareMode=0.
- Verification/Restore-Sandbox-Display-Workaround.cmd: restores the saved original value, withholding restoration if it detects a conflicting intervening value.
- Verification/Set-SandboxSoftwareDecoding.ps1: limited to that single graphics setting; no security-setting or certificate-store changes.

The setting affects software decoding for other new Windows Remote Desktop client connections while applied. It requires a new viewer connection to test. Successful elevation/application alone would not establish that the display is fixed; inspect a fresh Sandbox before resuming the recording test. Restore the setting if it does not help.

Evidence directory: verification-results/sandbox-display-8d97e368de09445c934fece9dbc1d830. Existing application checks remain 559; the two helper syntax checks are not added to that automated acceptance count. No new application release is asserted.

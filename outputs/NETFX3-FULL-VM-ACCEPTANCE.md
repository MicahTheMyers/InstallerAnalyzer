# .NET Framework 3.5 full-Windows VM acceptance — 2026-11-01

**PASS: command-line installation and real CLR/LINQ runtime execution.**

Owned Hyper-V guest: InstallerAnalyzer-NetFx3-6103d40d, ID 5ad5cdda-31bf-4b75-8234-81163a6e0eb7. Microsoft Windows 11 Enterprise LTSC Evaluation image 10.0.26100.1742; 4 GB RAM, two virtual CPUs, Secure Boot and vTPM. No external network switch or shared host folders. Microsoft evaluation ISO provenance/hash is retained under verification-results/netfx3-full-vm.

The pre-install DISM /ScanHealth completed with exit 0 and **No component store corruption detected**. NetFx3 began as DisabledWithPayloadRemoved. Installation used the Microsoft media's matching NetFx3 source CAB, copied to the guest-only source folder:

```
DISM /Online /Enable-Feature /FeatureName:NetFx3 /All /NoRestart /LimitAccess /Source:C:\InstallerAnalyzer-NetFx3-Test\Source /English
```

DISM exited **0**; final feature state was **Enabled**; no restart was required. The installed .NET 3.5 compiler built a small program using System.Core LINQ, with a runtime configuration requiring v2.0.50727. It exited 0 and printed:

```
CLR=2.0.50727.9179
LINQ=6
```

The guest was gracefully shut down; final Hyper-V state **Off** and network disconnected were confirmed. A NetFx3-Probe-Completed checkpoint is retained. The host's NetFx3 feature remains DisabledWithPayloadRemoved. Hyper-V host features were enabled with the user's authorization; this was separate from guest-only NetFx3 servicing. The user handled UAC settings; the assistant did not change them.

This establishes that the command-line approach works on this full Windows image. It does not establish that all Sandbox images support the same servicing path, or whether the earlier Sandbox failures were caused specifically by image trimming versus another servicing/environment condition. The earlier Sandbox installation failures remain failures. Automatic prerequisite provisioning/retry in Installer Analyzer and a dependent vendor install/remove/reinstall lifecycle remain unimplemented/unvalidated.

Provisioning required extra work before the test: host BCDBoot collided with its loaded BCD registry store, so boot files were created inside an owned temporary Windows PE guest instead. An automatic checkpoint/base-disk identifier mismatch caused by the harness's earlier base-disk inspection was repaired in the disposable VM; the later full-Windows pre-install component-store scan passed clean. Automatic checkpoints were disabled for subsequent provisioning. The successful .NET test ran after those fixes. The host boot store was not unloaded or edited. Test scripts used only process-scoped execution-policy bypass; no persistent execution-policy change was made.

Evidence: outputs/NetFx3-Full-VM-Acceptance.json includes exact result fields, artifact directory and individual artifact hashes. Guest results are under verification-results/netfx3-full-vm/InstallerAnalyzer-NetFx3-6103d40d/guest-results. final-vm-state.json records shutdown and the host NetFx3 state. Earlier failed setup attempts remain preserved; work-status.txt and latest-outcome.txt now identify the final pass and confirmed shutdown.

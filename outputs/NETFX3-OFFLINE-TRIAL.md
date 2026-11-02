# .NET Framework 3.5 offline source trial

2026-10-30. Result: matching Microsoft media acquired and tested; runtime installation remains unsuccessful. Production automatic provisioning/retry is not implemented.

Source: the Windows 11 24H2/25H2 Languages and Optional Features ISO linked directly by Microsoft Learn. HTTP range reads retrieved the required CAB and optional-feature metadata without downloading the complete 6.25 GB image. Original ISO URL, byte counts and SHA-256 values are retained in source-provenance.json and metadata-provenance.json. Microsoft-Windows-NetFx3-OnDemand-Package has amd64 build identity 10.0.26100.1, matching the guest's 26100 servicing family. Embedded package catalogs were extracted for verification only; every extracted catalog has a Valid Microsoft Windows signature. No catalog was registered on the host.

Main CAB: Microsoft-Windows-NetFx3-OnDemand-Package~31bf3856ad364e35~amd64~~.cab
Bytes: 71321276
SHA256: DC3AF93AF5C64DC115409437D31018BAF2C3C46167806A599124BC905AE512F6

Disposable guest image: 10.0.26100.9711, x64.

1. DISM /Online /Enable-Feature /FeatureName:NetFx3 /All /NoRestart /Quiet /LimitAccess /Source:C:\NetFx3Source failed with exit 12006 / 0x80072EE6. Feature remained Disabled with Payload Removed.
2. Repeating with the same official image's FoD metadata also failed with 0x80072EE6.
3. The Microsoft-documented DISM /Online /Add-Package path using the NetFx3 CAB processed the package but failed finalization with exit 14098 / 0x80073712. CBS reported missing unrelated Windows Sandbox, network-service resources and a CoreMessaging manifest. These were observed during the trial; no clean baseline health scan establishes whether all were present before the trial. The feature state changed to Disabled, which is not an enabled/runtime success.
4. A final Enable-Feature attempt still failed 0x80072EE6; feature remained Disabled. No successful .NET 3.5 runtime smoke test is claimed.

All servicing ran only inside one owned disposable guest. The guest was stopped after preserving artifacts. No vendor installer ran, and no host Windows feature, update policy, certificate or security setting changed. Source CABs and metadata remain outside the application's source package. Verification/Get-NetFx3SourceFromMicrosoft.py is an acquisition/inspection utility, not an automatic app updater or runtime installer.

The command-line route is supported on compatible normal Windows images, but has not passed in this Sandbox image. A healthy disposable Windows VM or a separately repaired test image is the next environment for acceptance. Do not enable automatic retry based only on a successful download or a Disabled state. A future implementation must verify feature Enabled, runtime availability, reboot state and a complete installer lifecycle; Windows build 28000+ also requires a distinct standalone installer path.

Microsoft references:
https://learn.microsoft.com/en-us/azure/virtual-desktop/windows-11-language-packs
https://learn.microsoft.com/en-us/windows-hardware/manufacture/desktop/deploy-net-framework-35-by-using-deployment-image-servicing-and-management--dism
https://learn.microsoft.com/en-us/dotnet/framework/install/dotnet-35-windows-11

Local evidence pointers:
outputs\NetFx3-Official-Source-Location.txt
outputs\NetFx3-Offline-Probe-Location.txt

2026-11-01 full-Windows VM follow-up: command-line NetFx3 installation and real CLR 2.0/LINQ runtime PASS on a guest with a clean pre-install component store. DISM exit 0; feature Enabled; no reboot needed. Guest shut down, host NetFx3 remains disabled. This does not validate automatic app provisioning or a dependent vendor lifecycle. See outputs/NETFX3-FULL-VM-ACCEPTANCE.md.


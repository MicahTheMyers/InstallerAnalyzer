using InstallerAnalyzer.Models;
using InstallerAnalyzer.Services;

internal static class AppControlChildChecks
{
    public static void Run(Action<bool,string> check)
    {
        const string image=@"C:\Windows\Temp\{E417B80A-202B-4CBE-A103-FE75DBECB362}\.cr\Setup_CONNECTIONClientx64_10_00_17_010.exe";
        var block=new AppControlBlock{EventId=3077,Provider="Microsoft-Windows-CodeIntegrity",ObservedAt="2026-11-03T21:43:50Z",ParentImage=image,BlockedFile=@"\Device\HarddiskVolume2\Windows\Temp\{E395BC1F-87DA-46A6-B36A-FB7C72D6C77C}\.ba\mbahost.dll",Correlation="Exact observed bootstrapper descendant image"};
        var proof=new InstallAnalysis{Installer="Gint.exe",BootstrapperObservedImages=new(){image},BootstrapperChildAppControl=new(){Status="Available",StartedAt="2026-11-03T21:40:00Z",CapturedAt="2026-11-03T21:45:00Z",Blocks=new(){block}}};
        check(AppControlEvidenceService.HasConfirmedBlock(proof),"Exact tracked child image and enforced event identify its blocked DLL");
        check(FailureClassificationService.Classify("FAIL","Bootstrapper timeout",proof,"Sandbox lifecycle").Category==FailureCategory.ApplicationControlBlocked,"Confirmed child policy block takes precedence over a generic timeout");
        proof.BootstrapperObservedImages.Clear();check(!AppControlEvidenceService.HasConfirmedBlock(proof),"Unobserved child image cannot establish a policy block");proof.BootstrapperObservedImages.Add(image);
        block.ParentImage=@"C:\unrelated.exe";check(!AppControlEvidenceService.HasConfirmedBlock(proof),"Unrelated event parent cannot match the tracked descendant");block.ParentImage=image;
        block.EventId=3076;check(!AppControlEvidenceService.HasConfirmedBlock(proof),"Audit-only child event is not an enforced block");block.EventId=3077;
        block.ObservedAt="2026-11-02T21:43:50Z";check(!AppControlEvidenceService.HasConfirmedBlock(proof),"Old child event cannot establish a current-session block");block.ObservedAt="2026-11-03T21:43:50Z";
        block.Correlation="Exact source process image";check(!AppControlEvidenceService.HasConfirmedBlock(proof),"Child policy evidence requires its observed-descendant correlation");block.Correlation="Exact observed bootstrapper descendant image";
        block.ParentImage=@"C:\InstallerInput\Gint.exe";proof.BootstrapperObservedImages.Add(block.ParentImage);check(!AppControlEvidenceService.HasConfirmedBlock(proof),"Source-image events cannot masquerade as child policy evidence");block.ParentImage=image;
        proof.Installer="";check(!AppControlEvidenceService.HasConfirmedBlock(proof),"Child evidence requires a valid source installer identity");
    }
}

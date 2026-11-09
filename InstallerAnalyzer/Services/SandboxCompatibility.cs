namespace InstallerAnalyzer.Services;

public static partial class SandboxIssRecorder
{
    private const string SandboxCompatibilityScript = """
function Ensure-SandboxInstallerCompatibility([bool]$requested) {
    $evidence=[ordered]@{Requested=$requested;Status='Not requested';BeforeState=$null;AfterState=$null;RefreshExitCode=$null;Prepared=$false;Detail=''}
    $result['SandboxCompatibility']=$evidence
    if(-not $requested){return}
    try {
        # This function is never used by StartLocal. Refuse any unexpected execution context.
        if($env:USERNAME -ne 'WDAGUtilityAccount' -or (Get-CimInstance Win32_ComputerSystem).Model -ne 'Virtual Machine' -or -not(Test-Path -LiteralPath 'C:\InstallerInput\Record-Iss.ps1')){
            throw 'This setting requires a disposable Windows Sandbox guest.'
        }
        Write-Checkpoint 'Sandbox compatibility: preparing legacy installer support'
        $key='HKLM:\SYSTEM\CurrentControlSet\Control\CI\Policy'
        $evidence.BeforeState=[int](Get-ItemProperty -LiteralPath $key -Name VerifiedAndReputablePolicyState -ErrorAction Stop).VerifiedAndReputablePolicyState
        if($evidence.BeforeState -notin @(0,1,2)){throw 'Unexpected Smart App Control state.'}
        if($evidence.BeforeState -ne 0){Set-ItemProperty -LiteralPath $key -Name VerifiedAndReputablePolicyState -Value 0 -Type DWord -ErrorAction Stop}
        $refresh=Invoke-NetFx3Command ($env:WINDIR+'\System32\CiTool.exe') '--refresh --json' 'sandbox-compatibility-refresh.txt' 20
        $evidence.RefreshExitCode=$refresh.ExitCode
        if($refresh.TimedOut -or $refresh.ExitCode -ne 0){throw 'Windows could not refresh the guest execution policy.'}
        $native=$refresh.Text.Trim()|ConvertFrom-Json -ErrorAction Stop
        if($null -eq $native.OperationResult -or $native.OperationResult -ne 0){throw 'Windows did not confirm the guest policy refresh.'}
        $evidence.AfterState=[int](Get-ItemProperty -LiteralPath $key -Name VerifiedAndReputablePolicyState -ErrorAction Stop).VerifiedAndReputablePolicyState
        if($evidence.AfterState -ne 0){throw 'Guest Smart App Control did not remain off.'}
        $evidence.Prepared=$true
        $evidence.Status='Prepared'
        $evidence.Detail='Smart App Control is off in this disposable guest; policy refresh succeeded. Installer results are validated separately.'
        Write-Checkpoint 'Sandbox compatibility: legacy installer support prepared'
    } catch {
        $evidence.Status='Failed';$evidence.Detail=$_.Exception.Message
        throw ('SANDBOX COMPATIBILITY FAILED: '+$_.Exception.Message+' Installer launch stopped.')
    } finally {
        # The context guard also protects this output path from local/host execution.
        if($env:USERNAME -eq 'WDAGUtilityAccount' -and (Test-Path -LiteralPath 'C:\InstallerInput\Record-Iss.ps1')){
            $evidence|ConvertTo-Json -Depth 3|Set-Content -LiteralPath 'C:\InstallerOutput\sandbox-compatibility.json' -Encoding UTF8
        }
    }
}
""";
}

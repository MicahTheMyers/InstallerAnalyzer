param([Parameter(Mandatory=$true)][string]$ResultRoot)
$ErrorActionPreference='Stop'
if(-not(Test-Path -LiteralPath (Join-Path $ResultRoot 'Input'))){throw 'Sandbox input folder is missing'}
New-Item -ItemType Directory -Path (Join-Path $ResultRoot 'Output') -Force|Out-Null
$wsb=Join-Path $env:LOCALAPPDATA 'Microsoft/WindowsApps/wsb.exe'
function Ids {
    $raw=& $wsb list --raw
    if($LASTEXITCODE -ne 0){throw 'Sandbox inventory failed'}
    @((($raw|Out-String)|ConvertFrom-Json).WindowsSandboxEnvironments|ForEach-Object Id)
}
if(@(Ids).Count){throw 'Existing Sandbox left untouched'}
$i=[Security.SecurityElement]::Escape((Join-Path $ResultRoot 'Input'))
$o=[Security.SecurityElement]::Escape((Join-Path $ResultRoot 'Output'))
$xml="<Configuration><vGPU>Disable</vGPU><MappedFolders><MappedFolder><HostFolder>$i</HostFolder><SandboxFolder>C:\InstallerInput</SandboxFolder><ReadOnly>true</ReadOnly></MappedFolder><MappedFolder><HostFolder>$o</HostFolder><SandboxFolder>C:\InstallerOutput</SandboxFolder><ReadOnly>false</ReadOnly></MappedFolder></MappedFolders><LogonCommand><Command>powershell.exe -NoProfile -ExecutionPolicy RemoteSigned -File C:\InstallerInput\Record-Iss.ps1</Command></LogonCommand></Configuration>"
$config=Join-Path $ResultRoot 'Signed-Component-Test.wsb'
[IO.File]::WriteAllText($config,$xml)
$owned=$null
$last=''
$lastVendor=''
$deadline=(Get-Date).AddMinutes(45)
try {
    Start-Process -FilePath $config -WindowStyle Hidden
    while((Get-Date) -lt $deadline){
        if(-not $owned){
            $ids=@(Ids)
            if($ids.Count -gt 1){throw 'Ambiguous Sandbox ownership'}
            if($ids.Count -eq 1){$owned=$ids[0];$owned|Set-Content (Join-Path $ResultRoot 'owned-id.txt')}
        }
        $checkpoint=Join-Path $ResultRoot 'Output/checkpoint.json'
        if(Test-Path $checkpoint){
            try{
                $stage=(Get-Content $checkpoint -Raw|ConvertFrom-Json).Stage
                if($stage -ne $last){$last=$stage;Write-Output $stage}
            }catch{}
        }
        $vendorFile=Join-Path $ResultRoot 'Output/vendor-step.txt'
        if(Test-Path $vendorFile){
            $vendor=Get-Content $vendorFile -Raw
            if($vendor -ne $lastVendor){$lastVendor=$vendor;Write-Output ('Package: '+$vendor.Trim())}
        }
        if(Test-Path (Join-Path $ResultRoot 'Output/result.json')){
            # The guest may still hold the output file while writing it.
            try {
                $null=Get-Content (Join-Path $ResultRoot 'Output/result.json') -Raw -ErrorAction Stop | ConvertFrom-Json -ErrorAction Stop
                Write-Output ('Result saved: '+(Join-Path $ResultRoot 'Output/result.json'))
                break
            } catch {}
        }
        Start-Sleep 3
    }
    if(-not(Test-Path (Join-Path $ResultRoot 'Output/result.json'))){throw 'Test exceeded its session budget'}
}finally{
    if($owned -and @(Ids) -contains $owned){& $wsb stop --id $owned --raw}
}

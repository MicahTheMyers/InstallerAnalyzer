namespace InstallerAnalyzer.Services;

public static partial class SandboxIssRecorder
{
    private const string GintPrerequisiteScript = """
function Ensure-GintWindowsCatalog {
$file='C:\Windows\WinSxS\x86_microsoft.windows.gdiplus_6595b64144ccf1df_1.1.26100.9711_none_b69fe26d52438af9\GdiPlus.dll'
$catalog='C:\Windows\servicing\Packages\Microsoft-Windows-Client-Desktop-Required-WOW64-Package0011~31bf3856ad364e35~amd64~~10.0.26100.9711.cat'
if((Get-CimInstance Win32_ComputerSystem).Model -ne 'Virtual Machine' -or -not(Test-Path 'C:\InstallerInput\Record-Iss.ps1')){throw 'Expected disposable guest context'}
# Only the exact Windows component/catalog pair verified in the live repair test is supported.
if(-not(Test-Path -LiteralPath $file)){return}
if((Get-AuthenticodeSignature -LiteralPath $file).Status -eq 'Valid'){return}
Write-Checkpoint 'gINT: restoring the Microsoft Windows catalog index'
if((Get-FileHash -LiteralPath $file).Hash -ne 'A194D3BE94FEDA1170AC91F9978E2ACDE8727C62F78862ECD5AD6D1A4599CFBE'){throw 'Unexpected Windows DLL version'}
if((Get-FileHash -LiteralPath $catalog).Hash -ne '3CDEF8A39132151CB5AB8F813EACE5BD3C33B0123F50F0C6CA37340169791904'){throw 'Unexpected Windows catalog content'}
$signature=Get-AuthenticodeSignature -LiteralPath $catalog
if($signature.Status -ne 'Valid' -or $signature.SignerCertificate.Subject -notmatch 'CN=Microsoft Windows, O=Microsoft Corporation'){throw 'Genuine Microsoft Windows catalog signature not verified'}
Add-Type -TypeDefinition @"
using System;
using System.IO;
using System.Runtime.InteropServices;
public static class WindowsCatalogRegistration {
 [DllImport("wintrust.dll",CharSet=CharSet.Unicode,SetLastError=true)]
 static extern bool CryptCATAdminAcquireContext2(out IntPtr context,ref Guid subsystem,string algorithm,IntPtr policy,uint flags);
 [DllImport("wintrust.dll",CharSet=CharSet.Unicode,SetLastError=true)]
 static extern IntPtr CryptCATAdminAddCatalog(IntPtr context,string source,string name,uint flags);
 [DllImport("wintrust.dll")] static extern bool CryptCATAdminReleaseCatalogContext(IntPtr context,IntPtr catalog,uint flags);
 [DllImport("wintrust.dll")] static extern bool CryptCATAdminReleaseContext(IntPtr context,uint flags);
 public static void RestoreExistingCatalogIndex(string path) {
  IntPtr context=IntPtr.Zero,catalog=IntPtr.Zero;
  try {
   var subsystem = new Guid("F750E6C3-38EE-11D1-85E5-00C04FC295EE");
   if(!CryptCATAdminAcquireContext2(out context,ref subsystem,"SHA256",IntPtr.Zero,0))throw new System.ComponentModel.Win32Exception();
   catalog=CryptCATAdminAddCatalog(context,path,Path.GetFileName(path),0);
   if(catalog==IntPtr.Zero)throw new System.ComponentModel.Win32Exception();
  }finally{
   if(catalog!=IntPtr.Zero)CryptCATAdminReleaseCatalogContext(context,catalog,0);
   if(context!=IntPtr.Zero)CryptCATAdminReleaseContext(context,0);
  }
 }
}
"@
[WindowsCatalogRegistration]::RestoreExistingCatalogIndex($catalog)
$after=Get-AuthenticodeSignature -LiteralPath $file
$unchanged=(Get-FileHash -LiteralPath $file).Hash -eq 'A194D3BE94FEDA1170AC91F9978E2ACDE8727C62F78862ECD5AD6D1A4599CFBE'
[ordered]@{Status=$after.Status.ToString();SignatureType=$after.SignatureType.ToString();Signer=$after.SignerCertificate.Subject;ComponentHashUnchanged=$unchanged;Catalog=$catalog;Scope='Existing Microsoft OS catalog index in Sandbox'}|ConvertTo-Json|Set-Content C:\InstallerOutput\gint-windows-catalog-repair.json -Encoding UTF8
if($after.Status -ne 'Valid' -or $after.SignatureType -ne 'Catalog' -or -not $unchanged){throw 'Windows catalog index repair did not restore the original component signature.'}
Write-Checkpoint 'gINT: Microsoft Windows catalog signature verified'
}
function Test-GintVbScript {
    $folder=Join-Path $env:TEMP ('InstallerAnalyzer-VbsProbe-'+[guid]::NewGuid().ToString('N'))
    New-Item -ItemType Directory -Path $folder | Out-Null
    $probe=Join-Path $folder 'probe.vbs'
    $marker=Join-Path $folder 'result.txt'
    @(
        'Set fs = CreateObject("Scripting.FileSystemObject")'
        ('Set result = fs.CreateTextFile("{0}", True)' -f $marker)
        'result.WriteLine "VBScript runtime OK"'
        'result.Close'
    ) | Set-Content -LiteralPath $probe -Encoding Ascii
    $run=Invoke-NetFx3Command ($env:WINDIR+'\SysWOW64\cscript.exe') ('//NoLogo //B "'+$probe+'"') 'gint-vbscript-probe.txt' 20
    return $run.ExitCode -eq 0 -and (Test-Path -LiteralPath $marker) -and ([IO.File]::ReadAllText($marker).Trim() -eq 'VBScript runtime OK')
}
function Get-GintVbScriptSource {
    $url='https://software-static.download.prss.microsoft.com/dbazure/888969d5-f34g-4e03-ac9d-1f9786c66749/26100.1.240331-1435.ge_release_amd64fre_CLIENT_LOF_PACKAGES_OEM.iso'
    $source=Join-Path $env:TEMP ('InstallerAnalyzer-VbsSource-'+[guid]::NewGuid().ToString('N'))
    $files=@"
FoDMetadata_Client.cab|15892480|510772|b825461369a531e76f3dda84840ec457d5f8062afd84381dd40938f69a60305b
metadata/DesktopTargetCompDB_Conditions.xml.cab|5580312576|18873|6468ef00378898f52b464d58f7d970a76360ed4085e8e7db77bc53358e5491d4
metadata/DesktopTargetCompDB_FOD_Metadata_Neutral.xml.cab|5580333056|441417|8bd0794d5f6461d0c2af9019f0685440790deef2dc1bab6a3e435d1d752c64a7
metadata/DesktopTargetCompDB_FOD_Neutral.xml.cab|5580775424|47682|401a1b189b94e8a614e5696394f2438c3eb4be9548ee742af0172b508c71028e
metadata/DesktopTargetCompDB_Neutral.xml.cab|5580824576|12406|1ea1fdbef7b3444e56265ecc4c6ddb1e4ede514b43ceaed311af511b6f5dab75
metadata/DesktopTargetCompDBForISO_en-us.xml.cab|5579882496|10578|ea6c2c05e140423c28f730471d069ebd797959987aed85e4db244d4978b9d673
metadata/DesktopTargetCompDBForISO_FOD_en-us.xml.cab|5579139072|17624|6b6573493e132271de0dcdf3413b9b0ca6a2ff0002958ba5dafe6a08dc42fa02
Microsoft-Windows-FodMetadataServicing-Desktop-CompDB-Package.cab|1760907264|190093|39c9527d88477a738956dbce0b585438e863eff89697024fa368dfa7d27b1709
Microsoft-Windows-FodMetadataServicing-Desktop-Metadata-Package.cab|1761097728|461137|2740089222b96ab1daff3dd7067c638bd1c010b0b81a41159490395cb4539470
Microsoft-Windows-VBSCRIPT-FoD-Package~31bf3856ad364e35~amd64~en-US~.cab|5486944256|26662|17c77252e0c66290b7fc102d945ec29199a27393c6af235350e8f8113b9eba49
Microsoft-Windows-VBSCRIPT-FoD-Package~31bf3856ad364e35~amd64~~.cab|5487878144|297810|86a02b3bab1c8a23d429b748c5522ec2284b27579a3a1e1008acaaa271c9ac24
Microsoft-Windows-VBSCRIPT-FoD-Package~31bf3856ad364e35~wow64~en-US~.cab|5488357376|21890|95728ea1dd368fb922df543c932c82a5045b26922fa5fd90e356e19258af855e
Microsoft-Windows-VBSCRIPT-FoD-Package~31bf3856ad364e35~wow64~~.cab|5489135616|258215|aac8173c8bf6a78787b39c929ae1fbc8e5e3d128979fcf5352b97ffb9a23965d
"@ -split '\r?\n'
    $clock=[Diagnostics.Stopwatch]::StartNew()
    foreach($entry in $files){
        $name,$offset,$size,$hash=$entry.Split('|')
        $path=Join-Path $source $name
        New-Item -ItemType Directory -Path (Split-Path -Parent $path) -Force | Out-Null
        $end=[long]$offset+[int]$size-1
        $request=[Net.HttpWebRequest]::Create($url)
        $request.AllowAutoRedirect=$false
        $request.Timeout=10000
        $request.ReadWriteTimeout=10000
        $request.AddRange([long]$offset,[long]$end)
        $response=$null;$stream=$null
        try {
            if($clock.Elapsed.TotalSeconds -gt 90){throw 'Microsoft VBScript source timed out'}
            $response=$request.GetResponse()
            if([int]$response.StatusCode -ne 206 -or $response.Headers['Content-Range'] -ne ('bytes '+$offset+'-'+$end+'/6251841536')){throw 'Microsoft VBScript source range validation failed'}
            $stream=$response.GetResponseStream()
            $bytes=New-Object byte[] ([int]$size)
            $received=0
            while($received -lt $bytes.Length){
                $read=$stream.Read($bytes,$received,$bytes.Length-$received)
                if($read -eq 0 -or $clock.Elapsed.TotalSeconds -gt 90){throw 'Microsoft VBScript source transfer was incomplete'}
                $received+=$read
            }
            [IO.File]::WriteAllBytes($path,$bytes)
        }finally{
            if($stream){$stream.Dispose()}
            if($response){$response.Dispose()}
            $request.Abort()
        }
        if((Get-FileHash -LiteralPath $path).Hash -ne $hash){throw 'Microsoft VBScript source checksum mismatch'}
        Set-AnalysisHeartbeat 'gint-vbscript-source'
    }
    return $source
}
function Ensure-GintVbScript {
    if(-not(Test-Path 'C:\InstallerInput\Record-Iss.ps1') -or (Get-CimInstance Win32_ComputerSystem).Model -ne 'Virtual Machine'){
        throw 'PREREQUISITE REQUIRED: VBScript provisioning requires a Sandbox guest.'
    }
    Write-Checkpoint 'gINT: verifying 32-bit VBScript'
    if(-not(Test-GintVbScript)){
        if([Environment]::OSVersion.Version.Build -ne 26100 -or $env:PROCESSOR_ARCHITECTURE -ne 'AMD64' -or (Get-UICulture).Name -ne 'en-US'){
            throw 'PREREQUISITE REQUIRED: The preview VBScript source supports Windows 11 24H2, x64, en-US.'
        }
        Write-Checkpoint 'gINT: preparing VBScript from Microsoft feature media'
        $source=Get-GintVbScriptSource
        $run=Invoke-NetFx3Command ($env:WINDIR+'\System32\dism.exe') ('/Online /Add-Capability /CapabilityName:VBSCRIPT /Source:"'+$source+'" /LimitAccess /NoRestart') 'gint-vbscript-servicing.txt' 300
        if($run.ExitCode -ne 0 -or -not(Test-GintVbScript)){
            throw ('PREREQUISITE REQUIRED: VBScript provisioning or execution failed. DISM exit '+$run.ExitCode+'. See gint-vbscript-servicing.txt.')
        }
    }
    Write-Checkpoint 'gINT: 32-bit VBScript verified'
}
function Test-GintSignedNetFx3Runtime {
    $file=Join-Path $env:WINDIR 'Microsoft.NET\Framework\v3.5\MSBuild.exe'
    if(-not(Test-Path -LiteralPath $file)){return $false}
    $signature=Get-AuthenticodeSignature -LiteralPath $file
    if($signature.Status -ne 'Valid' -or $signature.SignerCertificate.Subject -notmatch 'O=Microsoft Corporation'){return $false}
    $project=Join-Path $env:TEMP ('InstallerAnalyzer-'+[guid]::NewGuid().ToString('N')+'.proj')
    '<Project DefaultTargets="Probe" xmlns="http://schemas.microsoft.com/developer/msbuild/2003"><Target Name="Probe"><Message Text="MSBUILD35_RUNTIME_OK" Importance="High" /></Target></Project>' | Set-Content -LiteralPath $project -Encoding Ascii
    $run=Invoke-NetFx3Command $file ('"'+$project+'" /nologo /verbosity:minimal') 'netfx3-signed-msbuild.txt' 30
    return $run.ExitCode -eq 0 -and $run.Text -match 'MSBUILD35_RUNTIME_OK'
}
""";
}

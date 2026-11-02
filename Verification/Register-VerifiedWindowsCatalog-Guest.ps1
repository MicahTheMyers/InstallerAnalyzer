# Verification-only repair of missing Windows catalog metadata in one disposable guest.
# No certificate or policy setting is changed. The signed catalog is not redistributed.
$ErrorActionPreference='Stop'
if($env:USERNAME -ne 'WDAGUtilityAccount'){throw 'This fixture requires the disposable Sandbox account.'}
$output='C:\InstallerOutput'
try {
 $metadata=Get-Content -LiteralPath 'C:\InstallerInput\windows-catalog.json' -Raw|ConvertFrom-Json
 $catalog='C:\InstallerInput\component.cat';$component=[string]$metadata.Component
 if((Get-FileHash -LiteralPath $component).Hash -ne $metadata.ComponentSha256){throw 'Guest Windows component differs from the catalog discovery source.'}
 if((Get-FileHash -LiteralPath $catalog).Hash -ne $metadata.CatalogSha256){throw 'Catalog bytes changed.'}
 $signature=Get-AuthenticodeSignature -LiteralPath $catalog
 if($signature.Status -ne 'Valid' -or $signature.SignerCertificate.Thumbprint -ne $metadata.SignerThumbprint){throw 'The guest does not trust the original Windows catalog signature. No registration was attempted.'}
 $policyBefore=(Get-ItemProperty 'HKLM:\SYSTEM\CurrentControlSet\Control\CI\Policy' -Name VerifiedAndReputablePolicyState).VerifiedAndReputablePolicyState
 if($policyBefore -ne 1){throw 'This experiment requires the observed enforcing guest policy state.'}
 $before=Get-AuthenticodeSignature -LiteralPath $component
 $baseName=$null
 if($before.Status -ne 'Valid'){
  Add-Type -TypeDefinition @'
using System; using System.Runtime.InteropServices;
public static class InstallerAnalyzerGuestCatalogRepair {
 [DllImport("wintrust.dll",CharSet=CharSet.Unicode,ExactSpelling=true,SetLastError=true)] static extern bool CryptCATAdminAcquireContext2(out IntPtr admin,ref Guid subsystem,string algorithm,IntPtr strong,uint flags);
 [DllImport("wintrust.dll",CharSet=CharSet.Unicode,ExactSpelling=true,SetLastError=true)] static extern IntPtr CryptCATAdminAddCatalog(IntPtr admin,string catalog,string name,uint flags);
 [DllImport("wintrust.dll",ExactSpelling=true)] static extern bool CryptCATAdminReleaseCatalogContext(IntPtr admin,IntPtr catalog,uint flags);
 [DllImport("wintrust.dll",ExactSpelling=true)] static extern bool CryptCATAdminReleaseContext(IntPtr admin,uint flags);
 public static void Register(string path,string name){IntPtr admin=IntPtr.Zero,cat=IntPtr.Zero;try{
  var subsystem=new Guid("F750E6C3-38EE-11d1-85E5-00C04FC295EE");
  if(!CryptCATAdminAcquireContext2(out admin,ref subsystem,"SHA256",IntPtr.Zero,0))throw new System.ComponentModel.Win32Exception();
  cat=CryptCATAdminAddCatalog(admin,path,name,0);if(cat==IntPtr.Zero)throw new System.ComponentModel.Win32Exception();
 }finally{if(cat!=IntPtr.Zero)CryptCATAdminReleaseCatalogContext(admin,cat,0);if(admin!=IntPtr.Zero)CryptCATAdminReleaseContext(admin,0);}}
}
'@
  $baseName='InstallerAnalyzer-WindowsComponent-'+[guid]::NewGuid().ToString('N')+'.cat'
  [InstallerAnalyzerGuestCatalogRepair]::Register($catalog,$baseName)
 }
 $after=Get-AuthenticodeSignature -LiteralPath $component
 $policyAfter=(Get-ItemProperty 'HKLM:\SYSTEM\CurrentControlSet\Control\CI\Policy' -Name VerifiedAndReputablePolicyState).VerifiedAndReputablePolicyState
 $result=[ordered]@{BeforeStatus=$before.Status.ToString();AfterStatus=$after.Status.ToString();AfterIsOSBinary=$after.IsOSBinary;Signer=$after.SignerCertificate.Subject;RegisteredCatalog=$baseName;PolicyStateBefore=$policyBefore;PolicyStateAfter=$policyAfter;ComponentHashUnchanged=((Get-FileHash -LiteralPath $component).Hash -eq $metadata.ComponentSha256);CertificatesOrPolicySettingsChanged=$false;Scope='Disposable Sandbox catalog metadata experiment only'}
 $result|ConvertTo-Json|Set-Content -LiteralPath (Join-Path $output 'windows-catalog-repair.json')
 if($after.Status -ne 'Valid' -or -not $after.IsOSBinary -or $policyAfter -ne $policyBefore -or -not $result.ComponentHashUnchanged){throw 'Catalog metadata did not restore the expected Windows signature while preserving policy and component bytes.'}
 Set-Content -LiteralPath (Join-Path $output 'catalog-repair-ready.flag') 'Windows catalog signature restored; guest policy remains enforced'
}catch{$_|Out-String|Set-Content -LiteralPath (Join-Path $output 'catalog-repair-error.txt')}
finally{Set-Content -LiteralPath (Join-Path $output 'catalog-repair-complete.flag') ([DateTimeOffset]::UtcNow.ToString('o'))}

param([Parameter(Mandatory=$true)][string]$FilePath,[Parameter(Mandatory=$true)][string]$OutputFolder)
$ErrorActionPreference='Stop'
Add-Type -TypeDefinition @'
using System; using System.IO; using System.Runtime.InteropServices;
public static class InstallerAnalyzerCatalogInspector {
 [StructLayout(LayoutKind.Sequential,CharSet=CharSet.Unicode)] struct Info {public uint Size; [MarshalAs(UnmanagedType.ByValTStr,SizeConst=260)] public string Path;}
 [DllImport("wintrust.dll",CharSet=CharSet.Unicode,SetLastError=true)] static extern bool CryptCATAdminAcquireContext2(out IntPtr admin,IntPtr subsystem,string algorithm,IntPtr strong,uint flags);
 [DllImport("wintrust.dll",SetLastError=true)] static extern bool CryptCATAdminCalcHashFromFileHandle2(IntPtr admin,IntPtr file,ref uint size,byte[] hash,uint flags);
 [DllImport("wintrust.dll",SetLastError=true)] static extern IntPtr CryptCATAdminEnumCatalogFromHash(IntPtr admin,byte[] hash,uint size,uint flags,ref IntPtr previous);
 [DllImport("wintrust.dll",CharSet=CharSet.Unicode,SetLastError=true)] static extern bool CryptCATCatalogInfoFromContext(IntPtr catalog,ref Info info,uint flags);
 [DllImport("wintrust.dll")] static extern bool CryptCATAdminReleaseCatalogContext(IntPtr admin,IntPtr catalog,uint flags);
 [DllImport("wintrust.dll")] static extern bool CryptCATAdminReleaseContext(IntPtr admin,uint flags);
 public static string Find(string path) {
  IntPtr admin=IntPtr.Zero,catalog=IntPtr.Zero;
  try {
   if(!CryptCATAdminAcquireContext2(out admin,IntPtr.Zero,"SHA256",IntPtr.Zero,0))throw new System.ComponentModel.Win32Exception();
   using(var file=new FileStream(path,FileMode.Open,FileAccess.Read,FileShare.Read)) {
    uint size=0; CryptCATAdminCalcHashFromFileHandle2(admin,file.SafeFileHandle.DangerousGetHandle(),ref size,null,0);
    if(size==0 || size>128)throw new InvalidDataException("Invalid catalog hash length.");
    var hash=new byte[size];
    if(!CryptCATAdminCalcHashFromFileHandle2(admin,file.SafeFileHandle.DangerousGetHandle(),ref size,hash,0))throw new System.ComponentModel.Win32Exception();
    IntPtr previous=IntPtr.Zero; catalog=CryptCATAdminEnumCatalogFromHash(admin,hash,size,0,ref previous);
    if(catalog==IntPtr.Zero)throw new InvalidDataException("Matching SHA256 catalog not found.");
    var info=new Info();info.Size=(uint)Marshal.SizeOf(typeof(Info));
    if(!CryptCATCatalogInfoFromContext(catalog,ref info,0))throw new System.ComponentModel.Win32Exception();
    return info.Path;
   }
  }finally{if(catalog!=IntPtr.Zero)CryptCATAdminReleaseCatalogContext(admin,catalog,0);if(admin!=IntPtr.Zero)CryptCATAdminReleaseContext(admin,0);}
 }
}
'@
$path=[IO.Path]::GetFullPath($FilePath)
$signature=Get-AuthenticodeSignature -LiteralPath $path
if($signature.Status -ne 'Valid' -or $signature.SignatureType -ne 'Catalog' -or -not $signature.IsOSBinary){throw 'Expected a valid catalog-signed Windows component'}
$catalog=[InstallerAnalyzerCatalogInspector]::Find($path)
$catalogSignature=Get-AuthenticodeSignature -LiteralPath $catalog
if($catalogSignature.Status -ne 'Valid' -or $catalogSignature.SignerCertificate.Thumbprint -ne $signature.SignerCertificate.Thumbprint){throw 'Matching catalog signature differs from the validated Windows component signer'}
New-Item -ItemType Directory -Path $OutputFolder -Force|Out-Null
$metadata=[ordered]@{Component=$path;ComponentSha256=(Get-FileHash -LiteralPath $path).Hash;ComponentSignature=$signature.Status.ToString();ComponentIsOSBinary=$signature.IsOSBinary;Catalog=$catalog;CatalogSha256=(Get-FileHash -LiteralPath $catalog).Hash;CatalogSignature=$catalogSignature.Status.ToString();Signer=$catalogSignature.SignerCertificate.Subject;SignerThumbprint=$catalogSignature.SignerCertificate.Thumbprint;Operation='Read-only Windows catalog discovery; no trust registration performed'}
$metadata|ConvertTo-Json|Set-Content -LiteralPath (Join-Path $OutputFolder 'catalog-discovery.json')
$metadata|ConvertTo-Json|Write-Output

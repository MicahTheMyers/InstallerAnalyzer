param(
 [ValidateSet('Apply','Restore')][string]$Mode='Apply',
 [Parameter(Mandatory=$true)][string]$BackupPath
)
$ErrorActionPreference='Stop'
$identity=[Security.Principal.WindowsIdentity]::GetCurrent()
$principal=New-Object Security.Principal.WindowsPrincipal($identity)
if(-not $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)){
 throw 'Administrator approval is required for the Windows Remote Desktop client graphics policy. No change was made.'
}
$key='SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services\Client'
$name='EnableHardwareMode'
$backupFile=[IO.Path]::GetFullPath($BackupPath)
if($Mode -eq 'Apply'){
 if(Test-Path -LiteralPath $backupFile){throw 'Backup already exists; restore that saved state before applying again.'}
 $readKey=[Microsoft.Win32.Registry]::LocalMachine.OpenSubKey($key,$false)
 try {
  $exists=$null -ne $readKey -and $readKey.GetValueNames() -contains $name
  $backup=[ordered]@{Key=$key;Name=$name;KeyExisted=($null -ne $readKey);ValueExisted=$exists;Value=$null;Kind=$null;CreatedAt=[DateTimeOffset]::Now.ToString('o')}
  if($exists){$backup.Value=$readKey.GetValue($name);$backup.Kind=$readKey.GetValueKind($name).ToString()}
 }finally{if($readKey){$readKey.Dispose()}}
 # Save the original state before changing a single graphics value.
 [IO.File]::WriteAllText($backupFile,($backup|ConvertTo-Json))
 $writeKey=[Microsoft.Win32.Registry]::LocalMachine.CreateSubKey($key)
 try{$writeKey.SetValue($name,0,[Microsoft.Win32.RegistryValueKind]::DWord)}finally{$writeKey.Dispose()}
 Write-Output 'Remote Desktop clients will use software decoding on subsequent connections. Reconnect the test viewer. Other new Remote Desktop connections also use this setting while it is applied.'
}else{
 $backup=Get-Content -LiteralPath $backupFile -Raw|ConvertFrom-Json
 if($backup.Key -cne $key -or $backup.Name -cne $name){throw 'Backup does not describe the supported graphics value.'}
 $writeKey=[Microsoft.Win32.Registry]::LocalMachine.OpenSubKey($key,$true)
 if($writeKey){
  try {
   $current=$writeKey.GetValue($name,$null)
   if($null -ne $current -and ([int]$current -ne 0 -or $writeKey.GetValueKind($name) -ne [Microsoft.Win32.RegistryValueKind]::DWord)){throw 'Graphics value changed since this workaround; original state was not overwritten.'}
   if($backup.ValueExisted){
    $kind=[Microsoft.Win32.RegistryValueKind][Enum]::Parse([Microsoft.Win32.RegistryValueKind],[string]$backup.Kind)
    $writeKey.SetValue($name,$backup.Value,$kind)
   }else{$writeKey.DeleteValue($name,$false)}
  }finally{$writeKey.Dispose()}
 }elseif($backup.ValueExisted){throw 'Original policy key disappeared; review before restoring.'}
 # Leave any empty policy key in place; do not delete trees or other settings.
 Write-Output 'Original Remote Desktop client graphics value restored. Reconnect the viewer to use it.'
}

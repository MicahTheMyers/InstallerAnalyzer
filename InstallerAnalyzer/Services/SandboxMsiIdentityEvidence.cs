namespace InstallerAnalyzer.Services;

public static partial class SandboxIssRecorder
{
    private const string MsiIdentityEvidenceScript = """
$script:MsiApplicationRegistryBaseline=@()
function Get-NativeMsiProductState([string]$code) {
  if($code -notmatch '^\{[0-9A-Fa-f-]{36}\}$'){return $null}
  $engine=$null
  try{
    $engine=New-Object -ComObject WindowsInstaller.Installer
    return [int]$engine.GetType().InvokeMember('ProductState',[Reflection.BindingFlags]::GetProperty,$null,$engine,@($code))
  }catch{return $null}
  finally{if($null -ne $engine){try{[void][Runtime.InteropServices.Marshal]::FinalReleaseComObject($engine)}catch{}}}
}
function Get-NativeMsiProductEntry {
  $metadata=$script:MsiStaticMetadata
  if($null -eq $metadata -or [string]::IsNullOrWhiteSpace([string]$metadata.ProductCode)){return $null}
  if((Get-NativeMsiProductState ([string]$metadata.ProductCode)) -ne 5){return $null}
  $code=[string]$metadata.ProductCode
  return [PSCustomObject]@{Key=('MSI::'+$code);DisplayName=[string]$metadata.ProductName;DisplayVersion=[string]$metadata.ProductVersion;Publisher=[string]$metadata.Manufacturer;InstallLocation='';UninstallString=('msiexec.exe /x '+$code+' /qn /norestart');QuietUninstallString=('msiexec.exe /x '+$code+' /qn /norestart');WindowsInstaller=1;ProductCode=$code}
}
function Test-NativeMsiProductDetected([string]$code) {
  $state=Get-NativeMsiProductState $code
  if($null -eq $state){throw 'Windows Installer product-state query failed; absence is unverified.'}
  if($state -eq -1){return $false}
  if($state -in @(1,5)){return $true}
  throw ('Windows Installer product state '+$state+' cannot prove installation/removal in this user context.')
}
function Resolve-KnownMsiFormat([string]$value) {
  $known=New-Object 'System.Collections.Generic.Dictionary[string,string]' ([StringComparer]::Ordinal)
  foreach($name in @('ProductName','Manufacturer','ProductVersion','ProductCode','UpgradeCode')){$known[$name]=[string]$script:MsiStaticMetadata.$name}
  return [regex]::Replace($value,'\[(?<property>[A-Za-z_][A-Za-z0-9_]*)\]',[Text.RegularExpressions.MatchEvaluator]{
    param($match)
    $name=$match.Groups['property'].Value
    if($known.ContainsKey($name)){return $known[$name]}
    return $match.Value
  })
}
function Get-ApplicationRegistryPresence($rule) {
  $base=$null;$key=$null
  try{
    if($rule.RegistryHive -notin @('LocalMachine','CurrentUser') -or $rule.RegistryView -notin @('Registry32','Registry64')){return $null}
    $hive=[Microsoft.Win32.RegistryHive][Enum]::Parse([Microsoft.Win32.RegistryHive],[string]$rule.RegistryHive)
    $view=[Microsoft.Win32.RegistryView][Enum]::Parse([Microsoft.Win32.RegistryView],[string]$rule.RegistryView)
    $base=[Microsoft.Win32.RegistryKey]::OpenBaseKey($hive,$view)
    $key=$base.OpenSubKey([string]$rule.RegistrySubKey,$false)
    if($null -eq $key){return $false}
    return (@($key.GetValueNames() | Where-Object {$_ -eq [string]$rule.ValueName}).Count -gt 0)
  }catch{return $null}
  finally{if($null -ne $key){$key.Dispose()};if($null -ne $base){$base.Dispose()}}
}
function Get-MsiApplicationRegistryBaseline {
  $rules=@()
  foreach($definition in @($script:MsiStaticMetadata.ApplicationRegistry | Select-Object -First 64)){
    $subkey=Resolve-KnownMsiFormat ([string]$definition.Key)
    $name=Resolve-KnownMsiFormat ([string]$definition.Name)
    if($subkey -match '\[|\]' -or $name -match '\[|\]' -or $name -in @('+','-','*')){continue}
    $hives=switch([int]$definition.Root){1{@('CurrentUser')}2{@('LocalMachine')}-1{@('CurrentUser','LocalMachine')}default{@()}}
    foreach($hive in $hives){
      $root=if($hive -eq 'LocalMachine'){'HKLM:\'}else{'HKCU:\'}
      $rule=[PSCustomObject]@{Type='ApplicationRegistryValue';Identity=($root+$subkey+' :: '+$name);RegistryPath=($root+$subkey);RegistryHive=$hive;RegistrySubKey=$subkey;RegistryView=[string]$definition.RegistryView;ValueName=$name;ExecutablePath='';Provider='MsiComponentRegistryKeyPath';Version=$null;Rank=82;BeforeInstall=$null;AfterInstall=$null;AfterUninstall=$null;DeclaredRoot=[int]$definition.Root}
      $rule.BeforeInstall=Get-ApplicationRegistryPresence $rule
      $rules+=@($rule)
    }
  }
  return $rules
}
function Add-MsiApplicationRegistryCandidates($entry) {
  foreach($source in @($script:MsiApplicationRegistryBaseline)){
    if($source.DeclaredRoot -eq -1){
      $key=[string]$entry.Key
      if($key -match '(?i)HKEY_LOCAL_MACHINE|^HKLM:'){$hive='LocalMachine'}
      elseif($key -match '(?i)HKEY_CURRENT_USER|^HKCU:'){$hive='CurrentUser'}
      else{continue}
      if($source.RegistryHive -ne $hive){continue}
    }
    $source.AfterInstall=Get-ApplicationRegistryPresence $source
    if($source.AfterInstall -eq $true){$result.DetectionStrategies+=@($source)}
  }
}
""";
}


$ErrorActionPreference='Stop'
try{
  [IO.Directory]::CreateDirectory('C:\ConditionFixture\App')|Out-Null
  Copy-Item -Path 'C:\PublishedVerifier\*' -Destination C:\ConditionFixture\App -Recurse
  $engine=New-Object -ComObject WindowsInstaller.Installer
  $database=$engine.GetType().InvokeMember('OpenDatabase',[Reflection.BindingFlags]::InvokeMethod,$null,$engine,@('C:\ConditionFixture\context.msi',3))
  foreach($sql in @('CREATE TABLE `Property` (`Property` CHAR(72) NOT NULL, `Value` CHAR(0) PRIMARY KEY `Property`)',"INSERT INTO ``Property`` (``Property``,``Value``) VALUES ('ProductCode','{DA52A36C-7890-478B-AB4A-B6C28549D747}')","INSERT INTO ``Property`` (``Property``,``Value``) VALUES ('ProductName','Inert condition context')","INSERT INTO ``Property`` (``Property``,``Value``) VALUES ('ProductVersion','1.0.0')","INSERT INTO ``Property`` (``Property``,``Value``) VALUES ('Manufacturer','Installer Analyzer Tests')","INSERT INTO ``Property`` (``Property``,``Value``) VALUES ('ProductLanguage','1033')")){
    $view=$database.GetType().InvokeMember('OpenView',[Reflection.BindingFlags]::InvokeMethod,$null,$database,@($sql))
    try{[void]$view.GetType().InvokeMember('Execute',[Reflection.BindingFlags]::InvokeMethod,$null,$view,$null)}finally{[void][Runtime.InteropServices.Marshal]::FinalReleaseComObject($view)}
  }
  $summary=$database.GetType().InvokeMember('SummaryInformation',[Reflection.BindingFlags]::GetProperty,$null,$database,@(5))
  foreach($pair in @(@(7,'Intel;1033'),@(9,'{72064738-3933-4C7C-988B-8EF47C65DD6F}'),@(14,200),@(15,0))){[void]$summary.GetType().InvokeMember('Property',[Reflection.BindingFlags]::SetProperty,$null,$summary,@($pair[0],$pair[1]))}
  [void]$summary.GetType().InvokeMember('Persist',[Reflection.BindingFlags]::InvokeMethod,$null,$summary,$null)
  [void]$database.GetType().InvokeMember('Commit',[Reflection.BindingFlags]::InvokeMethod,$null,$database,$null)
  foreach($item in @($summary,$database,$engine)){[void][Runtime.InteropServices.Marshal]::FinalReleaseComObject($item)}
  $info=New-Object Diagnostics.ProcessStartInfo;$info.FileName='C:\ConditionFixture\App\Verification.exe';$info.Arguments='C:\InstallerOutput --condition-oracle C:\ConditionFixture\context.msi';$info.UseShellExecute=$false;$info.CreateNoWindow=$true;$info.RedirectStandardOutput=$true;$info.RedirectStandardError=$true
  $p=New-Object Diagnostics.Process;$p.StartInfo=$info;[void]$p.Start();$stdout=$p.StandardOutput.ReadToEndAsync();$stderr=$p.StandardError.ReadToEndAsync()
  if(-not $p.WaitForExit(30000)){try{$p.Kill()}catch{};throw 'Condition oracle timed out'}
  [IO.File]::WriteAllText('C:\InstallerOutput\stdout.txt',$stdout.GetAwaiter().GetResult());[IO.File]::WriteAllText('C:\InstallerOutput\stderr.txt',$stderr.GetAwaiter().GetResult())
  if($p.ExitCode -ne 0){throw 'Condition oracle failed; see stdout/stderr'}
}catch{$_|Out-String|Set-Content C:\InstallerOutput\error.txt}finally{Set-Content C:\InstallerOutput\done.txt 'done'}

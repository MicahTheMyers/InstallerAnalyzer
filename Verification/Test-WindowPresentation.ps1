param([string]$Repository=(Split-Path $PSScriptRoot -Parent))
$ErrorActionPreference='Stop'
$text=Get-Content -LiteralPath (Join-Path $Repository 'InstallerAnalyzer\Services\SandboxIssRecorder.cs') -Raw
$code=[regex]::Match($text,"(?s)Add-Type @'\r?\n(using System;.*?InstallerAnalyzerWindowProbe.*?)\r?\n'@").Groups[1].Value
if(-not $code){throw 'Production window probe not found'}
Add-Type -TypeDefinition $code
Add-Type -AssemblyName System.Windows.Forms
$form=New-Object Windows.Forms.Form
$count=0
function Check($ok,[string]$name){if(-not $ok){throw $name};$script:count++;Write-Output "PASS $name"}
try {
  $form.Text='Installer Analyzer presentation test fixture'
  $form.StartPosition='Manual';$form.Location=New-Object Drawing.Point(100,100)
  $form.Show();[Windows.Forms.Application]::DoEvents()
  Check ([InstallerAnalyzerWindowProbe]::IsPresentedWindow($form.Handle.ToInt64())) 'On-screen installer window remains detectable'
  $form.Location=New-Object Drawing.Point(-32000,-32000);[Windows.Forms.Application]::DoEvents()
  Check (-not [InstallerAnalyzerWindowProbe]::IsPresentedWindow($form.Handle.ToInt64())) 'Off-screen visible-style window is not presented UI'
  Check (@([InstallerAnalyzerWindowProbe]::DesktopWindows($true)|Where-Object {$_ -like '*presentation test fixture'}).Count -eq 1) 'Raw diagnostic preserves the off-screen owner window'
  Check (@([InstallerAnalyzerWindowProbe]::DesktopWindows()|Where-Object {$_ -like '*presentation test fixture'}).Count -eq 0) 'Desktop UI monitoring omits off-screen owner window'
  $form.Location=New-Object Drawing.Point(100,100);$form.Hide();[Windows.Forms.Application]::DoEvents()
  Check (-not [InstallerAnalyzerWindowProbe]::IsPresentedWindow($form.Handle.ToInt64())) 'Hidden window is not presented UI'
  Check (-not [InstallerAnalyzerWindowProbe]::IsPresentedWindow(0)) 'Invalid window is ignored safely'
} finally {$form.Dispose()}
Write-Output "RESULT: $count passed, 0 failed"

@echo off
echo This restores the Remote Desktop graphics policy saved before the test.
echo Windows will ask for administrator approval.
powershell.exe -NoProfile -ExecutionPolicy Bypass -File "%~dp0Invoke-SandboxDisplayRepair.ps1" -Mode Restore
pause

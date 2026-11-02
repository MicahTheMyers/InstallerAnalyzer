@echo off
echo This tests software graphics decoding for Windows Remote Desktop clients.
echo Windows will ask for administrator approval. Other new Remote Desktop
echo connections also use software decoding until the workaround is restored.
powershell.exe -NoProfile -ExecutionPolicy Bypass -File "%~dp0Invoke-SandboxDisplayRepair.ps1" -Mode Apply
pause

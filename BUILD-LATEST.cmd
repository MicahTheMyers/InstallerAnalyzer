@echo off
setlocal
cd /d "%~dp0"
where dotnet >nul 2>&1
if errorlevel 1 (
 echo Install the .NET 8 SDK, then run this file again.
 echo https://dotnet.microsoft.com/download/dotnet/8.0
 pause
 exit /b 1
)
dotnet publish "InstallerAnalyzer\InstallerAnalyzer.csproj" -c Release -r win-x64 --self-contained true -p:PublishSingleFile=true -p:IncludeNativeLibrariesForSelfExtract=true -p:InformationalVersion=0.12.10-sandbox-netfx3-fix-20261101 -o "Build"
if errorlevel 1 (
 echo Build failed. Review the messages above.
 pause
 exit /b 1
)
echo Build complete. Run Build\InstallerAnalyzer.exe with its adjacent files.
pause
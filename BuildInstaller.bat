@echo off
setlocal EnableExtensions EnableDelayedExpansion
cd /d "%~dp0"

echo ============================================
echo   Installer Analyzer v0.10.9 Release Builder
echo ============================================
echo.

call Build.bat --no-open
if errorlevel 1 exit /b 1

call :FindInno
if defined ISCC goto :buildinstaller

echo Inno Setup 6 was not found. Attempting installation with winget...
where winget >nul 2>&1 || goto :noinno
winget install --id JRSoftware.InnoSetup --exact --source winget --accept-source-agreements --accept-package-agreements
if errorlevel 1 (
  echo.
  echo winget did not complete successfully. Checking for an existing Inno Setup installation anyway...
)

call :FindInno
if not defined ISCC goto :noinno

:buildinstaller
echo.
echo Using Inno Setup compiler:
echo %ISCC%
echo.
if not exist Release mkdir Release
"%ISCC%" "Installer\InstallerAnalyzer.iss"
if errorlevel 1 goto :failed

copy /Y "Build\InstallerAnalyzer.exe" "Release\InstallerAnalyzer-Portable.exe" >nul

echo.
echo ============================================
echo RELEASE BUILD COMPLETE
echo ============================================
echo Release\InstallerAnalyzer-Setup.exe
echo Release\InstallerAnalyzer-Portable.exe
echo.
explorer "%~dp0Release"
pause
exit /b 0

:FindInno
set "ISCC="
for %%P in (
  "%ProgramFiles(x86)%\Inno Setup 6\ISCC.exe"
  "%ProgramFiles%\Inno Setup 6\ISCC.exe"
  "%LOCALAPPDATA%\Programs\Inno Setup 6\ISCC.exe"
  "%LOCALAPPDATA%\Inno Setup 6\ISCC.exe"
) do (
  if not defined ISCC if exist "%%~P" set "ISCC=%%~P"
)
if defined ISCC exit /b 0
for /f "delims=" %%I in ('where ISCC.exe 2^>nul') do (
  if not defined ISCC set "ISCC=%%I"
)
exit /b 0

:noinno
echo.
echo ERROR: Inno Setup 6 is installed according to winget, but ISCC.exe could not be located.
echo Checked Program Files, Program Files ^(x86^), LocalAppData, and PATH.
echo.
echo If needed, locate ISCC.exe and send me its path.
pause
exit /b 1

:failed
echo ERROR: Installer build failed.
pause
exit /b 1

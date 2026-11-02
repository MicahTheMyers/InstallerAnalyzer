@echo off
setlocal EnableExtensions
cd /d "%~dp0"

echo ============================================
echo   Installer Analyzer - Windows x64 Builder
echo ============================================
echo.

where dotnet >nul 2>&1
if errorlevel 1 (
    echo .NET SDK was not found.
    echo Attempting to install the Microsoft .NET 8 SDK automatically...
    echo.

    where winget >nul 2>&1
    if errorlevel 1 (
        echo ERROR: Windows Package Manager ^(winget^) is not available.
        echo Install the .NET 8 SDK manually from:
        echo https://dotnet.microsoft.com/download/dotnet/8.0
        echo.
        pause
        exit /b 1
    )

    winget install --id Microsoft.DotNet.SDK.8 --exact --source winget --accept-source-agreements --accept-package-agreements

    if errorlevel 1 (
        echo.
        echo ERROR: Automatic .NET 8 SDK installation failed.
        echo Install it manually from:
        echo https://dotnet.microsoft.com/download/dotnet/8.0
        echo.
        pause
        exit /b 1
    )

    echo.
    echo .NET 8 SDK installation completed.
    echo Refreshing environment...
    echo.

    if exist "%ProgramFiles%\dotnet\dotnet.exe" (
        set "PATH=%ProgramFiles%\dotnet;%PATH%"
    )
)

if not exist "%ProgramFiles%\dotnet\dotnet.exe" (
    where dotnet >nul 2>&1
    if errorlevel 1 (
        echo ERROR: dotnet is still unavailable after installation.
        echo Close this window and run Build.bat again.
        echo.
        pause
        exit /b 1
    )
)

echo Installed .NET SDKs:
dotnet --list-sdks
echo.

dotnet --list-sdks | findstr /R /C:"^8\." >nul
if errorlevel 1 (
    echo .NET is installed, but the .NET 8 SDK is missing.
    echo Installing Microsoft .NET 8 SDK...
    echo.

    where winget >nul 2>&1
    if errorlevel 1 (
        echo ERROR: winget is unavailable.
        echo Install .NET 8 SDK manually from:
        echo https://dotnet.microsoft.com/download/dotnet/8.0
        echo.
        pause
        exit /b 1
    )

    winget install --id Microsoft.DotNet.SDK.8 --exact --source winget --accept-source-agreements --accept-package-agreements

    if errorlevel 1 (
        echo.
        echo ERROR: Automatic .NET 8 SDK installation failed.
        pause
        exit /b 1
    )

    if exist "%ProgramFiles%\dotnet\dotnet.exe" (
        set "PATH=%ProgramFiles%\dotnet;%PATH%"
    )
)

echo.
echo Building self-contained Windows x64 executable...
echo.

if not exist "InstallerAnalyzer.csproj" (
    echo ERROR: InstallerAnalyzer.csproj was not found.
    echo Keep Build.bat in the InstallerAnalyzer project folder.
    echo.
    pause
    exit /b 1
)

dotnet publish "InstallerAnalyzer.csproj" ^
  -c Release ^
  -r win-x64 ^
  --self-contained true ^
  -p:PublishSingleFile=true ^
  -p:IncludeNativeLibrariesForSelfExtract=true ^
  -o "%~dp0Build"

if errorlevel 1 (
    echo.
    echo ============================================
    echo BUILD FAILED
    echo ============================================
    echo Review the errors above.
    echo.
    pause
    exit /b 1
)

echo.
echo ============================================
echo BUILD COMPLETE
echo ============================================
echo.
echo Output folder:
echo %~dp0Build
echo.

if exist "%~dp0Build\InstallerAnalyzer.exe" (
    echo InstallerAnalyzer.exe was created successfully.
    echo.
    if /I not "%~1"=="--no-open" explorer "%~dp0Build"
) else (
    echo Build completed, but InstallerAnalyzer.exe was not found
    echo under the expected filename.
    if /I not "%~1"=="--no-open" explorer "%~dp0Build"
)

echo.
if /I not "%~1"=="--no-open" pause
endlocal

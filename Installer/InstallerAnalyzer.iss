#define MyAppName "Installer Analyzer for ImmyBot"
#define MyAppVersion "0.9.5"
#define MyAppPublisher "InstallerAnalyzer"
#define MyAppURL "https://github.com/MicahTheMyers/InstallerAnalyzer"
#define MyAppExeName "InstallerAnalyzer.exe"

[Setup]
AppId={{6F7D5E8D-9A61-4C93-BD40-A18430B7D4F2}
AppName={#MyAppName}
AppVersion={#MyAppVersion}
AppPublisher={#MyAppPublisher}
AppPublisherURL={#MyAppURL}
AppSupportURL={#MyAppURL}/issues
AppUpdatesURL={#MyAppURL}/releases
DefaultDirName={autopf}\Installer Analyzer
DefaultGroupName=Installer Analyzer
DisableProgramGroupPage=yes
OutputDir=..\Release
OutputBaseFilename=InstallerAnalyzer-Setup
SetupIconFile=..\Assets\InstallerAnalyzer.ico
UninstallDisplayIcon={app}\{#MyAppExeName}
Compression=lzma2/max
SolidCompression=yes
WizardStyle=modern
PrivilegesRequired=admin
ArchitecturesAllowed=x64compatible
ArchitecturesInstallIn64BitMode=x64compatible
CloseApplications=yes
RestartApplications=yes
VersionInfoVersion={#MyAppVersion}.0
VersionInfoProductName={#MyAppName}
VersionInfoProductVersion={#MyAppVersion}
VersionInfoCompany={#MyAppPublisher}
VersionInfoDescription={#MyAppName} Setup

[Files]
Source: "..\Build\InstallerAnalyzer.exe"; DestDir: "{app}"; Flags: ignoreversion

[Icons]
Name: "{autoprograms}\Installer Analyzer"; Filename: "{app}\{#MyAppExeName}"
Name: "{autodesktop}\Installer Analyzer"; Filename: "{app}\{#MyAppExeName}"; Tasks: desktopicon

[Tasks]
Name: "desktopicon"; Description: "Create a &desktop shortcut"; GroupDescription: "Additional icons:"; Flags: unchecked

[Run]
Filename: "{app}\{#MyAppExeName}"; Description: "Launch Installer Analyzer"; Flags: nowait postinstall skipifsilent

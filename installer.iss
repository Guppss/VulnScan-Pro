[Setup]
AppName=VulnScan Pro
AppVersion=1.0
AppPublisher=Guppss
DefaultDirName={autopf}\VulnScan Pro
DefaultGroupName=VulnScan Pro
OutputDir=installer_output
OutputBaseFilename=VulnScan-Pro-Setup
Compression=lzma2/ultra64
SolidCompression=yes
WizardStyle=modern

[Files]
Source: "dist\VulnScan Pro\*"; DestDir: "{app}"; Flags: ignoreversion recursesubdirs

[Icons]
Name: "{group}\VulnScan Pro"; Filename: "{app}\VulnScan Pro.exe"
Name: "{commondesktop}\VulnScan Pro"; Filename: "{app}\VulnScan Pro.exe"

[Run]
Filename: "{app}\VulnScan Pro.exe"; Description: "Launch VulnScan Pro"; Flags: nowait postinstall skipifsilent
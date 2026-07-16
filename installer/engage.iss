#ifndef MyAppVersion
  #define MyAppVersion "0.1.0"
#endif

#define MyAppName "Engage"
#define MyAppPublisher "Engage contributors"
#define MyGuiExe "engage.exe"
#define MyCliExe "engage-cli.exe"

[Setup]
AppId={{3F4F766A-7E7E-4DB9-9C69-E56BB1447549}
AppName={#MyAppName}
AppVersion={#MyAppVersion}
AppVerName={#MyAppName} {#MyAppVersion}
AppPublisher={#MyAppPublisher}
DefaultDirName={localappdata}\Programs\Engage
DefaultGroupName={#MyAppName}
DisableProgramGroupPage=yes
PrivilegesRequired=lowest
ArchitecturesAllowed=x64compatible
ArchitecturesInstallIn64BitMode=x64compatible
MinVersion=10.0
OutputDir=..\dist
OutputBaseFilename=engage-{#MyAppVersion}-windows-x64-setup
SetupIconFile=..\assets\windows\engage.ico
UninstallDisplayIcon={app}\{#MyGuiExe}
Compression=lzma2
SolidCompression=yes
WizardStyle=modern dynamic windows11 includetitlebar
ChangesAssociations=yes
CloseApplications=yes
RestartApplications=no
UsePreviousAppDir=yes
VersionInfoVersion={#MyAppVersion}
VersionInfoDescription={#MyAppName} installer
VersionInfoProductName={#MyAppName}
VersionInfoProductVersion={#MyAppVersion}

[Languages]
Name: "english"; MessagesFile: "compiler:Default.isl"
Name: "chinesesimplified"; MessagesFile: "compiler:Languages\ChineseSimplified.isl"

[Tasks]
Name: "desktopicon"; Description: "{cm:CreateDesktopIcon}"; GroupDescription: "{cm:AdditionalIcons}"; Flags: unchecked

[Files]
Source: "..\target\release\{#MyGuiExe}"; DestDir: "{app}"; Flags: ignoreversion
Source: "..\target\release\{#MyCliExe}"; DestDir: "{app}"; Flags: ignoreversion

[Icons]
Name: "{autoprograms}\{#MyAppName}"; Filename: "{app}\{#MyGuiExe}"
Name: "{autodesktop}\{#MyAppName}"; Filename: "{app}\{#MyGuiExe}"; Tasks: desktopicon

[Registry]
Root: HKCU; Subkey: "Software\Microsoft\Windows\CurrentVersion\App Paths\{#MyGuiExe}"; ValueType: string; ValueName: ""; ValueData: "{app}\{#MyGuiExe}"; Flags: uninsdeletekey
Root: HKCU; Subkey: "Software\Microsoft\Windows\CurrentVersion\App Paths\{#MyGuiExe}"; ValueType: string; ValueName: "Path"; ValueData: "{app}"
Root: HKCU; Subkey: "Software\Microsoft\Windows\CurrentVersion\App Paths\{#MyCliExe}"; ValueType: string; ValueName: ""; ValueData: "{app}\{#MyCliExe}"; Flags: uninsdeletekey
Root: HKCU; Subkey: "Software\Microsoft\Windows\CurrentVersion\App Paths\{#MyCliExe}"; ValueType: string; ValueName: "Path"; ValueData: "{app}"

[Run]
Filename: "{app}\{#MyGuiExe}"; Description: "{cm:LaunchProgram,{#StringChange(MyAppName, '&', '&&')}}"; Flags: nowait postinstall skipifsilent

[Code]
const
  ClassesRoot = 'Software\Classes';
  ExtensionKey = 'Software\Classes\.engage';
  OpenWithKey = 'Software\Classes\.engage\OpenWithProgids';
  ProgId = 'Engage.Archive';
  ProgIdKey = 'Software\Classes\Engage.Archive';
  BackupKey = 'Software\Engage\InstallerBackup\FileAssociation';

procedure CapturePreviousAssociation;
var
  PreviousProgId: String;
  HadPreviousValue: Cardinal;
begin
  if RegValueExists(HKCU, BackupKey, 'Captured') then
    exit;

  HadPreviousValue := 0;
  if RegQueryStringValue(HKCU, ExtensionKey, '', PreviousProgId) then
  begin
    HadPreviousValue := 1;
    RegWriteStringValue(HKCU, BackupKey, 'PreviousProgId', PreviousProgId);
  end;

  RegWriteDWordValue(HKCU, BackupKey, 'HadPreviousValue', HadPreviousValue);
  RegWriteDWordValue(HKCU, BackupKey, 'Captured', 1);
end;

procedure RegisterFileAssociation;
var
  OpenCommand: String;
begin
  CapturePreviousAssociation;
  OpenCommand := '"' + ExpandConstant('{app}\{#MyGuiExe}') + '" "%1"';

  RegDeleteKeyIncludingSubkeys(HKCU, ProgIdKey);
  RegWriteStringValue(HKCU, ProgIdKey, '', 'Engage encrypted archive');
  RegWriteStringValue(HKCU, ProgIdKey + '\DefaultIcon', '',
    ExpandConstant('{app}\{#MyGuiExe},0'));
  RegWriteStringValue(HKCU, ProgIdKey + '\shell\open\command', '', OpenCommand);
  RegWriteStringValue(HKCU, OpenWithKey, ProgId, '');
  RegWriteStringValue(HKCU, ExtensionKey, '', ProgId);
end;

procedure RestorePreviousAssociation;
var
  CurrentProgId: String;
  PreviousProgId: String;
  Captured: Cardinal;
  HadPreviousValue: Cardinal;
begin
  if not RegQueryDWordValue(HKCU, BackupKey, 'Captured', Captured) then
    Captured := 0;
  if not RegQueryDWordValue(HKCU, BackupKey, 'HadPreviousValue', HadPreviousValue) then
    HadPreviousValue := 0;

  if RegQueryStringValue(HKCU, ExtensionKey, '', CurrentProgId) and
     (CompareText(CurrentProgId, ProgId) = 0) then
  begin
    if (Captured <> 0) and (HadPreviousValue <> 0) and
       RegQueryStringValue(HKCU, BackupKey, 'PreviousProgId', PreviousProgId) then
      RegWriteStringValue(HKCU, ExtensionKey, '', PreviousProgId)
    else
      RegDeleteValue(HKCU, ExtensionKey, '');
  end;

  RegDeleteValue(HKCU, OpenWithKey, ProgId);
  RegDeleteKeyIncludingSubkeys(HKCU, ProgIdKey);
  RegDeleteKeyIncludingSubkeys(HKCU, BackupKey);
end;

procedure CurStepChanged(CurStep: TSetupStep);
begin
  if CurStep = ssPostInstall then
    RegisterFileAssociation;
end;

procedure CurUninstallStepChanged(CurUninstallStep: TUninstallStep);
begin
  if CurUninstallStep = usUninstall then
    RestorePreviousAssociation;
end;

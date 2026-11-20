#define MyAppName "BootCounter"
#define MyAppVersion "1.0.0"
#define MyAppPublisher "BootCounter"
#define MyAppExeName "BootCounter.exe"

[Setup]
AppId={{8B3C5A92-4D17-4E91-9A2F-7F10E3C6B421}
AppName={#MyAppName}
AppVersion={#MyAppVersion}
AppPublisher={#MyAppPublisher}
DefaultDirName={autopf}\{#MyAppName}
DefaultGroupName={#MyAppName}
DisableProgramGroupPage=yes
DisableDirPage=no
AllowNoIcons=yes
PrivilegesRequired=admin
PrivilegesRequiredOverridesAllowed=dialog
WizardStyle=modern
CloseApplications=yes
RestartApplications=no
SetupIconFile=app.ico
UninstallDisplayIcon={app}\{#MyAppExeName}
OutputDir=dist
OutputBaseFilename=BootCounter_Setup_{#MyAppVersion}
Compression=lzma2
SolidCompression=yes
ArchitecturesInstallIn64BitMode=x64compatible
ShowLanguageDialog=auto
UsePreviousLanguage=no

[Languages]
Name: "chinesesimplified"; MessagesFile: "ChineseSimplified.isl"
Name: "english"; MessagesFile: "compiler:Default.isl"

[Tasks]
Name: "desktopicon"; Description: "{cm:CreateDesktopIcon}"; GroupDescription: "{cm:AdditionalIcons}"

[Files]
Source: "build\BootCounter_App\*"; DestDir: "{app}"; Flags: ignoreversion recursesubdirs createallsubdirs

[Icons]
Name: "{autoprograms}\{#MyAppName}"; Filename: "{app}\{#MyAppExeName}"; IconFilename: "{app}\app.ico"
Name: "{autodesktop}\{#MyAppName}"; Filename: "{app}\{#MyAppExeName}"; IconFilename: "{app}\app.ico"; Tasks: desktopicon

[UninstallDelete]
; 卸载时删除 state.json 与整个安装目录，确保不残留任何 exe/dll 文件且重装必换 6 位 Emoji 指纹
; 同时保留注册表防回滚锚点（HKCU\Software\BootCounter）与 audit.log，使重装后同步触发告警
Type: files; Name: "{userappdata}\BootCounter\state.json"
Type: filesandordirs; Name: "{app}"

[Registry]
Root: HKCU; Subkey: "Software\Microsoft\Windows\CurrentVersion\Run"; ValueName: "BootCounter"; Flags: uninsdeletevalue

[Run]
Filename: "{app}\{#MyAppExeName}"; Description: "{cm:LaunchProgram,{#StringChange(MyAppName, '&', '&&')}}"; Flags: nowait postinstall skipifsilent

[Code]
procedure KillRunningBootCounter();
var
  ResultCode: Integer;
begin
  Exec(ExpandConstant('{sys}\taskkill.exe'), '/F /IM BootCounter.exe', '', SW_HIDE, ewWaitUntilTerminated, ResultCode);
  Sleep(300);
end;

function InitializeSetup(): Boolean;
begin
  KillRunningBootCounter();
  Result := True;
end;

function InitializeUninstall(): Boolean;
begin
  KillRunningBootCounter();
  Result := True;
end;

procedure CurStepChanged(CurStep: TSetupStep);
var
  SealFile: String;
  SealVal: String;
begin
  if CurStep = ssPostInstall then
  begin
    SealFile := ExpandConstant('{app}\install_seal.dat');
    SealVal := GetDateTimeString('yyyymmddhhnnss', #0, #0) + '-' + IntToStr(Random(2147483647)) + '-' + IntToStr(Random(2147483647));
    SaveStringToFile(SealFile, SealVal, False);
  end;
end;

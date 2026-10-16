; Установщик Secret-bot (Inno Setup 6).
; Сборка: build\build.ps1  (он вызывает ISCC с /DMyAppVersion=...)
;
; Установка по умолчанию — для текущего пользователя, без прав администратора
; ({autopf} в этом режиме указывает на %LOCALAPPDATA%\Programs). Файл настроек
; кладётся в %APPDATA%\SecretBot\secret-bot.env — туда программа пишет и базу,
; и его можно править без администратора.

#define MyAppName "Secret-bot"
#define MyAppExeName "SecretBot.exe"
#ifndef MyAppVersion
  #define MyAppVersion "1.1.0"
#endif
#define MyAppPublisher "TeivrimOriginal"
#define MyAppUrl "https://github.com/TeivrimOriginal/Secret-bot"
#define MyDataDirName "SecretBot"

[Setup]
AppId={{8C4A1D2E-6B77-4E3A-9F21-5D0C9B7A4E10}
AppName={#MyAppName}
AppVersion={#MyAppVersion}
AppVerName={#MyAppName} {#MyAppVersion}
AppPublisher={#MyAppPublisher}
AppPublisherURL={#MyAppUrl}
AppSupportURL={#MyAppUrl}
AppUpdatesURL={#MyAppUrl}
DefaultDirName={autopf}\{#MyAppName}
DefaultGroupName={#MyAppName}
DisableProgramGroupPage=yes
PrivilegesRequired=lowest
PrivilegesRequiredOverridesAllowed=dialog
LicenseFile=LICENSE.txt
OutputDir=dist
OutputBaseFilename=SecretBot-{#MyAppVersion}-setup
Compression=lzma2/max
SolidCompression=yes
WizardStyle=modern
ArchitecturesAllowed=x64compatible
ArchitecturesInstallIn64BitMode=x64compatible
UninstallDisplayIcon={app}\{#MyAppExeName}
UninstallDisplayName={#MyAppName} {#MyAppVersion}

[Languages]
Name: "russian"; MessagesFile: "compiler:Languages\Russian.isl"
Name: "english"; MessagesFile: "compiler:Default.isl"

[Tasks]
Name: "desktopicon"; Description: "{cm:CreateDesktopIcon}"; \
    GroupDescription: "{cm:AdditionalIcons}"; Flags: unchecked

[Files]
; Вся onedir-сборка PyInstaller
Source: "dist\SecretBot\{#MyAppExeName}"; DestDir: "{app}"; Flags: ignoreversion
Source: "dist\SecretBot\_internal\*"; DestDir: "{app}\_internal"; \
    Flags: ignoreversion recursesubdirs createallsubdirs
Source: "..\README.md"; DestDir: "{app}"; Flags: ignoreversion isreadme
; Шаблон настроек кладём сразу в пользовательский каталог (не перезаписываем)
Source: "secret-bot.env.template"; DestDir: "{userappdata}\{#MyDataDirName}"; \
    DestName: "secret-bot.env.new"; Flags: onlyifdoesntexist uninsneveruninstall

[Icons]
Name: "{group}\{#MyAppName}"; Filename: "{app}\{#MyAppExeName}"
Name: "{group}\Настроить (secret-bot.env)"; Filename: "{sys}\notepad.exe"; \
    Parameters: """{userappdata}\{#MyDataDirName}\secret-bot.env"""
Name: "{group}\Проверить сборку"; Filename: "{app}\{#MyAppExeName}"; \
    Parameters: "--selftest"
Name: "{group}\Папка с данными"; Filename: "{userappdata}\{#MyDataDirName}"
Name: "{group}\{cm:UninstallProgram,{#MyAppName}}"; Filename: "{uninstallexe}"
Name: "{autodesktop}\{#MyAppName}"; Filename: "{app}\{#MyAppExeName}"; \
    Tasks: desktopicon

[Run]
Filename: "{sys}\notepad.exe"; \
    Parameters: """{userappdata}\{#MyDataDirName}\secret-bot.env"""; \
    Description: "Открыть файл настроек (впишите BOT_TOKEN и BASE_URL)"; \
    Flags: postinstall shellexec skipifsilent nowait unchecked
Filename: "{app}\{#MyAppExeName}"; Parameters: "--selftest"; \
    Description: "Проверить сборку"; \
    Flags: postinstall nowait skipifsilent unchecked

[UninstallDelete]
; Ничего из пользовательских данных не удаляем: там ключи ссылок и passkey.
Type: files; Name: "{app}\*.log"

[Code]
const
  EnvTemplate =
    '; Настройки Secret-bot. Изменения вступают в силу при следующем запуске.' + #13#10 +
    '; Строки, начинающиеся с ; или #, игнорируются.' + #13#10 +
    '' + #13#10 +
    '; Токен бота от @BotFather — обязателен.' + #13#10 +
    'BOT_TOKEN=' + #13#10 +
    '' + #13#10 +
    '; Публичный адрес сайта БЕЗ слеша на конце.' + #13#10 +
    '; WebAuthn (passkey) работает только по HTTPS; для локальной проверки' + #13#10 +
    '; можно оставить http://localhost:8080' + #13#10 +
    'BASE_URL=http://localhost:8080' + #13#10 +
    '' + #13#10 +
    '; Поднимать ли сайт (1 — да). Без сайта бот только шифрует и даёт ссылки.' + #13#10 +
    'ENABLE_WEB=1' + #13#10 +
    'WEB_HOST=0.0.0.0' + #13#10 +
    'WEB_PORT=8080' + #13#10 +
    '' + #13#10 +
    '; База ссылок. По умолчанию — %APPDATA%\SecretBot\links.db' + #13#10 +
    '; DB_PATH=' + #13#10;

function EnvPath(): String;
begin
  Result := ExpandConstant('{userappdata}\{#MyDataDirName}\secret-bot.env');
end;

procedure CreateEnvIfMissing();
var
  Target, Renamed: String;
begin
  Target := EnvPath();
  Renamed := Target + '.new';
  if FileExists(Target) then
  begin
    // Конфиг уже есть (обновление) — шаблон .new просто убираем.
    if FileExists(Renamed) then DeleteFile(Renamed);
    Exit;
  end;
  if FileExists(Renamed) then
  begin
    if not RenameFile(Renamed, Target) then
      SaveStringToFile(Target, EnvTemplate, False);
  end
  else
    SaveStringToFile(Target, EnvTemplate, False);
end;

procedure CurStepChanged(CurStep: TSetupStep);
begin
  if CurStep = ssPostInstall then
    CreateEnvIfMissing();
end;

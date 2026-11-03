; Установщик DeepSec Agent (Inno Setup 6). Собирается скриптом packaging\build.ps1.
; Файл должен оставаться в UTF-8 с BOM — иначе русский текст в мастере испортится.

#ifndef AppVersion
  #define AppVersion "0.0.0"
#endif
#define TaskName "DeepSec Agent"

[Setup]
AppId={{8C1B6E2A-6F2D-4D59-9C4B-0B7F5A1E2D31}
AppName=DeepSec Agent
AppVersion={#AppVersion}
AppPublisher=DeepSec
AppComments=Защита сессий Telegram Desktop от стилеров
DefaultDirName={autopf}\DeepSec
DefaultGroupName=DeepSec
DisableProgramGroupPage=yes
PrivilegesRequired=admin
ArchitecturesAllowed=x64compatible
ArchitecturesInstallIn64BitMode=x64compatible
MinVersion=10.0
OutputDir=..\dist
OutputBaseFilename=DeepSecSetup-{#AppVersion}
Compression=lzma2
SolidCompression=yes
WizardStyle=modern
UninstallDisplayName=DeepSec Agent
UninstallDisplayIcon={app}\DeepSecAgent.exe

[Languages]
Name: "ru"; MessagesFile: "compiler:Languages\Russian.isl"

[Files]
Source: "..\dist\DeepSecAgent\*"; DestDir: "{app}"; Flags: ignoreversion recursesubdirs createallsubdirs

[Icons]
Name: "{group}\Настроить DeepSec"; Filename: "{app}\DeepSecAgent.exe"; Parameters: "setup --pause"
Name: "{group}\Проверить DeepSec"; Filename: "{app}\DeepSecAgent.exe"; Parameters: "check --pause"
Name: "{group}\Удалить DeepSec"; Filename: "{uninstallexe}"

[Run]
; Окно консоли остаётся открытым до Enter (--pause): видно ход настройки и ошибки, если они будут.
Filename: "{app}\DeepSecAgent.exe"; Parameters: "{code:SetupParams}"; StatusMsg: "Настраиваю защиту…"; Flags: waituntilterminated

[UninstallRun]
Filename: "{app}\DeepSecAgent.exe"; Parameters: "uninstall"; RunOnceId: "DeepSecUninstall"; Flags: runhidden waituntilterminated

[Code]
var
  ServerPage: TInputQueryWizardPage;

procedure InitializeWizard;
begin
  ServerPage := CreateInputQueryPage(wpSelectDir,
    'Подключение к серверу',
    'Данные напечатал ./deploy.sh при выкладке бота на сервер.',
    'Перед продолжением запустите Telegram Desktop. При обновлении поля можно оставить пустыми — сохранятся прежние настройки.');
  ServerPage.Add('Адрес сервера (IP или домен):', False);
  { Порт не заполняем заранее: при обновлении подставленный 8443 затёр бы прежний порт. }
  ServerPage.Add('Порт агентов (LISTEN_PORT, пусто — 8443 или прежний):', False);
  ServerPage.Add('Отпечаток сертификата (SHA-256):', False);
  ServerPage.Add('AGENT_TOKEN:', True);
end;

function Quote(S: String): String;
begin
  Result := '"' + Trim(S) + '"';
end;

function SetupParams(Param: String): String;
begin
  Result := 'setup --yes --pause';
  if Trim(ServerPage.Values[0]) <> '' then
    Result := Result + ' --server ' + Quote(ServerPage.Values[0]);
  { Порт передаём и без адреса — при обновлении он заменит порт в прежнем SERVER_URL. }
  if Trim(ServerPage.Values[1]) <> '' then
    Result := Result + ' --port ' + Quote(ServerPage.Values[1]);
  if Trim(ServerPage.Values[2]) <> '' then
    Result := Result + ' --fingerprint ' + Quote(ServerPage.Values[2]);
  if Trim(ServerPage.Values[3]) <> '' then
    Result := Result + ' --token ' + Quote(ServerPage.Values[3]);
end;

function PrepareToInstall(var NeedsRestart: Boolean): String;
var
  ResultCode: Integer;
begin
  { При обновлении агент запущен от SYSTEM и держит свои файлы — останавливаем его. }
  Exec(ExpandConstant('{sys}\schtasks.exe'), '/End /TN "{#TaskName}"', '', SW_HIDE, ewWaitUntilTerminated, ResultCode);
  Sleep(2000);
  Result := '';
end;

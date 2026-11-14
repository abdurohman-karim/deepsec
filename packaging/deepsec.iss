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
; Иконку и картинку мастера рисует build.ps1 (python -m deepsec.brand build)
; Процессы DeepSecAgent.exe закрывает PrepareToInstall — Restart Manager не нужен (из другого сеанса он не может)
CloseApplications=no
SetupIconFile=..\build\deepsec.ico
WizardSmallImageFile=..\build\wizard-small.bmp

[Languages]
Name: "ru"; MessagesFile: "compiler:Languages\Russian.isl"

[Files]
Source: "..\dist\DeepSecAgent\*"; DestDir: "{app}"; Flags: ignoreversion recursesubdirs createallsubdirs

[Icons]
Name: "{group}\DeepSec"; Filename: "{app}\DeepSecAgent.exe"; Parameters: "ui"
Name: "{group}\Настроить DeepSec"; Filename: "{app}\DeepSecAgent.exe"; Parameters: "setup --pause"
Name: "{group}\Проверить DeepSec"; Filename: "{app}\DeepSecAgent.exe"; Parameters: "check --pause"
Name: "{group}\Удалить DeepSec"; Filename: "{uninstallexe}"

[Run]
; Окно консоли остаётся открытым до Enter (--pause): видно ход настройки и ошибки, если они будут.
; При тихом обновлении (кнопка в окне DeepSec или в боте) настройки и задача уже есть — агента перезапускает
; DeinitializeSetup, в том числе если установка сорвалась.
Filename: "{app}\DeepSecAgent.exe"; Parameters: "{code:SetupParams}"; StatusMsg: "Настраиваю защиту…"; Flags: waituntilterminated; Check: not WizardSilent

[UninstallRun]
Filename: "{app}\DeepSecAgent.exe"; Parameters: "uninstall"; RunOnceId: "DeepSecUninstall"; Flags: runhidden waituntilterminated

[Code]
var
  ServerPage: TInputQueryWizardPage;
  AgentStopped: Boolean;

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

{ Настройки от прошлой установки: адрес и токен уже есть — страницу подключения при обновлении не показываем. }
function HasConfig: Boolean;
var
  Lines: TArrayOfString;
  I: Integer;
  Url, Token: Boolean;
begin
  Url := False;
  Token := False;
  if LoadStringsFromFile(ExpandConstant('{commonappdata}\DeepSec\.env'), Lines) then
    for I := 0 to GetArrayLength(Lines) - 1 do
    begin
      if Pos('SERVER_URL=', Lines[I]) = 1 then Url := Length(Lines[I]) > Length('SERVER_URL=');
      if Pos('AGENT_TOKEN=', Lines[I]) = 1 then Token := Length(Lines[I]) > Length('AGENT_TOKEN=');
    end;
  Result := Url and Token;
end;

function ShouldSkipPage(PageID: Integer): Boolean;
begin
  Result := (PageID = ServerPage.ID) and HasConfig;
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
  { При обновлении агент запущен от SYSTEM и держит свои файлы — останавливаем его. А ещё DeepSecAgent.exe
    бывает запущен в сеансе пользователя (окно DeepSec, глаз, помощники): их Restart Manager из другого
    сеанса закрыть не может, и замена exe срывается — завершаем все процессы DeepSecAgent.exe. }
  Exec(ExpandConstant('{sys}\schtasks.exe'), '/End /TN "{#TaskName}"', '', SW_HIDE, ewWaitUntilTerminated, ResultCode);
  Exec(ExpandConstant('{sys}\taskkill.exe'), '/F /T /IM DeepSecAgent.exe', '', SW_HIDE, ewWaitUntilTerminated, ResultCode);
  AgentStopped := True;
  Sleep(1500);
  Result := '';
end;

procedure DeinitializeSetup;
var
  ResultCode: Integer;
begin
  { Агента остановили — запускаем при любом исходе: обновился он или установка сорвалась и откатилась,
    ПК не должен остаться без защиты. }
  if AgentStopped then
    Exec(ExpandConstant('{sys}\schtasks.exe'), '/Run /TN "{#TaskName}"', '', SW_HIDE, ewWaitUntilTerminated, ResultCode);
end;

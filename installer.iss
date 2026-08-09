[Setup]
AppId={{C1542B73-8902-4A8D-9E11-3E5A4B1A77E2}}
AppName=LanScanner
AppVersion=1.2.0
AppPublisher=NGV Group S.R.L.
AppPublisherURL=https://vcuria.app
AppSupportURL=https://vcuria.app
AppUpdatesURL=https://github.com/vincenzocuria/LanScannerPortable
DefaultDirName={userpf}\LanScanner
DefaultGroupName=LanScanner
DisableProgramGroupPage=yes
DisableDirPage=yes
UsePreviousAppDir=no
OutputDir=dist
OutputBaseFilename=LanScanner_Setup_v1.2.0
SetupIconFile=app_icon.ico
Compression=lzma2/ultra64
SolidCompression=yes
WizardStyle=modern
PrivilegesRequired=lowest

[Languages]
Name: "it"; MessagesFile: "compiler:Languages\Italian.isl"

[Tasks]
Name: "desktopicon"; Description: "{cm:CreateDesktopIcon}"; Flags: unchecked

[Files]
Source: "dist\LanScanner.exe"; DestDir: "{app}"; Flags: ignoreversion

[Icons]
Name: "{group}\LanScanner"; Filename: "{app}\LanScanner.exe"; WorkingDir: "{app}"
Name: "{autodesktop}\LanScanner"; Filename: "{app}\LanScanner.exe"; WorkingDir: "{app}"; Tasks: desktopicon

[Run]
Filename: "{app}\LanScanner.exe"; WorkingDir: "{app}"; Description: "{cm:LaunchProgram,LanScanner}"; Flags: nowait postinstall skipifsilent

[Code]
var
  HeaderLabel: TNewStaticText;
  DesktopCheck: TNewCheckBox;
  RunCheck: TNewCheckBox;

procedure DesktopCheckClick(Sender: TObject);
begin
  if WizardForm.TasksList.Items.Count > 0 then
    WizardForm.TasksList.Checked[0] := DesktopCheck.Checked;
end;

procedure RunCheckClick(Sender: TObject);
begin
  if WizardForm.RunList.Items.Count > 0 then
    WizardForm.RunList.Checked[0] := RunCheck.Checked;
end;

procedure InitializeWizard();
var
  BaseLeft, BaseTop: Integer;
begin
  // Nascondi il controllo TasksList originale col bordo grigio
  WizardForm.TasksList.Visible := False;

  BaseLeft := WizardForm.TasksList.Left;
  BaseTop := WizardForm.TasksList.Top;

  // Intestazione personalizzata
  HeaderLabel := TNewStaticText.Create(WizardForm);
  HeaderLabel.Parent := WizardForm.SelectTasksPage;
  HeaderLabel.Left := BaseLeft;
  HeaderLabel.Top := BaseTop;
  HeaderLabel.Font.Style := [fsBold];
  HeaderLabel.Caption := 'Opzioni di installazione e icone aggiuntive:';

  // Checkbox: Icona Desktop
  DesktopCheck := TNewCheckBox.Create(WizardForm);
  DesktopCheck.Parent := WizardForm.SelectTasksPage;
  DesktopCheck.Left := BaseLeft;
  DesktopCheck.Top := BaseTop + ScaleY(28);
  DesktopCheck.Width := WizardForm.TasksList.Width;
  DesktopCheck.Height := ScaleY(22);
  DesktopCheck.Caption := 'Crea un''icona di LanScanner sul desktop';
  DesktopCheck.Checked := True;
  DesktopCheck.OnClick := @DesktopCheckClick;

  // Nascondi RunList originale
  WizardForm.RunList.Visible := False;

  // Checkbox personalizzato finale "Avvia LanScanner"
  RunCheck := TNewCheckBox.Create(WizardForm);
  RunCheck.Parent := WizardForm.FinishedPage;
  RunCheck.Left := WizardForm.RunList.Left;
  RunCheck.Top := WizardForm.RunList.Top;
  RunCheck.Width := WizardForm.RunList.Width;
  RunCheck.Height := ScaleY(28);
  RunCheck.Caption := 'Avvia LanScanner';
  RunCheck.Checked := True;
  RunCheck.OnClick := @RunCheckClick;
end;

procedure CurPageChanged(CurPageID: Integer);
begin
  if CurPageID = wpSelectTasks then
  begin
    if WizardForm.TasksList.Items.Count > 0 then
      WizardForm.TasksList.Checked[0] := DesktopCheck.Checked;
  end;
  if CurPageID = wpFinished then
  begin
    if WizardForm.RunList.Items.Count > 0 then
      WizardForm.RunList.Checked[0] := RunCheck.Checked;
  end;
end;

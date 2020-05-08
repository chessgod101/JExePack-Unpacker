program JExePackUnpacker;

uses
  Forms,
  MainUnit in 'MainUnit.pas' {JUMain};

{$R *.res}

begin
  Application.Initialize;
  Application.MainFormOnTaskbar := True;
  Application.CreateForm(TJUMain, JUMain);
  Application.Run;
end.

unit injection;

interface

uses
  System.SysUtils, Winapi.Windows, Data.DB, FireDAC.Comp.Client, ADODB;

type
  TInjection = class
  private
    FQuery: TADOQuery;
  public
    procedure RunQuery(conn: TADOConnection; id: string);
    function UpdateBalance(conn: TADOConnection; amt: string): Integer;
    procedure DeleteSession(conn: TADOConnection; sid: string);
    procedure DropRow(FD: TFDQuery; uid: string);
    procedure ListDir(dir: string);
    procedure ShowFile(fileName: string);
    procedure PingHost(host: string);
  end;

implementation

// +-concatenated query string fed to an ADOQuery.SQL.Text
procedure TInjection.RunQuery(conn: TADOConnection; id: string);
var
  cmd: TADOQuery;
begin
  cmd := TADOQuery.Create(nil);
  cmd.Connection := conn;
  cmd.SQL.Text := 'SELECT * FROM users WHERE id = ' + id;
  cmd.Open;
end;

// Format-built query string fed to a FireDAC FDQuery.SQL.Text
function TInjection.UpdateBalance(conn: TADOConnection; amt: string): Integer;
var
  qry: TFDQuery;
begin
  qry := TFDQuery.Create(nil);
  qry.SQL.Text := Format('UPDATE accounts SET balance = %s', [amt]);
  Result := qry.ExecSQL;
end;

// :param must stay quiet; +-concatenated command into WinExec
procedure TInjection.DeleteSession(conn: TADOConnection; sid: string);
var
  qry: TADOQuery;
begin
  qry := TADOQuery.Create(nil);
  // Parameterized query with :sid bind.
  qry.SQL.Text := 'DELETE FROM sessions WHERE sid = :sid';
  qry.Parameters.ParamByName('sid').Value := sid;
  qry.ExecSQL;
  WinExec(PChar('net session ' + sid), SW_HIDE);
end;

// +-concatenated query string assigned through FDQuery.SQL.Add
procedure TInjection.DropRow(FD: TFDQuery; uid: string);
begin
  FD.SQL.Add('DELETE FROM orders WHERE uid = ' + uid);
  FD.ExecSQL;
end;

// :param bound, static SQL stays quiet
procedure TInjection.ListDir(dir: string);
var
  cmd: TADOQuery;
begin
  cmd := TADOQuery.Create(nil);
  cmd.SQL.Text := 'SELECT * FROM files WHERE dir = :dir';
  cmd.Parameters.ParamByName('dir').Value := dir;
  cmd.Open;
  ShellExecute(0, nil, PChar('cmd.exe'), PChar('/c dir ' + dir), nil, SW_HIDE);
end;

// Format-built command string fed to ShellExecute
procedure TInjection.ShowFile(fileName: string);
var
  buf: array[0..MAX_PATH] of Char;
begin
  GetCurrentDir(buf);
  ShellExecute(0, nil, 'notepad.exe', PChar(Format('"%s\%s"', [buf, fileName])), nil, SW_SHOW);
end;

// +-concatenated command line fed to CreateProcess
procedure TInjection.PingHost(host: string);
var
  si: STARTUPINFO;
  pi: PROCESS_INFORMATION;
begin
  ZeroMemory(@si, SizeOf(si));
  si.cb := SizeOf(si);
  if CreateProcess(nil, PChar('ping -n 1 ' + host), nil, nil, False,
     CREATE_NO_WINDOW, nil, nil, si, pi) then
    CloseHandle(pi.hProcess);
end;

end.

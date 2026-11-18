unit secure_injection;

interface

uses
  System.SysUtils, Winapi.Windows, Data.DB, FireDAC.Comp.Client, ADODB;

type
  TSecureInjection = class
  private
    FQuery: TADOQuery;
  public
    procedure RunQuery(conn: TADOConnection; id: string);
    function UpdateBalance(conn: TADOConnection; amt: string): Integer;
    procedure DeleteSession(conn: TADOConnection; sid: string);
    procedure ListDir(dir: string);
  end;

implementation

// Parameterized query: :id placeholder with Parameters.ParamByName bind.
procedure TSecureInjection.RunQuery(conn: TADOConnection; id: string);
var
  cmd: TADOQuery;
begin
  cmd := TADOQuery.Create(nil);
  cmd.Connection := conn;
  cmd.SQL.Text := 'SELECT * FROM users WHERE id = :id';
  cmd.Parameters.ParamByName('id').Value := id;
  cmd.Open;
end;

// Parameterized update with a bound parameter, no concatenation.
function TSecureInjection.UpdateBalance(conn: TADOConnection; amt: string): Integer;
var
  qry: TADOQuery;
begin
  qry := TADOQuery.Create(nil);
  qry.Connection := conn;
  qry.SQL.Text := 'UPDATE accounts SET balance = :amt WHERE id = :id';
  qry.Parameters.ParamByName('amt').Value := amt;
  qry.Parameters.ParamByName('id').Value := 1;
  Result := qry.ExecSQL;
end;

// Static SQL literal, no concatenation; static command line, no concat.
procedure TSecureInjection.DeleteSession(conn: TADOConnection; sid: string);
var
  qry: TADOQuery;
  si: STARTUPINFO;
  pi: PROCESS_INFORMATION;
begin
  qry := TADOQuery.Create(nil);
  qry.Connection := conn;
  qry.SQL.Text := 'DELETE FROM sessions WHERE sid = :sid';
  qry.Parameters.ParamByName('sid').Value := sid;
  qry.ExecSQL;
  ZeroMemory(@si, SizeOf(si));
  si.cb := SizeOf(si);
  CreateProcess(nil, PChar('cmd.exe /c cls'), nil, nil, False,
     CREATE_NO_WINDOW, nil, nil, si, pi);
end;

// Static command string fed to ShellExecute, no input splice.
procedure TSecureInjection.ListDir(dir: string);
begin
  ShellExecute(0, nil, PChar('cmd.exe'), PChar('/c dir C:\'), nil, SW_HIDE);
end;

end.

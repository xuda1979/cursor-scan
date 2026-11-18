# Good: $1 positional binds, ? placeholders, the Ecto query-builder pin form
# and argument-list process calls leave injection scanners quiet.
defmodule SafeRepo do
  def find_user(conn, uid) do
    Repo.query("SELECT * FROM users WHERE id = $1", [uid])
    Postgrex.query(conn, "SELECT * FROM t WHERE id = ?", [uid])
    Repo.one("SELECT COUNT(*) FROM orders")
    Repo.all(from u in User, where: u.id == ^uid)
    Repo.get(User, uid)
  end

  def ping(host) do
    System.cmd("ping", ["-c", "1", host])
    :os.cmd('printf ok')
  end
end

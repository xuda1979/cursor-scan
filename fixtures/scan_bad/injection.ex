# Bad: #{}–interpolated / <>–concatenated SQL and shell commands.
defmodule UnsafeRepo do
  def find_user(conn, uid) do
    Repo.query("SELECT * FROM users WHERE id = #{uid}")
    Repo.one("SELECT * FROM t WHERE id = " <> uid)
    Postgrex.query(conn, "SELECT * FROM users WHERE name = #{name}", [])
    MyXQL.query!(conn, "DELETE FROM logs WHERE id = " <> lid, [])
  end

  def run_script(host, dir) do
    System.cmd("ping -c 1 #{host}", [])
    System.cmd("ls " <> dir, [])
    Port.open({:spawn, "cat " <> path}, [:binary])
    :os.cmd('mkdir /tmp/#{name}')
  end
end

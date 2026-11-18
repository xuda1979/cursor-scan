// Bad: interpolated / concatenated SQL and shell commands.
import 'package:sqflite/sqflite.dart';

class UnsafeDao {
  Future<List<Map<String, dynamic>>> findUser(Database db, String uid) async {
    final rows = await db.rawQuery("SELECT * FROM users WHERE id = ${uid}");
    return rows;
  }

  Future<int> deleteLog(Database db, String lid) async {
    final affected = await db.rawDelete("DELETE FROM logs WHERE id = " + lid);
    return affected;
  }

  Future<int> touchRow(Database db, String tid) async {
    final n = await db.rawUpdate("UPDATE t SET v = 1 WHERE id = " + tid);
    return n;
  }

  Future<int> addLog(Database db, String payload) async {
    final n = await db.rawInsert("INSERT INTO logs VALUES (" + payload + ")");
    return n;
  }

  Future<void> runLookup(String name, String uid) async {
    await db.execute("SELECT * FROM t WHERE name = $name AND id = ${uid}");
  }

  Future<List<Map<String, dynamic>>> byRole(String role) async {
    String sql = 'SELECT * FROM users WHERE role = $role';
    final rs = await db.rawQuery(sql);
    return rs;
  }

  void ping(String host) {
    Process.run("ping -c 1 ${host}");
    Process.run('cmd /c $cmd', runInShell: true);
    Process.run("sh -c " + script);
    Process.start("git log " + ref);
  }
}

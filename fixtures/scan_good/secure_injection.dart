// Good: parameterized, positional-placeholder and argument-list database and
// process calls leave injection scanners quiet.
import 'package:sqflite/sqflite.dart';

class SafeDao {
  Future<List<Map<String, dynamic>>> findUser(Database db, String uid) async {
    final rows = await db.rawQuery("SELECT * FROM users WHERE id = ?",
        whereArgs: [uid]);
    return rows;
  }

  Future<List<Map<String, dynamic>>> count(Database db) async {
    final rows = await db.rawQuery('SELECT COUNT(*) FROM orders');
    return rows;
  }

  Future<void> load(Connection conn, String id) async {
    await conn.execute("SELECT * FROM t WHERE id = $1", [id]);
  }

  Future<List<Map<String, dynamic>>> byName(Database db, String name) async {
    final rows = await db.query("users", where: "name = ?", whereArgs: [name]);
    return rows;
  }

  void ping(String host) {
    Process.run("ping", ["-c", "1", host]);
    Process.start("ls", ["-l"]);
  }
}

<script>
  import { exec, execSync } from 'child_process';

  // 6 SQL positives: JS-style receivers fed a concatenated / `${}`-interpolated query
  function lookupUser(userId) {
    return db.query('SELECT * FROM users WHERE id = ' + userId);
  }

  function listPayments(ownerId) {
    return pool.query(`SELECT * FROM payments WHERE owner = ${ownerId}`);
  }

  function insertLog(payload) {
    mysql2.query('INSERT INTO logs VALUES (' + payload);
  }

  function findItems(name) {
    return knex.raw('SELECT * FROM items WHERE name = ' + name);
  }

  function chargeAccount(amount) {
    return sequelize.query('UPDATE accounts SET balance = balance - ' + amount);
  }

  function deleteSession(sid) {
    connection.execute('DELETE FROM sessions WHERE sid = ' + sid);
  }

  // 1 SQL positive: assignment build
  function dropTable(tbl) {
    const q = 'DROP TABLE ' + tbl;
    return db.query(q);
  }

  // 3 shell positives: child_process exec/execSync fed a concatenated command
  function runBackup(target) {
    execSync('tar -czf backup.tar.gz ' + target);
  }

  function pingHost(host) {
    exec('ping -c 1 ' + host);
  }

  function grepLogs(path, needle) {
    execSync(`cat ${path} | grep ${needle}`);
  }
</script>

<h1>Admin {username}</h1>

<template>
  <div>
    <h1>Results</h1>
    <p :class="'row-' + rowId">{{ 'a' + b }}</p>
  </div>
</template>

<script setup>
import { execSync } from 'child_process';

// parameterized binds, static SQL, static commands and args arrays stay quiet
function lookupUser(userId) {
  return db.query('SELECT * FROM users WHERE id = ?', [userId]);
}

function countItems() {
  return db.query('SELECT count(*) FROM items');
}

function findByName(name) {
  const sql = 'SELECT * FROM users WHERE name = ?';
  return pool.query(sql, [name]);
}

function runBackup() {
  execSync('tar -czf backup.tar.gz /data');
}

function runList(dir) {
  execSync('ls', [dir]);
}

function compose(name) {
  return 'hello, ' + name;
}
</script>

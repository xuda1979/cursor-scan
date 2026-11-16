"""Injection-safe patterns — must produce zero findings."""

import subprocess


def get_user(conn, username: str):
    cur = conn.cursor()
    cur.execute(
        "SELECT * FROM users WHERE name = %s", (username,)
    )
    return cur.fetchall()


def get_by_id(conn, user_id: int):
    cur = conn.cursor()
    cur.execute("SELECT * FROM users WHERE id = %s", (user_id,))
    return cur.fetchone()


def list_backup(log_dir: str):
    # Argument list form: no shell involvement.
    subprocess.run(["grep", "-r", "error", log_dir])
    return "ok"


def run_update():
    subprocess.run(["apt-get", "update"], timeout=120)

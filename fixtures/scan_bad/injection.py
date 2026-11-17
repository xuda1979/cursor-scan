"""Deliberately insecure injection patterns."""

import os
import subprocess

import psycopg2


def get_user_v1(conn, username: str):
    cur = conn.cursor()
    cur.execute(
        "SELECT * FROM users WHERE name = '" + username + "'"
    )
    return cur.fetchall()


def get_user_v2(conn, username: str):
    cur = conn.cursor()
    query = f"SELECT * FROM users WHERE name = '{username}'"
    cur.execute(query)
    return cur.fetchall()


def get_user_v3(conn, username: str):
    cur = conn.cursor()
    cur.execute(f"SELECT * FROM users WHERE name = '{username}'")
    return cur.fetchall()


def list_backup(log_dir: str):
    grep = os.system("grep -r error " + log_dir + "/ > out.txt")
    return grep


def run_update(name: str):
    subprocess.run("apt-get update && apt-get install " + name, shell=True)


def run_ping(host: str):
    subprocess.call("ping -c 1 " + host)


def purge_by_owner(conn, owner: str):
    return conn.query(f"DELETE FROM invoices WHERE owner = '{owner}'")


def wipe_stale_logs(run_query, days: int):
    return run_query(f"DELETE FROM audit_log WHERE created < {days}")


def fetch_favorites(query_all, category: str):
    return query_all(f"SELECT * FROM products WHERE cat = {category}")


def fetch_profile(query_one, u_id: int):
    return query_one(f"SELECT email FROM profiles WHERE id = {u_id}")


def reset_workdir(workdir: str):
    system(f"rm -rf {workdir}")


def peek_service_log(popen, log_file: str):
    return popen(f"tail -n 1 {log_file}")

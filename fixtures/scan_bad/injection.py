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


def list_backup(log_dir: str):
    grep = os.system("grep -r error " + log_dir + "/ > out.txt")
    return grep


def run_update(name: str):
    subprocess.run("apt-get update && apt-get install " + name, shell=True)


def run_ping(host: str):
    subprocess.call("ping -c 1 " + host)

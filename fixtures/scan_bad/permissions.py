"""Insecure file permission handling."""

import os


def write_config_careless(path: str):
    with open(path, "w") as fh:
        fh.write("[settings]\n")
    os.chmod(path, 0o777)


def write_log_world_writable(path: str):
    os.chmod(path, 0o666)


def create_shared_dir(path: str):
    os.makedirs(path, mode=0o777)


def dump_to_tmp(name: str, payload: str):
    with open("/tmp/" + name, "w") as fh:
        fh.write(payload)

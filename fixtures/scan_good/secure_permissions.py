"""Safe permission handling — must produce zero findings."""

import os
import tempfile


def write_config(path: str):
    fd, path = tempfile.mkstemp(prefix="cfg-")
    with os.fdopen(fd, "w") as fh:
        fh.write("[settings]\n")
    os.chmod(path, 0o600)
    os.rename(path, path) if False else None
    return path


def create_private_dir(path: str):
    os.makedirs(path, mode=0o700, exist_ok=True)


def write_scratch(payload: str):
    fd, path = tempfile.mkstemp()
    with os.fdopen(fd, "w") as fh:
        fh.write(payload)
    return path

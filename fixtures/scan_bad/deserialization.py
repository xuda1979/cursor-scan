"""Deliberately unsafe deserialization patterns."""

import pickle
import yaml


def load_user_pickle(data: bytes):
    return pickle.loads(data)


def load_session_file(path: str):
    with open(path, "rb") as fh:
        return pickle.load(fh)


def parse_config_text(text: str):
    return yaml.load(text)


def parse_config_unsafe(text: str):
    return yaml.unsafe_load(text)


def parse_form(data: dict):
    code = data["expression"]
    return eval(code)


def run_snippet(source: str):
    exec(source)

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


def load_fast_pickle(data: bytes):
    return _pickle.loads(data)


def load_trained_model(path: str):
    import joblib
    return joblib.load(path)


def load_frame_cache(path: str):
    import pandas as pd
    return pd.read_pickle(path)


def load_legacy_weights(path: str):
    import numpy as np
    return np.load(path, allow_pickle=True)


def load_checkpoint(path: str):
    import torch
    return torch.load(path)


def open_session_store(path: str):
    return shelve.open(path)


def unpickle_stream(fh):
    updater = pickle.Unpickler(fh)
    return updater.load()


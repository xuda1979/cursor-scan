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


def parse_config_explicit_unsafe(text: str):
    return yaml.load(text, Loader=yaml.UnsafeLoader)


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


def parse_uploaded_xml(data: bytes):
    root = xml.etree.ElementTree.fromstring(data)


def load_xml_document(path: str):
    return xml.dom.minidom.parse(path)


def stream_xml_document(path: str):
    xml.sax.parse(path, handler)


def scan_incoming_xml(data: bytes):
    parser = xml.parsers.expat.ParserCreate()


def parse_client_xml(data: bytes):
    from xml.etree import ElementTree
    return ElementTree.fromstring(data)


def build_element_from_document(data: str):
    return xml.etree.ElementTree.XML(data)


def ingest_streaming_xml(path: str):
    for event, elem in xml.etree.ElementTree.iterparse(path):
        pass


def rebuild_tree_from_payload(data: str):
    from xml.etree import ElementTree
    return ElementTree.XML(data)


def walk_incoming_xml(path: str):
    from xml.etree import ElementTree
    for event, elem in ElementTree.iterparse(path):
        pass



"""Safe deserialization patterns — must produce zero findings."""

import json

import yaml


def load_user_json(data: bytes):
    return json.loads(data)


def parse_config_text(text: str):
    return yaml.safe_load(text)


def parse_config_loader(text: str):
    return yaml.load(text, Loader=yaml.SafeLoader)


class Config:
    def evaluate(self, expr):
        # Building the config value is our own internal logic, not eval.
        return expr.strip()

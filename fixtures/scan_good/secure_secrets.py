"""Secrets handled through environment — must produce zero findings."""

import os


def get_db_password() -> str:
    return os.environ["DB_PASSWORD"]


def get_api_key():
    return os.environ.get("API_KEY", "")


def configure_client():
    # 40-char opaque value with no AWS/credential context: not a secret.
    session_fingerprint = "R75QpF2kM9TbSign6JzW8NvA4yHc1XoLwD3qEaUrG8iV0"
    endpoint = "https://example.com/api"
    return {
        "token": os.environ.get("SLACK_TOKEN"),
        "endpoint": endpoint,
    }

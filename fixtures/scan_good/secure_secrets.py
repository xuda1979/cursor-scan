"""Secrets handled through environment — must produce zero findings."""

import os


def get_db_password() -> str:
    return os.environ["DB_PASSWORD"]


def get_api_key():
    return os.environ.get("API_KEY", "")


def configure_client():
    return {
        "token": os.environ.get("SLACK_TOKEN"),
        "endpoint": "https://example.com/api",
    }

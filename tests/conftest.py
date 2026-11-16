"""Shared pytest fixtures: path helpers for the scan fixtures trees."""

from __future__ import annotations

import os

import pytest

REPO_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
FIXTURES = os.path.join(REPO_ROOT, "fixtures")
SCAN_BAD = os.path.join(FIXTURES, "scan_bad")
SCAN_GOOD = os.path.join(FIXTURES, "scan_good")


@pytest.fixture(scope="session")
def scan_bad_dir() -> str:
    return SCAN_BAD


@pytest.fixture(scope="session")
def scan_good_dir() -> str:
    return SCAN_GOOD


@pytest.fixture(scope="session")
def fixtures_dir() -> str:
    return FIXTURES

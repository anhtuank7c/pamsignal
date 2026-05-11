"""Shared pytest configuration — silence noisy app logging during tests."""

from __future__ import annotations

import logging

import pytest


@pytest.fixture(autouse=True)
def _quiet_test_env(monkeypatch):
    """Mark the env as 'test' so app.py skips its per-event print() calls."""
    monkeypatch.setenv("FLASK_ENV", "test")
    logging.getLogger("pamsignal-webhook").setLevel(logging.CRITICAL)
    yield

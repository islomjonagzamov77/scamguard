"""Shared test setup."""

import pytest


@pytest.fixture(autouse=True)
def no_network(monkeypatch):
    """Tests never call real online services. Tests of the online checks switch them back on
    and replace the HTTP function with a fake."""
    monkeypatch.setenv("SCAMGUARD_ONLINE_CHECKS", "0")
    monkeypatch.delenv("GOOGLE_SAFE_BROWSING_KEY", raising=False)
    monkeypatch.delenv("VIRUSTOTAL_API_KEY", raising=False)

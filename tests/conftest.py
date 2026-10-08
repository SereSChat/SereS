import importlib
import os
import sys

import pytest

BACKEND = os.path.join(os.path.dirname(__file__), "..", "src", "backend")
sys.path.insert(0, os.path.abspath(BACKEND))


@pytest.fixture
def app_module(tmp_path, monkeypatch):
    monkeypatch.setenv("SERES_DATA_DIR", str(tmp_path))
    monkeypatch.delenv("URL", raising=False)
    for name in ("app", "db", "legacy_migration"):
        sys.modules.pop(name, None)
    module = importlib.import_module("app")
    module.app.config["TESTING"] = True
    module.app.config["TESTING_DISABLE_RATE_LIMIT"] = True
    return module


@pytest.fixture
def make_client(app_module):
    def factory():
        return app_module.app.test_client()

    return factory

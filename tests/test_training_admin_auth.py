"""Training administration must stay disabled until a non-default token is configured."""

import os
import sys
import tempfile
from pathlib import Path

import pytest

pytest.importorskip("fastapi")
pytest.importorskip("pandas")
pytest.importorskip("httpx")

ROOT = Path(__file__).resolve().parent.parent
# Isolate core.settings from the real gui_data/ before it is imported: in a full run this module is
# collected before test_training_console.py, whose autouse fixture empties S.DATASETS and S.RUNS.
os.environ.setdefault("TRAINGUI_HOME", tempfile.mkdtemp(prefix="traingui_test_"))
os.environ.setdefault("ADMIN_TOKEN", "test-token")   # same token the other training test modules use; tests here monkeypatch S.ADMIN_TOKEN
sys.path.insert(0, str(ROOT / "dashboard" / "training-gui"))

from fastapi.testclient import TestClient  # noqa: E402
from api import main  # noqa: E402
from core import settings as S  # noqa: E402


@pytest.mark.parametrize("token", ["", " ", "admin", "ADMIN", "change-me", " admin "])
def test_training_api_rejects_unconfigured_admin_token(monkeypatch, token):
    monkeypatch.setattr(S, "ADMIN_TOKEN", token)
    client = TestClient(main.app)
    for method, path in [("get", "/api/config"), ("post", "/api/models/rollback")]:
        response = getattr(client, method)(path, headers={"X-Admin-Token": token})
        assert response.status_code == 503
        assert "set a non-default ADMIN_TOKEN" in response.json()["detail"]


def test_training_api_accepts_only_configured_token(monkeypatch):
    monkeypatch.setattr(S, "ADMIN_TOKEN", "local-demo-secret")
    client = TestClient(main.app)
    assert client.get("/api/config").status_code == 401
    assert client.get("/api/config", headers={"X-Admin-Token": "admin"}).status_code == 401
    assert client.get("/api/config", headers={"X-Admin-Token": "local-demo-secret"}).status_code == 200

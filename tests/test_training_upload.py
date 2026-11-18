"""Training console dataset upload: streamed upload, bounded validation, no partial files.

Regression tests for the 2026-11-19 audit (big uploads gave no feedback and never reached step 2;
unreadable CSVs crashed the check with a 500)."""

import asyncio
import os
import sys
import tempfile
from pathlib import Path

import pytest

pytest.importorskip("fastapi")
pytest.importorskip("pandas")
pytest.importorskip("httpx")

ROOT = Path(__file__).resolve().parent.parent
os.environ["TRAINGUI_HOME"] = tempfile.mkdtemp(prefix="traingui_test_")   # before core.settings is imported
os.environ["ADMIN_TOKEN"] = "test-token"
sys.path.insert(0, str(ROOT / "dashboard" / "training-gui"))

from fastapi import HTTPException  # noqa: E402
from fastapi.testclient import TestClient  # noqa: E402

from api import main  # noqa: E402
from core import settings as S  # noqa: E402

TOKEN = {"X-Admin-Token": "test-token"}
RAW = {**TOKEN, "Content-Type": "application/octet-stream"}


def _csv(rows, every=10):
    """Raw DNS query records in the shape scripts/train_models.sh accepts (label 1 = attack)."""
    lines = ["timestamp,client_ip,domain,label"] + [
        f"2026-11-18T10:{i // 60 % 60:02d}:{i % 60:02d},10.0.0.{i % 5},q{i}.example.com,{1 if i % every == 0 else 0}"
        for i in range(rows)]
    return ("\n".join(lines) + "\n").encode()


@pytest.fixture(autouse=True)
def clean(monkeypatch):
    for p in S.DATASETS.iterdir():
        p.unlink()
    monkeypatch.setattr(S, "MAX_UPLOAD_MB", 0)
    monkeypatch.setattr(S, "VALIDATE_SAMPLE_ROWS", 200_000)
    yield


@pytest.fixture
def client():
    return TestClient(main.app)


def _files():
    return sorted(p.name for p in S.DATASETS.iterdir())


def test_streamed_upload_saves_the_exact_file_and_checks_it(client):
    body = _csv(300)
    r = client.post("/api/datasets/upload", params={"name": "d.csv"}, headers=RAW, content=body)
    assert r.status_code == 200, r.text
    j = r.json()
    assert j["ok"] is True and j["name"] == "d.csv" and j["rows"] == 300 and j["sampled"] is False
    assert j["class_counts"] == {"0": 270, "1": 30}
    assert j["pipeline"] == {"compatible": True, "query_column": "domain", "path_b_ready": True}
    assert (S.DATASETS / "d.csv").read_bytes() == body
    assert _files() == ["d.csv"]                                  # no leftover .part file
    assert "d.csv" in [d["name"] for d in client.get("/api/datasets", headers=TOKEN).json()]


def test_upload_needs_the_admin_token(client):
    r = client.post("/api/datasets/upload", params={"name": "d.csv"},
                    headers={"Content-Type": "application/octet-stream"}, content=_csv(10))
    assert r.status_code == 401
    assert _files() == []


def test_upload_rejects_other_file_types_and_strips_folders(client):
    r = client.post("/api/datasets/upload", params={"name": "evil.exe"}, headers=RAW, content=b"x")
    assert r.status_code == 400 and _files() == []
    for hidden in (".csv", "  "):
        assert client.post("/api/datasets/upload", params={"name": hidden}, headers=RAW, content=b"x").status_code == 400
    r = client.post("/api/datasets/upload", params={"name": "../../escape.csv"}, headers=RAW, content=_csv(5))
    assert r.status_code == 200 and _files() == ["escape.csv"]
    assert not (S.DATASETS.parent / "escape.csv").exists() and not (S.DATASETS.parent.parent / "escape.csv").exists()


def test_big_csv_check_reads_only_a_sample(client, monkeypatch):
    monkeypatch.setattr(S, "VALIDATE_SAMPLE_ROWS", 100)
    r = client.post("/api/datasets/upload", params={"name": "big.csv"}, headers=RAW, content=_csv(1000))
    j = r.json()
    assert r.status_code == 200 and j["ok"] is True
    assert j["sampled"] is True and j["rows"] is None and j["columns"] == 4
    assert sum(j["class_counts"].values()) == 100
    assert any("first 100 rows" in w for w in j["warnings"])
    assert (S.DATASETS / "big.csv").stat().st_size == len(_csv(1000))   # the whole file is still stored


def test_unreadable_csv_is_reported_not_a_server_error(client):
    r = client.post("/api/datasets/upload", params={"name": "empty.csv"}, headers=RAW, content=b"")
    assert r.status_code == 200, r.text
    j = r.json()
    assert j["ok"] is False and any("Could not read" in e for e in j["errors"])
    v = client.get("/api/datasets/empty.csv/validate", headers=TOKEN)
    assert v.status_code == 200 and v.json()["ok"] is False


def test_size_cap_still_works_and_leaves_no_partial_file(client, monkeypatch):
    monkeypatch.setattr(S, "MAX_UPLOAD_MB", 1)
    r = client.post("/api/datasets/upload", params={"name": "big.csv"}, headers=RAW, content=b"a,label\n" + b"1,0\n" * 600_000)
    assert r.status_code == 413
    assert _files() == []


def _chunks(*parts, fail_after=None):
    async def gen():
        for i, p in enumerate(parts):
            if fail_after is not None and i == fail_after:
                raise ConnectionError("client went away")
            yield p
    return gen()


def test_incomplete_upload_is_discarded():
    with pytest.raises(HTTPException) as e:
        asyncio.run(main._store("cut.csv", _chunks(b"a,label\n", b"1,0\n"), expected=10_000))
    assert e.value.status_code == 400 and "incomplete" in e.value.detail
    assert _files() == []


def test_cancelled_upload_leaves_nothing_behind():
    with pytest.raises(ConnectionError):
        asyncio.run(main._store("gone.csv", _chunks(b"a,label\n", b"1,0\n", b"2,1\n", fail_after=2)))
    assert _files() == []


def test_multipart_upload_still_works(client):
    r = client.post("/api/datasets", headers=TOKEN, files={"file": ("m.csv", _csv(50), "text/csv")})
    assert r.status_code == 200 and r.json()["ok"] is True
    assert _files() == ["m.csv"]


def test_console_page_uses_the_streamed_upload_and_only_advances_when_ok():
    page = (ROOT / "dashboard" / "training-gui" / "api" / "static" / "index.html").read_text(encoding="utf-8")
    assert "/training/api/datasets/upload?name=" in page and "x.upload.onprogress" in page
    handler = page[page.index('$("upload").onclick'):page.index('$("upcancel").onclick')]
    ok_branch = handler[handler.index("if(r.ok)"):handler.index("}else{")]
    assert 'go("#/train?dataset="' in ok_branch and handler.count('go("#/train') == 1
    assert "setUploading(true)" in handler and "if(st.uploading)return" in handler

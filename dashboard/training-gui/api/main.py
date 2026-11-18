"""FastAPI admin backend.  Run:  uvicorn api.main:app --reload --port 8100"""
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

import uuid

from fastapi import Depends, FastAPI, Header, HTTPException, Request, UploadFile
from fastapi.concurrency import run_in_threadpool
from fastapi.responses import FileResponse
from fastapi.staticfiles import StaticFiles
from typing import Literal

from pydantic import BaseModel

from core import data, jobs, registry
from core import settings as S

app = FastAPI(title="DNS detection - admin training console")


def admin(x_admin_token: str = Header(default="")):
    if x_admin_token != S.ADMIN_TOKEN:
        raise HTTPException(401, "Invalid admin token")


def guarded(fn, *a, **kw):
    """Turn expected errors into clean 4xx responses."""
    try:
        return fn(*a, **kw)
    except (FileNotFoundError, KeyError) as e:
        raise HTTPException(404, str(e))
    except (RuntimeError, ValueError) as e:
        raise HTTPException(409, str(e))


class TrainRequest(BaseModel):
    dataset: str
    train_path: Literal["A", "B", "both"] = "both"
    seed: int = 42
    # demo trainer only
    n_estimators: int = 200
    epochs: int = 10
    test_size: float = 0.2
    # Capstone train_models.sh only
    n_days: int = 20
    path_b_model: Literal["trafficformer", "iforest"] = "trafficformer"
    retrain: Literal["all", "new_only"] = "all"
    new_split: bool = False
    pcap_label: Literal["", "0", "1"] = ""
    allow_heuristic_labels: bool = False


class PromoteRequest(BaseModel):
    force: bool = False


@app.get("/api/config", dependencies=[Depends(admin)])
def config():
    return {"mode": S.MODE, "upload_exts": sorted(S.UPLOAD_EXTS)}


@app.get("/api/datasets", dependencies=[Depends(admin)])
def datasets():
    return data.list_datasets()


WRITE_BLOCK = 8 << 20   # bytes collected before each disk write (fewer, larger writes)


def _upload_name(raw: str) -> str:
    """File name to store an upload under: no folders, no hidden files, allowed type only."""
    name = Path((raw or "").replace("\\", "/")).name.strip()
    if not name or name.startswith("."):
        raise HTTPException(400, "The file needs a name.")
    if Path(name).suffix.lower() not in S.UPLOAD_EXTS:
        raise HTTPException(400, "Accepted file types: " + ", ".join(sorted(S.UPLOAD_EXTS)))
    return name


async def _store(name: str, chunks, expected: int | None = None) -> dict:
    """Write an async stream of byte chunks to the datasets folder, then check the file.

    Data goes to a unique '.part' file (never listed as a dataset) and is renamed into place
    only when complete, so a cancelled or broken upload leaves nothing behind. Disk writes and
    the check run in worker threads so other API calls stay responsive during a big upload."""
    dest = S.DATASETS / name
    part = dest.with_name(f"{dest.name}.{uuid.uuid4().hex[:8]}.part")
    limit = S.MAX_UPLOAD_MB * 1_000_000 if S.MAX_UPLOAD_MB > 0 else None
    size, buf = 0, bytearray()
    try:
        with open(part, "wb") as out:
            async for chunk in chunks:
                size += len(chunk)
                if limit is not None and size > limit:
                    raise HTTPException(413, f"File is over {S.MAX_UPLOAD_MB} MB")
                buf += chunk
                if len(buf) >= WRITE_BLOCK:
                    block, buf = bytes(buf), bytearray()
                    await run_in_threadpool(out.write, block)
            if buf:
                await run_in_threadpool(out.write, bytes(buf))
        if expected is not None and size != expected:
            raise HTTPException(400, f"Upload incomplete: received {size:,} of {expected:,} bytes. Try again.")
        await run_in_threadpool(part.replace, dest)
    finally:
        part.unlink(missing_ok=True)
    return await run_in_threadpool(data.validate_csv, name)


async def _uploadfile_chunks(file: UploadFile):
    while chunk := await file.read(WRITE_BLOCK):
        yield chunk


@app.post("/api/datasets/upload", dependencies=[Depends(admin)])
async def upload_stream(request: Request, name: str):
    """Fast path used by the web console: the raw file is the request body (no multipart),
    streamed straight to the datasets folder, so each byte is written to disk once."""
    name = _upload_name(name)
    length = request.headers.get("content-length")
    expected = int(length) if length and length.isdigit() else None
    return await _store(name, request.stream(), expected)


@app.post("/api/datasets", dependencies=[Depends(admin)])
async def upload(file: UploadFile):
    """Multipart upload, kept for scripts and older clients. Starlette spools the file to a temp
    file first, so this path writes the data twice; the console uses /api/datasets/upload."""
    return await _store(_upload_name(file.filename), _uploadfile_chunks(file))


@app.get("/api/datasets/{name}/validate", dependencies=[Depends(admin)])
def validate(name: str):
    return guarded(data.validate_csv, name)


@app.post("/api/train", dependencies=[Depends(admin)])
def train(r: TrainRequest):
    check = guarded(data.validate_csv, r.dataset)
    if not check["ok"]:
        raise HTTPException(422, "; ".join(check["errors"]))
    params = r.model_dump(exclude={"dataset", "train_path"})
    return guarded(jobs.start_job, r.dataset, r.train_path, params)


@app.get("/api/jobs", dependencies=[Depends(admin)])
def list_jobs():
    return jobs.list_jobs()


@app.get("/api/jobs/{run_id}", dependencies=[Depends(admin)])
def job(run_id: str):
    j = guarded(jobs.get_job, run_id)
    return {**j, "metrics": jobs.get_metrics(run_id), "log": jobs.tail_log(run_id)}


@app.post("/api/jobs/{run_id}/cancel", dependencies=[Depends(admin)])
def cancel(run_id: str):
    return guarded(jobs.cancel_job, run_id)


@app.get("/api/models", dependencies=[Depends(admin)])
def models():
    return registry.list_models()


@app.get("/api/models/{version}/compare", dependencies=[Depends(admin)])
def compare(version: str):
    return guarded(registry.compare, version)


@app.post("/api/models/{version}/promote", dependencies=[Depends(admin)])
def promote(version: str, r: PromoteRequest):
    return guarded(registry.promote, version, r.force)


@app.post("/api/models/rollback", dependencies=[Depends(admin)])
def rollback():
    return guarded(registry.rollback)


@app.get("/")
def index():
    return FileResponse(Path(__file__).parent / "static" / "index.html")


app.mount("/static", StaticFiles(directory=Path(__file__).parent / "static"), name="static")

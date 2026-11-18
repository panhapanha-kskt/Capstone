"""FastAPI admin backend.  Run:  uvicorn api.main:app --reload --port 8100"""
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from fastapi import Depends, FastAPI, Header, HTTPException, UploadFile
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


@app.post("/api/datasets", dependencies=[Depends(admin)])
async def upload(file: UploadFile):
    name = Path(file.filename or "").name
    if Path(name).suffix.lower() not in S.UPLOAD_EXTS:
        raise HTTPException(400, "Accepted file types: " + ", ".join(sorted(S.UPLOAD_EXTS)))
    dest = S.DATASETS / name
    part = dest.with_name(dest.name + ".part")      # not listed as a dataset until complete
    limit = S.MAX_UPLOAD_MB * 1_000_000 if S.MAX_UPLOAD_MB > 0 else None
    size = 0
    try:
        with open(part, "wb") as out:
            while chunk := await file.read(8 << 20):
                size += len(chunk)
                if limit is not None and size > limit:
                    raise HTTPException(413, f"File is over {S.MAX_UPLOAD_MB} MB")
                out.write(chunk)
        part.replace(dest)
    finally:
        part.unlink(missing_ok=True)
    return data.validate_csv(name)


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

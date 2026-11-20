"""Detection ↔ promote lock (audit H1).

Detection (run_pipeline.sh, the dashboard's watch loop) holds a *reader* lock while it scores;
a promote (scripts/part_b.py, the training console) refuses to swap models/ while any reader is
active. Two mechanisms, so it works on Linux, WSL and a Windows-hosted dashboard alike:

  1. flock(LOCK_SH) on runs/.pipeline.lock          — POSIX processes (run_pipeline.sh, Linux dashboard)
  2. a heartbeat file runs/.pipeline.readers/<id>     — every platform; WSL sees the Windows file

A heartbeat older than STALE_SECONDS is ignored, so a crashed reader can't block promotes forever.
"""
import contextlib
import os
import socket
import time
import uuid
from pathlib import Path

try:
    import fcntl  # POSIX only
except ImportError:  # Windows
    fcntl = None

STALE_SECONDS = 20 * 60


def _readers(runs_dir):
    return Path(runs_dir) / ".pipeline.readers"


@contextlib.contextmanager
def detection_running(runs_dir):
    """Hold for the whole detection run. Call beat() between steps to refresh the heartbeat."""
    runs_dir = Path(runs_dir)
    runs_dir.mkdir(parents=True, exist_ok=True)
    rd = _readers(runs_dir)
    rd.mkdir(exist_ok=True)
    marker = rd / f"{socket.gethostname()}-{os.getpid()}-{uuid.uuid4().hex[:6]}"
    marker.write_text(str(time.time()))
    fh = None
    if fcntl is not None:
        fh = open(runs_dir / ".pipeline.lock", "a")
        fcntl.flock(fh, fcntl.LOCK_SH)
    try:
        yield lambda: marker.write_text(str(time.time()))
    finally:
        if fh is not None:
            fcntl.flock(fh, fcntl.LOCK_UN)
            fh.close()
        with contextlib.suppress(OSError):
            marker.unlink()


def active_readers(runs_dir, now=None):
    """Heartbeat files younger than STALE_SECONDS."""
    now = time.time() if now is None else now
    rd = _readers(runs_dir)
    if not rd.is_dir():
        return []
    out = []
    for f in rd.iterdir():
        try:
            if now - f.stat().st_mtime < STALE_SECONDS:
                out.append(f.name)
        except OSError:
            pass
    return out


def pipeline_running(runs_dir):
    """True if any detection run holds the lock right now (don't swap models/ under it)."""
    runs_dir = Path(runs_dir)
    runs_dir.mkdir(parents=True, exist_ok=True)
    if fcntl is not None:
        with open(runs_dir / ".pipeline.lock", "a") as f:
            try:
                fcntl.flock(f, fcntl.LOCK_EX | fcntl.LOCK_NB)
            except BlockingIOError:
                return True
            fcntl.flock(f, fcntl.LOCK_UN)
    return bool(active_readers(runs_dir))

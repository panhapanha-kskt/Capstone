"""Project root resolution and path helpers."""
import os
from pathlib import Path


def find_project_root() -> Path:
    """Walk up from this file to find the directory containing config/settings.yaml."""
    env_root = os.environ.get("DNS_DETECT_HOME")
    if env_root:
        return Path(env_root).resolve()

    current = Path(__file__).resolve().parent
    for _ in range(10):
        if (current / "config" / "settings.yaml").exists():
            return current
        current = current.parent
    raise RuntimeError("Cannot find project root (no config/settings.yaml found)")


PROJECT_ROOT = find_project_root()

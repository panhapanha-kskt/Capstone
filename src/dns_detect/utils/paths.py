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


def _models_dir() -> Path:
    """models/, or DNS_DETECT_MODELS_DIR (relative to the project root) for experiments."""
    env = os.environ.get("DNS_DETECT_MODELS_DIR")
    p = Path(env) if env else PROJECT_ROOT / "models"
    return p if p.is_absolute() else PROJECT_ROOT / p


# Where every model is trained to and loaded from.
MODELS_DIR = _models_dir()

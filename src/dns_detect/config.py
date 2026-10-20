"""Settings loader — reads config/settings.yaml with env var overrides."""
import os
from pathlib import Path

import yaml

from dns_detect.utils.paths import PROJECT_ROOT


class _Namespace:
    """Dot-access wrapper over a dict."""

    def __init__(self, d: dict):
        for k, v in d.items():
            setattr(self, k, _Namespace(v) if isinstance(v, dict) else v)

    def __repr__(self):
        return repr(self.__dict__)


def _load_settings() -> _Namespace:
    cfg_path = PROJECT_ROOT / "config" / "settings.yaml"
    with open(cfg_path) as f:
        raw = yaml.safe_load(f)

    # Env var overrides
    if os.environ.get("DNS_DETECT_MODELS_DIR"):
        raw["paths"]["models_dir"] = os.environ["DNS_DETECT_MODELS_DIR"]
    if os.environ.get("DNS_DETECT_LOG_DIR"):
        raw["paths"]["dns_logs_dir"] = os.environ["DNS_DETECT_LOG_DIR"]

    return _Namespace(raw)


def resolve_path(key: str) -> Path:
    """Resolve a paths.* key from settings to an absolute path."""
    rel = getattr(settings.paths, key)
    p = Path(rel)
    if p.is_absolute():
        return p
    return PROJECT_ROOT / p


settings = _load_settings()

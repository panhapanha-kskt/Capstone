"""Path B model loading: .keras is preferred over a legacy .h5 (TEST_REPORT §4, next step 4)."""

import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))

from dns_detect.models import path_b_predict  # noqa: E402


def _fake_model_dir(tmp_path, exts):
    for ext in exts:
        (tmp_path / f"m{ext}").write_bytes(b"x")
    (tmp_path / "m_threshold.json").write_text(json.dumps({"threshold": 0.1, "window_size": 20}))
    return str(tmp_path)


def test_keras_preferred_over_h5(monkeypatch, tmp_path):
    loaded = []
    monkeypatch.setattr(path_b_predict.tf.keras.models, "load_model",
                        lambda p, compile=False: loaded.append(p) or object())
    path_b_predict.load_model_artifacts("m", _fake_model_dir(tmp_path, [".h5", ".keras"]))
    assert loaded and loaded[0].endswith("m.keras")


def test_h5_used_when_no_keras(monkeypatch, tmp_path):
    loaded = []
    monkeypatch.setattr(path_b_predict.tf.keras.models, "load_model",
                        lambda p, compile=False: loaded.append(p) or object())
    path_b_predict.load_model_artifacts("m", _fake_model_dir(tmp_path, [".h5"]))
    assert loaded[0].endswith("m.h5")

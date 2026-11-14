"""Path B with --model iforest: the Isolation Forest is trained, saved, loaded and scored
through the same functions the bridge and the fusion use (path_b_predict). No TensorFlow."""

import json
import sys
from pathlib import Path

import numpy as np
import pytest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))

pytest.importorskip("sklearn")
joblib = pytest.importorskip("joblib")

from dns_detect.models import path_b_predict as pbp  # noqa: E402

WINDOW, F = 20, 5


def _windows(n, seed, shift=0.0):
    """Synthetic normalised windows; `shift` moves every feature away from the benign range."""
    rng = np.random.default_rng(seed)
    return (rng.normal(0.3, 0.05, size=(n, WINDOW, F)) + shift).astype(np.float32)


def test_fit_iforest_flags_abnormal_windows():
    model = pbp.fit_iforest(_windows(500, seed=0), seed=42, n_estimators=50)
    val = pbp.compute_reconstruction_errors(model, _windows(200, seed=1))
    threshold = float(np.percentile(val, 99))          # same rule as path_b_train
    abnormal = pbp.compute_reconstruction_errors(model, _windows(50, seed=2, shift=0.6))
    assert abnormal.shape == (50,)
    assert (abnormal > threshold).mean() > 0.9         # clearly abnormal windows score above it


def test_scores_one_per_window_and_empty_input():
    model = pbp.fit_iforest(_windows(100, seed=0), n_estimators=10)
    assert pbp.compute_reconstruction_errors(model, _windows(7, seed=3)).shape == (7,)
    assert len(pbp.compute_reconstruction_errors(model, np.zeros((0, WINDOW, F), np.float32))) == 0


def test_same_seed_gives_same_scores():
    x, probe = _windows(300, seed=0), _windows(20, seed=4)
    a = pbp.compute_reconstruction_errors(pbp.fit_iforest(x, seed=42, n_estimators=20), probe)
    b = pbp.compute_reconstruction_errors(pbp.fit_iforest(x, seed=42, n_estimators=20), probe)
    np.testing.assert_allclose(a, b)


def test_load_model_artifacts_reads_iforest_from_threshold_file(tmp_path):
    joblib.dump(pbp.fit_iforest(_windows(100, seed=0), n_estimators=10), tmp_path / "m_iforest.pkl")
    (tmp_path / "m.keras").write_bytes(b"x")            # a leftover autoencoder file is ignored
    (tmp_path / "m_threshold.json").write_text(json.dumps({
        "model_type": "iforest", "threshold": 0.5, "window_size": WINDOW,
        "error_mean": 0.4, "error_std": 0.05}))
    model, threshold, window, err_mean, err_std, _norm, _feats = pbp.load_model_artifacts("m", str(tmp_path))
    assert hasattr(model, "score_samples")
    assert (threshold, window, err_mean, err_std) == (0.5, WINDOW, 0.4, 0.05)


def test_missing_iforest_file_is_an_error(tmp_path):
    (tmp_path / "m_threshold.json").write_text(json.dumps({"model_type": "iforest", "threshold": 0.5}))
    with pytest.raises(FileNotFoundError):
        pbp.load_model_artifacts("m", str(tmp_path))

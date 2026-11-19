"""Week 7 Task 8: the live pipeline refuses models whose saved inputs differ from the code."""
import json
import shutil
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))

from dns_detect.models.schema import (  # noqa: E402
    schema_problems, check_model_schema, ModelSchemaError, main)
from dns_detect.parsing.dns_parser import PATH_A_FEATURES, PATH_B_FEATURES  # noqa: E402
from dns_detect.fusion.stacker import FUSION_INPUTS  # noqa: E402

NAME = "dns_trafficformer"


@pytest.fixture
def good(tmp_path):
    d = tmp_path / "models"
    d.mkdir()
    (d / "dns_threshold.json").write_text(json.dumps({"features": list(PATH_A_FEATURES), "threshold": 0.5}))
    (d / f"{NAME}_norm.json").write_text(json.dumps({"features": list(PATH_B_FEATURES)}))
    (d / f"{NAME}_threshold.json").write_text(json.dumps(
        {"model_type": "iforest", "n_features": len(PATH_B_FEATURES), "window_size": 20, "threshold": 0.5}))
    (d / f"{NAME}_iforest.pkl").write_bytes(b"x")
    (d / "fusion_lr.json").write_text(json.dumps({"inputs": list(FUSION_INPUTS), "threshold": 0.5}))
    return d


def _edit(path, **kw):
    data = json.loads(path.read_text())
    data.update(kw)
    path.write_text(json.dumps(data))


def test_matching_folder_passes(good):
    assert schema_problems(good, NAME) == []
    assert check_model_schema(good, NAME) == []


def test_live_models_folder_passes():
    """The promoted models/ (read only) matches the code."""
    if not (ROOT / "models" / "dns_threshold.json").is_file():
        pytest.skip("no models/ on this machine")
    assert schema_problems(ROOT / "models", NAME) == []


def test_reordered_path_a_features_fail(good):
    _edit(good / "dns_threshold.json", features=list(reversed(PATH_A_FEATURES)))
    probs = schema_problems(good, NAME)
    assert any("Path A" in p and "different order" in p for p in probs)
    with pytest.raises(ModelSchemaError):
        check_model_schema(good, NAME)


def test_missing_and_extra_path_b_feature_fail(good):
    _edit(good / f"{NAME}_norm.json", features=list(PATH_B_FEATURES[:-1]) + ["new_feature"])
    probs = schema_problems(good, NAME)
    assert any("Path B features" in p and "missing" in p and "extra" in p for p in probs)


def test_forbidden_feature_fails(good):
    _edit(good / "dns_threshold.json", features=list(PATH_A_FEATURES) + ["client_ip"])
    assert any("identity/time/provenance" in p for p in schema_problems(good, NAME))


def test_model_type_without_file_fails(good):
    (good / f"{NAME}_iforest.pkl").unlink()
    assert any("_iforest.pkl is missing" in p for p in schema_problems(good, NAME))


def test_autoencoder_type_needs_keras_file(good):
    _edit(good / f"{NAME}_threshold.json", model_type="trafficformer")
    assert any(".keras / .h5 is missing" in p for p in schema_problems(good, NAME))
    (good / f"{NAME}.keras").write_bytes(b"x")
    assert schema_problems(good, NAME) == []


def test_window_and_n_features_mismatch_fail(good):
    _edit(good / f"{NAME}_threshold.json", window_size=10, n_features=3)
    probs = schema_problems(good, NAME)
    assert any("window_size" in p for p in probs) and any("n_features" in p for p in probs)


def test_fusion_inputs_mismatch_fails(good):
    _edit(good / "fusion_lr.json", inputs=["ml_score_A"])
    assert any("Fusion inputs" in p for p in schema_problems(good, NAME))


def test_skip_path_b_and_warn_only(good, capsys):
    (good / f"{NAME}_norm.json").unlink()
    assert schema_problems(good, NAME, check_path_b=False) == []
    assert check_model_schema(good, NAME, strict=False)            # warns, no raise
    assert main(["--models-dir", str(good), "--path-b-model", NAME]) == 2
    assert main(["--models-dir", str(good), "--path-b-model", NAME, "--warn-only"]) == 0


def test_bridge_refuses_mismatched_models_in_production(good, tmp_path):
    pytest.importorskip("tensorflow")                               # bridge imports path_a (keras)
    from dns_detect.fusion import bridge
    _edit(good / "dns_threshold.json", features=list(reversed(PATH_A_FEATURES)))
    week3 = tmp_path / "w3.json"
    week3.write_text(json.dumps([{"domain": "a.example", "query_length": 9}]))
    with pytest.raises(ModelSchemaError):
        bridge.run_bridge(str(week3), str(tmp_path / "out.json"), path_b_model=NAME,
                          model_dir=str(good), mode="production")
    assert not (tmp_path / "out.json").exists()


def test_scripts_call_the_check():
    assert "dns_detect.models.schema" in (ROOT / "scripts" / "run_pipeline.sh").read_text()
    assert "dns_detect.models.schema" in (ROOT / "scripts" / "promote_model.sh").read_text()

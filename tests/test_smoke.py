"""Smoke tests: verify all modules import and config loads."""
import os
import sys

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "src"))


def test_config_loads():
    from dns_detect.config import settings
    assert settings.ensemble.rf_weight == 0.6
    assert settings.ensemble.tf_weight == 0.4
    assert settings.detection.zscore_threshold == 2.0


def test_paths_resolve():
    from dns_detect.utils.paths import PROJECT_ROOT
    assert (PROJECT_ROOT / "config" / "settings.yaml").exists()


def test_parser_imports():
    from dns_detect.parsing.dns_parser import FEATURES_8, load_as_dataframe
    assert len(FEATURES_8) == 8
    assert callable(load_as_dataframe)


def test_extractor_imports():
    from dns_detect.features.extractor import DNSFeatureExtractor
    assert callable(DNSFeatureExtractor)


def test_detection_imports():
    from dns_detect.detection.engine import RuleBasedDNSDetector, ZScoreDetector
    assert callable(RuleBasedDNSDetector)
    assert callable(ZScoreDetector)

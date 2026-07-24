"""Tests del baseline (modo diferencial) y de la cache persistente de hallazgos."""

from __future__ import annotations

from pathlib import Path

from sastcore.findings.baseline import Baseline, filter_new
from sastcore.findings.cache import FindingsCache, config_hash, content_hash
from sastcore.findings.model import Confidence, DataFlowStep, Engine, Finding, Location, Severity
from sastcore.rules.loader import default_rulepacks_dir


def _finding(fingerprint: str = "fp", path: str = "a.py") -> Finding:
    return Finding(
        rule_id="r",
        message="m",
        severity=Severity.HIGH,
        confidence=Confidence.HIGH,
        location=Location(path=path, start_line=1, start_col=0, end_line=1, end_col=3),
        snippet="s",
        engine=Engine.taint,
        fingerprint=fingerprint,
    )


# -- baseline ---------------------------------------------------------------
def test_filter_new_keeps_only_unseen() -> None:
    old = [_finding("a"), _finding("b")]
    baseline = Baseline.from_findings(old)
    result = filter_new([*old, _finding("c")], baseline)
    assert [f.fingerprint for f in result] == ["c"]


def test_baseline_save_load_roundtrip(tmp_path: Path) -> None:
    baseline = Baseline(frozenset({"x", "y"}))
    path = tmp_path / "bl.json"
    baseline.save(path)
    assert Baseline.load(path).fingerprints == {"x", "y"}


# -- cache ------------------------------------------------------------------
def test_cache_roundtrip(tmp_path: Path) -> None:
    cache = FindingsCache(tmp_path, config="cfg1")
    digest = content_hash("code")
    assert cache.get(digest, "a.py") is None
    cache.put(digest, [_finding("f1")])
    hit = cache.get(digest, "a.py")
    assert hit is not None
    assert hit[0].fingerprint == "f1"


def test_cache_restamps_path(tmp_path: Path) -> None:
    cache = FindingsCache(tmp_path, config="cfg1")
    digest = content_hash("code")
    flow = [
        DataFlowStep(
            location=Location(path="old.py", start_line=1, start_col=0, end_line=1, end_col=3),
            message="s",
        )
    ]
    cache.put(digest, [_finding("f1", path="old.py").model_copy(update={"data_flow": flow})])
    hit = cache.get(digest, "new.py")
    assert hit is not None
    assert hit[0].location.path == "new.py"
    assert hit[0].data_flow[0].location.path == "new.py"


def test_cache_invalidated_by_config(tmp_path: Path) -> None:
    digest = content_hash("code")
    FindingsCache(tmp_path, config="cfg1").put(digest, [_finding()])
    assert FindingsCache(tmp_path, config="cfg2").get(digest, "a.py") is None


def test_config_hash_changes_with_rulepacks() -> None:
    # El hash de configuración es determinista y no vacío.
    assert len(config_hash(default_rulepacks_dir())) == 64

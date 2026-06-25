"""Tests for already-remediated and partial-remediation workflows."""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from cst_auto_remediator import remediate_file

ROOT = Path(__file__).resolve().parent.parent
TESTING = ROOT / "testing"
INPUTS = TESTING / "inputs"


def _read(path: Path) -> str:
    return path.read_bytes().decode("utf-8")


def test_clean_passthrough2_unchanged() -> None:
    path = ROOT / "fixtures" / "clean_passthrough2.yml"
    output, report = remediate_file(path)
    assert output == _read(path)
    assert len(report) == 1
    assert report[0]["action"] == "SKIPPED"
    assert report[0]["reason"] == "ALREADY_REMEDIATED"


def _normalize_report(report: list[dict], fixture_path: Path) -> list[dict]:
    rel_file = fixture_path.relative_to(ROOT).as_posix()
    normalized = []
    for entry in report:
        item = dict(entry)
        item["file"] = rel_file
        normalized.append(item)
    return normalized


def _load_expected_json(name: str) -> list[dict]:
    path = TESTING / "expected" / f"{name}.expected.json"
    raw = json.loads(path.read_text(encoding="utf-8"))
    return _normalize_report(raw, INPUTS / name)


@pytest.mark.parametrize(
    "name",
    ["multi_step_mixed.yml", "partial_env_run_only.yml"],
)
def test_testing_scenarios(name: str) -> None:
    path = INPUTS / name
    output, report = remediate_file(path)
    expected_report = _load_expected_json(name)
    expected_yml_path = TESTING / "expected" / f"{name}.expected.yml"
    assert _normalize_report(report, path) == expected_report
    if expected_yml_path.exists():
        assert output == _read(expected_yml_path)

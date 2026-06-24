"""Integration tests over fixture workflows."""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from cst_auto_remediator import remediate_file

FIXTURES = Path(__file__).resolve().parent.parent / "fixtures"

FIXTURE_NAMES = [
    "clean_passthrough",
    "bail_sink",
    "bail_collision",
    "block_scalar_flagged",
]


def _normalize_report(report: list[dict], fixture_path: Path) -> list[dict]:
    rel_file = fixture_path.relative_to(FIXTURES.parent).as_posix()
    normalized = []
    for entry in report:
        item = dict(entry)
        item["file"] = rel_file
        normalized.append(item)
    return normalized


def _load_expected_json(name: str) -> list[dict]:
    path = FIXTURES / f"{name}.expected.json"
    raw = json.loads(path.read_text(encoding="utf-8"))
    fixture_path = FIXTURES / f"{name}.yml"
    return _normalize_report(raw, fixture_path)


@pytest.mark.parametrize("name", FIXTURE_NAMES)
def test_fixture_report(name: str) -> None:
    fixture_path = FIXTURES / f"{name}.yml"
    expected = _load_expected_json(name)

    output, report = remediate_file(fixture_path)
    assert report == expected

    expected_yaml_path = FIXTURES / f"{name}.expected.yml"
    if expected_yaml_path.exists():
        assert output == expected_yaml_path.read_text(encoding="utf-8")
    elif name == "block_scalar_flagged":
        assert output == fixture_path.read_text(encoding="utf-8")
    elif name in {"bail_sink", "bail_collision"}:
        assert output == fixture_path.read_text(encoding="utf-8")

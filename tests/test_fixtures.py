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
    "crlf_preservation",
]


def _read_fixture_text(path: Path) -> str:
    """Read fixture bytes without normalizing line endings."""
    return path.read_bytes().decode("utf-8")


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
        assert output == _read_fixture_text(expected_yaml_path)
    elif name in {"block_scalar_flagged", "bail_sink", "bail_collision"}:
        assert output == _read_fixture_text(fixture_path)


@pytest.mark.parametrize("name", FIXTURE_NAMES)
def test_report_offsets_match_run_value_slice(name: str) -> None:
    """Every expression-site report entry must slice correctly into the run value."""
    from cst_auto_remediator.ingest import ingest
    from cst_auto_remediator.models import IngestSuccess
    from cst_auto_remediator.traverse import traverse_jobs

    fixture_path = FIXTURES / f"{name}.yml"
    _, report = remediate_file(fixture_path)
    result = ingest(fixture_path)
    assert isinstance(result, IngestSuccess)
    sites = {s.expression_text: s for s in traverse_jobs(result.document)}

    for entry in report:
        if entry.get("start_offset") is None:
            continue
        site = sites[entry["expression_text"]]
        assert site.start_offset == entry["start_offset"]
        assert site.end_offset == entry["end_offset"]
        assert (
            site.run_value[entry["start_offset"] : entry["end_offset"]]
            == entry["expression_text"]
        )

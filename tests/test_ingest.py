"""Stage 1 ingestion tests."""

from pathlib import Path

import pytest

from cst_auto_remediator.ingest import detect_line_ending, ingest, read_source_text
from cst_auto_remediator.models import IngestSuccess

FIXTURES = Path(__file__).resolve().parent.parent / "fixtures"


def test_detect_line_ending_crlf() -> None:
    assert detect_line_ending(b"a\r\nb") == "\r\n"


def test_detect_line_ending_lf() -> None:
    assert detect_line_ending(b"a\nb") == "\n"


def test_ingest_preserves_source_text_line_endings() -> None:
    path = FIXTURES / "clean_passthrough.yml"
    raw = path.read_bytes()
    result = ingest(path)
    assert isinstance(result, IngestSuccess)
    assert result.metadata.line_ending == detect_line_ending(raw)
    assert result.source_text == read_source_text(raw)
    assert "\r\n" in result.source_text or result.metadata.line_ending == "\n"


def test_crlf_fixture_metadata() -> None:
    path = FIXTURES / "crlf_preservation.yml"
    raw = path.read_bytes()
    result = ingest(path)
    assert isinstance(result, IngestSuccess)
    assert result.metadata.line_ending == "\r\n"
    assert "\r\n" in result.source_text

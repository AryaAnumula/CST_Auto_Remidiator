"""
Stage 1 — file ingestion and round-trip YAML parsing.

Reads raw bytes, records audit metadata (SHA-256, line endings), and parses with
ruamel.yaml in round-trip mode. Failures return structured ReasonCode values.

MAINTAINER NOTE: When you change this file, update explanation.md at the project root.
"""

from __future__ import annotations

import hashlib
from io import StringIO
from pathlib import Path

from ruamel.yaml import YAML
from ruamel.yaml.error import YAMLError

from cst_auto_remediator.models import (
    FileMetadata,
    IngestFailure,
    IngestResult,
    IngestSuccess,
    ReasonCode,
)

MAX_FILE_SIZE = 2 * 1024 * 1024  # 2 MB
MAX_ALIAS_COUNT = 10


def detect_line_ending(raw_bytes: bytes) -> str:
    """Detect the dominant line-ending convention from raw file bytes."""
    if b"\r\n" in raw_bytes:
        return "\r\n"
    return "\n"


def read_source_text(raw_bytes: bytes) -> str:
    """Decode UTF-8 source text without normalizing line endings."""
    return raw_bytes.decode("utf-8")


def _make_yaml() -> YAML:
    yaml = YAML(typ="rt")
    yaml.preserve_quotes = True
    yaml.default_flow_style = False
    yaml.width = 4096
    yaml.max_alias_count = MAX_ALIAS_COUNT
    return yaml


def ingest(path: str | Path) -> IngestResult:
    """Read and parse a workflow YAML file with audit metadata."""
    file_path = Path(path)
    raw_bytes = file_path.read_bytes()

    if len(raw_bytes) > MAX_FILE_SIZE:
        return IngestFailure(
            metadata=_metadata(file_path, raw_bytes),
            reason=ReasonCode.FILE_TOO_LARGE,
        )

    sha256 = hashlib.sha256(raw_bytes).hexdigest()
    line_ending = detect_line_ending(raw_bytes)

    try:
        source_text = read_source_text(raw_bytes)
    except UnicodeDecodeError:
        return IngestFailure(
            metadata=FileMetadata(
                path=str(file_path),
                size=len(raw_bytes),
                sha256=sha256,
                encoding="invalid",
                line_ending=line_ending,
            ),
            reason=ReasonCode.INVALID_ENCODING,
        )

    metadata = FileMetadata(
        path=str(file_path),
        size=len(raw_bytes),
        sha256=sha256,
        encoding="utf-8",
        line_ending=line_ending,
    )

    yaml = _make_yaml()
    try:
        document = yaml.load(StringIO(source_text))
    except YAMLError as exc:
        if "alias" in str(exc).lower():
            return IngestFailure(metadata=metadata, reason=ReasonCode.YAML_BOMB)
        return IngestFailure(metadata=metadata, reason=ReasonCode.PARSE_ERROR)

    if document is None:
        return IngestFailure(metadata=metadata, reason=ReasonCode.PARSE_ERROR)

    return IngestSuccess(document=document, metadata=metadata, source_text=source_text)


def _metadata(file_path: Path, raw_bytes: bytes) -> FileMetadata:
    return FileMetadata(
        path=str(file_path),
        size=len(raw_bytes),
        sha256=hashlib.sha256(raw_bytes).hexdigest(),
        encoding="utf-8",
        line_ending=detect_line_ending(raw_bytes),
    )


def create_yaml_dumper() -> YAML:
    """Return a round-trip YAML instance configured for serialization."""
    return _make_yaml()

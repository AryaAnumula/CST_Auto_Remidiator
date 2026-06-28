"""
Stage 1 — Lossless YAML Parsing.

Wrapper around ruamel.yaml that parses raw bytes to a lossless, round-trip
backend representation (ParseTree), preserving comments, quotes, newlines, etc.,
along with raw source metadata.
"""

from __future__ import annotations

import hashlib
from io import StringIO
from typing import Any

from ruamel.yaml import YAML
from ruamel.yaml.error import YAMLError


class FileTooLargeError(ValueError):
    """Raised when file size exceeds the 2 MB limit."""
    pass


class InvalidEncodingError(ValueError):
    """Raised when input bytes are not valid UTF-8."""
    pass


class YamlBombError(ValueError):
    """Raised when the document contains recursive alias references exceeding limits."""
    pass


class ParsingError(ValueError):
    """Raised when the YAML document is malformed or empty."""
    pass


MAX_FILE_SIZE = 2 * 1024 * 1024  # 2 MB
MAX_ALIAS_COUNT = 10


def detect_line_ending(raw_bytes: bytes) -> str:
    """Detect the dominant line-ending convention from raw bytes."""
    if b"\r\n" in raw_bytes:
        return "\r\n"
    return "\n"


def read_source_text(raw_bytes: bytes) -> str:
    """Decode UTF-8 source text without normalizing line endings."""
    return raw_bytes.decode("utf-8")


def check_alias_bomb(node: Any, visited: set[int] = None, alias_counter: list[int] = None) -> None:
    """Recursively traverse parsing tree to detect billionaire laughs / alias bomb loops."""
    if visited is None:
        visited = set()
    if alias_counter is None:
        alias_counter = [0]

    node_id = id(node)
    if not isinstance(node, (dict, list)):
        return

    if node_id in visited:
        alias_counter[0] += 1
        if alias_counter[0] > MAX_ALIAS_COUNT:
            raise YamlBombError("YAML bomb detected: alias limit exceeded")
        return

    visited.add(node_id)
    if isinstance(node, dict):
        for v in node.values():
            check_alias_bomb(v, visited, alias_counter)
    elif isinstance(node, list):
        for item in node:
            check_alias_bomb(item, visited, alias_counter)


def parse_yaml(raw_bytes: bytes) -> tuple[Any, dict[str, Any]]:
    """
    Parse raw YAML bytes into a ruamel.yaml parsed document.

    Returns a tuple of (document, metadata).
    Raises FileTooLargeError, InvalidEncodingError, YamlBombError, or ParsingError on failure.
    """
    size = len(raw_bytes)
    if size > MAX_FILE_SIZE:
        raise FileTooLargeError(f"File size {size} exceeds 2 MB limit")

    sha256 = hashlib.sha256(raw_bytes).hexdigest()
    line_ending = detect_line_ending(raw_bytes)

    try:
        source_text = read_source_text(raw_bytes)
    except UnicodeDecodeError as e:
        raise InvalidEncodingError("Input is not valid UTF-8") from e

    metadata = {
        "size": size,
        "sha256": sha256,
        "encoding": "utf-8",
        "line_ending": line_ending,
    }

    yaml = YAML(typ="rt")
    yaml.preserve_quotes = True
    yaml.default_flow_style = False
    yaml.width = 4096
    yaml.max_alias_count = MAX_ALIAS_COUNT

    try:
        document = yaml.load(StringIO(source_text))
    except YAMLError as exc:
        if "alias" in str(exc).lower():
            raise YamlBombError("YAML bomb detected: alias limit exceeded") from exc
        raise ParsingError(f"Malformed YAML: {exc}") from exc

    if document is None:
        raise ParsingError("Empty YAML document")

    check_alias_bomb(document)

    return document, metadata

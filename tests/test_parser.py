"""Comprehensive unit tests for Stage 1 parser."""

from typing import Any
import pytest
from io import StringIO
from ruamel.yaml import YAML
from cst_auto_remediator.yaml_cst.parser import (
    parse_yaml,
    detect_line_ending,
    read_source_text,
    FileTooLargeError,
    InvalidEncodingError,
    YamlBombError,
    ParsingError,
)

def _serialize(doc: Any) -> bytes:
    yaml = YAML(typ="rt")
    yaml.preserve_quotes = True
    yaml.default_flow_style = False
    yaml.width = 4096
    yaml.indent(mapping=2, sequence=4, offset=2)
    stream = StringIO()
    yaml.dump(doc, stream)
    return stream.getvalue().encode('utf-8')


def test_line_ending_lf() -> None:
    content = b"name: test-workflow\non: push\n"
    doc, meta = parse_yaml(content)
    assert meta["line_ending"] == "\n"
    assert _serialize(doc) == content


def test_line_ending_crlf() -> None:
    content = b"name: test-workflow\r\non: push\r\n"
    doc, meta = parse_yaml(content)
    assert meta["line_ending"] == "\r\n"
    assert meta["size"] == len(content)


def test_utf8_valid() -> None:
    content = "name: 🚀 workflow\n".encode("utf-8")
    doc, meta = parse_yaml(content)
    assert meta["encoding"] == "utf-8"
    assert doc["name"] == "🚀 workflow"


def test_utf8_invalid() -> None:
    content = b"name: \xff\xfe workflow\n"
    with pytest.raises(InvalidEncodingError):
        parse_yaml(content)


def test_large_file_error() -> None:
    # 2 MB + 1 byte
    content = b"a" * (2 * 1024 * 1024 + 1)
    with pytest.raises(FileTooLargeError):
        parse_yaml(content)


def test_malformed_yaml() -> None:
    content = b"jobs:\n  - invalid: [unclosed seq"
    with pytest.raises(ParsingError):
        parse_yaml(content)


def test_empty_document() -> None:
    content = b""
    with pytest.raises(ParsingError):
        parse_yaml(content)


def test_comments_preservation() -> None:
    content = (
        b"# Root Comment\n"
        b"name: comment-test # Inline Comment\n"
        b"jobs:\n"
        b"  # Job comment\n"
        b"  test:\n"
        b"    runs-on: ubuntu-latest\n"
    )
    doc, meta = parse_yaml(content)
    assert _serialize(doc) == content


def test_anchors_and_aliases() -> None:
    content = (
        b"defaults: &defaults\n"
        b"  run:\n"
        b"    shell: bash\n"
        b"jobs:\n"
        b"  build:\n"
        b"    <<: *defaults\n"
        b"    runs-on: ubuntu-latest\n"
    )
    doc, meta = parse_yaml(content)
    assert _serialize(doc) == content


def test_alias_bomb_detection() -> None:
    content = (
        b"a: &a [\"lol\",\"lol\",\"lol\",\"lol\",\"lol\",\"lol\",\"lol\",\"lol\",\"lol\"]\n"
        b"b: &b [*a,*a,*a,*a,*a,*a,*a,*a,*a]\n"
        b"c: &c [*b,*b,*b,*b,*b,*b,*b,*b,*b]\n"
        b"d: &d [*c,*c,*c,*c,*c,*c,*c,*c,*c]\n"
        b"e: &e [*d,*d,*d,*d,*d,*d,*d,*d,*d]\n"
        b"f: &f [*e,*e,*e,*e,*e,*e,*e,*e,*e]\n"
    )
    with pytest.raises(YamlBombError):
        parse_yaml(content)


def test_indentation_preservation() -> None:
    content = (
        b"name: indentation-test\n"
        b"jobs:\n"
        b"  test:\n"
        b"    runs-on: ubuntu-latest\n"
        b"    steps:\n"
        b"      - name: Step 1\n"
        b"        run: echo\n"
    )
    doc, meta = parse_yaml(content)
    assert _serialize(doc) == content


def test_nested_mappings_and_sequences() -> None:
    content = (
        b"jobs:\n"
        b"  build:\n"
        b"    strategy:\n"
        b"      matrix:\n"
        b"        version: [10, 12, 14]\n"
        b"        os: [ubuntu-latest, macos-latest]\n"
        b"    steps:\n"
        b"      - name: setup\n"
        b"        uses: actions/setup@v2\n"
        b"        with:\n"
        b"          node-version: ${{ matrix.version }}\n"
    )
    doc, meta = parse_yaml(content)
    assert _serialize(doc) == content


def test_true_lossless_round_trip() -> None:
    content = (
        b"# comment\n"
        b"\n"
        b"name: Test\n"
        b"\n"
        b"jobs:\n"
        b"  test:\n"
        b"    runs-on: ubuntu-latest\n"
    )
    doc, meta = parse_yaml(content)
    assert _serialize(doc) == content


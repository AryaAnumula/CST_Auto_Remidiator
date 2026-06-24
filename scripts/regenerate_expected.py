"""Generate verified offsets and expected outputs for all fixtures."""

from __future__ import annotations

import json
from pathlib import Path

from cst_auto_remediator import remediate_file
from cst_auto_remediator.ingest import ingest
from cst_auto_remediator.traverse import traverse_jobs

ROOT = Path(__file__).resolve().parent.parent
FIXTURES = ROOT / "fixtures"

NAMES = [
    "clean_passthrough",
    "bail_sink",
    "bail_collision",
    "block_scalar_flagged",
    "crlf_preservation",
]


def verify_offsets(name: str) -> None:
    path = FIXTURES / f"{name}.yml"
    result = ingest(path)
    from cst_auto_remediator.models import IngestFailure, IngestSuccess

    if isinstance(result, IngestFailure):
        raise RuntimeError(f"{name}: ingest failed: {result.reason}")

    for site in traverse_jobs(result.document):
        slice_text = site.run_value[site.start_offset : site.end_offset]
        assert slice_text == site.expression_text, (
            f"{name}: offset slice mismatch: {slice_text!r} != {site.expression_text!r}"
        )
        print(
            f"{name}: start={site.start_offset} end={site.end_offset} "
            f"slice={slice_text!r} OK"
        )


def main() -> None:
    for name in NAMES:
        path = FIXTURES / f"{name}.yml"
        if not path.exists():
            print(f"SKIP missing {name}")
            continue
        verify_offsets(name)
        output, report = remediate_file(path)
        json_path = FIXTURES / f"{name}.expected.json"
        json_path.write_text(json.dumps(report, indent=2) + "\n", encoding="utf-8")
        if output is not None and output != path.read_bytes().decode("utf-8"):
            yml_path = FIXTURES / f"{name}.expected.yml"
            yml_path.write_bytes(output.encode("utf-8"))
            print(f"Wrote {yml_path.name}")
        print(f"Wrote {json_path.name}")


if __name__ == "__main__":
    main()

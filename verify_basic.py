"""
Verification script — Task 1 & 3 from the handoff doc.
Run from PowerShell: python verify_basic.py
"""
import sys
from pathlib import Path
from cst_auto_remediator import remediate_file
from cst_auto_remediator.ingest import ingest
from cst_auto_remediator.models import IngestSuccess
from cst_auto_remediator.traverse import traverse_jobs
import json

# FIXTURE = "fixtures/clean_passthrough.yml"
# FIXTURE = "testing/stage3/T002_unquoted_echo.yml"

import sys
from pathlib import Path

DEFAULT_FIXTURE = Path("fixtures/clean_passthrough.yml")

FIXTURE = Path(sys.argv[1]) if len(sys.argv) > 1 else DEFAULT_FIXTURE

if not FIXTURE.exists():
    raise FileNotFoundError(f"Fixture not found: {FIXTURE}")

yaml_out, report = remediate_file(FIXTURE)

print("=" * 60)
print("OUTPUT YAML")
print("=" * 60)
print(yaml_out, end="" if yaml_out and yaml_out.endswith(("\n", "\r\n")) else "\n")

print("=" * 60)
print("REPORT")
print("=" * 60)
print(json.dumps(report, indent=2))

print("=" * 60)
print("MANUAL OFFSET CHECK (run_value slice)")
print("=" * 60)
ingest_result = ingest(FIXTURE)
if isinstance(ingest_result, IngestSuccess):
    sites_by_expr = {s.expression_text: s for s in traverse_jobs(ingest_result.document)}
    for entry in report:
        start = entry.get("start_offset")
        end = entry.get("end_offset")
        expr = entry.get("expression_text")
        if start is None or end is None or expr is None:
            print(f"Entry: {entry.get('action')} / {entry.get('reason')} — no offsets present")
            continue
        site = sites_by_expr.get(expr)
        if site is None:
            print(f"Entry: {expr} — no matching ExpressionSite")
            continue
        slice_text = site.run_value[start:end]
        ok = slice_text == expr
        print(f"Entry: {expr}")
        print(f"  start={start}, end={end}")
        print(f"  run_value={site.run_value!r}")
        print(f"  slice={slice_text!r}  match={'OK' if ok else 'FAIL'}")

print("=" * 60)
print("LINE ENDING CHECK")
print("=" * 60)
if isinstance(ingest_result, IngestSuccess):
    print(f"  detected line_ending={ingest_result.metadata.line_ending!r}")
    print(f"  input CRLF count={ingest_result.source_text.count(chr(13)+chr(10))}")
    print(f"  output CRLF count={yaml_out.count(chr(13)+chr(10)) if yaml_out else 0}")

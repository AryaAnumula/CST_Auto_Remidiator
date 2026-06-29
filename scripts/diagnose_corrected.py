from pathlib import Path

from cst_auto_remediator import remediate_file
from cst_auto_remediator.ingest import ingest
from cst_auto_remediator.models import IngestSuccess
from cst_auto_remediator.traverse import traverse_jobs

ROOT = Path(__file__).resolve().parent.parent


def check(path: str) -> None:
    p = ROOT / path
    result = ingest(p)
    sites = traverse_jobs(result.document) if isinstance(result, IngestSuccess) else []
    out, report = remediate_file(p)
    src = p.read_bytes().decode("utf-8")
    print(f"=== {path} ===")
    print(f"sites: {len(sites)}")
    for s in sites:
        print(f"  expr={s.expression_text!r} run={s.run_value!r}")
    print(f"report actions: {[e.get('action') for e in report]}")
    print(f"changed: {out != src}")
    print()


check("fixtures/clean_passthrough2.yml")

corrected = ROOT / "testing" / "tmp_corrected.yml"
corrected.parent.mkdir(exist_ok=True)
corrected.write_text(
    """\
# .github/workflows/issue-triage.yml
name: Issue triage

on:
  issues:
    types: [opened]

jobs:
  triage:
    runs-on: ubuntu-latest
    steps:
      - name: Checkout repo
        uses: actions/checkout@v4

      - name: Greet reporter
        env:
          ISSUE_TITLE: ${{ github.event.issue.title }}
        run: 'echo "Thanks for opening: $ISSUE_TITLE"'

      - name: Add label
        run: echo "Labeling issue"
""",
    encoding="utf-8",
)
check("testing/tmp_corrected.yml")

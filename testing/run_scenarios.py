"""
Run all testing/inputs scenarios and write outputs to testing/output/.

Usage: python testing/run_scenarios.py
"""
from __future__ import annotations

import json
from pathlib import Path

from cst_auto_remediator import remediate_file

ROOT = Path(__file__).resolve().parent
INPUTS = ROOT / "inputs"
OUTPUT = ROOT / "output"


def main() -> None:
    OUTPUT.mkdir(exist_ok=True)
    scenarios = sorted(INPUTS.glob("*.yml"))
    if not scenarios:
        print("No scenarios found in testing/inputs/")
        return

    for scenario in scenarios:
        name = scenario.stem
        yaml_out, report = remediate_file(scenario)
        source = scenario.read_bytes().decode("utf-8")

        out_yml = OUTPUT / f"{name}.output.yml"
        out_json = OUTPUT / f"{name}.report.json"
        out_diff = OUTPUT / f"{name}.diff.txt"

        out_yml.write_bytes((yaml_out or "").encode("utf-8"))
        out_json.write_text(json.dumps(report, indent=2) + "\n", encoding="utf-8")

        changed = yaml_out != source
        diff_lines = []
        if changed:
            import difflib

            diff_lines = list(
                difflib.unified_diff(
                    source.splitlines(keepends=False),
                    (yaml_out or "").splitlines(keepends=False),
                    fromfile=str(scenario),
                    tofile=str(out_yml),
                )
            )
        out_diff.write_text(
            "NO CHANGES\n" if not diff_lines else "\n".join(diff_lines) + "\n",
            encoding="utf-8",
        )

        actions = [entry.get("action") for entry in report]
        print(f"{name}: changed={changed} report_actions={actions}")


if __name__ == "__main__":
    main()

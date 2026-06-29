"""
Verification — already-remediated workflow must pass through unchanged.

Run from PowerShell: python verify_diff2.py
"""
from cst_auto_remediator import remediate_file
import difflib
import json

FIXTURE = "fixtures/clean_passthrough2.yml"
OUTPUT_PATH = "verify_output2.yml"

yaml_out, report = remediate_file(FIXTURE)

with open(FIXTURE, "r", encoding="utf-8", newline="") as f:
    original = f.read()

with open(OUTPUT_PATH, "w", encoding="utf-8", newline="") as f:
    f.write(yaml_out)

print("=" * 60)
print("REPORT")
print("=" * 60)
print(json.dumps(report, indent=2))

print("=" * 60)
print(f"DIFF: {FIXTURE} vs {OUTPUT_PATH}")
print("=" * 60)

diff = difflib.unified_diff(
    original.splitlines(keepends=False),
    yaml_out.splitlines(keepends=False),
    fromfile=FIXTURE,
    tofile=OUTPUT_PATH,
)
diff_lines = list(diff)
if not diff_lines:
    print("NO DIFFERENCE — already-remediated file passed through unchanged (expected)")
else:
    print("UNEXPECTED CHANGES:")
    for line in diff_lines:
        print(line)

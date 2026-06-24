"""
Verification script — Task 2 (byte preservation).
Run from PowerShell: python verify_diff.py
"""
from cst_auto_remediator import remediate_file
import difflib

FIXTURE = "fixtures/clean_passthrough.yml"
OUTPUT_PATH = "verify_output.yml"

yaml_out, report = remediate_file(FIXTURE)

with open(FIXTURE, "r", encoding="utf-8", newline="") as f:
    original = f.read()

with open(OUTPUT_PATH, "w", encoding="utf-8", newline="") as f:
    f.write(yaml_out)

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
    print("NO DIFFERENCE — output identical to input (unexpected for this fixture)")
else:
    for line in diff_lines:
        print(line)

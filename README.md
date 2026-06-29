# CST Auto Remediator

Deterministic, CST-based auto-remediation for command injection in GitHub Actions workflow YAML.

**Start here for full project documentation:** [`explanation.md`](explanation.md) — the project secretary. Read it before making changes; update it whenever you change core behavior.

## Quick start

```powershell
pip install -e ".[dev]"
pytest tests -v
python verify_basic.py
```

## Public API

```python
from cst_auto_remediator import remediate_file

yaml_out, report = remediate_file("path/to/workflow.yml")
```

## Testing a New/Arbitrary Workflow File

To run the auto-remediator and verify if a new or arbitrary workflow YAML file works correctly:

1. **Place the file** in the `testing/inputs/` directory (e.g., `testing/inputs/your_workflow.yml`).
2. **Execute the test runner script** to run the tool on all inputs and automatically output the results:
   ```powershell
   python testing/run_scenarios.py
   ```
3. **Verify the generated outputs** in the `testing/output/` directory:
   - **Remediated YAML:** [testing/output/your_workflow.output.yml](file:///d:/Cybersec/internship/CST_Auto_Remidiator-cst-engine-v1/testing/output/your_workflow.output.yml)
   - **Remediation Report:** [testing/output/your_workflow.report.json](file:///d:/Cybersec/internship/CST_Auto_Remidiator-cst-engine-v1/testing/output/your_workflow.report.json)
   - **Unified Difference (Diff):** [testing/output/your_workflow.diff.txt](file:///d:/Cybersec/internship/CST_Auto_Remidiator-cst-engine-v1/testing/output/your_workflow.diff.txt)
   *(Note: No other script or file needs to be created to test a new file; the runner automatically scans `testing/inputs/` and runs on all YAML files).*

Alternatively, you can run a single file test and print its results (including character offset check and line ending checks) directly to the console by running:
```powershell
python verify_basic.py testing/inputs/your_workflow.yml
```

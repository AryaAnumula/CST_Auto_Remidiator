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

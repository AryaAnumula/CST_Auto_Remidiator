# Testing scenarios for CST Auto Remediator (Stages 1–3)

This folder holds **integration scenarios** beyond the minimal `fixtures/` set.

## Layout

```
testing/
├── inputs/           # Scenario workflow YAML files
├── expected/         # Expected report JSON + patched YAML (test oracle)
├── output/           # Latest outputs from run_scenarios.py (kept for manual review)
└── run_scenarios.py  # Regenerate testing/output/ from inputs/
```

## Run manually

```powershell
python testing/run_scenarios.py
pytest tests/test_already_remediated.py -v
python verify_diff2.py
```

## Scenarios

| Input | What it exercises |
|-------|-------------------|
| `multi_step_mixed.yml` | Already-remediated step, vulnerable step, block scalar, eval sink — all in one file |
| `partial_env_run_only.yml` | Env already binds expression but run still has `${{ ... }}` (run-only patch) plus a fully remediated step |

After changing remediation behavior, regenerate expected files:

```powershell
python testing/run_scenarios.py
# then update testing/expected/ via scripts or copy from output after review
```

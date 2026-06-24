"""CST-based auto-remediation for GitHub Actions command injection."""

from cst_auto_remediator.pipeline import remediate_file

__all__ = ["remediate_file"]

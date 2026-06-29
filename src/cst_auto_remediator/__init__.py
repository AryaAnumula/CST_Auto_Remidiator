"""
CST-based auto-remediation for GitHub Actions command injection.

Public API: remediate_file()

MAINTAINER NOTE: When you change this file, update explanation.md at the project root.
"""

from cst_auto_remediator.pipeline import remediate_file
from cst_auto_remediator.gha_verify import verify_output, VerificationContext

__all__ = ["remediate_file", "verify_output", "VerificationContext"]

"""
CST-based auto-remediation for GitHub Actions command injection.

Public API: remediate_file()

MAINTAINER NOTE: When you change this file, update explanation.md at the project root.
"""

from cst_auto_remediator.pipeline import remediate_file

__all__ = ["remediate_file"]

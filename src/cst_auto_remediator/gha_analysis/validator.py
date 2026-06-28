"""
Stage 5 — GitHub Actions Security Analysis Validator.

Implements structural validation checks (supported shell, runners, and styles).
"""

from __future__ import annotations

import re


def is_shell_supported(effective_shell: str) -> bool:
    """Only standard Unix-style shells (bash, sh) are supported in V1."""
    return effective_shell.lower() in ("bash", "sh")


def is_runner_supported(runner_default_shell: str) -> bool:
    """If the runner default is pwsh (e.g. Windows runner), it is unsupported in V1."""
    return runner_default_shell.lower() in ("bash", "sh")


def is_style_supported(style: str) -> bool:
    """PLAIN, SINGLE_QUOTED, and DOUBLE_QUOTED are supported. Block scalars are not."""
    return style.upper() in ("PLAIN", "SINGLE_QUOTED", "DOUBLE_QUOTED")


def is_expression_single_quoted(run_value: str, start: int, end: int) -> bool:
    """
    Check if the expression site is enclosed inside single quotes.
    Bash/sh does not expand environment variables inside single quotes.
    """
    in_single = False
    in_double = False
    region_start = 0
    cursor = 0
    while cursor < len(run_value):
        char = run_value[cursor]
        if char == "\\" and (in_single or in_double) and cursor + 1 < len(run_value):
            cursor += 2
            continue
        if char == "'" and not in_double:
            if not in_single:
                region_start = cursor
                in_single = True
            else:
                # Check if our expression range lies inside this single-quoted region
                if region_start <= start and end <= (cursor + 1):
                    return True
                in_single = False
        elif char == '"' and not in_single:
            in_double = not in_double
        cursor += 1
    return False

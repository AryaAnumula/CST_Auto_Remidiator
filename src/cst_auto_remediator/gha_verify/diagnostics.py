"""
Diagnostic codes and mappings for Stage 8 Verification findings.
"""

from __future__ import annotations

DIAGNOSTICS = {
    "VER001": "Parse failure: The output YAML is syntactically invalid.",
    "VER002": "Semantic mismatch: Structural workflow definitions differ from original.",
    "VER003": "Security failure: Expected step classification (safe/remediated/bailout) was violated.",
    "VER004": "Formatting failure: Indents, spaces, flow/block style attributes changed unexpectedly.",
    "VER005": "Comment loss: Comments were modified, misplaced, or dropped in output.",
    "VER006": "Line ending change: Line ending layout was not preserved.",
    "VER007": "CoW violation: A mutated node shares identity with the original object.",
    "VER008": "Structural sharing failure: Untouched sibling nodes did not preserve python identity.",
    "VER009": "Idempotence failure: Sequential compiler passes caused code modifications.",
    "VER010": "Determinism failure: Multi-pass compilations of identical files generated divergent bytes.",
    "VER011": "Unexpected mutation: A syntax block was edited outside the planned patch scope.",
    "VER012": "Internal verifier error: Stage 8 encountered an untrapped runtime exception.",
}

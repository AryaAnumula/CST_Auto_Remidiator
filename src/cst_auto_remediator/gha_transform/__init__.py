"""
Stage 6 - GitHub Actions CST Transformation Phase.
"""

from cst_auto_remediator.gha_transform.namer import gen_safe_var_name
from cst_auto_remediator.gha_transform.nodes import (
    EnvVarEntry,
    MutationPlan,
    SiteReplacement,
    StepMutation,
    TransformationResult,
)
from cst_auto_remediator.gha_transform.planner import (
    MutationPlanner,
    Stage6InvariantError,
)
from cst_auto_remediator.gha_transform.rtl import apply_rtl_substitutions
from cst_auto_remediator.gha_transform.transformer import CSTTransformer
from cst_auto_remediator.gha_transform.serializer import serialize_document

__all__ = [
    "CSTTransformer",
    "EnvVarEntry",
    "MutationPlan",
    "MutationPlanner",
    "SiteReplacement",
    "Stage6InvariantError",
    "StepMutation",
    "TransformationResult",
    "apply_rtl_substitutions",
    "gen_safe_var_name",
    "serialize_document",
]

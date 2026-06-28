"""
Stage 4 Metadata Providers Public API.
"""

from cst_auto_remediator.gha_metadata.engine import MetadataWrapper, MetadataProvider
from cst_auto_remediator.gha_metadata.nodes import (
    ShellCapabilities,
    PositionMetadata,
    ScopeMetadata,
    ShellMetadata,
    ExpressionMetadata,
    MetadataBundle,
)
from cst_auto_remediator.gha_metadata.providers import (
    PositionProvider,
    ScopeProvider,
    ShellProvider,
    ExpressionProvider,
)

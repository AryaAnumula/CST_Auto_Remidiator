"""
Stage 4 — GitHub Actions Metadata Resolution Engine.

Implements the central MetadataWrapper cache engine and the MetadataProvider base class.
"""

from __future__ import annotations

from typing import Any, TYPE_CHECKING
from cst_auto_remediator.gha_metadata.nodes import MetadataBundle

if TYPE_CHECKING:
    from cst_auto_remediator.gha_semantic.nodes import Workflow


class MetadataWrapper:
    def __init__(self, workflow: Workflow):
        self.workflow = workflow
        self.cache: dict[type[MetadataProvider], dict[Any, Any]] = {}

    def get_metadata(self, provider_class: type[MetadataProvider]) -> dict[Any, Any]:
        """Resolves dependencies and executes the provider, caching results."""
        if provider_class not in self.cache:
            for dep in provider_class.dependencies():
                self.get_metadata(dep)
            provider = provider_class(self)
            self.cache[provider_class] = provider.resolve(self.workflow)
        return self.cache[provider_class]

    def get(self, provider_class: type[MetadataProvider], node: Any) -> Any:
        """Get metadata associated with a specific node."""
        return self.get_metadata(provider_class).get(id(node))

    def get_bundle(self, node: Any) -> MetadataBundle:
        """Aggregates position, scope, shell, and expression metadata for a node."""
        from cst_auto_remediator.gha_metadata.providers import (
            PositionProvider,
            ScopeProvider,
            ShellProvider,
            ExpressionProvider,
        )
        return MetadataBundle(
            position=self.get(PositionProvider, node),
            scope=self.get(ScopeProvider, node),
            shell=self.get(ShellProvider, node),
            expression=self.get(ExpressionProvider, node),
        )


class MetadataProvider:
    def __init__(self, wrapper: MetadataWrapper):
        self.wrapper = wrapper

    @classmethod
    def dependencies(cls) -> list[type[MetadataProvider]]:
        """List of metadata providers that must be resolved first."""
        return []

    def resolve(self, workflow: Workflow) -> dict[Any, Any]:
        """Resolve metadata mapping for all nodes in the workflow semantic tree."""
        raise NotImplementedError()

    def get_metadata(self, provider_class: type[MetadataProvider], node: Any) -> Any:
        """Helper to request metadata from another provider on this wrapper."""
        return self.wrapper.get(provider_class, node)

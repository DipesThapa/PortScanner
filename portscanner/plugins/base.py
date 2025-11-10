"""
Base classes and helpers for scanner plugins.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional, Sequence


@dataclass
class PluginContext:
    """
    Context passed to plugins so they can understand the current run.
    """

    settings: Dict[str, Any] = field(default_factory=dict)
    asset_catalog: Any = None
    diff_results: Optional[Dict[str, Any]] = None
    config: Dict[str, Any] = field(default_factory=dict)
    credentials: Any = None


class ScanPlugin:
    """
    Base class that plugins should inherit. All hook methods are optional.
    """

    name: str = "scan-plugin"
    description: str = ""

    def __init__(self, options: Optional[Dict[str, Any]] = None):
        self.options = options or {}
        self.context: Optional[PluginContext] = None

    # lifecycle -----------------------------------------------------------

    def initialize(self, context: PluginContext) -> None:
        """
        Called once before any per-host processing.
        """
        self.context = context

    def process_host(self, host: Dict[str, Any]) -> None:
        """
        Called for each host report after core enrichments but before final output.
        """

    def finalize(self) -> Dict[str, Any]:
        """
        Called once after all hosts have been processed. Return structured data
        to be merged into the final structured output.
        """
        return {}

    # helper --------------------------------------------------------------

    def get_option(self, key: str, default: Any = None) -> Any:
        return self.options.get(key, default)

    def add_note(self, host: Dict[str, Any], category: str, message: str) -> None:
        notes = host.setdefault("plugin_notes", {})
        notes.setdefault(category, [])
        notes[category].append(message)

"""
Plugin framework for extending scan enrichment and reporting.
"""

from __future__ import annotations

from .manager import PluginManager
from .base import ScanPlugin, PluginContext

__all__ = ["PluginManager", "ScanPlugin", "PluginContext"]

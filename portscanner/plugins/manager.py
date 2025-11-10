"""
Simple plugin manager that loads and orchestrates scan plugins.
"""

from __future__ import annotations

import importlib
from typing import Dict, Iterable, List, Optional, Sequence, Tuple, Type

from .base import PluginContext, ScanPlugin

BUILTIN_PLUGIN_MODULES = {
    "threat-intel": "portscanner.plugins.threatintel:ThreatIntelPlugin",
    "auto-responder": "portscanner.plugins.responder:ResponderPlugin",
    "deep-dive": "portscanner.plugins.deepdive:DeepDivePlugin",
}


def _resolve_spec(spec: str) -> Tuple[str, str]:
    if ":" in spec:
        module_name, class_name = spec.split(":", 1)
    else:
        module_name, class_name = spec, "Plugin"
    return module_name, class_name


class PluginManager:
    def __init__(self, plugin_specs: Optional[Sequence[str]] = None, options: Optional[Dict[str, Dict]] = None):
        self.plugin_specs = list(plugin_specs or [])
        self.options = options or {}
        self.instances: List[ScanPlugin] = []

    def load_plugins(self) -> None:
        self.instances = []
        for spec in self.plugin_specs:
            module_name, class_name = self._resolve_spec(spec)
            plugin_cls = self._import_plugin(module_name, class_name)
            if plugin_cls is None:
                continue
            opts = self.options.get(spec, {})
            try:
                instance = plugin_cls(opts)
            except Exception as exc:  # pragma: no cover - defensive
                print(f"[-] Failed to instantiate plugin {spec}: {exc}")
                continue
            self.instances.append(instance)

    def _resolve_spec(self, spec: str) -> Tuple[str, str]:
        if spec in BUILTIN_PLUGIN_MODULES:
            mapped = BUILTIN_PLUGIN_MODULES[spec]
            return _resolve_spec(mapped)
        return _resolve_spec(spec)

    def _import_plugin(self, module_name: str, class_name: str) -> Optional[Type[ScanPlugin]]:
        try:
            module = importlib.import_module(module_name)
        except ImportError as exc:
            print(f"[-] Unable to import plugin module {module_name}: {exc}")
            return None
        try:
            plugin_cls = getattr(module, class_name)
        except AttributeError:
            print(f"[-] Plugin class {class_name} not found in module {module_name}")
            return None
        if not issubclass(plugin_cls, ScanPlugin):
            print(f"[-] {class_name} is not a ScanPlugin subclass")
            return None
        return plugin_cls

    def initialize(self, context: PluginContext) -> None:
        for plugin in self.instances:
            plugin.initialize(context)

    def process_host(self, host: Dict) -> None:
        for plugin in self.instances:
            try:
                plugin.process_host(host)
            except Exception as exc:  # pragma: no cover - defensive
                print(f"[-] Plugin {plugin.name} failed during process_host: {exc}")

    def finalize(self) -> Dict[str, Dict]:
        aggregate: Dict[str, Dict] = {}
        for plugin in self.instances:
            try:
                result = plugin.finalize() or {}
            except Exception as exc:  # pragma: no cover - defensive
                print(f"[-] Plugin {plugin.name} failed during finalize: {exc}")
                continue
            aggregate[plugin.name] = result
        return aggregate

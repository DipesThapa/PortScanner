"""
Asset catalog support for enriching host reports with metadata and tags.
"""

from __future__ import annotations

import json
from dataclasses import dataclass, field
from pathlib import Path
from typing import Dict, List, Optional, Sequence


class AssetCatalogLoadError(RuntimeError):
    """Raised when an asset catalog cannot be loaded."""


@dataclass
class AssetRecord:
    data: Dict
    targets: List[str] = field(default_factory=list)
    hostnames: List[str] = field(default_factory=list)
    addresses: List[str] = field(default_factory=list)


def _ensure_list(value) -> List[str]:
    if value is None:
        return []
    if isinstance(value, str):
        return [value]
    if isinstance(value, Sequence):
        return [str(v) for v in value if v]
    return []


class AssetCatalog:
    def __init__(self, assets: Sequence[Dict]):
        self.assets: List[AssetRecord] = []
        self.by_target: Dict[str, AssetRecord] = {}
        self.by_hostname: Dict[str, AssetRecord] = {}
        self.by_address: Dict[str, AssetRecord] = {}
        for asset in assets:
            if not isinstance(asset, dict):
                continue
            record = AssetRecord(
                data=dict(asset),
                targets=_ensure_list(asset.get("target")),
                hostnames=_ensure_list(asset.get("hostnames")),
                addresses=_ensure_list(asset.get("addresses")),
            )
            self.assets.append(record)
            for target in record.targets:
                self.by_target[target.lower()] = record
            for hostname in record.hostnames:
                self.by_hostname[hostname.lower()] = record
            for address in record.addresses:
                self.by_address[address] = record

    def find_for_host(self, host: Dict) -> Optional[Dict]:
        target = host.get("target")
        if target:
            record = self.by_target.get(str(target).lower())
            if record:
                return record.data

        for hostname in host.get("hostnames") or []:
            record = self.by_hostname.get(str(hostname).lower())
            if record:
                return record.data

        for addr_rec in host.get("addresses") or []:
            address = addr_rec.get("address")
            if address:
                record = self.by_address.get(str(address))
                if record:
                    return record.data
        return None

    def enrich_hosts(self, hosts: Sequence[Dict]) -> None:
        for host in hosts:
            asset = self.find_for_host(host)
            if asset:
                host["asset"] = asset


def load_catalog(path: str) -> AssetCatalog:
    try:
        raw = json.loads(Path(path).read_text(encoding="utf-8"))
    except FileNotFoundError as exc:
        raise AssetCatalogLoadError(f"Asset file not found: {path}") from exc
    except json.JSONDecodeError as exc:
        raise AssetCatalogLoadError(f"Failed to parse asset JSON: {exc}") from exc

    if isinstance(raw, dict):
        assets = raw.get("assets")
        if assets is None:
            raise AssetCatalogLoadError("Asset JSON must contain an 'assets' list.")
    elif isinstance(raw, list):
        assets = raw
    else:
        raise AssetCatalogLoadError("Asset JSON must be a list or object with an 'assets' key.")

    return AssetCatalog(assets)

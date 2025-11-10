"""
Credential store utilities for authenticated scans and plugins.
"""

from __future__ import annotations

import json
from dataclasses import dataclass
from pathlib import Path
from typing import Dict, Optional

from .secrets import SecretProvider, build_provider, SecretProviderError


@dataclass
class Credential:
    service: str
    username: Optional[str] = None
    password: Optional[str] = None
    secret: Optional[str] = None
    extra: Dict[str, str] = None


class CredentialStore:
    """
    Lightweight credential store keyed by service and optionally target.
    """

    def __init__(self, records: Dict[str, Dict], provider: Optional[SecretProvider] = None):
        normalized: Dict[str, Dict] = {}
        for key, value in records.items():
            if not isinstance(value, dict):
                continue
            normalized[key.lower()] = {k: str(v) for k, v in value.items()}
        self.records = normalized
        self.provider = provider

    @classmethod
    def load(cls, path: str, secret_provider: Optional[SecretProvider] = None) -> "CredentialStore":
        try:
            data = json.loads(Path(path).read_text(encoding="utf-8"))
        except FileNotFoundError as exc:
            raise ValueError(f"Credential file not found: {path}") from exc
        except json.JSONDecodeError as exc:
            raise ValueError(f"Failed to parse credential JSON: {exc}") from exc
        if not isinstance(data, dict):
            raise ValueError("Credential file must be a JSON object keyed by service name.")
        if secret_provider:
            for service, record in list(data.items()):
                if not isinstance(record, dict):
                    continue
                for key, value in list(record.items()):
                    if isinstance(value, str) and value.startswith("secret://"):
                        secret_key = value.split("secret://", 1)[1]
                        secret_value = secret_provider.get_secret(secret_key)
                        if secret_value is None:
                            raise ValueError(f"Secret '{secret_key}' not found for service {service}.")
                        record[key] = secret_value
        return cls(data, provider)

    @classmethod
    def from_sources(
        cls,
        path: Optional[str],
        env_prefix: str = "PORTSCANNER_",
        secret_file: Optional[str] = None,
    ) -> Optional["CredentialStore"]:
        if not path and not secret_file:
            return None
        provider = None
        if secret_file or env_prefix:
            try:
                provider = build_provider(env_prefix=env_prefix, secret_file=secret_file)
            except SecretProviderError as exc:
                raise ValueError(str(exc)) from exc
        if path:
            return cls.load(path, provider)
        return cls({}, provider)

    def get_for_service(self, service: str) -> Dict[str, str]:
        record = dict(self.records.get(service.lower(), {}))
        if self.provider:
            secret_username = self.provider.get_secret(f"{service}_username")
            secret_password = self.provider.get_secret(f"{service}_password")
            if secret_username and "username" not in record:
                record["username"] = secret_username
            if secret_password and "password" not in record:
                record["password"] = secret_password
        return record

    def to_summary(self) -> Dict[str, Dict[str, str]]:
        return self.records.copy()

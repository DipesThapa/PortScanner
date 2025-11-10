"""
Secret provider utilities for retrieving credentials from multiple backends.
"""

from __future__ import annotations

import json
import os
from pathlib import Path
from typing import Dict, Optional


class SecretProviderError(RuntimeError):
    pass


class SecretProvider:
    def get_secret(self, key: str) -> Optional[str]:
        raise NotImplementedError


class EnvSecretProvider(SecretProvider):
    def __init__(self, prefix: str = "PORTSCANNER_"):
        self.prefix = prefix

    def get_secret(self, key: str) -> Optional[str]:
        return os.getenv(f"{self.prefix}{key.upper()}")


class FileSecretProvider(SecretProvider):
    def __init__(self, path: str):
        self.path = Path(path)
        if not self.path.exists():
            raise SecretProviderError(f"Secret file not found: {path}")
        try:
            self.data = json.loads(self.path.read_text(encoding="utf-8"))
        except json.JSONDecodeError as exc:
            raise SecretProviderError(f"Failed to read secret file: {exc}") from exc
        if not isinstance(self.data, dict):
            raise SecretProviderError("Secret file must contain a JSON object.")

    def get_secret(self, key: str) -> Optional[str]:
        value = self.data.get(key)
        if isinstance(value, (str, int, float)):
            return str(value)
        return None


class CompositeSecretProvider(SecretProvider):
    def __init__(self, providers):
        self.providers = providers

    def get_secret(self, key: str) -> Optional[str]:
        for provider in self.providers:
            value = provider.get_secret(key)
            if value is not None:
                return value
        return None


def build_provider(env_prefix: str = "PORTSCANNER_", secret_file: Optional[str] = None) -> SecretProvider:
    providers = [EnvSecretProvider(prefix=env_prefix)]
    if secret_file:
        try:
            providers.append(FileSecretProvider(secret_file))
        except SecretProviderError as exc:
            raise SecretProviderError(str(exc)) from exc
    return CompositeSecretProvider(providers)

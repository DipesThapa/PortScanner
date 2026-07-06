"""
API authentication and request-validation helpers for the web app.

Design goals:
* The API must never be reachable without a credential. If the operator does
  not supply ``PORTSCANNER_API_KEY``, a strong random key is generated on first
  boot and persisted to ``web_runs/.api_key`` (mode 0600) so the service still
  works out of the box but is never anonymous.
* Auth is applied to every ``/api`` route (via a router dependency) and to the
  status WebSocket (which reads the key from a query parameter or header).
"""

from __future__ import annotations

import hmac
import os
import secrets
from pathlib import Path
from typing import Optional

from fastapi import Header, HTTPException, status

API_KEY_ENV = "PORTSCANNER_API_KEY"
_KEY_FILE = Path("web_runs") / ".api_key"
_MIN_KEY_LEN = 16


def _generate_key() -> str:
    return secrets.token_urlsafe(32)


def load_or_create_api_key() -> str:
    """Return the configured API key, generating and persisting one if absent."""
    env_key = os.getenv(API_KEY_ENV)
    if env_key and env_key.strip():
        key = env_key.strip()
        if len(key) < _MIN_KEY_LEN:
            raise RuntimeError(
                f"{API_KEY_ENV} is too short; use at least {_MIN_KEY_LEN} characters."
            )
        return key

    if _KEY_FILE.exists():
        existing = _KEY_FILE.read_text(encoding="utf-8").strip()
        if existing:
            return existing

    key = _generate_key()
    _KEY_FILE.parent.mkdir(parents=True, exist_ok=True)
    _KEY_FILE.write_text(key, encoding="utf-8")
    try:
        os.chmod(_KEY_FILE, 0o600)
    except OSError:  # pragma: no cover - platform dependent
        pass
    print(
        "[portscanner] No PORTSCANNER_API_KEY set. Generated a new API key and "
        f"stored it at {_KEY_FILE}. Send it as the 'X-API-Key' header.\n"
        f"[portscanner] API key: {key}"
    )
    return key


# Resolved once at import so every dependency sees the same value.
API_KEY: str = load_or_create_api_key()


def _valid(candidate: Optional[str]) -> bool:
    if not candidate:
        return False
    # Constant-time comparison to avoid timing side channels.
    return hmac.compare_digest(candidate.strip(), API_KEY)


def require_api_key(x_api_key: Optional[str] = Header(default=None)) -> None:
    """FastAPI dependency: reject requests without a valid X-API-Key header."""
    if not _valid(x_api_key):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Missing or invalid API key.",
            headers={"WWW-Authenticate": "ApiKey"},
        )


def websocket_key_ok(token: Optional[str], header_key: Optional[str]) -> bool:
    """Validate a WebSocket connection using either a query token or header."""
    return _valid(token) or _valid(header_key)

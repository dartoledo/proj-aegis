"""Fail-fast configuration loader and secret masking utilities for Aegis SSL Tracker."""

from __future__ import annotations

from dataclasses import dataclass
import hmac
import logging
import os
from typing import Mapping


class ConfigurationError(RuntimeError):
    """Raised when required configuration or environment tokens are missing or invalid."""


class MaskedSecret:
    """Wraps sensitive secret tokens so they never surface in logs, repr(), or str()."""

    __slots__ = ("_value",)

    def __init__(self, value: str) -> None:
        if not isinstance(value, str) or not value.strip():
            raise ValueError("Secret value must be a non-empty string.")
        self._value = value.strip()

    def get_secret_value(self) -> str:
        """Return the underlying raw secret value for authorized cryptographic/auth checks."""
        return self._value

    def matches(self, candidate: str) -> bool:
        """Constant-time comparison against a candidate token."""
        if not isinstance(candidate, str):
            return False
        return hmac.compare_digest(self._value.encode("utf-8"), candidate.encode("utf-8"))

    def __repr__(self) -> str:
        return "MaskedSecret('***')"

    def __str__(self) -> str:
        return "***"

    def __eq__(self, other: object) -> bool:
        if isinstance(other, MaskedSecret):
            return hmac.compare_digest(self._value, other._value)
        return False


class SecretRedactingFilter(logging.Filter):
    """Logging filter that scrubs registered raw secrets from log records and arguments."""

    def __init__(self, secrets: list[MaskedSecret]) -> None:
        super().__init__()
        self._raw_secrets = [s.get_secret_value() for s in secrets if s.get_secret_value()]

    def _scrub(self, text: str) -> str:
        scrubbed = text
        for raw in self._raw_secrets:
            if raw and raw in scrubbed:
                scrubbed = scrubbed.replace(raw, "***")
        return scrubbed

    def filter(self, record: logging.LogRecord) -> bool:
        if isinstance(record.msg, str):
            record.msg = self._scrub(record.msg)
        if record.args:
            if isinstance(record.args, dict):
                record.args = {
                    k: self._scrub(v) if isinstance(v, str) else v
                    for k, v in record.args.items()
                }
            elif isinstance(record.args, tuple):
                record.args = tuple(
                    self._scrub(a) if isinstance(a, str) else a for a in record.args
                )
        return True


@dataclass(frozen=True)
class AppConfig:
    """Validated runtime configuration for the SSL Tracker microservice."""

    api_token: MaskedSecret
    db_path: str
    default_haproxy_host: str = "127.0.0.1:8443"


REQUIRED_ENV_VARS = (
    "AEGIS_SSL_TRACKER_API_TOKEN",
    "AEGIS_SSL_TRACKER_DB_PATH",
)


def load_config(env: Mapping[str, str] | None = None) -> AppConfig:
    """Validate required environment variables once at startup and return AppConfig."""
    source = os.environ if env is None else env

    for var_name in REQUIRED_ENV_VARS:
        raw_val = source.get(var_name, "")
        if not isinstance(raw_val, str) or not raw_val.strip():
            raise ConfigurationError(f"Missing required environment variable: {var_name}")

    token = MaskedSecret(source["AEGIS_SSL_TRACKER_API_TOKEN"])
    db_path = source["AEGIS_SSL_TRACKER_DB_PATH"].strip()
    haproxy_host = source.get("AEGIS_HAPROXY_HOST", "127.0.0.1:8443").strip() or "127.0.0.1:8443"

    logger = logging.getLogger("ssl_tracker")
    logger.filters.clear()
    logger.addFilter(SecretRedactingFilter([token]))

    return AppConfig(
        api_token=token,
        db_path=db_path,
        default_haproxy_host=haproxy_host,
    )

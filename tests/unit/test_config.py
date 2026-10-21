"""Unit and security tests for fail-fast configuration and secret masking."""

from __future__ import annotations

import logging
import pytest

from services.ssl_tracker.config import (
    ConfigurationError,
    MaskedSecret,
    SecretRedactingFilter,
    load_config,
)


def test_load_config_fails_fast_when_api_token_missing() -> None:
    with pytest.raises(
        ConfigurationError,
        match="Missing required environment variable: AEGIS_SSL_TRACKER_API_TOKEN",
    ):
        load_config(env={"AEGIS_SSL_TRACKER_DB_PATH": ":memory:"})


def test_load_config_fails_fast_when_db_path_missing() -> None:
    with pytest.raises(
        ConfigurationError,
        match="Missing required environment variable: AEGIS_SSL_TRACKER_DB_PATH",
    ):
        load_config(env={"AEGIS_SSL_TRACKER_API_TOKEN": "test-token-123"})


def test_load_config_fails_fast_on_blank_values() -> None:
    with pytest.raises(
        ConfigurationError,
        match="Missing required environment variable: AEGIS_SSL_TRACKER_API_TOKEN",
    ):
        load_config(
            env={
                "AEGIS_SSL_TRACKER_API_TOKEN": "   ",
                "AEGIS_SSL_TRACKER_DB_PATH": ":memory:",
            }
        )


def test_masked_secret_rejects_empty_input() -> None:
    with pytest.raises(ValueError, match="non-empty string"):
        MaskedSecret("")
    with pytest.raises(ValueError, match="non-empty string"):
        MaskedSecret("   ")


def test_masked_secret_never_leaks_in_repr_or_str() -> None:
    raw = "super-sensitive-api-token-999"
    secret = MaskedSecret(raw)
    assert raw not in repr(secret)
    assert raw not in str(secret)
    assert repr(secret) == "MaskedSecret('***')"
    assert str(secret) == "***"
    assert secret.matches(raw) is True
    assert secret.matches("wrong-token") is False
    assert secret == MaskedSecret(raw)
    assert secret != MaskedSecret("other")
    assert secret != raw


def test_secret_never_surfaces_in_runtime_logs(caplog: pytest.LogCaptureFixture) -> None:
    raw_token = "ultra-secret-bearer-xyz-98765"
    cfg = load_config(
        env={
            "AEGIS_SSL_TRACKER_API_TOKEN": raw_token,
            "AEGIS_SSL_TRACKER_DB_PATH": ":memory:",
        }
    )
    logger = logging.getLogger("ssl_tracker")
    with caplog.at_level(logging.INFO, logger="ssl_tracker"):
        logger.info(f"Loaded config with token={raw_token} and repr={cfg.api_token!r}")
        logger.warning("Failed auth check for %s", raw_token)

    for record in caplog.records:
        assert raw_token not in record.getMessage()
        assert "***" in record.getMessage()

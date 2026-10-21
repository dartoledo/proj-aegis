"""Unit tests for the 5 X.509 certificate compliance pillars."""

from __future__ import annotations

from datetime import datetime, timedelta, timezone
import pytest

from services.ssl_tracker.compliance import (
    evaluate_crypto_compliance,
    evaluate_expiry,
    inspect_x509_certificate_bytes,
    match_hostname_san,
    normalize_serial_hex,
)
from services.ssl_tracker.scanner import mint_synthetic_x509_pem


def test_normalize_serial_hex_formats_integers_and_strings() -> None:
    assert normalize_serial_hex(0x3C7B365E) == "3C:7B:36:5E"
    assert normalize_serial_hex("3c7b365e") == "3C:7B:36:5E"
    assert normalize_serial_hex("0x0a1b") == "0A:1B"
    assert normalize_serial_hex(0) == "00"


def test_normalize_serial_hex_rejects_invalid_inputs() -> None:
    with pytest.raises(ValueError, match="non-negative"):
        normalize_serial_hex(-5)
    with pytest.raises(ValueError, match="Invalid hexadecimal"):
        normalize_serial_hex("not-a-hex-serial")
    with pytest.raises(ValueError, match="Invalid hexadecimal"):
        normalize_serial_hex("")
    with pytest.raises(ValueError, match="boolean"):
        normalize_serial_hex(True)


def test_match_hostname_san_handles_exact_and_wildcards() -> None:
    assert match_hostname_san(
        "stg.auth.internal",
        "auth.internal",
        ["stg.auth.internal", "prod.auth.internal"],
    ) is True
    assert match_hostname_san(
        "stg-eu.auth.internal",
        "auth.internal",
        ["*.auth.internal"],
    ) is True
    # Multi-level subdomain must NOT match single-label wildcard per RFC 6125
    assert match_hostname_san(
        "deep.stg.auth.internal",
        "auth.internal",
        ["*.auth.internal"],
    ) is False
    assert match_hostname_san("", "auth.internal", ["auth.internal"]) is False


def test_evaluate_expiry_thresholds_and_private_cloud_self_renewal_sla() -> None:
    now = datetime(2026, 10, 21, 0, 0, 0, tzinfo=timezone.utc)

    days, status, findings = evaluate_expiry(now + timedelta(days=60), now=now)
    assert days == 60
    assert status == "HEALTHY"
    assert findings == []

    days, status, findings = evaluate_expiry(now + timedelta(days=20), now=now)
    assert status == "WARNING"
    assert any("EXPIRY_WARNING" in f for f in findings)

    days, status, findings = evaluate_expiry(now + timedelta(days=5), now=now)
    assert status == "CRITICAL"
    assert any("EXPIRY_CRITICAL" in f for f in findings)

    days, status, findings = evaluate_expiry(now - timedelta(days=1), now=now)
    assert status == "EXPIRED"
    assert any("CERT_EXPIRED" in f for f in findings)

    # Private Cloud LB self-renewing SLA check (e.g. <= 15 days triggers SELF_RENEWAL_STALLED)
    days, status, findings = evaluate_expiry(
        now + timedelta(days=12),
        now=now,
        renewal_mode="self-renewing-monitored",
        auto_renew_threshold_days=15,
    )
    assert any("SELF_RENEWAL_STALLED" in f for f in findings)


def test_evaluate_crypto_compliance_flags_sha1_and_1024_bit_keys() -> None:
    ok, findings = evaluate_crypto_compliance("sha256WithRSAEncryption", "SHA256", "RSA", 2048)
    assert ok is True
    assert findings == []

    ok, findings = evaluate_crypto_compliance("ecdsa-with-SHA256", "SHA256", "ECDSA", 256)
    assert ok is True
    assert findings == []

    # Weak 1024-bit RSA + SHA-1
    ok, findings = evaluate_crypto_compliance("sha1WithRSAEncryption", "SHA1", "RSA", 1024)
    assert ok is False
    assert any("INSECURE_SIGNATURE_HASH" in f for f in findings)
    assert any("WEAK_KEY_SIZE" in f and "1024-bit" in f for f in findings)


def test_inspect_x509_certificate_bytes_parses_all_5_pillars() -> None:
    now = datetime(2026, 10, 21, 0, 0, 0, tzinfo=timezone.utc)
    pem = mint_synthetic_x509_pem(
        subject_cn="stg-primary.auth.internal",
        san_dns_names=["stg-primary.auth.internal", "*.auth.internal"],
        issuer_cn="Aegis Private Cloud Vault Intermediate CA G2",
        issuer_org="Aegis Enterprise Private PKI",
        serial_number=0x1A2B3C4D5E,
        not_before=now - timedelta(days=5),
        not_after=now + timedelta(days=80),
        key_algorithm="RSA-2048",
        use_weak_sha1=False,
        is_self_signed=False,
    )
    res = inspect_x509_certificate_bytes(
        pem_or_der=pem,
        expected_hostname="stg-primary.auth.internal",
        environment="stg",
        provider_type="private-cloud-lb",
        renewal_mode="self-renewing-monitored",
        now=now,
    )
    assert res["serial_number_hex"] == "1A:2B:3C:4D:5E"
    assert res["days_remaining"] == 80
    assert res["expiry_status"] == "HEALTHY"
    assert res["subject_cn"] == "stg-primary.auth.internal"
    assert "stg-primary.auth.internal" in res["san_dns_names"]
    assert res["hostname_matches_san"] is True
    assert res["issuer_cn"] == "Aegis Private Cloud Vault Intermediate CA G2"
    assert res["public_key_algorithm"] == "RSA"
    assert res["public_key_bits"] == 2048
    assert res["signature_hash_algorithm"] == "SHA256"
    assert res["compliance_status"] == "COMPLIANT"


def test_inspect_x509_certificate_bytes_detects_weak_1024_sha1_cert() -> None:
    now = datetime(2026, 10, 21, 0, 0, 0, tzinfo=timezone.utc)
    weak_pem = mint_synthetic_x509_pem(
        subject_cn="stress.backend.internal",
        san_dns_names=["stress.backend.internal"],
        issuer_cn="Legacy Internal CA",
        issuer_org="Legacy Corp",
        serial_number=0x99887766,
        not_before=now - timedelta(days=10),
        not_after=now + timedelta(days=45),
        key_algorithm="RSA-1024",
        use_weak_sha1=True,
        is_self_signed=False,
    )
    res = inspect_x509_certificate_bytes(
        pem_or_der=weak_pem,
        expected_hostname="stress.backend.internal",
        environment="stress-test",
        provider_type="private-cloud-lb",
        now=now,
    )
    assert res["compliance_status"] == "NON_COMPLIANT"
    assert res["public_key_bits"] == 1024
    assert res["signature_hash_algorithm"] == "SHA1"
    assert any("WEAK_KEY_SIZE" in f for f in res["compliance_findings"])
    assert any("INSECURE_SIGNATURE_HASH" in f for f in res["compliance_findings"])

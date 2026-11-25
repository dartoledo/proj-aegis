"""Unit, integration, and E2E tests for the Project Aegis Active Endpoint Prober."""

from __future__ import annotations

from datetime import datetime, timedelta, timezone
from pathlib import Path
from unittest.mock import patch

from fastapi.testclient import TestClient
import pytest

from services.ssl_tracker.active_prober import (
    classify_source_ip_zscaler_context,
    detect_waf_protection,
    is_zscaler_ip_cidr,
    normalize_endpoint_target,
    probe_endpoints_list,
)
from services.ssl_tracker.app import create_app
from services.ssl_tracker.scanner import mint_synthetic_x509_pem


def test_is_zscaler_ip_cidr_and_classification() -> None:
    matched, cidr = is_zscaler_ip_cidr("165.225.72.45")
    assert matched is True
    assert cidr == "165.225.0.0/16"

    matched_non, cidr_non = is_zscaler_ip_cidr("203.0.113.55")
    assert matched_non is False
    assert cidr_non is None

    z_ctx = classify_source_ip_zscaler_context("165.225.72.45")
    assert z_ctx["is_zscaler_source_ip"] is True
    assert z_ctx["network_origin"] == "PRIVATE_NETWORK_ZSCALER"

    ptr_ctx = classify_source_ip_zscaler_context(
        "198.51.100.22",
        ptr_hostnames=["gateway.zscloud.net"],
    )
    assert ptr_ctx["is_zscaler_source_ip"] is True
    assert ptr_ctx["network_origin"] == "PRIVATE_NETWORK_ZSCALER"

    pub_ctx = classify_source_ip_zscaler_context("203.0.113.55")
    assert pub_ctx["is_zscaler_source_ip"] is False
    assert pub_ctx["network_origin"] == "PUBLIC_INTERNET"


def test_detect_waf_protection_akamai_fastly_cloud_armor() -> None:
    akamai = detect_waf_protection(
        headers={"Server": "AkamaiGHost", "X-Akamai-Transformed": "9 0"},
    )
    assert akamai["waf_provider"] == "Akamai"
    assert akamai["waf_detected"] is True

    fastly = detect_waf_protection(
        headers={"X-Served-By": "cache-tyo11928-TYO", "X-Timer": "S17123.1,VS0,VE1"},
    )
    assert fastly["waf_provider"] == "Fastly"
    assert fastly["waf_detected"] is True

    armor = detect_waf_protection(
        headers={"Server": "Google Frontend", "Via": "1.1 google"},
    )
    assert armor["waf_provider"] == "Cloud Armor"
    assert armor["waf_detected"] is True

    none_waf = detect_waf_protection(headers={"Server": "nginx"})
    assert none_waf["waf_provider"] == "None"
    assert none_waf["waf_detected"] is False


def test_normalize_endpoint_target_validation() -> None:
    with pytest.raises(ValueError, match="Target endpoint must be a non-empty string"):
        normalize_endpoint_target("   ")

    url, host, port = normalize_endpoint_target("login.aegis.cloud.goog")
    assert url == "https://login.aegis.cloud.goog"
    assert host == "login.aegis.cloud.goog"
    assert port == 443


def test_probe_endpoints_list_public_vs_zscaler_source_ip() -> None:
    now = datetime(2026, 11, 26, 0, 0, 0, tzinfo=timezone.utc)
    pem_bytes = mint_synthetic_x509_pem(
        subject_cn="login.aegis.cloud.goog",
        san_dns_names=["login.aegis.cloud.goog", "*.aegis.cloud.goog"],
        issuer_cn="GTS CA 1C3",
        issuer_org="Google Trust Services LLC",
        serial_number=0x0A1B2C3D,
        not_before=now - timedelta(days=5),
        not_after=now + timedelta(days=75),
        key_algorithm="RSA-2048",
    )

    def mock_cert_fetcher(_host: str, _port: int, _sni: str, _timeout: float) -> bytes:
        return pem_bytes

    def mock_header_fetcher(_url: str, _timeout: float) -> tuple[int | None, dict[str, str]]:
        return 200, {"server": "AkamaiGHost", "x-akamai-transformed": "9 123"}

    # 1. Non-Zscaler Public IP -> accessible_from_public_internet = True
    pub_report = probe_endpoints_list(
        ["https://login.aegis.cloud.goog"],
        source_ip="203.0.113.10",
        cert_fetcher=mock_cert_fetcher,
        header_fetcher=mock_header_fetcher,
        now=now,
    )
    assert pub_report["network_context"]["is_zscaler_source_ip"] is False
    assert pub_report["public_accessible_count"] == 1
    assert pub_report["waf_protected_count"] == 1
    res_pub = pub_report["results"][0]
    assert res_pub["accessible_from_public_internet"] is True
    assert res_pub["waf_provider"] == "Akamai"
    assert res_pub["ssl_details"]["subject_cn"] == "login.aegis.cloud.goog"
    assert res_pub["ssl_details"]["issuer_cn"] == "GTS CA 1C3"
    assert res_pub["ssl_details"]["serial_number_hex"] == "0A:1B:2C:3D"
    assert res_pub["ssl_details"]["public_key_algorithm"] == "RSA"
    assert res_pub["ssl_details"]["public_key_bits"] == 2048
    assert res_pub["ssl_details"]["days_remaining"] == 75

    # 2. Zscaler Source IP -> private network assumed -> accessible_from_public_internet = False
    z_report = probe_endpoints_list(
        ["https://login.aegis.cloud.goog"],
        source_ip="165.225.72.45",
        cert_fetcher=mock_cert_fetcher,
        header_fetcher=mock_header_fetcher,
        now=now,
    )
    assert z_report["network_context"]["is_zscaler_source_ip"] is True
    assert z_report["public_accessible_count"] == 0
    res_z = z_report["results"][0]
    assert res_z["accessible_from_public_internet"] is False
    assert res_z["exposure_scope"] == "strictly-private"


def test_e2e_probe_active_endpoint(tmp_path: Path) -> None:
    now = datetime(2026, 11, 26, 0, 0, 0, tzinfo=timezone.utc)
    pem_bytes = mint_synthetic_x509_pem(
        subject_cn="api.aegis.cloud.goog",
        san_dns_names=["api.aegis.cloud.goog"],
        issuer_cn="GTS CA 1C3",
        issuer_org="Google Trust Services LLC",
        serial_number=0x11223344,
        not_before=now - timedelta(days=2),
        not_after=now + timedelta(days=60),
        key_algorithm="ECDSA-P256",
    )

    app = create_app(
        env={
            "AEGIS_SSL_TRACKER_API_TOKEN": "test-token",
            "AEGIS_SSL_TRACKER_DB_PATH": str(tmp_path / "prober_e2e.db"),
        }
    )
    client = TestClient(app)

    with (
        patch(
            "services.ssl_tracker.active_prober.fetch_live_peer_certificate_der",
            return_value=pem_bytes,
        ),
        patch(
            "services.ssl_tracker.active_prober.default_fetch_https_headers",
            return_value=(200, {"server": "Google Frontend", "via": "1.1 google"}),
        ),
    ):
        resp = client.post(
            "/api/v1/probe-active",
            headers={"Authorization": "Bearer test-token"},
            json={
                "endpoints": ["https://api.aegis.cloud.goog"],
                "source_ip": "203.0.113.77",
            },
        )
        assert resp.status_code == 200
        data = resp.json()
        assert data["total_probed"] == 1
        assert data["public_accessible_count"] == 1
        item = data["results"][0]
        assert item["waf_provider"] == "Cloud Armor"
        assert item["accessible_from_public_internet"] is True
        assert item["ssl_details"]["public_key_algorithm"] == "ECDSA"
        assert item["ssl_details"]["public_key_bits"] == 256

"""E2E tests for the FastAPI SSL Compliance Service endpoints."""

from __future__ import annotations

from pathlib import Path
from fastapi.testclient import TestClient
import pytest

from services.ssl_tracker.app import create_app


@pytest.fixture()
def client(tmp_path: Path) -> TestClient:
    db_file = tmp_path / "e2e_ssl.db"
    app = create_app(
        env={
            "AEGIS_SSL_TRACKER_API_TOKEN": "test-token-e2e-secret",
            "AEGIS_SSL_TRACKER_DB_PATH": str(db_file),
        }
    )
    return TestClient(app)


def test_healthz_returns_200(client: TestClient) -> None:
    resp = client.get("/healthz")
    assert resp.status_code == 200
    body = resp.json()
    assert body["status"] == "ok"
    assert "stg" in body["environments"]
    assert "qa" not in body["environments"]


def test_scan_rejects_unauthenticated_or_invalid_token(client: TestClient) -> None:
    resp_no_auth = client.get("/api/v1/endpoints")
    assert resp_no_auth.status_code == 401

    resp_bad_auth = client.get(
        "/api/v1/endpoints",
        headers={"Authorization": "Bearer wrong-token"},
    )
    assert resp_bad_auth.status_code == 401


def test_full_scan_and_gcp_auto_renew_workflow(client: TestClient) -> None:
    headers = {"Authorization": "Bearer test-token-e2e-secret"}
    scan_payload = {
        "endpoints": [
            {
                "entity_ref": "component:default/aegis-auth",
                "service_name": "aegis-auth",
                "environment": "stg",
                "endpoint_key": "primary",
                "endpoint_url": "https://stg.auth.internal:8443/healthz",
                "provider_type": "private-cloud-lb",
                "renewal_mode": "self-renewing-monitored",
            },
            {
                "entity_ref": "component:default/aegis-auth",
                "service_name": "aegis-auth",
                "environment": "stg",
                "endpoint_key": "eu-central",
                "endpoint_url": "https://stg-eu.auth.internal:8443/healthz",
                "provider_type": "private-cloud-lb",
                "renewal_mode": "self-renewing-monitored",
            },
            {
                "entity_ref": "component:default/aegis-auth",
                "service_name": "aegis-auth",
                "environment": "stg",
                "endpoint_key": "partner-sso",
                "endpoint_url": "https://stg-sso.auth.internal:8443/healthz",
                "provider_type": "private-cloud-lb",
                "renewal_mode": "self-renewing-monitored",
            },
            {
                "entity_ref": "component:default/aegis-ui",
                "service_name": "aegis-ui",
                "environment": "prod",
                "endpoint_key": "default",
                "endpoint_url": "https://prod.ui.aegis.cloud.goog/healthz",
                "provider_type": "gcp-cloud-lb",
                "renewal_mode": "workflow-auto-renew",
                "gcp_project": "aegis-prod-cloud",
                "gcp_target_proxy": "aegis-ui-https-proxy",
            },
        ]
    }
    scan_resp = client.post("/api/v1/scan", json=scan_payload, headers=headers)
    assert scan_resp.status_code == 200
    data = scan_resp.json()
    assert data["scanned_count"] == 4

    # Filter endpoints by entity_ref and environment=stg (verifying 3 stg endpoints returned)
    list_resp = client.get(
        "/api/v1/endpoints?entity_ref=component:default/aegis-auth&environment=stg",
        headers=headers,
    )
    assert list_resp.status_code == 200
    assert list_resp.json()["count"] == 3

    # Trigger GCP Auto-Renew on aegis-ui prod
    renew_resp = client.post(
        "/api/v1/gcp/auto-renew",
        json={
            "entity_ref": "component:default/aegis-ui",
            "service_name": "aegis-ui",
            "environment": "prod",
            "key_algorithm": "ECDSA-P256",
            "validity_days": 90,
        },
        headers=headers,
    )
    assert renew_resp.status_code == 200
    renew_data = renew_resp.json()
    assert renew_data["status"] == "RENEWED"
    assert renew_data["renewed_count"] == 1
    renewal_item = renew_data["renewals"][0]
    assert renewal_item["previous_serial"] != renewal_item["new_serial"]
    assert renewal_item["authorization_status"] == "AUTHORIZED"

    # Check history endpoint shows both old and new serial numbers
    hist_resp = client.get(
        "/api/v1/history?entity_ref=component:default/aegis-ui&environment=prod",
        headers=headers,
    )
    assert hist_resp.status_code == 200
    assert hist_resp.json()["history_count"] == 2

    # Check Prometheus metrics endpoint
    metrics_resp = client.get("/metrics")
    assert metrics_resp.status_code == 200
    assert "aegis_ssl_endpoint_expiry_days" in metrics_resp.text
    assert 'env="stg"' in metrics_resp.text

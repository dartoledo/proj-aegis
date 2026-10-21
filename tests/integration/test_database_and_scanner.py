"""Integration tests for SQLite persistence, 1:N environment endpoints, and provider adapters."""

from __future__ import annotations

from pathlib import Path
import pytest

from services.ssl_tracker.database import (
    create_db_engine,
    make_session_factory,
    upsert_certificate_observation,
)
from services.ssl_tracker.models import CertificateInventoryModel, EndpointTargetInput
from services.ssl_tracker.scanner import ProviderAdapterRegistry


def test_multiple_stg_endpoints_persisted_independently(tmp_path: Path) -> None:
    db_file = tmp_path / "ssl_tracker_test.db"
    engine = create_db_engine(str(db_file))
    session_factory = make_session_factory(engine)
    registry = ProviderAdapterRegistry()

    stg_targets = [
        EndpointTargetInput(
            entity_ref="component:default/aegis-auth",
            service_name="aegis-auth",
            environment="stg",
            endpoint_key="primary",
            endpoint_url="https://stg.auth.internal:8443/healthz",
            provider_type="private-cloud-lb",
            renewal_mode="self-renewing-monitored",
        ),
        EndpointTargetInput(
            entity_ref="component:default/aegis-auth",
            service_name="aegis-auth",
            environment="stg",
            endpoint_key="eu-central",
            endpoint_url="https://stg-eu.auth.internal:8443/healthz",
            provider_type="private-cloud-lb",
            renewal_mode="self-renewing-monitored",
        ),
        EndpointTargetInput(
            entity_ref="component:default/aegis-auth",
            service_name="aegis-auth",
            environment="stg",
            endpoint_key="partner-sso",
            endpoint_url="https://stg-sso.auth.internal:8443/healthz",
            provider_type="private-cloud-lb",
            renewal_mode="self-renewing-monitored",
        ),
    ]

    with session_factory() as session:
        records = []
        for target in stg_targets:
            adapter = registry.get(target.provider_type)
            cert_info = adapter.inspect_endpoint(target)
            rec = upsert_certificate_observation(session, target, cert_info)
            records.append(rec)

        assert len(records) == 3
        serials = {r["certificate"]["serial_number_hex"] for r in records}
        # Each of the 3 stg endpoints gets its own unique serial number & endpoint_id
        assert len(serials) == 3
        endpoint_ids = {r["endpoint_id"] for r in records}
        assert endpoint_ids == {
            "component:default/aegis-auth:stg:primary",
            "component:default/aegis-auth:stg:eu-central",
            "component:default/aegis-auth:stg:partner-sso",
        }


def test_gcp_auto_renewal_rotates_serial_and_preserves_history(tmp_path: Path) -> None:
    db_file = tmp_path / "gcp_rotation.db"
    engine = create_db_engine(str(db_file))
    session_factory = make_session_factory(engine)
    registry = ProviderAdapterRegistry()

    target = EndpointTargetInput(
        entity_ref="component:default/aegis-ui",
        service_name="aegis-ui",
        environment="prod",
        endpoint_key="global-lb",
        endpoint_url="https://prod.ui.aegis.cloud.goog/healthz",
        provider_type="gcp-cloud-lb",
        renewal_mode="workflow-auto-renew",
        gcp_project="aegis-prod-cloud",
        gcp_target_proxy="aegis-ui-https-proxy",
    )

    with session_factory() as session:
        initial_info = registry.gcp_adapter.inspect_endpoint(target)
        first_rec = upsert_certificate_observation(session, target, initial_info)
        old_serial = first_rec["certificate"]["serial_number_hex"]

        renewal = registry.gcp_adapter.mock_auto_renew_endpoint(
            target=target,
            key_algorithm="ECDSA-P256",
            validity_days=90,
        )
        second_rec = upsert_certificate_observation(session, target, renewal["cert_info"])
        new_serial = second_rec["certificate"]["serial_number_hex"]

        assert new_serial != old_serial
        assert second_rec["certificate"]["rotated_from_serial"] == old_serial
        assert second_rec["certificate"]["history_count"] == 2
        assert second_rec["certificate"]["issuer_cn"] == "GTS CA 1C3"

        old_row = session.get(CertificateInventoryModel, (first_rec["endpoint_id"], old_serial))
        new_row = session.get(CertificateInventoryModel, (first_rec["endpoint_id"], new_serial))
        assert old_row is not None and old_row.is_active is False
        assert new_row is not None and new_row.is_active is True


def test_registry_rejects_unknown_provider() -> None:
    registry = ProviderAdapterRegistry()
    with pytest.raises(ValueError, match="Unsupported SSL provider"):
        registry.get("unknown-cloud-lb")

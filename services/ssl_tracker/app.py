"""FastAPI application for the Project Aegis Multi-Environment & Multi-Provider SSL Compliance Tracker."""

from __future__ import annotations

import logging
from typing import Any, Mapping

from fastapi import Depends, FastAPI, Header, HTTPException, Query, Response, status
from sqlalchemy import select
from sqlalchemy.orm import Session

from services.ssl_tracker.config import AppConfig, load_config
from services.ssl_tracker.database import (
    create_db_engine,
    make_session_factory,
    upsert_certificate_observation,
)
from services.ssl_tracker.models import (
    CertificateInventoryModel,
    EndpointTargetInput,
    GcpAutoRenewRequest,
    ScanBatchRequest,
    TrackedEndpointModel,
    serialize_endpoint_and_cert,
)
from services.ssl_tracker.scanner import ProviderAdapterRegistry

logger = logging.getLogger("ssl_tracker")


def create_app(env: Mapping[str, str] | None = None) -> FastAPI:
    """Create and configure the FastAPI SSL Compliance Service (fails fast if required env vars are missing)."""
    config: AppConfig = load_config(env=env)
    engine = create_db_engine(config.db_path)
    session_factory = make_session_factory(engine)
    registry = ProviderAdapterRegistry(default_haproxy_host=config.default_haproxy_host)

    app = FastAPI(
        title="Project Aegis Multi-Env SSL/TLS Compliance Tracker",
        version="1.0.0",
    )
    app.state.config = config
    app.state.session_factory = session_factory
    app.state.registry = registry

    def get_db() -> Any:
        db = session_factory()
        try:
            yield db
        finally:
            db.close()

    def verify_bearer_token(authorization: str | None = Header(default=None)) -> None:
        if not authorization or not authorization.startswith("Bearer "):
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Missing or invalid Bearer token.",
            )
        candidate = authorization[len("Bearer ") :].strip()
        if not config.api_token.matches(candidate):
            logger.warning("Unauthorized API request rejected (token=%s)", candidate)
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Invalid API token.",
            )

    @app.get("/healthz")
    def healthz() -> dict[str, Any]:
        return {
            "status": "ok",
            "service": "aegis-ssl-tracker",
            "providers": ["haproxy-edge", "private-cloud-lb", "gcp-cloud-lb"],
            "environments": ["dev", "stg", "stress-test", "preprod", "prod"],
        }

    @app.post("/api/v1/scan", dependencies=[Depends(verify_bearer_token)])
    def scan_endpoints(
        payload: ScanBatchRequest,
        db: Session = Depends(get_db),
    ) -> dict[str, Any]:
        results: list[dict[str, Any]] = []
        for target in payload.endpoints:
            adapter = registry.get(target.provider_type)
            cert_info = adapter.inspect_endpoint(target)
            record = upsert_certificate_observation(db, target, cert_info)
            results.append(record)
        return {
            "scanned_count": len(results),
            "results": results,
        }

    @app.get("/api/v1/endpoints", dependencies=[Depends(verify_bearer_token)])
    def list_endpoints(
        entity_ref: str | None = Query(default=None),
        environment: str | None = Query(default=None),
        db: Session = Depends(get_db),
    ) -> dict[str, Any]:
        stmt = select(TrackedEndpointModel)
        if entity_ref:
            stmt = stmt.where(TrackedEndpointModel.entity_ref == entity_ref)
        if environment:
            stmt = stmt.where(TrackedEndpointModel.environment == environment)
        endpoints = db.scalars(stmt).all()

        items: list[dict[str, Any]] = []
        for ep in endpoints:
            if not ep.active_serial_number:
                continue
            cert = db.get(CertificateInventoryModel, (ep.id, ep.active_serial_number))
            if cert is None:
                continue
            all_certs = db.scalars(
                select(CertificateInventoryModel).where(CertificateInventoryModel.endpoint_id == ep.id)
            ).all()
            items.append(serialize_endpoint_and_cert(ep, cert, history_count=len(all_certs)))

        return {
            "count": len(items),
            "endpoints": items,
        }

    @app.get("/api/v1/history", dependencies=[Depends(verify_bearer_token)])
    def get_certificate_history(
        entity_ref: str = Query(...),
        environment: str | None = Query(default=None),
        db: Session = Depends(get_db),
    ) -> dict[str, Any]:
        stmt = select(TrackedEndpointModel).where(TrackedEndpointModel.entity_ref == entity_ref)
        if environment:
            stmt = stmt.where(TrackedEndpointModel.environment == environment)
        endpoints = db.scalars(stmt).all()

        history: list[dict[str, Any]] = []
        for ep in endpoints:
            certs = db.scalars(
                select(CertificateInventoryModel)
                .where(CertificateInventoryModel.endpoint_id == ep.id)
                .order_by(CertificateInventoryModel.last_seen_at.desc())
            ).all()
            for c in certs:
                history.append(
                    {
                        "endpoint_id": ep.id,
                        "environment": ep.environment,
                        "endpoint_key": ep.endpoint_key,
                        "endpoint_url": ep.endpoint_url,
                        "serial_number_hex": c.serial_number_hex,
                        "not_after": c.not_after,
                        "days_remaining": c.days_remaining,
                        "subject_cn": c.subject_cn,
                        "san_dns_names": c.san_dns_names,
                        "issuer_cn": c.issuer_cn,
                        "signature_algorithm": c.signature_algorithm,
                        "public_key_algorithm": c.public_key_algorithm,
                        "public_key_bits": c.public_key_bits,
                        "compliance_status": c.compliance_status,
                        "is_active": c.is_active,
                        "rotated_from_serial": c.rotated_from_serial,
                        "last_seen_at": c.last_seen_at.isoformat(),
                    }
                )
        return {
            "entity_ref": entity_ref,
            "history_count": len(history),
            "history": history,
        }

    @app.post("/api/v1/gcp/auto-renew", dependencies=[Depends(verify_bearer_token)])
    def trigger_gcp_auto_renew(
        req: GcpAutoRenewRequest,
        db: Session = Depends(get_db),
    ) -> dict[str, Any]:
        stmt = select(TrackedEndpointModel).where(
            TrackedEndpointModel.entity_ref == req.entity_ref,
            TrackedEndpointModel.provider_type == "gcp-cloud-lb",
        )
        if req.environment != "all":
            stmt = stmt.where(TrackedEndpointModel.environment == req.environment)
        if req.endpoint_key:
            stmt = stmt.where(TrackedEndpointModel.endpoint_key == req.endpoint_key)

        matching_endpoints = db.scalars(stmt).all()
        if not matching_endpoints:
            # Create a default endpoint entry if not previously scanned
            default_env = "prod" if req.environment == "all" else req.environment
            ep_key = req.endpoint_key or "default"
            target = EndpointTargetInput(
                entity_ref=req.entity_ref,
                service_name=req.service_name,
                environment=default_env,
                endpoint_key=ep_key,
                endpoint_url=f"https://{default_env}.{req.service_name}.aegis.cloud.goog/healthz",
                provider_type="gcp-cloud-lb",
                renewal_mode="workflow-auto-renew",
                gcp_project=req.gcp_project,
                gcp_target_proxy=req.gcp_target_proxy,
            )
            initial_info = registry.gcp_adapter.inspect_endpoint(target)
            upsert_certificate_observation(db, target, initial_info)
            matching_endpoints = db.scalars(stmt).all()

        renewed_items: list[dict[str, Any]] = []
        for ep in matching_endpoints:
            previous_serial = ep.active_serial_number
            target = EndpointTargetInput(
                entity_ref=ep.entity_ref,
                service_name=ep.service_name,
                environment=ep.environment,
                endpoint_key=ep.endpoint_key,
                endpoint_url=ep.endpoint_url,
                provider_type="gcp-cloud-lb",
                renewal_mode="workflow-auto-renew",
                auto_renew_threshold_days=ep.auto_renew_threshold_days,
                gcp_project=req.gcp_project or ep.gcp_project,
                gcp_target_proxy=req.gcp_target_proxy or ep.gcp_target_proxy,
            )
            renewal_outcome = registry.gcp_adapter.mock_auto_renew_endpoint(
                target=target,
                key_algorithm=req.key_algorithm,
                validity_days=req.validity_days,
            )
            updated_record = upsert_certificate_observation(db, target, renewal_outcome["cert_info"])
            renewed_items.append(
                {
                    "endpoint_id": ep.id,
                    "environment": ep.environment,
                    "endpoint_key": ep.endpoint_key,
                    "previous_serial": previous_serial,
                    "new_serial": updated_record["certificate"]["serial_number_hex"],
                    "gcp_operation_id": renewal_outcome["gcp_operation_id"],
                    "dns_authorization": renewal_outcome["dns_authorization"],
                    "authorization_status": renewal_outcome["authorization_status"],
                    "ssl_certificate_resource": renewal_outcome["ssl_certificate_resource"],
                    "endpoint": updated_record,
                }
            )

        return {
            "status": "RENEWED",
            "entity_ref": req.entity_ref,
            "renewed_count": len(renewed_items),
            "renewals": renewed_items,
        }

    @app.get("/metrics")
    def prometheus_metrics(db: Session = Depends(get_db)) -> Response:
        lines = [
            "# HELP aegis_ssl_endpoint_expiry_days Days remaining before SSL certificate Not After expiry",
            "# TYPE aegis_ssl_endpoint_expiry_days gauge",
            "# HELP aegis_ssl_endpoint_compliant 1 if endpoint SSL certificate passes all 5 compliance pillars else 0",
            "# TYPE aegis_ssl_endpoint_compliant gauge",
            "# HELP aegis_ssl_endpoint_key_bits Public key bit length of the endpoint SSL certificate",
            "# TYPE aegis_ssl_endpoint_key_bits gauge",
        ]
        endpoints = db.scalars(select(TrackedEndpointModel)).all()
        for ep in endpoints:
            if not ep.active_serial_number:
                continue
            cert = db.get(CertificateInventoryModel, (ep.id, ep.active_serial_number))
            if not cert:
                continue
            labels = (
                f'entity="{ep.entity_ref}",service="{ep.service_name}",env="{ep.environment}",'
                f'endpoint_key="{ep.endpoint_key}",provider="{ep.provider_type}",'
                f'serial="{cert.serial_number_hex}",subject_cn="{cert.subject_cn}",'
                f'issuer_cn="{cert.issuer_cn}",sig_alg="{cert.signature_algorithm}"'
            )
            compliant_val = 1 if cert.compliance_status == "COMPLIANT" else 0
            lines.append(f"aegis_ssl_endpoint_expiry_days{{{labels}}} {cert.days_remaining}")
            lines.append(f"aegis_ssl_endpoint_compliant{{{labels}}} {compliant_val}")
            lines.append(f"aegis_ssl_endpoint_key_bits{{{labels}}} {cert.public_key_bits}")

        return Response(content="\n".join(lines) + "\n", media_type="text/plain; version=0.0.4")

    return app

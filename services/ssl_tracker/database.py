"""SQLite database persistence layer for endpoint and X.509 certificate inventory."""

from __future__ import annotations

from datetime import datetime, timezone
import json
from pathlib import Path
from typing import Any
from urllib.parse import urlparse

from sqlalchemy import create_engine, select
from sqlalchemy.engine import Engine
from sqlalchemy.orm import Session, sessionmaker

from services.ssl_tracker.models import (
    Base,
    CertificateInventoryModel,
    EndpointTargetInput,
    TrackedEndpointModel,
    serialize_endpoint_and_cert,
)


def create_db_engine(db_path: str) -> Engine:
    """Create a SQLAlchemy engine for the configured SQLite path."""
    if db_path == ":memory:":
        url = "sqlite:///:memory:"
    else:
        path_obj = Path(db_path)
        path_obj.parent.mkdir(parents=True, exist_ok=True)
        url = f"sqlite:///{path_obj}"
    engine = create_engine(url, connect_args={"check_same_thread": False})
    Base.metadata.create_all(engine)
    return engine


def make_session_factory(engine: Engine) -> sessionmaker[Session]:
    """Return a configured SQLAlchemy sessionmaker."""
    return sessionmaker(bind=engine, autoflush=False, autocommit=False, expire_on_commit=False)


def build_endpoint_id(entity_ref: str, environment: str, endpoint_key: str) -> str:
    """Build deterministic composite key supporting 1:N endpoints per environment."""
    return f"{entity_ref.strip()}:{environment.strip()}:{endpoint_key.strip()}"


def extract_hostname_from_url(endpoint_url: str) -> str:
    """Extract hostname from an HTTPS URL or host:port string."""
    parsed = urlparse(endpoint_url if "://" in endpoint_url else f"https://{endpoint_url}")
    return parsed.hostname or "localhost"


def upsert_certificate_observation(
    session: Session,
    target: EndpointTargetInput,
    cert_info: dict[str, Any],
) -> dict[str, Any]:
    """Persist an endpoint and its inspected X.509 certificate, tracking serial rotation history."""
    endpoint_id = build_endpoint_id(target.entity_ref, target.environment, target.endpoint_key)
    sni_hostname = extract_hostname_from_url(target.endpoint_url)
    now_utc = datetime.now(timezone.utc)

    ep = session.get(TrackedEndpointModel, endpoint_id)
    previous_serial: str | None = None
    if ep is None:
        ep = TrackedEndpointModel(
            id=endpoint_id,
            entity_ref=target.entity_ref,
            service_name=target.service_name,
            environment=target.environment,
            endpoint_key=target.endpoint_key,
            endpoint_url=target.endpoint_url,
            sni_hostname=sni_hostname,
            provider_type=target.provider_type,
            renewal_mode=target.renewal_mode,
            auto_renew_threshold_days=target.auto_renew_threshold_days,
            gcp_project=target.gcp_project,
            gcp_target_proxy=target.gcp_target_proxy,
            active_serial_number=cert_info["serial_number_hex"],
            last_probed_at=now_utc,
        )
        session.add(ep)
    else:
        previous_serial = ep.active_serial_number
        ep.service_name = target.service_name
        ep.endpoint_url = target.endpoint_url
        ep.sni_hostname = sni_hostname
        ep.provider_type = target.provider_type
        ep.renewal_mode = target.renewal_mode
        ep.auto_renew_threshold_days = target.auto_renew_threshold_days
        ep.gcp_project = target.gcp_project
        ep.gcp_target_proxy = target.gcp_target_proxy
        ep.last_probed_at = now_utc

    serial_hex = cert_info["serial_number_hex"]

    # If the serial changed on this endpoint, mark any older certificates on this endpoint inactive
    if previous_serial and previous_serial != serial_hex:
        existing_active = session.scalars(
            select(CertificateInventoryModel).where(
                CertificateInventoryModel.endpoint_id == endpoint_id,
                CertificateInventoryModel.is_active.is_(True),
            )
        ).all()
        for old_cert in existing_active:
            old_cert.is_active = False

    ep.active_serial_number = serial_hex

    cert_record = session.get(CertificateInventoryModel, (endpoint_id, serial_hex))
    rotated_from = (
        previous_serial
        if (previous_serial and previous_serial != serial_hex)
        else (cert_record.rotated_from_serial if cert_record else None)
    )

    if cert_record is None:
        cert_record = CertificateInventoryModel(
            endpoint_id=endpoint_id,
            serial_number_hex=serial_hex,
            serial_number_decimal=cert_info["serial_number_decimal"],
            not_before=cert_info["not_before"],
            not_after=cert_info["not_after"],
            days_remaining=cert_info["days_remaining"],
            expiry_status=cert_info["expiry_status"],
            subject_cn=cert_info["subject_cn"],
            subject_dn=cert_info["subject_dn"],
            san_dns_names_json=json.dumps(cert_info["san_dns_names"]),
            hostname_matches_san=cert_info["hostname_matches_san"],
            issuer_cn=cert_info["issuer_cn"],
            issuer_org=cert_info["issuer_org"],
            issuer_dn=cert_info["issuer_dn"],
            is_self_signed=cert_info["is_self_signed"],
            signature_algorithm=cert_info["signature_algorithm"],
            signature_hash_algorithm=cert_info["signature_hash_algorithm"],
            public_key_algorithm=cert_info["public_key_algorithm"],
            public_key_bits=cert_info["public_key_bits"],
            fingerprint_sha256=cert_info["fingerprint_sha256"],
            compliance_status=cert_info["compliance_status"],
            compliance_findings_json=json.dumps(cert_info["compliance_findings"]),
            is_active=True,
            rotated_from_serial=rotated_from,
            first_seen_at=now_utc,
            last_seen_at=now_utc,
        )
        session.add(cert_record)
    else:
        cert_record.not_before = cert_info["not_before"]
        cert_record.not_after = cert_info["not_after"]
        cert_record.days_remaining = cert_info["days_remaining"]
        cert_record.expiry_status = cert_info["expiry_status"]
        cert_record.subject_cn = cert_info["subject_cn"]
        cert_record.subject_dn = cert_info["subject_dn"]
        cert_record.san_dns_names_json = json.dumps(cert_info["san_dns_names"])
        cert_record.hostname_matches_san = cert_info["hostname_matches_san"]
        cert_record.issuer_cn = cert_info["issuer_cn"]
        cert_record.issuer_org = cert_info["issuer_org"]
        cert_record.issuer_dn = cert_info["issuer_dn"]
        cert_record.is_self_signed = cert_info["is_self_signed"]
        cert_record.signature_algorithm = cert_info["signature_algorithm"]
        cert_record.signature_hash_algorithm = cert_info["signature_hash_algorithm"]
        cert_record.public_key_algorithm = cert_info["public_key_algorithm"]
        cert_record.public_key_bits = cert_info["public_key_bits"]
        cert_record.fingerprint_sha256 = cert_info["fingerprint_sha256"]
        cert_record.compliance_status = cert_info["compliance_status"]
        cert_record.compliance_findings_json = json.dumps(cert_info["compliance_findings"])
        cert_record.is_active = True
        if rotated_from:
            cert_record.rotated_from_serial = rotated_from
        cert_record.last_seen_at = now_utc

    session.commit()

    all_certs = session.scalars(
        select(CertificateInventoryModel).where(CertificateInventoryModel.endpoint_id == endpoint_id)
    ).all()
    return serialize_endpoint_and_cert(ep, cert_record, history_count=len(all_certs))

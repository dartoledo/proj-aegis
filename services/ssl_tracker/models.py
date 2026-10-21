"""SQLAlchemy ORM models and Pydantic v2 schemas for multi-environment (1:N) SSL certificate tracking."""

from __future__ import annotations

from datetime import datetime, timezone
import json
from typing import Any

from pydantic import BaseModel, Field
from sqlalchemy import Boolean, DateTime, ForeignKey, Integer, String, Text
from sqlalchemy.orm import DeclarativeBase, Mapped, mapped_column


class Base(DeclarativeBase):
    """SQLAlchemy declarative base."""


class TrackedEndpointModel(Base):
    """Represents a single monitored endpoint within an environment (supports 1:N endpoints per env)."""

    __tablename__ = "tracked_endpoints"

    # Deterministic composite identifier: "<entity_ref>:<environment>:<endpoint_key>"
    id: Mapped[str] = mapped_column(String(255), primary_key=True)
    entity_ref: Mapped[str] = mapped_column(String(128), index=True, nullable=False)
    service_name: Mapped[str] = mapped_column(String(128), index=True, nullable=False)
    environment: Mapped[str] = mapped_column(String(32), index=True, nullable=False)
    endpoint_key: Mapped[str] = mapped_column(String(64), nullable=False, default="default")
    endpoint_url: Mapped[str] = mapped_column(String(512), nullable=False)
    sni_hostname: Mapped[str] = mapped_column(String(255), nullable=False)
    provider_type: Mapped[str] = mapped_column(String(64), nullable=False, default="private-cloud-lb")
    renewal_mode: Mapped[str] = mapped_column(String(64), nullable=False, default="self-renewing-monitored")
    auto_renew_threshold_days: Mapped[int] = mapped_column(Integer, nullable=False, default=15)
    gcp_project: Mapped[str | None] = mapped_column(String(128), nullable=True)
    gcp_target_proxy: Mapped[str | None] = mapped_column(String(128), nullable=True)
    active_serial_number: Mapped[str | None] = mapped_column(String(128), nullable=True)
    last_probed_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        default=lambda: datetime.now(timezone.utc),
        nullable=False,
    )


class CertificateInventoryModel(Base):
    """Stores X.509 certificate compliance details keyed by (endpoint_id, serial_number_hex)."""

    __tablename__ = "certificate_inventory"

    endpoint_id: Mapped[str] = mapped_column(
        String(255),
        ForeignKey("tracked_endpoints.id", ondelete="CASCADE"),
        primary_key=True,
    )
    serial_number_hex: Mapped[str] = mapped_column(String(128), primary_key=True)
    serial_number_decimal: Mapped[str] = mapped_column(String(128), nullable=False)

    # Pillar 1: Not After (Expiry Date)
    not_before: Mapped[str] = mapped_column(String(64), nullable=False)
    not_after: Mapped[str] = mapped_column(String(64), nullable=False)
    days_remaining: Mapped[int] = mapped_column(Integer, nullable=False)
    expiry_status: Mapped[str] = mapped_column(String(32), nullable=False)

    # Pillar 2: Subject (Common Name & SANs)
    subject_cn: Mapped[str] = mapped_column(String(255), nullable=False)
    subject_dn: Mapped[str] = mapped_column(String(512), nullable=False)
    san_dns_names_json: Mapped[str] = mapped_column(Text, nullable=False, default="[]")
    hostname_matches_san: Mapped[bool] = mapped_column(Boolean, nullable=False, default=True)

    # Pillar 3: Issuer
    issuer_cn: Mapped[str] = mapped_column(String(255), nullable=False)
    issuer_org: Mapped[str] = mapped_column(String(255), nullable=False)
    issuer_dn: Mapped[str] = mapped_column(String(512), nullable=False)
    is_self_signed: Mapped[bool] = mapped_column(Boolean, nullable=False, default=False)

    # Pillar 5: Signature Algorithm & Key Size
    signature_algorithm: Mapped[str] = mapped_column(String(128), nullable=False)
    signature_hash_algorithm: Mapped[str] = mapped_column(String(64), nullable=False)
    public_key_algorithm: Mapped[str] = mapped_column(String(64), nullable=False)
    public_key_bits: Mapped[int] = mapped_column(Integer, nullable=False)
    fingerprint_sha256: Mapped[str] = mapped_column(String(128), nullable=False)

    # Compliance Verdict & Rotation Lineage
    compliance_status: Mapped[str] = mapped_column(String(32), nullable=False)
    compliance_findings_json: Mapped[str] = mapped_column(Text, nullable=False, default="[]")
    is_active: Mapped[bool] = mapped_column(Boolean, nullable=False, default=True)
    rotated_from_serial: Mapped[str | None] = mapped_column(String(128), nullable=True)
    first_seen_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        default=lambda: datetime.now(timezone.utc),
        nullable=False,
    )
    last_seen_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        default=lambda: datetime.now(timezone.utc),
        nullable=False,
    )

    @property
    def san_dns_names(self) -> list[str]:
        return json.loads(self.san_dns_names_json or "[]")

    @property
    def compliance_findings(self) -> list[str]:
        return json.loads(self.compliance_findings_json or "[]")


class EndpointTargetInput(BaseModel):
    """Input descriptor for a single environment endpoint (supports 1:N endpoints per environment)."""

    entity_ref: str = Field(..., min_length=3)
    service_name: str = Field(..., min_length=1)
    environment: str = Field(..., pattern="^(dev|stg|stress-test|preprod|prod)$")
    endpoint_key: str = Field(default="default", min_length=1)
    endpoint_url: str = Field(..., min_length=8)
    provider_type: str = Field(
        default="private-cloud-lb",
        pattern="^(haproxy-edge|private-cloud-lb|gcp-cloud-lb)$",
    )
    renewal_mode: str = Field(default="self-renewing-monitored")
    auto_renew_threshold_days: int = Field(default=15, ge=1, le=90)
    gcp_project: str | None = Field(default=None)
    gcp_target_proxy: str | None = Field(default=None)
    simulate_weak_crypto: bool = Field(default=False)
    simulate_days_remaining: int | None = Field(default=None)


class ScanBatchRequest(BaseModel):
    """Request payload to scan 1:N endpoints across environments."""

    endpoints: list[EndpointTargetInput] = Field(..., min_length=1)


class GcpAutoRenewRequest(BaseModel):
    """Request payload to trigger mocked GCP Public Cloud LB auto-renewal."""

    entity_ref: str = Field(..., min_length=3)
    service_name: str = Field(..., min_length=1)
    environment: str = Field(..., pattern="^(dev|stg|stress-test|preprod|prod|all)$")
    endpoint_key: str | None = Field(default=None)
    key_algorithm: str = Field(default="ECDSA-P256", pattern="^(RSA-2048|ECDSA-P256)$")
    validity_days: int = Field(default=90, ge=1, le=398)
    gcp_project: str = Field(default="aegis-prod-cloud")
    gcp_target_proxy: str = Field(default="aegis-ui-https-proxy")


def serialize_endpoint_and_cert(
    ep: TrackedEndpointModel,
    cert: CertificateInventoryModel,
    history_count: int = 1,
) -> dict[str, Any]:
    """Serialize an endpoint and its active certificate into a structured API response."""
    return {
        "endpoint_id": ep.id,
        "entity_ref": ep.entity_ref,
        "service_name": ep.service_name,
        "environment": ep.environment,
        "endpoint_key": ep.endpoint_key,
        "endpoint_url": ep.endpoint_url,
        "sni_hostname": ep.sni_hostname,
        "provider_type": ep.provider_type,
        "renewal_mode": ep.renewal_mode,
        "auto_renew_threshold_days": ep.auto_renew_threshold_days,
        "gcp_project": ep.gcp_project,
        "gcp_target_proxy": ep.gcp_target_proxy,
        "last_probed_at": ep.last_probed_at.isoformat(),
        "certificate": {
            "serial_number_hex": cert.serial_number_hex,
            "serial_number_decimal": cert.serial_number_decimal,
            "not_before": cert.not_before,
            "not_after": cert.not_after,
            "days_remaining": cert.days_remaining,
            "expiry_status": cert.expiry_status,
            "subject_cn": cert.subject_cn,
            "subject_dn": cert.subject_dn,
            "san_dns_names": cert.san_dns_names,
            "hostname_matches_san": cert.hostname_matches_san,
            "issuer_cn": cert.issuer_cn,
            "issuer_org": cert.issuer_org,
            "issuer_dn": cert.issuer_dn,
            "is_self_signed": cert.is_self_signed,
            "signature_algorithm": cert.signature_algorithm,
            "signature_hash_algorithm": cert.signature_hash_algorithm,
            "public_key_algorithm": cert.public_key_algorithm,
            "public_key_bits": cert.public_key_bits,
            "fingerprint_sha256": cert.fingerprint_sha256,
            "compliance_status": cert.compliance_status,
            "compliance_findings": cert.compliance_findings,
            "is_active": cert.is_active,
            "rotated_from_serial": cert.rotated_from_serial,
            "history_count": history_count,
        },
    }

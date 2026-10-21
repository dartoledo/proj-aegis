"""Extensible Provider Adapter Registry and X.509 Certificate Lifecycle Engine.

Supports three distinct Load Balancer & SSL topologies across dev, stg, stress-test, preprod, prod:
1. haproxy-edge: HAProxy Runtime Socket Edge Proxy (probes live TLS socket / PEM or deterministic fallback).
2. private-cloud-lb: Private Cloud Load Balancer (F5 BIG-IP / NSX-T / Vault PKI) — Autonomous Self-Renewing, Monitored-Only.
3. gcp-cloud-lb: Google Public Cloud Load Balancer (GCP Certificate Manager + TargetHttpsProxy) — Workflow Auto-Renewal.
"""

from __future__ import annotations

from abc import ABC, abstractmethod
from datetime import datetime, timedelta, timezone
import hashlib
import socket
import ssl
from typing import Any
from urllib.parse import urlparse

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec, rsa
from cryptography.x509.oid import NameOID

from services.ssl_tracker.compliance import inspect_x509_certificate_bytes
from services.ssl_tracker.database import build_endpoint_id, extract_hostname_from_url
from services.ssl_tracker.models import EndpointTargetInput


def mint_synthetic_x509_pem(
    *,
    subject_cn: str,
    san_dns_names: list[str],
    issuer_cn: str,
    issuer_org: str,
    serial_number: int,
    not_before: datetime,
    not_after: datetime,
    key_algorithm: str = "RSA-2048",
    use_weak_sha1: bool = False,
    is_self_signed: bool = False,
) -> bytes:
    """Generate a real, cryptographically parseable X.509 certificate in PEM format."""
    if key_algorithm == "RSA-1024":
        subject_key = rsa.generate_private_key(public_exponent=65537, key_size=1024)
        issuer_key = subject_key if is_self_signed else rsa.generate_private_key(public_exponent=65537, key_size=2048)
    elif key_algorithm == "ECDSA-P256":
        subject_key = ec.generate_private_key(ec.SECP256R1())
        issuer_key = subject_key if is_self_signed else ec.generate_private_key(ec.SECP256R1())
    else:
        subject_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        issuer_key = subject_key if is_self_signed else rsa.generate_private_key(public_exponent=65537, key_size=2048)

    subject_name = x509.Name(
        [
            x509.NameAttribute(NameOID.ORGANIZATION_NAME, "Project Aegis Platform"),
            x509.NameAttribute(NameOID.COMMON_NAME, subject_cn),
        ]
    )
    issuer_name = (
        subject_name
        if is_self_signed
        else x509.Name(
            [
                x509.NameAttribute(NameOID.ORGANIZATION_NAME, issuer_org),
                x509.NameAttribute(NameOID.COMMON_NAME, issuer_cn),
            ]
        )
    )

    builder = (
        x509.CertificateBuilder()
        .subject_name(subject_name)
        .issuer_name(issuer_name)
        .public_key(subject_key.public_key())
        .serial_number(serial_number)
        .not_valid_before(not_before)
        .not_valid_after(not_after)
    )

    if san_dns_names:
        builder = builder.add_extension(
            x509.SubjectAlternativeName([x509.DNSName(name) for name in san_dns_names]),
            critical=False,
        )

    if use_weak_sha1:
        builder = builder.add_extension(
            x509.UnrecognizedExtension(
                x509.ObjectIdentifier("1.3.6.1.4.1.99999.1.1"),
                b"SIMULATED_LEGACY_SHA1_SIGNATURE",
            ),
            critical=False,
        )

    cert = builder.sign(private_key=issuer_key, algorithm=hashes.SHA256())
    return cert.public_bytes(serialization.Encoding.PEM)


def _deterministic_serial(seed_text: str) -> int:
    digest = hashlib.sha256(seed_text.encode("utf-8")).digest()[:10]
    val = int.from_bytes(digest, "big")
    return val if val > 0 else 1


def fetch_live_peer_certificate_der(
    host: str,
    port: int,
    sni_hostname: str,
    timeout_sec: float = 2.0,
) -> bytes:
    """Perform a live TLS handshake and return the peer's raw DER X.509 certificate."""
    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    with socket.create_connection((host, port), timeout=timeout_sec) as raw_sock:
        with ctx.wrap_socket(raw_sock, server_hostname=sni_hostname) as tls_sock:
            der_cert = tls_sock.getpeercert(binary_form=True)
            if not der_cert:
                raise RuntimeError(f"No peer certificate returned from {host}:{port}")
            return der_cert


class CertificateProviderAdapter(ABC):
    """Abstract base class for extensible SSL/TLS Load Balancer providers."""

    provider_type: str

    @abstractmethod
    def obtain_certificate_bytes(
        self,
        target: EndpointTargetInput,
        now: datetime | None = None,
    ) -> bytes:
        """Obtain raw PEM or DER certificate bytes for the given endpoint."""

    def inspect_endpoint(
        self,
        target: EndpointTargetInput,
        now: datetime | None = None,
    ) -> dict[str, Any]:
        """Obtain the endpoint's X.509 certificate and evaluate all 5 compliance pillars."""
        ref_now = now or datetime.now(timezone.utc)
        hostname = extract_hostname_from_url(target.endpoint_url)
        cert_bytes = self.obtain_certificate_bytes(target, now=ref_now)
        return inspect_x509_certificate_bytes(
            pem_or_der=cert_bytes,
            expected_hostname=hostname,
            environment=target.environment,
            provider_type=target.provider_type,
            renewal_mode=target.renewal_mode,
            auto_renew_threshold_days=target.auto_renew_threshold_days,
            now=ref_now,
        )


class HaproxyEdgeAdapter(CertificateProviderAdapter):
    """Adapter for HAProxy Edge Load Balancers (probes live TLS socket if reachable, else sandbox PEM)."""

    provider_type = "haproxy-edge"

    def __init__(self, default_probe_host: str = "127.0.0.1:8443") -> None:
        self._default_probe_host = default_probe_host

    def obtain_certificate_bytes(
        self,
        target: EndpointTargetInput,
        now: datetime | None = None,
    ) -> bytes:
        ref_now = now or datetime.now(timezone.utc)
        hostname = extract_hostname_from_url(target.endpoint_url)
        parsed = urlparse(target.endpoint_url if "://" in target.endpoint_url else f"https://{target.endpoint_url}")
        port = parsed.port or 8443

        if not target.simulate_weak_crypto and target.simulate_days_remaining is None:
            try:
                probe_host = self._default_probe_host.split(":")[0]
                probe_port = int(self._default_probe_host.split(":")[1]) if ":" in self._default_probe_host else port
                return fetch_live_peer_certificate_der(probe_host, probe_port, sni_hostname=hostname, timeout_sec=1.2)
            except Exception:
                pass

        days = target.simulate_days_remaining if target.simulate_days_remaining is not None else 89
        serial = _deterministic_serial(f"haproxy:{target.entity_ref}:{target.environment}:{target.endpoint_key}:{days}")
        return mint_synthetic_x509_pem(
            subject_cn=hostname,
            san_dns_names=[hostname, f"*.{hostname.split('.', 1)[-1]}"],
            issuer_cn="Aegis HAProxy Edge Root CA",
            issuer_org="Project Aegis Edge Resiliency",
            serial_number=serial,
            not_before=ref_now - timedelta(days=5),
            not_after=ref_now + timedelta(days=days, hours=12),
            key_algorithm="RSA-1024" if target.simulate_weak_crypto else "RSA-2048",
            use_weak_sha1=target.simulate_weak_crypto,
            is_self_signed=True,
        )


class PrivateCloudLbAdapter(CertificateProviderAdapter):
    """Adapter for Self-Renewing Private Cloud Load Balancers (F5 BIG-IP / NSX-T / Vault PKI).

    Monitors all 5 X.509 compliance pillars and flags SELF_RENEWAL_STALLED if remaining validity
    drops below auto_renew_threshold_days.
    """

    provider_type = "private-cloud-lb"

    def obtain_certificate_bytes(
        self,
        target: EndpointTargetInput,
        now: datetime | None = None,
    ) -> bytes:
        ref_now = now or datetime.now(timezone.utc)
        hostname = extract_hostname_from_url(target.endpoint_url)

        env_default_days = {
            "dev": 62,
            "stg": 58,
            "stress-test": 45,
            "preprod": 74,
            "prod": 82,
        }
        days = (
            target.simulate_days_remaining
            if target.simulate_days_remaining is not None
            else env_default_days.get(target.environment, 60)
        )
        serial = _deterministic_serial(
            f"private-cloud-lb:{target.entity_ref}:{target.environment}:{target.endpoint_key}:{days}:{target.simulate_weak_crypto}"
        )
        return mint_synthetic_x509_pem(
            subject_cn=hostname,
            san_dns_names=[hostname, f"*.{hostname.split('.', 1)[-1]}"],
            issuer_cn="Aegis Private Cloud Vault Intermediate CA G2",
            issuer_org="Aegis Enterprise Private PKI (Self-Renewing)",
            serial_number=serial,
            not_before=ref_now - timedelta(days=10),
            not_after=ref_now + timedelta(days=days, hours=6),
            key_algorithm="RSA-1024" if target.simulate_weak_crypto else "RSA-2048",
            use_weak_sha1=target.simulate_weak_crypto,
            is_self_signed=False,
        )


class GcpPublicCloudLbAdapter(CertificateProviderAdapter):
    """Adapter for Google Public Cloud HTTPS Load Balancers (GCP Certificate Manager + TargetHttpsProxy).

    Supports mocked automated DNS-01/HTTP-01 renewal that mints a fresh Google Trust Services (GTS CA 1C3)
    certificate with a new Serial Number and updates the active certificate cache.
    """

    provider_type = "gcp-cloud-lb"

    def __init__(self) -> None:
        self._renewed_cache: dict[str, bytes] = {}
        self._renewal_counter: dict[str, int] = {}

    def obtain_certificate_bytes(
        self,
        target: EndpointTargetInput,
        now: datetime | None = None,
    ) -> bytes:
        endpoint_id = build_endpoint_id(target.entity_ref, target.environment, target.endpoint_key)
        if endpoint_id in self._renewed_cache and not target.simulate_weak_crypto and target.simulate_days_remaining is None:
            return self._renewed_cache[endpoint_id]

        ref_now = now or datetime.now(timezone.utc)
        hostname = extract_hostname_from_url(target.endpoint_url)
        env_default_days = {
            "dev": 41,
            "stg": 36,
            "stress-test": 25,
            "preprod": 68,
            "prod": 79,
        }
        days = (
            target.simulate_days_remaining
            if target.simulate_days_remaining is not None
            else env_default_days.get(target.environment, 75)
        )
        serial = _deterministic_serial(
            f"gcp-cloud-lb:v1:{target.entity_ref}:{target.environment}:{target.endpoint_key}:{days}:{target.simulate_weak_crypto}"
        )
        return mint_synthetic_x509_pem(
            subject_cn=hostname,
            san_dns_names=[hostname, f"*.{hostname.split('.', 1)[-1]}"],
            issuer_cn="GTS CA 1C3",
            issuer_org="Google Trust Services LLC",
            serial_number=serial,
            not_before=ref_now - timedelta(days=11),
            not_after=ref_now + timedelta(days=days, hours=12),
            key_algorithm="RSA-1024" if target.simulate_weak_crypto else "ECDSA-P256",
            use_weak_sha1=target.simulate_weak_crypto,
            is_self_signed=False,
        )

    def mock_auto_renew_endpoint(
        self,
        target: EndpointTargetInput,
        key_algorithm: str = "ECDSA-P256",
        validity_days: int = 90,
        now: datetime | None = None,
    ) -> dict[str, Any]:
        """Simulate Google Certificate Manager DNS authorization, cert issuance, and TargetHttpsProxy binding."""
        ref_now = now or datetime.now(timezone.utc)
        endpoint_id = build_endpoint_id(target.entity_ref, target.environment, target.endpoint_key)
        hostname = extract_hostname_from_url(target.endpoint_url)
        gen_version = self._renewal_counter.get(endpoint_id, 1) + 1
        self._renewal_counter[endpoint_id] = gen_version

        new_serial = _deterministic_serial(
            f"gcp-cloud-lb:renewed:v{gen_version}:{endpoint_id}:{ref_now.isoformat()}:{key_algorithm}"
        )
        pem_bytes = mint_synthetic_x509_pem(
            subject_cn=hostname,
            san_dns_names=[hostname, f"*.{hostname.split('.', 1)[-1]}"],
            issuer_cn="GTS CA 1C3",
            issuer_org="Google Trust Services LLC",
            serial_number=new_serial,
            not_before=ref_now - timedelta(minutes=5),
            not_after=ref_now + timedelta(days=validity_days),
            key_algorithm=key_algorithm,
            use_weak_sha1=False,
            is_self_signed=False,
        )
        self._renewed_cache[endpoint_id] = pem_bytes
        cert_info = inspect_x509_certificate_bytes(
            pem_or_der=pem_bytes,
            expected_hostname=hostname,
            environment=target.environment,
            provider_type="gcp-cloud-lb",
            renewal_mode="workflow-auto-renew",
            auto_renew_threshold_days=target.auto_renew_threshold_days,
            now=ref_now,
        )
        return {
            "gcp_operation_id": f"operation-gcp-certmgr-{gen_version}-{new_serial % 1000000}",
            "dns_authorization": f"_acme-challenge.{hostname} CNAME auth.certificatemanager.goog.",
            "authorization_status": "AUTHORIZED",
            "gcp_project": target.gcp_project or "aegis-prod-cloud",
            "gcp_target_proxy": target.gcp_target_proxy or "aegis-ui-https-proxy",
            "ssl_certificate_resource": f"projects/{target.gcp_project or 'aegis-prod-cloud'}/locations/global/certificates/aegis-{target.service_name}-{target.environment}-{target.endpoint_key}-v{gen_version}",
            "cert_info": cert_info,
        }


class ProviderAdapterRegistry:
    """Pluggable registry mapping provider_type strings to CertificateProviderAdapter instances."""

    def __init__(self, default_haproxy_host: str = "127.0.0.1:8443") -> None:
        self._adapters: dict[str, CertificateProviderAdapter] = {}
        self.register(HaproxyEdgeAdapter(default_probe_host=default_haproxy_host))
        self.register(PrivateCloudLbAdapter())
        self.register(GcpPublicCloudLbAdapter())

    def register(self, adapter: CertificateProviderAdapter) -> None:
        self._adapters[adapter.provider_type] = adapter

    def get(self, provider_type: str) -> CertificateProviderAdapter:
        if provider_type not in self._adapters:
            raise ValueError(
                f"Unsupported SSL provider '{provider_type}'. "
                f"Registered providers: {sorted(self._adapters.keys())}"
            )
        return self._adapters[provider_type]

    @property
    def gcp_adapter(self) -> GcpPublicCloudLbAdapter:
        adapter = self._adapters["gcp-cloud-lb"]
        assert isinstance(adapter, GcpPublicCloudLbAdapter)
        return adapter

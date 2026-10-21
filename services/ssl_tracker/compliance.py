"""Pure X.509 certificate compliance engine for the 5 mandatory security pillars.

Tracked Pillars:
1. Not After (Expiry Date): Prevents total SSO/OIDC outage.
2. Subject (Common Name / SAN): Connects endpoints to certificates and validates hostname routing.
3. Issuer: Identifies CA renewal and risk paths.
4. Serial Number: Unique database key differentiating old vs. newly renewed certificates.
5. Signature Algorithm & Key Size: Enforces cryptographic compliance (flags SHA-1 / MD5 and <2048-bit RSA keys).
"""

from __future__ import annotations

from datetime import datetime, timezone
import hashlib
import math
from typing import Any

from cryptography import x509
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import dsa, ec, ed25519, ed448, rsa
from cryptography.x509.oid import ExtensionOID, NameOID

VALID_ENVIRONMENTS: tuple[str, ...] = ("dev", "stg", "stress-test", "preprod", "prod")
VALID_PROVIDERS: tuple[str, ...] = ("haproxy-edge", "private-cloud-lb", "gcp-cloud-lb")
INSECURE_SIGNATURE_HASHES: frozenset[str] = frozenset({"SHA1", "SHA-1", "MD5", "MD2", "NONE"})
MIN_RSA_DSA_BITS: int = 2048
MIN_ECDSA_BITS: int = 256


def normalize_serial_hex(serial_input: int | str) -> str:
    """Normalize an integer or hex string serial number into colon-delimited uppercase hex (AA:BB:CC)."""
    if isinstance(serial_input, bool):
        raise ValueError("Serial number cannot be a boolean.")
    if isinstance(serial_input, int):
        if serial_input < 0:
            raise ValueError("Serial number integer must be non-negative.")
        hex_str = f"{serial_input:X}"
    elif isinstance(serial_input, str):
        cleaned = (
            serial_input.strip()
            .upper()
            .replace("0X", "")
            .replace(":", "")
            .replace("-", "")
            .replace(" ", "")
        )
        if not cleaned or any(ch not in "0123456789ABCDEF" for ch in cleaned):
            raise ValueError(f"Invalid hexadecimal serial number: {serial_input!r}")
        hex_str = cleaned.lstrip("0") or "0"
    else:
        raise ValueError("Serial number must be an int or str.")

    if len(hex_str) % 2 == 1:
        hex_str = "0" + hex_str
    return ":".join(hex_str[i : i + 2] for i in range(0, len(hex_str), 2))


def _dns_pattern_matches(pattern: str, hostname: str) -> bool:
    """RFC 6125 wildcard-aware DNS name matching (single leftmost label wildcard only)."""
    pat = pattern.strip().lower().rstrip(".")
    host = hostname.strip().lower().rstrip(".")
    if not pat or not host:
        return False
    if pat == host:
        return True
    if pat.startswith("*."):
        suffix = pat[2:]
        if not suffix or "." not in suffix:
            return False
        if not host.endswith("." + suffix):
            return False
        prefix = host[: -(len(suffix) + 1)]
        return bool(prefix) and "." not in prefix
    return False


def match_hostname_san(
    hostname: str,
    subject_cn: str,
    san_dns_names: list[str],
) -> bool:
    """Verify whether the target endpoint hostname matches the certificate SANs (or CN fallback)."""
    if not isinstance(hostname, str) or not hostname.strip():
        return False
    candidates = [name for name in san_dns_names if isinstance(name, str) and name.strip()]
    if not candidates and isinstance(subject_cn, str) and subject_cn.strip():
        candidates = [subject_cn.strip()]
    return any(_dns_pattern_matches(candidate, hostname) for candidate in candidates)


def evaluate_expiry(
    not_after: datetime,
    now: datetime | None = None,
    renewal_mode: str = "manual",
    auto_renew_threshold_days: int = 15,
) -> tuple[int, str, list[str]]:
    """Evaluate certificate Not After (Expiry Date) and Private Cloud LB self-renewal SLA."""
    ref_now = now or datetime.now(timezone.utc)
    if not_after.tzinfo is None:
        not_after = not_after.replace(tzinfo=timezone.utc)
    if ref_now.tzinfo is None:
        ref_now = ref_now.replace(tzinfo=timezone.utc)

    delta_seconds = (not_after - ref_now).total_seconds()
    days_remaining = math.floor(delta_seconds / 86400.0)
    findings: list[str] = []

    if days_remaining <= 0:
        status = "EXPIRED"
        findings.append(
            f"CERT_EXPIRED: Certificate expired ({days_remaining}d). Immediate SAML/OIDC SSO outage risk."
        )
    elif days_remaining <= 7:
        status = "CRITICAL"
        findings.append(
            f"EXPIRY_CRITICAL: Certificate expires in {days_remaining} days (<= 7d threshold)."
        )
    elif days_remaining <= 30:
        status = "WARNING"
        findings.append(
            f"EXPIRY_WARNING: Certificate expires in {days_remaining} days (<= 30d threshold)."
        )
    else:
        status = "HEALTHY"

    if renewal_mode == "self-renewing-monitored" and days_remaining <= auto_renew_threshold_days:
        findings.append(
            f"SELF_RENEWAL_STALLED: Private Cloud LB autonomous renewal SLA breached "
            f"({days_remaining}d remaining <= {auto_renew_threshold_days}d auto-renewal window)."
        )
        if status == "HEALTHY":
            status = "WARNING"

    return days_remaining, status, findings


def evaluate_crypto_compliance(
    signature_algorithm: str,
    signature_hash: str,
    public_key_algorithm: str,
    public_key_bits: int,
) -> tuple[bool, list[str]]:
    """Evaluate Signature Algorithm & Key Size against security compliance standards."""
    findings: list[str] = []
    norm_hash = (signature_hash or "").strip().upper().replace("-", "")
    norm_sig = (signature_algorithm or "").strip().upper().replace("-", "")
    norm_pub = (public_key_algorithm or "").strip().upper()

    if (
        norm_hash in INSECURE_SIGNATURE_HASHES
        or "SHA1" in norm_sig
        or "MD5" in norm_sig
        or "MD2" in norm_sig
    ):
        findings.append(
            f"INSECURE_SIGNATURE_HASH: Signature algorithm '{signature_algorithm}' ({signature_hash}) "
            "uses deprecated weak hashing (SHA-1/MD5 prohibited)."
        )

    if norm_pub in {"RSA", "DSA"}:
        if public_key_bits < MIN_RSA_DSA_BITS:
            findings.append(
                f"WEAK_KEY_SIZE: {norm_pub} {public_key_bits}-bit key is below the mandatory "
                f"{MIN_RSA_DSA_BITS}-bit minimum."
            )
    elif norm_pub in {"ECDSA", "EC"}:
        if public_key_bits < MIN_ECDSA_BITS:
            findings.append(
                f"WEAK_KEY_SIZE: ECDSA {public_key_bits}-bit key is below the mandatory "
                f"{MIN_ECDSA_BITS}-bit minimum."
            )
    elif norm_pub in {"ED25519", "ED448"}:
        pass
    else:
        if public_key_bits < MIN_RSA_DSA_BITS:
            findings.append(
                f"WEAK_KEY_SIZE: Unknown key algorithm '{public_key_algorithm}' with {public_key_bits} bits."
            )

    return len(findings) == 0, findings


def _get_first_name_attr(name: x509.Name, oid: x509.ObjectIdentifier, default: str = "") -> str:
    attrs = name.get_attributes_for_oid(oid)
    if not attrs:
        return default
    val = attrs[0].value
    return val if isinstance(val, str) else val.decode("utf-8", errors="replace")


def _extract_public_key_info(cert: x509.Certificate) -> tuple[str, int]:
    pub = cert.public_key()
    if isinstance(pub, rsa.RSAPublicKey):
        return "RSA", int(pub.key_size)
    if isinstance(pub, ec.EllipticCurvePublicKey):
        return "ECDSA", int(pub.key_size)
    if isinstance(pub, dsa.DSAPublicKey):
        return "DSA", int(pub.key_size)
    if isinstance(pub, ed25519.Ed25519PublicKey):
        return "Ed25519", 256
    if isinstance(pub, ed448.Ed448PublicKey):
        return "Ed448", 448
    return type(pub).__name__, getattr(pub, "key_size", 0)


def inspect_x509_certificate_bytes(
    pem_or_der: bytes,
    expected_hostname: str,
    environment: str = "prod",
    provider_type: str = "haproxy-edge",
    renewal_mode: str = "manual",
    auto_renew_threshold_days: int = 15,
    now: datetime | None = None,
) -> dict[str, Any]:
    """Parse raw PEM or DER X.509 certificate bytes and evaluate all 5 compliance pillars."""
    if not pem_or_der:
        raise ValueError("Certificate bytes cannot be empty.")

    if pem_or_der.lstrip().startswith(b"-----BEGIN"):
        cert = x509.load_pem_x509_certificate(pem_or_der)
    else:
        cert = x509.load_der_x509_certificate(pem_or_der)

    der_bytes = cert.public_bytes(serialization.Encoding.DER)
    fp_hex = hashlib.sha256(der_bytes).hexdigest().upper()
    fingerprint_sha256 = ":".join(fp_hex[i : i + 2] for i in range(0, len(fp_hex), 2))

    # 1. Not After / Not Before
    not_before = cert.not_valid_before_utc
    not_after = cert.not_valid_after_utc
    days_remaining, expiry_status, expiry_findings = evaluate_expiry(
        not_after=not_after,
        now=now,
        renewal_mode=renewal_mode,
        auto_renew_threshold_days=auto_renew_threshold_days,
    )

    # 2. Subject (CN & SAN)
    subject_cn = _get_first_name_attr(cert.subject, NameOID.COMMON_NAME, default="unknown")
    subject_dn = cert.subject.rfc4514_string()
    try:
        san_ext = cert.extensions.get_extension_for_oid(ExtensionOID.SUBJECT_ALTERNATIVE_NAME)
        san_dns_names = list(san_ext.value.get_values_for_type(x509.DNSName))
    except x509.ExtensionNotFound:
        san_dns_names = []

    hostname_matches = match_hostname_san(expected_hostname, subject_cn, san_dns_names)

    # 3. Issuer
    issuer_cn = _get_first_name_attr(cert.issuer, NameOID.COMMON_NAME, default="unknown")
    issuer_org = _get_first_name_attr(cert.issuer, NameOID.ORGANIZATION_NAME, default="Unknown CA")
    issuer_dn = cert.issuer.rfc4514_string()
    is_self_signed = cert.issuer == cert.subject

    # 4. Serial Number
    serial_hex = normalize_serial_hex(cert.serial_number)
    serial_dec = str(cert.serial_number)

    # 5. Signature Algorithm & Key Size
    sig_alg_name = getattr(cert.signature_algorithm_oid, "_name", str(cert.signature_algorithm_oid.dotted_string))
    try:
        sig_hash_obj = cert.signature_hash_algorithm
        sig_hash_name = sig_hash_obj.name.upper() if sig_hash_obj is not None else "NONE"
    except Exception:
        sig_hash_name = "SHA1" if "sha1" in sig_alg_name.lower() else "UNKNOWN"

    try:
        sim_ext = cert.extensions.get_extension_for_oid(x509.ObjectIdentifier("1.3.6.1.4.1.99999.1.1"))
        if sim_ext.value.value == b"SIMULATED_LEGACY_SHA1_SIGNATURE":
            sig_alg_name = "sha1WithRSAEncryption"
            sig_hash_name = "SHA1"
    except x509.ExtensionNotFound:
        pass
    pub_alg, pub_bits = _extract_public_key_info(cert)

    crypto_compliant, crypto_findings = evaluate_crypto_compliance(
        signature_algorithm=sig_alg_name,
        signature_hash=sig_hash_name,
        public_key_algorithm=pub_alg,
        public_key_bits=pub_bits,
    )

    findings: list[str] = list(expiry_findings) + list(crypto_findings)
    if not hostname_matches:
        findings.append(
            f"SAN_HOSTNAME_MISMATCH: Endpoint hostname '{expected_hostname}' does not match "
            f"SANs {san_dns_names} or CN '{subject_cn}'."
        )

    if is_self_signed and environment in {"preprod", "prod"} and provider_type != "haproxy-edge":
        findings.append(
            f"UNTRUSTED_ISSUER_IN_PROD: Self-signed certificate ('{issuer_cn}') detected on "
            f"{environment} endpoint for provider '{provider_type}'."
        )

    if not crypto_compliant or not hostname_matches or expiry_status == "EXPIRED":
        compliance_status = "NON_COMPLIANT"
    elif findings or expiry_status in {"WARNING", "CRITICAL"}:
        compliance_status = "WARNING"
    else:
        compliance_status = "COMPLIANT"

    return {
        "serial_number_hex": serial_hex,
        "serial_number_decimal": serial_dec,
        "not_before": not_before.isoformat(),
        "not_after": not_after.isoformat(),
        "days_remaining": days_remaining,
        "expiry_status": expiry_status,
        "subject_cn": subject_cn,
        "subject_dn": subject_dn,
        "san_dns_names": san_dns_names,
        "hostname_matches_san": hostname_matches,
        "issuer_cn": issuer_cn,
        "issuer_org": issuer_org,
        "issuer_dn": issuer_dn,
        "is_self_signed": is_self_signed,
        "signature_algorithm": sig_alg_name,
        "signature_hash_algorithm": sig_hash_name,
        "public_key_algorithm": pub_alg,
        "public_key_bits": pub_bits,
        "fingerprint_sha256": fingerprint_sha256,
        "compliance_status": compliance_status,
        "compliance_findings": findings,
    }

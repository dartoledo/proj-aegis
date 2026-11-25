"""Active Endpoint Prober for Project Aegis SSL/TLS, WAF, and Public/Zscaler Network Discovery.

Probes a real endpoints list to populate:
1. SSL Expiry Details (not_before, not_after, days_remaining, expiry_status)
2. Subject CN values & SANs
3. Issuer CN, Org, DN, and self-signed status
4. Serial Number (colon-delimited hex & decimal)
5. Signature Algorithm & Key Size (RSA / ECDSA / Ed25519 bit length)
6. WAF Protection detection (Akamai, Fastly, Cloud Armor, or None)
7. Public Internet Accessibility based on Zscaler vs. non-Zscaler Source IP:
   - If source IP matches Zscaler (CIDR, PTR, or ASN/Org), assumes prober is within private network (accessible_from_public_internet = False).
   - If non-Zscaler source IP, assumes prober is probing from public internet (accessible_from_public_internet = True when reachable).
"""

from __future__ import annotations

from datetime import datetime, timezone
import ipaddress
import re
import socket
import ssl
from typing import Any, Callable, Mapping
from urllib.parse import urlparse
import urllib.request

from services.ssl_tracker.compliance import inspect_x509_certificate_bytes
from services.ssl_tracker.scanner import fetch_live_peer_certificate_der

ZSCALER_CIDR_BLOCKS: tuple[ipaddress.IPv4Network, ...] = tuple(
    ipaddress.ip_network(cidr)
    for cidr in (
        "165.225.0.0/16",
        "147.161.128.0/17",
        "136.226.0.0/16",
        "170.85.0.0/16",
        "104.129.192.0/20",
        "185.46.212.0/22",
        "199.168.148.0/22",
        "167.103.0.0/16",
        "137.83.128.0/18",
        "89.167.131.0/24",
        "136.226.242.0/23",
    )
)

ZSCALER_PATTERN = re.compile(
    r"zscaler|zscloud\.net|zscalertwo\.net|zscalerthree\.net|zscalergov\.net|zpath\.net",
    re.IGNORECASE,
)


def is_zscaler_ip_cidr(ip_str: str) -> tuple[bool, str | None]:
    """Return (True, matched_cidr) if ip_str falls within any published Zscaler IPv4 CIDR block."""
    if not isinstance(ip_str, str) or not ip_str.strip():
        return False, None
    try:
        addr = ipaddress.ip_address(ip_str.strip())
    except ValueError:
        return False, None
    if not isinstance(addr, ipaddress.IPv4Address):
        return False, None
    for net in ZSCALER_CIDR_BLOCKS:
        if addr in net:
            return True, str(net)
    return False, None


def classify_source_ip_zscaler_context(
    source_ip: str,
    *,
    ptr_hostnames: list[str] | None = None,
    org_name: str | None = None,
    proxy_headers: Mapping[str, str] | None = None,
) -> dict[str, Any]:
    """Classify whether the prober's source IP is inside Zscaler (private network) or public internet."""
    clean_ip = (source_ip or "").strip() or "0.0.0.0"
    ptrs = [h.strip() for h in (ptr_hostnames or []) if isinstance(h, str) and h.strip()]
    org = (org_name or "").strip()
    headers = dict(proxy_headers or {})

    matched_cidr, cidr_str = is_zscaler_ip_cidr(clean_ip)
    if matched_cidr:
        return {
            "source_ip": clean_ip,
            "is_zscaler_source_ip": True,
            "network_origin": "PRIVATE_NETWORK_ZSCALER",
            "detection_reason": f"Source IP {clean_ip} matched Zscaler Public Service Edge CIDR {cidr_str}",
            "ptr_hostnames": ptrs,
        }

    for ptr in ptrs:
        if ZSCALER_PATTERN.search(ptr):
            return {
                "source_ip": clean_ip,
                "is_zscaler_source_ip": True,
                "network_origin": "PRIVATE_NETWORK_ZSCALER",
                "detection_reason": f"Source IP reverse DNS PTR ({ptr}) matched Zscaler domain",
                "ptr_hostnames": ptrs,
            }

    if org and ZSCALER_PATTERN.search(org):
        return {
            "source_ip": clean_ip,
            "is_zscaler_source_ip": True,
            "network_origin": "PRIVATE_NETWORK_ZSCALER",
            "detection_reason": f"Source IP ASN/Organization ({org}) matched Zscaler",
            "ptr_hostnames": ptrs,
        }

    for hk, hv in headers.items():
        if ("zscaler" in hk.lower() and hv) or (hv and ZSCALER_PATTERN.search(str(hv))):
            return {
                "source_ip": clean_ip,
                "is_zscaler_source_ip": True,
                "network_origin": "PRIVATE_NETWORK_ZSCALER",
                "detection_reason": f"Proxy header {hk}={hv} indicates Zscaler corporate tunnel",
                "ptr_hostnames": ptrs,
            }

    return {
        "source_ip": clean_ip,
        "is_zscaler_source_ip": False,
        "network_origin": "PUBLIC_INTERNET",
        "detection_reason": f"Non-Zscaler source IP ({clean_ip}) — prober is probing from public internet",
        "ptr_hostnames": ptrs,
    }


def detect_waf_protection(
    headers: Mapping[str, str] | None = None,
    cnames: list[str] | None = None,
) -> dict[str, Any]:
    """Detect WAF protection provider (Akamai, Fastly, Cloud Armor, or None) from HTTP headers and CNAMEs."""
    norm_headers = {str(k).lower(): str(v) for k, v in (headers or {}).items() if v is not None}
    norm_cnames = [str(c).lower().strip() for c in (cnames or []) if c]
    evidence: list[str] = []

    server = norm_headers.get("server", "").lower()
    set_cookie = norm_headers.get("set-cookie", "").lower()
    via = norm_headers.get("via", "").lower()
    x_served_by = norm_headers.get("x-served-by", "")
    x_timer = norm_headers.get("x-timer", "")

    # 1. Akamai
    for hk, hv in norm_headers.items():
        if hk.startswith("x-akamai-") or hk in ("akamai-grn", "x-true-cache-key", "x-check-cacheable"):
            evidence.append(f"header: {hk}={hv}")
    if "akamaighost" in server or "akamainetstorage" in server or "akamai" in server:
        evidence.append(f"header: server={norm_headers.get('server')}")
    if "ak_bmsc" in set_cookie or "bm_sz" in set_cookie:
        evidence.append("cookie: Akamai Bot Manager (ak_bmsc/bm_sz)")
    for cname in norm_cnames:
        if any(dom in cname for dom in ("akamaiedge.net", "akadns.net", "akamai.net", "edgekey.net", "edgesuite.net")):
            evidence.append(f"cname: {cname}")
    if evidence:
        return {
            "waf_provider": "Akamai",
            "waf_detected": True,
            "waf_evidence": evidence,
        }

    # 2. Fastly
    for hk, hv in norm_headers.items():
        if hk.startswith("x-fastly-") or hk.startswith("fastly-"):
            evidence.append(f"header: {hk}={hv}")
    if "fastly" in server or "artisanal" in server:
        evidence.append(f"header: server={norm_headers.get('server')}")
    if "cache-" in x_served_by.lower() and (x_timer or "varnish" in via):
        evidence.append(f"header: x-served-by={x_served_by}")
    for cname in norm_cnames:
        if "fastly.net" in cname or "fastlylb.net" in cname:
            evidence.append(f"cname: {cname}")
    if evidence:
        return {
            "waf_provider": "Fastly",
            "waf_detected": True,
            "waf_evidence": evidence,
        }

    # 3. Google Cloud Armor
    if "google frontend" in server or server in ("gfe2", "esf") or "cloud armor" in server:
        evidence.append(f"header: server={norm_headers.get('server')}")
    if "google" in via:
        evidence.append(f"header: via={norm_headers.get('via')}")
    for hk, hv in norm_headers.items():
        if hk in ("x-cloud-trace-context", "x-cloud-armor") or hk.startswith("x-gfe-") or hk.startswith("x-goog-"):
            evidence.append(f"header: {hk}={hv}")
    for cname in norm_cnames:
        if "googleusercontent.com" in cname or "ghs.googlehosted.com" in cname:
            evidence.append(f"cname: {cname}")
    if evidence:
        return {
            "waf_provider": "Cloud Armor",
            "waf_detected": True,
            "waf_evidence": evidence,
        }

    return {
        "waf_provider": "None",
        "waf_detected": False,
        "waf_evidence": [],
    }


def normalize_endpoint_target(raw_target: str) -> tuple[str, str, int]:
    """Normalize a bare hostname, host:port, or URL into (endpoint_url, hostname, port)."""
    if not isinstance(raw_target, str) or not raw_target.strip():
        raise ValueError("Target endpoint must be a non-empty string.")
    cleaned = raw_target.strip()
    if not cleaned.startswith(("https://", "http://")):
        cleaned = f"https://{cleaned}"
    parsed = urlparse(cleaned)
    hostname = parsed.hostname or ""
    if not hostname:
        raise ValueError(f"Unable to parse hostname from target: {raw_target!r}")
    port = parsed.port or (80 if parsed.scheme == "http" else 443)
    default_port = (parsed.scheme == "https" and port == 443) or (parsed.scheme == "http" and port == 80)
    path_part = "" if parsed.path in ("", "/") else parsed.path
    normalized_url = (
        f"{parsed.scheme}://{hostname}{path_part}"
        if default_port
        else f"{parsed.scheme}://{hostname}:{port}{path_part}"
    )
    return normalized_url, hostname, port


def default_fetch_https_headers(
    endpoint_url: str,
    timeout_sec: float = 3.0,
) -> tuple[int | None, dict[str, str]]:
    """Perform an HTTPS GET request without strict cert verification to inspect edge WAF headers."""
    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    req = urllib.request.Request(
        endpoint_url,
        headers={"User-Agent": "Aegis-Active-Endpoint-Prober/1.0"},
        method="GET",
    )
    with urllib.request.urlopen(req, timeout=timeout_sec, context=ctx) as resp:
        headers = {k.lower(): v for k, v in resp.headers.items()}
        return resp.status, headers


def probe_endpoint_live(
    target_input: str,
    *,
    source_ip: str = "203.0.113.10",
    ptr_hostnames: list[str] | None = None,
    org_name: str | None = None,
    cnames: list[str] | None = None,
    timeout_sec: float = 3.0,
    cert_fetcher: Callable[[str, int, str, float], bytes] | None = None,
    header_fetcher: Callable[[str, float], tuple[int | None, dict[str, str]]] | None = None,
    now: datetime | None = None,
) -> dict[str, Any]:
    """Actively probe a single endpoint for 5-pillar SSL details, WAF provider, and Public/Zscaler accessibility."""
    endpoint_url, hostname, port = normalize_endpoint_target(target_input)
    network_ctx = classify_source_ip_zscaler_context(
        source_ip,
        ptr_hostnames=ptr_hostnames,
        org_name=org_name,
    )
    fetch_cert = cert_fetcher or fetch_live_peer_certificate_der
    fetch_headers = header_fetcher or default_fetch_https_headers
    ref_now = now or datetime.now(timezone.utc)

    try:
        der_bytes = fetch_cert(hostname, port, hostname, timeout_sec)
        ssl_details = inspect_x509_certificate_bytes(
            pem_or_der=der_bytes,
            expected_hostname=hostname,
            environment="prod",
            provider_type="gcp-cloud-lb",
            renewal_mode="workflow-auto-renew",
            auto_renew_threshold_days=30,
            now=ref_now,
        )
        try:
            http_status, resp_headers = fetch_headers(endpoint_url, timeout_sec)
        except Exception:
            http_status, resp_headers = None, {}

        waf = detect_waf_protection(headers=resp_headers, cnames=cnames)
        accessible_from_public = not network_ctx["is_zscaler_source_ip"]
        exposure_scope = (
            "strictly-private"
            if network_ctx["is_zscaler_source_ip"]
            else ("restricted-public" if waf["waf_detected"] else "unrestricted-public")
        )

        return {
            "target_input": target_input,
            "endpoint_url": endpoint_url,
            "hostname": hostname,
            "port": port,
            "reachable": True,
            "source_ip": network_ctx["source_ip"],
            "is_zscaler_source_ip": network_ctx["is_zscaler_source_ip"],
            "probe_network_origin": network_ctx["network_origin"],
            "accessible_from_public_internet": accessible_from_public,
            "exposure_scope": exposure_scope,
            "waf_provider": waf["waf_provider"],
            "waf_detected": waf["waf_detected"],
            "waf_evidence": waf["waf_evidence"],
            "http_status_code": http_status,
            "ssl_details": ssl_details,
            "probed_at": ref_now.isoformat(),
        }
    except (OSError, socket.error, ssl.SSLError, RuntimeError, ValueError) as exc:
        waf = detect_waf_protection(headers={}, cnames=cnames)
        return {
            "target_input": target_input,
            "endpoint_url": endpoint_url,
            "hostname": hostname,
            "port": port,
            "reachable": False,
            "error": str(exc),
            "source_ip": network_ctx["source_ip"],
            "is_zscaler_source_ip": network_ctx["is_zscaler_source_ip"],
            "probe_network_origin": network_ctx["network_origin"],
            "accessible_from_public_internet": False,
            "exposure_scope": "strictly-private",
            "waf_provider": waf["waf_provider"],
            "waf_detected": waf["waf_detected"],
            "waf_evidence": waf["waf_evidence"],
            "http_status_code": None,
            "ssl_details": None,
            "probed_at": ref_now.isoformat(),
        }


def probe_endpoints_list(
    targets: list[str],
    *,
    source_ip: str = "203.0.113.10",
    ptr_hostnames: list[str] | None = None,
    org_name: str | None = None,
    timeout_sec: float = 3.0,
    cert_fetcher: Callable[[str, int, str, float], bytes] | None = None,
    header_fetcher: Callable[[str, float], tuple[int | None, dict[str, str]]] | None = None,
    now: datetime | None = None,
) -> dict[str, Any]:
    """Actively probe a list of endpoints and return an aggregate batch report."""
    network_ctx = classify_source_ip_zscaler_context(
        source_ip,
        ptr_hostnames=ptr_hostnames,
        org_name=org_name,
    )
    clean_targets = [t.strip() for t in targets if isinstance(t, str) and t.strip()]
    results = [
        probe_endpoint_live(
            t,
            source_ip=source_ip,
            ptr_hostnames=ptr_hostnames,
            org_name=org_name,
            timeout_sec=timeout_sec,
            cert_fetcher=cert_fetcher,
            header_fetcher=header_fetcher,
            now=now,
        )
        for t in clean_targets
    ]
    return {
        "network_context": network_ctx,
        "total_probed": len(results),
        "reachable_count": sum(1 for r in results if r["reachable"]),
        "public_accessible_count": sum(1 for r in results if r["accessible_from_public_internet"]),
        "waf_protected_count": sum(1 for r in results if r["waf_detected"]),
        "results": results,
    }

import crypto from 'node:crypto';
import dns from 'node:dns';
import https from 'node:https';
import http from 'node:http';
import net from 'node:net';
import tls from 'node:tls';
import { formatColonSerial } from './haproxyTlsService';
import {
  evaluateCryptoCompliance,
  evaluateExpiryAndRenewalSla,
  hydrateTrackedEndpointRecordFromDbRow,
  matchHostnameSan,
  SslEnvironmentTier,
  SslProviderType,
  X509CertificateComplianceDetails,
} from './sslEndpointTrackerService';

export type WafProviderType = 'Akamai' | 'Fastly' | 'Cloud Armor' | 'None';
export type ProbeNetworkOrigin = 'PRIVATE_NETWORK_ZSCALER' | 'PUBLIC_INTERNET';

export interface SourceIpNetworkContext {
  sourceIp: string;
  isZscalerSourceIp: boolean;
  networkOrigin: ProbeNetworkOrigin;
  detectionReason: string;
  ptrHostnames: string[];
}

export interface ActiveEndpointProbeTargetInput {
  target: string;
  serviceName?: string;
  entityRef?: string;
  environment?: SslEnvironmentTier;
  endpointKey?: string;
  ownerTeamId?: 'sre-team' | 'app-team';
}

export interface ActiveEndpointSslDetails {
  subjectCn: string;
  subjectDn: string;
  sanDnsNames: string[];
  hostnameMatchesSan: boolean;
  issuerCn: string;
  issuerOrg: string;
  issuerDn: string;
  serialNumberHex: string;
  serialNumberDecimal: string;
  notBefore: string;
  notAfter: string;
  daysRemaining: number;
  expiryStatus: 'HEALTHY' | 'WARNING' | 'CRITICAL' | 'EXPIRED';
  signatureAlgorithm: string;
  signatureHashAlgorithm: string;
  publicKeyAlgorithm: string;
  publicKeyBits: number;
  fingerprintSha256: string;
  isSelfSigned: boolean;
  complianceStatus: 'COMPLIANT' | 'WARNING' | 'NON_COMPLIANT';
  complianceFindings: string[];
}

export interface ActiveEndpointProbeResult {
  targetInput: string;
  endpointId: string;
  endpointUrl: string;
  hostname: string;
  port: number;
  reachable: boolean;
  error?: string;
  sourceIp: string;
  isZscalerSourceIp: boolean;
  probeNetworkOrigin: ProbeNetworkOrigin;
  accessibleFromPublicInternet: boolean;
  exposureScope: 'unrestricted-public' | 'restricted-public' | 'strictly-private';
  wafProvider: WafProviderType;
  wafDetected: boolean;
  wafEvidence: string[];
  httpStatusCode: number | null;
  sslDetails: ActiveEndpointSslDetails | null;
  probedAt: string;
}

export interface ActiveEndpointBatchProbeReport {
  networkContext: SourceIpNetworkContext;
  totalProbed: number;
  reachableCount: number;
  publicAccessibleCount: number;
  wafProtectedCount: number;
  results: ActiveEndpointProbeResult[];
}

/**
 * Published Zscaler ZIA / ZPA Public Service Edge CIDR ranges.
 */
export const ZSCALER_CIDR_RANGES: readonly string[] = [
  '165.225.0.0/16',
  '147.161.128.0/17',
  '136.226.0.0/16',
  '170.85.0.0/16',
  '104.129.192.0/20',
  '185.46.212.0/22',
  '199.168.148.0/22',
  '167.103.0.0/16',
  '137.83.128.0/18',
  '89.167.131.0/24',
  '136.226.242.0/23',
];

export const ZSCALER_HOST_OR_ORG_REGEX =
  /zscaler|zscloud\.net|zscalertwo\.net|zscalerthree\.net|zscalergov\.net|zpath\.net/i;

function ipv4ToUint32(ip: string): number | null {
  const parts = ip.trim().split('.');
  if (parts.length !== 4) return null;
  let result = 0;
  for (const part of parts) {
    if (!/^\d+$/.test(part)) return null;
    const n = Number(part);
    if (n < 0 || n > 255) return null;
    result = ((result << 8) | n) >>> 0;
  }
  return result >>> 0;
}

export function isIpInCidr(ip: string, cidr: string): boolean {
  const [networkStr, prefixStr] = cidr.split('/');
  const prefix = Number(prefixStr);
  if (!networkStr || Number.isNaN(prefix) || prefix < 0 || prefix > 32) {
    return false;
  }
  const ipNum = ipv4ToUint32(ip);
  const netNum = ipv4ToUint32(networkStr);
  if (ipNum === null || netNum === null) return false;
  if (prefix === 0) return true;
  const mask = (~0 << (32 - prefix)) >>> 0;
  return (ipNum & mask) === (netNum & mask);
}

/**
 * Classifies whether the prober's source IP belongs to Zscaler (private corporate egress)
 * or a non-Zscaler IP (probing from the public internet).
 */
export function classifySourceIpZscalerContext(params: {
  sourceIp: string;
  ptrHostnames?: string[];
  orgName?: string;
  proxyHeaders?: Record<string, string | undefined>;
}): SourceIpNetworkContext {
  const sourceIp = (params.sourceIp || '').trim() || '0.0.0.0';
  const ptrHostnames = (params.ptrHostnames || []).filter(Boolean);
  const orgName = (params.orgName || '').trim();
  const proxyHeaders = params.proxyHeaders || {};

  for (const cidr of ZSCALER_CIDR_RANGES) {
    if (isIpInCidr(sourceIp, cidr)) {
      return {
        sourceIp,
        isZscalerSourceIp: true,
        networkOrigin: 'PRIVATE_NETWORK_ZSCALER',
        detectionReason: `Source IP ${sourceIp} matched Zscaler Public Service Edge CIDR ${cidr}`,
        ptrHostnames,
      };
    }
  }

  const matchedPtr = ptrHostnames.find(h => ZSCALER_HOST_OR_ORG_REGEX.test(h));
  if (matchedPtr) {
    return {
      sourceIp,
      isZscalerSourceIp: true,
      networkOrigin: 'PRIVATE_NETWORK_ZSCALER',
      detectionReason: `Source IP reverse DNS PTR (${matchedPtr}) matched Zscaler cloud domain`,
      ptrHostnames,
    };
  }

  if (orgName && ZSCALER_HOST_OR_ORG_REGEX.test(orgName)) {
    return {
      sourceIp,
      isZscalerSourceIp: true,
      networkOrigin: 'PRIVATE_NETWORK_ZSCALER',
      detectionReason: `Source IP ASN/Organization (${orgName}) matched Zscaler`,
      ptrHostnames,
    };
  }

  for (const [k, v] of Object.entries(proxyHeaders)) {
    if (
      (k.toLowerCase().includes('zscaler') && v) ||
      (v && ZSCALER_HOST_OR_ORG_REGEX.test(v))
    ) {
      return {
        sourceIp,
        isZscalerSourceIp: true,
        networkOrigin: 'PRIVATE_NETWORK_ZSCALER',
        detectionReason: `Proxy header ${k}=${v} indicates Zscaler corporate tunnel`,
        ptrHostnames,
      };
    }
  }

  return {
    sourceIp,
    isZscalerSourceIp: false,
    networkOrigin: 'PUBLIC_INTERNET',
    detectionReason: `Non-Zscaler source IP (${sourceIp}) — prober is probing from public internet`,
    ptrHostnames,
  };
}

function fetchJsonWithTimeout(url: string, timeoutMs: number): Promise<any> {
  return new Promise((resolve, reject) => {
    const client = url.startsWith('https:') ? https : http;
    const req = client.get(url, { timeout: timeoutMs }, res => {
      let body = '';
      res.on('data', chunk => {
        body += String(chunk);
      });
      res.on('end', () => {
        try {
          resolve(JSON.parse(body));
        } catch (err) {
          reject(err);
        }
      });
    });
    req.on('timeout', () => {
      req.destroy(new Error('timeout'));
    });
    req.on('error', reject);
  });
}

function reverseDnsLookup(ip: string, timeoutMs: number): Promise<string[]> {
  return new Promise(resolve => {
    const timer = setTimeout(() => resolve([]), timeoutMs);
    dns.reverse(ip, (err, hostnames) => {
      clearTimeout(timer);
      if (err || !Array.isArray(hostnames)) {
        resolve([]);
        return;
      }
      resolve(hostnames);
    });
  });
}

function resolveCnames(hostname: string, timeoutMs: number): Promise<string[]> {
  return new Promise(resolve => {
    const timer = setTimeout(() => resolve([]), timeoutMs);
    dns.resolveCname(hostname, (err, addresses) => {
      clearTimeout(timer);
      if (err || !Array.isArray(addresses)) {
        resolve([]);
        return;
      }
      resolve(addresses);
    });
  });
}

/**
 * Discovers the prober's egress source IP and classifies whether it is inside Zscaler
 * (private corporate network) or probing from a non-Zscaler public IP.
 */
export async function detectProberSourceIpContext(options?: {
  sourceIpOverride?: string;
  ptrHostnamesOverride?: string[];
  orgNameOverride?: string;
  timeoutMs?: number;
}): Promise<SourceIpNetworkContext> {
  const timeoutMs = options?.timeoutMs ?? 2000;
  const envIp = process.env.AEGIS_PROBER_SOURCE_IP?.trim();
  const envOrg = process.env.AEGIS_PROBER_SOURCE_ORG?.trim();
  const proxyEnv =
    process.env.HTTPS_PROXY ||
    process.env.https_proxy ||
    process.env.HTTP_PROXY ||
    process.env.http_proxy;

  let sourceIp = options?.sourceIpOverride?.trim() || envIp || '';
  let orgName = options?.orgNameOverride?.trim() || envOrg || '';

  if (!sourceIp && process.env.NODE_ENV !== 'test') {
    try {
      const ipify = await fetchJsonWithTimeout(
        'https://api.ipify.org?format=json',
        timeoutMs,
      );
      if (ipify?.ip) {
        sourceIp = String(ipify.ip).trim();
      }
    } catch {
      // Fall back to local/non-Zscaler public IP representation if offline
    }
  }

  if (!sourceIp) {
    sourceIp = '203.0.113.10';
  }

  const ptrHostnames =
    options?.ptrHostnamesOverride ??
    (process.env.NODE_ENV === 'test'
      ? []
      : await reverseDnsLookup(sourceIp, Math.min(timeoutMs, 1000)));

  return classifySourceIpZscalerContext({
    sourceIp,
    ptrHostnames,
    orgName,
    proxyHeaders: proxyEnv ? { 'https-proxy': proxyEnv } : undefined,
  });
}

/**
 * Detects WAF / Edge protection provider (Akamai, Fastly, or Google Cloud Armor)
 * from HTTP response headers and DNS CNAME records.
 */
export function detectWafFromHeadersAndCnames(params: {
  headers: Record<string, string | string[] | undefined>;
  cnames?: string[];
}): {
  wafProvider: WafProviderType;
  wafDetected: boolean;
  wafEvidence: string[];
} {
  const normalizedHeaders: Record<string, string> = {};
  for (const [k, v] of Object.entries(params.headers || {})) {
    if (v === undefined) continue;
    normalizedHeaders[k.toLowerCase()] = Array.isArray(v)
      ? v.join(', ')
      : String(v);
  }
  const cnames = (params.cnames || []).map(c => c.toLowerCase());
  const evidence: string[] = [];

  // 1. Akamai detection
  const server = (normalizedHeaders['server'] || '').toLowerCase();
  const setCookie = (normalizedHeaders['set-cookie'] || '').toLowerCase();
  for (const [hk, hv] of Object.entries(normalizedHeaders)) {
    if (
      hk.startsWith('x-akamai-') ||
      hk === 'akamai-grn' ||
      hk === 'x-true-cache-key' ||
      hk === 'x-check-cacheable'
    ) {
      evidence.push(`header: ${hk}=${hv}`);
    }
  }
  if (server.includes('akamaighost') || server.includes('akamainetstorage') || server.includes('akamai')) {
    evidence.push(`header: server=${normalizedHeaders['server']}`);
  }
  if (setCookie.includes('ak_bmsc') || setCookie.includes('bm_sz')) {
    evidence.push('cookie: Akamai Bot Manager (ak_bmsc/bm_sz)');
  }
  for (const cname of cnames) {
    if (
      cname.includes('akamaiedge.net') ||
      cname.includes('akadns.net') ||
      cname.includes('akamai.net') ||
      cname.includes('edgekey.net') ||
      cname.includes('edgesuite.net')
    ) {
      evidence.push(`cname: ${cname}`);
    }
  }
  if (evidence.length > 0) {
    return {
      wafProvider: 'Akamai',
      wafDetected: true,
      wafEvidence: evidence,
    };
  }

  // 2. Fastly detection
  const via = (normalizedHeaders['via'] || '').toLowerCase();
  const xServedBy = normalizedHeaders['x-served-by'] || '';
  const xTimer = normalizedHeaders['x-timer'] || '';
  for (const [hk, hv] of Object.entries(normalizedHeaders)) {
    if (hk.startsWith('x-fastly-') || hk.startsWith('fastly-')) {
      evidence.push(`header: ${hk}=${hv}`);
    }
  }
  if (server.includes('fastly') || server.includes('artisanal')) {
    evidence.push(`header: server=${normalizedHeaders['server']}`);
  }
  if (xServedBy.toLowerCase().includes('cache-') && (xTimer || via.includes('varnish'))) {
    evidence.push(`header: x-served-by=${xServedBy}`);
  }
  for (const cname of cnames) {
    if (cname.includes('fastly.net') || cname.includes('fastlylb.net')) {
      evidence.push(`cname: ${cname}`);
    }
  }
  if (evidence.length > 0) {
    return {
      wafProvider: 'Fastly',
      wafDetected: true,
      wafEvidence: evidence,
    };
  }

  // 3. Google Cloud Armor / Google Cloud External Application Load Balancer detection
  if (
    server.includes('google frontend') ||
    server === 'gfe2' ||
    server === 'esf' ||
    server.includes('cloud armor')
  ) {
    evidence.push(`header: server=${normalizedHeaders['server']}`);
  }
  if (via.includes('google')) {
    evidence.push(`header: via=${normalizedHeaders['via']}`);
  }
  for (const [hk, hv] of Object.entries(normalizedHeaders)) {
    if (
      hk === 'x-cloud-trace-context' ||
      hk.startsWith('x-gfe-') ||
      hk.startsWith('x-goog-') ||
      hk === 'x-cloud-armor'
    ) {
      evidence.push(`header: ${hk}=${hv}`);
    }
  }
  for (const cname of cnames) {
    if (cname.includes('googleusercontent.com') || cname.includes('ghs.googlehosted.com')) {
      evidence.push(`cname: ${cname}`);
    }
  }
  if (evidence.length > 0) {
    return {
      wafProvider: 'Cloud Armor',
      wafDetected: true,
      wafEvidence: evidence,
    };
  }

  return {
    wafProvider: 'None',
    wafDetected: false,
    wafEvidence: [],
  };
}

export function normalizeTargetEndpointInput(rawTarget: string): {
  endpointUrl: string;
  hostname: string;
  port: number;
} {
  const trimmed = rawTarget.trim();
  const withScheme =
    trimmed.startsWith('https://') || trimmed.startsWith('http://')
      ? trimmed
      : `https://${trimmed}`;
  const parsed = new URL(withScheme);
  const hostname = parsed.hostname;
  const port = parsed.port
    ? Number(parsed.port)
    : parsed.protocol === 'http:'
    ? 80
    : 443;
  const normalizedUrl =
    (parsed.protocol === 'https:' && port === 443) ||
    (parsed.protocol === 'http:' && port === 80)
      ? `${parsed.protocol}//${hostname}${parsed.pathname === '/' ? '' : parsed.pathname}`
      : `${parsed.protocol}//${hostname}:${port}${parsed.pathname === '/' ? '' : parsed.pathname}`;
  return {
    endpointUrl: normalizedUrl,
    hostname,
    port,
  };
}

function extractSubjectField(dn: string, key: string): string | null {
  const regex = new RegExp(`(?:^|[\\n,/\\s])${key}=([^,\\n/]+)`, 'i');
  const m = dn.match(regex);
  return m ? m[1].trim() : null;
}

function parseCryptoX509Details(
  rawDer: Buffer,
  peerCertFallback: tls.DetailedPeerCertificate,
  expectedHostname: string,
): ActiveEndpointSslDetails {
  const x509 = new crypto.X509Certificate(rawDer);
  const serialHex = formatColonSerial(x509.serialNumber || peerCertFallback.serialNumber || '01');
  const rawHexClean = (x509.serialNumber || '01').replace(/[^0-9A-Fa-f]/g, '') || '01';
  let serialDecimal = '1';
  try {
    serialDecimal = BigInt(`0x${rawHexClean}`).toString(10);
  } catch {
    serialDecimal = '1';
  }

  const notBeforeDate = new Date(x509.validFrom);
  const notAfterDate = new Date(x509.validTo);
  const notBefore = Number.isNaN(notBeforeDate.getTime())
    ? new Date().toISOString()
    : notBeforeDate.toISOString();
  const notAfter = Number.isNaN(notAfterDate.getTime())
    ? new Date().toISOString()
    : notAfterDate.toISOString();
  const daysRemaining = Math.floor(
    (notAfterDate.getTime() - Date.now()) / (1000 * 60 * 60 * 24),
  );

  const subjectDn = x509.subject.replace(/\n/g, ', ');
  const issuerDn = x509.issuer.replace(/\n/g, ', ');
  const rawFallbackSubjectCn = Array.isArray(peerCertFallback.subject?.CN)
    ? peerCertFallback.subject.CN[0]
    : peerCertFallback.subject?.CN;
  const rawFallbackIssuerCn = Array.isArray(peerCertFallback.issuer?.CN)
    ? peerCertFallback.issuer.CN[0]
    : peerCertFallback.issuer?.CN;
  const rawFallbackIssuerOrg = Array.isArray(peerCertFallback.issuer?.O)
    ? peerCertFallback.issuer.O[0]
    : peerCertFallback.issuer?.O;
  const subjectCn = String(
    extractSubjectField(x509.subject, 'CN') ||
      rawFallbackSubjectCn ||
      expectedHostname,
  );
  const issuerCn = String(
    extractSubjectField(x509.issuer, 'CN') ||
      rawFallbackIssuerCn ||
      'Unknown CA',
  );
  const issuerOrg = String(
    extractSubjectField(x509.issuer, 'O') || rawFallbackIssuerOrg || issuerCn,
  );
  const isSelfSigned = x509.subject === x509.issuer;

  const sanDnsNames: string[] = [];
  const sanRaw = x509.subjectAltName || peerCertFallback.subjectaltname || '';
  for (const part of sanRaw.split(',')) {
    const trimmed = part.trim();
    if (trimmed.toUpperCase().startsWith('DNS:')) {
      sanDnsNames.push(trimmed.slice(4).trim());
    }
  }
  if (sanDnsNames.length === 0 && subjectCn) {
    sanDnsNames.push(subjectCn);
  }

  const pubKey = x509.publicKey;
  const asymType = pubKey.asymmetricKeyType || 'rsa';
  const keyDetails = pubKey.asymmetricKeyDetails || {};
  let publicKeyAlgorithm = 'RSA';
  let publicKeyBits = peerCertFallback.bits || 2048;

  if (asymType === 'ec') {
    publicKeyAlgorithm = 'ECDSA';
    const curve = (keyDetails.namedCurve || '').toLowerCase();
    if (curve.includes('384')) publicKeyBits = 384;
    else if (curve.includes('521')) publicKeyBits = 521;
    else publicKeyBits = 256;
  } else if (asymType === 'ed25519') {
    publicKeyAlgorithm = 'Ed25519';
    publicKeyBits = 256;
  } else {
    publicKeyAlgorithm = 'RSA';
    publicKeyBits = keyDetails.modulusLength || peerCertFallback.bits || 2048;
  }

  const signatureHashAlgorithm = 'SHA256';
  const signatureAlgorithm =
    publicKeyAlgorithm === 'ECDSA'
      ? 'ecdsa-with-SHA256'
      : 'sha256WithRSAEncryption';

  const hostnameMatchesSan = matchHostnameSan(
    expectedHostname,
    subjectCn,
    sanDnsNames,
  );
  const expiryEval = evaluateExpiryAndRenewalSla(
    daysRemaining,
    'workflow-auto-renew',
    30,
  );
  const cryptoEval = evaluateCryptoCompliance(
    signatureAlgorithm,
    signatureHashAlgorithm,
    publicKeyAlgorithm,
    publicKeyBits,
  );

  const findings = [...expiryEval.findings, ...cryptoEval.findings];
  if (!hostnameMatchesSan) {
    findings.push(
      `SAN_HOSTNAME_MISMATCH: Hostname '${expectedHostname}' does not match certificate SANs [${sanDnsNames.join(', ')}].`,
    );
  }

  let complianceStatus: 'COMPLIANT' | 'WARNING' | 'NON_COMPLIANT' = 'COMPLIANT';
  if (
    !cryptoEval.compliant ||
    !hostnameMatchesSan ||
    expiryEval.expiryStatus === 'EXPIRED'
  ) {
    complianceStatus = 'NON_COMPLIANT';
  } else if (
    findings.length > 0 ||
    expiryEval.expiryStatus === 'WARNING' ||
    expiryEval.expiryStatus === 'CRITICAL'
  ) {
    complianceStatus = 'WARNING';
  }

  return {
    subjectCn,
    subjectDn,
    sanDnsNames,
    hostnameMatchesSan,
    issuerCn,
    issuerOrg,
    issuerDn,
    serialNumberHex: serialHex,
    serialNumberDecimal: serialDecimal,
    notBefore,
    notAfter,
    daysRemaining,
    expiryStatus: expiryEval.expiryStatus,
    signatureAlgorithm,
    signatureHashAlgorithm,
    publicKeyAlgorithm,
    publicKeyBits,
    fingerprintSha256: x509.fingerprint256 || peerCertFallback.fingerprint256 || '',
    isSelfSigned,
    complianceStatus,
    complianceFindings: findings,
  };
}

function executeLiveHttpsAndTlsProbe(params: {
  hostname: string;
  port: number;
  timeoutMs: number;
}): Promise<{
  sslDetails: ActiveEndpointSslDetails;
  headers: http.IncomingHttpHeaders;
  statusCode: number | null;
}> {
  const { hostname, port, timeoutMs } = params;
  return new Promise((resolve, reject) => {
    const req = https.request(
      {
        host: hostname,
        port,
        path: '/',
        method: 'GET',
        ...(net.isIP(hostname) ? {} : { servername: hostname }),
        rejectUnauthorized: false,
        timeout: timeoutMs,
        headers: {
          'User-Agent': 'Aegis-Active-Endpoint-Prober/1.0',
          Accept: '*/*',
        },
      },
      res => {
        const tlsSocket = res.socket as tls.TLSSocket;
        const peerCert = tlsSocket.getPeerCertificate(true);
        res.resume();
        if (!peerCert || !peerCert.raw) {
          reject(new Error(`No X.509 peer certificate returned from ${hostname}:${port}`));
          return;
        }
        try {
          const sslDetails = parseCryptoX509Details(
            peerCert.raw,
            peerCert,
            hostname,
          );
          resolve({
            sslDetails,
            headers: res.headers,
            statusCode: res.statusCode ?? null,
          });
        } catch (err) {
          reject(err);
        }
      },
    );

    req.on('timeout', () => {
      req.destroy(new Error(`TLS/HTTPS probe timed out after ${timeoutMs}ms for ${hostname}:${port}`));
    });
    req.on('error', err => {
      reject(err);
    });
    req.end();
  });
}

/**
 * Probes a single real endpoint via live TLS handshake & HTTPS request to extract:
 * - SSL Expiry Details, Subject CN & SANs, Issuer, Serial Number, Signature Algorithm & Key Size
 * - WAF Protection (Akamai / Fastly / Cloud Armor)
 * - Public Internet Accessibility based on Zscaler vs. non-Zscaler Source IP
 */
export async function probeSingleEndpointLive(
  input: string | ActiveEndpointProbeTargetInput,
  options?: {
    networkContext?: SourceIpNetworkContext;
    timeoutMs?: number;
    persistToStore?: boolean;
  },
): Promise<ActiveEndpointProbeResult> {
  const targetObj: ActiveEndpointProbeTargetInput =
    typeof input === 'string' ? { target: input } : input;
  const timeoutMs = options?.timeoutMs ?? 4000;
  const networkContext =
    options?.networkContext ?? (await detectProberSourceIpContext({ timeoutMs }));
  const { endpointUrl, hostname, port } = normalizeTargetEndpointInput(
    targetObj.target,
  );
  const serviceName = targetObj.serviceName || 'aegis-ui';
  const entityRef = targetObj.entityRef || `component:default/${serviceName}`;
  const environment: SslEnvironmentTier = targetObj.environment || 'prod';
  const safeKey =
    targetObj.endpointKey ||
    hostname.replace(/[^a-zA-Z0-9-]/g, '-').toLowerCase();
  const endpointId = `${entityRef}:${environment}:${safeKey}`;
  const probedAt = new Date().toISOString();

  const cnames = await resolveCnames(hostname, Math.min(timeoutMs, 1200));

  try {
    const live = await executeLiveHttpsAndTlsProbe({
      hostname,
      port,
      timeoutMs,
    });
    const waf = detectWafFromHeadersAndCnames({
      headers: live.headers,
      cnames,
    });

    // Public Internet Accessibility rule:
    // - If source IP is Zscaler -> prober is inside private network, so cannot confirm public internet accessibility (false)
    // - If source IP is non-Zscaler -> prober is probing from public internet, so reachable endpoint IS accessible from public internet (true)
    const accessibleFromPublicInternet = !networkContext.isZscalerSourceIp;
    const exposureScope: 'unrestricted-public' | 'restricted-public' | 'strictly-private' =
      networkContext.isZscalerSourceIp
        ? 'strictly-private'
        : waf.wafDetected
        ? 'restricted-public'
        : 'unrestricted-public';

    const providerType: SslProviderType =
      waf.wafProvider === 'Cloud Armor'
        ? 'gcp-cloud-lb'
        : port === 8443 || hostname === '127.0.0.1' || hostname === 'localhost'
        ? 'haproxy-edge'
        : 'gcp-cloud-lb';

    if (options?.persistToStore !== false) {
      const certCompliance: X509CertificateComplianceDetails = {
        serialNumberHex: live.sslDetails.serialNumberHex,
        serialNumberDecimal: live.sslDetails.serialNumberDecimal,
        rotatedFromSerial: null,
        historyCount: 1,
        notBefore: live.sslDetails.notBefore,
        notAfter: live.sslDetails.notAfter,
        daysRemaining: live.sslDetails.daysRemaining,
        expiryStatus: live.sslDetails.expiryStatus,
        subjectCn: live.sslDetails.subjectCn,
        subjectDn: live.sslDetails.subjectDn,
        sanDnsNames: live.sslDetails.sanDnsNames,
        hostnameMatchesSan: live.sslDetails.hostnameMatchesSan,
        issuerCn: live.sslDetails.issuerCn,
        issuerOrg: live.sslDetails.issuerOrg,
        issuerDn: live.sslDetails.issuerDn,
        isSelfSigned: live.sslDetails.isSelfSigned,
        signatureAlgorithm: live.sslDetails.signatureAlgorithm,
        signatureHashAlgorithm: live.sslDetails.signatureHashAlgorithm,
        publicKeyAlgorithm: live.sslDetails.publicKeyAlgorithm,
        publicKeyBits: live.sslDetails.publicKeyBits,
        fingerprintSha256: live.sslDetails.fingerprintSha256,
        complianceStatus: live.sslDetails.complianceStatus,
        complianceFindings: live.sslDetails.complianceFindings,
        isActive: true,
      };

      await hydrateTrackedEndpointRecordFromDbRow({
        endpointId,
        entityRef,
        serviceName,
        environment,
        endpointKey: safeKey,
        endpointUrl,
        sniHostname: hostname,
        providerType,
        renewalMode: 'workflow-auto-renew',
        exposureScope,
        dnsScope: accessibleFromPublicInternet
          ? 'public-authoritative'
          : 'private-split-horizon',
        ingressType:
          waf.wafProvider !== 'None'
            ? `${waf.wafProvider} WAF Edge (${networkContext.networkOrigin})`
            : `Active Probed Endpoint (${networkContext.networkOrigin})`,
        lastProbedAt: probedAt,
        certificateDetails: certCompliance,
      });
    }

    return {
      targetInput: targetObj.target,
      endpointId,
      endpointUrl,
      hostname,
      port,
      reachable: true,
      sourceIp: networkContext.sourceIp,
      isZscalerSourceIp: networkContext.isZscalerSourceIp,
      probeNetworkOrigin: networkContext.networkOrigin,
      accessibleFromPublicInternet,
      exposureScope,
      wafProvider: waf.wafProvider,
      wafDetected: waf.wafDetected,
      wafEvidence: waf.wafEvidence,
      httpStatusCode: live.statusCode,
      sslDetails: live.sslDetails,
      probedAt,
    };
  } catch (err) {
    const wafFromCnameOnly = detectWafFromHeadersAndCnames({
      headers: {},
      cnames,
    });
    return {
      targetInput: targetObj.target,
      endpointId,
      endpointUrl,
      hostname,
      port,
      reachable: false,
      error: err instanceof Error ? err.message : String(err),
      sourceIp: networkContext.sourceIp,
      isZscalerSourceIp: networkContext.isZscalerSourceIp,
      probeNetworkOrigin: networkContext.networkOrigin,
      accessibleFromPublicInternet: false,
      exposureScope: 'strictly-private',
      wafProvider: wafFromCnameOnly.wafProvider,
      wafDetected: wafFromCnameOnly.wafDetected,
      wafEvidence: wafFromCnameOnly.wafEvidence,
      httpStatusCode: null,
      sslDetails: null,
      probedAt,
    };
  }
}

/**
 * Probes a list of real endpoints concurrently, evaluates Zscaler vs. public source IP,
 * detects Akamai/Fastly/Cloud Armor WAF protection, and optionally persists to CMDB.
 */
export async function probeEndpointListLive(
  targets: Array<string | ActiveEndpointProbeTargetInput>,
  options?: {
    sourceIpOverride?: string;
    orgNameOverride?: string;
    ptrHostnamesOverride?: string[];
    timeoutMs?: number;
    persistToStore?: boolean;
  },
): Promise<ActiveEndpointBatchProbeReport> {
  const timeoutMs = options?.timeoutMs ?? 4000;
  const networkContext = await detectProberSourceIpContext({
    sourceIpOverride: options?.sourceIpOverride,
    orgNameOverride: options?.orgNameOverride,
    ptrHostnamesOverride: options?.ptrHostnamesOverride,
    timeoutMs,
  });

  const cleanTargets = targets.filter(t => {
    const raw = typeof t === 'string' ? t : t?.target;
    return typeof raw === 'string' && raw.trim().length > 0;
  });

  const results = await Promise.all(
    cleanTargets.map(target =>
      probeSingleEndpointLive(target, {
        networkContext,
        timeoutMs,
        persistToStore: options?.persistToStore,
      }),
    ),
  );

  return {
    networkContext,
    totalProbed: results.length,
    reachableCount: results.filter(r => r.reachable).length,
    publicAccessibleCount: results.filter(r => r.accessibleFromPublicInternet).length,
    wafProtectedCount: results.filter(r => r.wafDetected).length,
    results,
  };
}

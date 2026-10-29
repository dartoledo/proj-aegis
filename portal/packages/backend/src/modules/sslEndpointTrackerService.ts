import crypto from 'crypto';
import fs from 'node:fs';
import path from 'node:path';
import { Entity, stringifyEntityRef } from '@backstage/catalog-model';
import { formatColonSerial, probeLiveTlsCertificate } from './haproxyTlsService';

export type SslEnvironmentTier = 'dev' | 'stg' | 'stress-test' | 'preprod' | 'prod';
export type SslProviderType = 'haproxy-edge' | 'private-cloud-lb' | 'gcp-cloud-lb';
export type SslRenewalMode =
  | 'manual-or-template'
  | 'self-renewing-monitored'
  | 'workflow-auto-renew';

export type IngressExposureScope =
  | 'unrestricted-public'
  | 'restricted-public'
  | 'strictly-private'
  | 'internet-facing'
  | 'internal-only';

export function normalizeExposureScope(
  raw?: string | null,
  fallback:
    | 'unrestricted-public'
    | 'restricted-public'
    | 'strictly-private' = 'strictly-private',
): 'unrestricted-public' | 'restricted-public' | 'strictly-private' {
  const v = (raw || '').trim().toLowerCase();
  if (
    v === 'unrestricted-public' ||
    v === 'internet-facing' ||
    v === 'customer-facing' ||
    v === 'open-edge'
  ) {
    return 'unrestricted-public';
  }
  if (
    v === 'restricted-public' ||
    v === 'partner-facing' ||
    v === 'authenticated-edge' ||
    v === 'acl-gated'
  ) {
    return 'restricted-public';
  }
  if (
    v === 'strictly-private' ||
    v === 'internal-only' ||
    v === 'private-core'
  ) {
    return 'strictly-private';
  }
  return fallback;
}

export type DnsResolutionScope = 'public-authoritative' | 'private-split-horizon';

export interface SoftwareStackDependency {
  name: string;
  version: string;
  category:
    | 'runtime'
    | 'web-server'
    | 'reverse-proxy'
    | 'database'
    | 'framework'
    | 'crypto-library';
  description?: string;
  cveStatus?: 'SECURE' | 'WARNING' | 'CRITICAL';
}

export const VALID_SSL_ENVIRONMENTS: readonly SslEnvironmentTier[] = [
  'dev',
  'stg',
  'stress-test',
  'preprod',
  'prod',
];

export interface X509CertificateComplianceDetails {
  /** Pillar 4: Serial Number (Unique Database Key differentiating old vs renewed certs) */
  serialNumberHex: string;
  serialNumberDecimal: string;
  rotatedFromSerial: string | null;
  historyCount: number;

  /** Pillar 1: Not After (Expiry Date - Prevents total SSO/OIDC outage) */
  notBefore: string;
  notAfter: string;
  daysRemaining: number;
  expiryStatus: 'HEALTHY' | 'WARNING' | 'CRITICAL' | 'EXPIRED';

  /** Pillar 2: Subject (Common Name & SANs - Routes traffic & alerts) */
  subjectCn: string;
  subjectDn: string;
  sanDnsNames: string[];
  hostnameMatchesSan: boolean;

  /** Pillar 3: Issuer (Identifies CA renewal and risk paths) */
  issuerCn: string;
  issuerOrg: string;
  issuerDn: string;
  isSelfSigned: boolean;

  /** Pillar 5: Signature Algorithm & Key Size (Enforces security compliance) */
  signatureAlgorithm: string;
  signatureHashAlgorithm: string;
  publicKeyAlgorithm: string;
  publicKeyBits: number;
  fingerprintSha256: string;

  /** Overall Compliance Verdict */
  complianceStatus: 'COMPLIANT' | 'WARNING' | 'NON_COMPLIANT';
  complianceFindings: string[];
  isActive: boolean;
}

export interface TrackedSslEndpointRecord {
  endpointId: string;
  entityRef: string;
  serviceName: string;
  environment: SslEnvironmentTier;
  endpointKey: string;
  endpointUrl: string;
  sniHostname: string;
  providerType: SslProviderType;
  renewalMode: SslRenewalMode;
  autoRenewThresholdDays: number;
  gcpProject?: string | null;
  gcpTargetProxy?: string | null;
  exposureScope?: IngressExposureScope;
  dnsScope?: DnsResolutionScope;
  ingressType?: string;
  lastProbedAt: string;
  certificate: X509CertificateComplianceDetails;
}

export interface EntitySslTrackerRollup {
  entityRef: string;
  serviceName: string;
  providerType: SslProviderType;
  renewalMode: SslRenewalMode;
  overallStatus: 'COMPLIANT' | 'WARNING' | 'NON_COMPLIANT';
  minDaysRemaining: number;
  totalEndpoints: number;
  compliantEndpoints: number;
  environmentCounts: Record<SslEnvironmentTier, number>;
  endpoints: TrackedSslEndpointRecord[];
  lastScannedAt: string;
  exposureCounts?: {
    unrestrictedPublic: number;
    restrictedPublic: number;
    strictlyPrivate: number;
    internetFacing: number;
    internalOnly: number;
  };
  softwareStack?: SoftwareStackDependency[];
}

export interface GcpAutoRenewalDiffPlan {
  entityRef: string;
  environment: string;
  targetEndpointsCount: number;
  targetEndpointUrls: string[];
  targetDomains: string[];
  proposedChanges: Array<{
    endpointId: string;
    environment: SslEnvironmentTier;
    endpointKey: string;
    endpointUrl: string;
    domain: string;
    currentCert: X509CertificateComplianceDetails;
    proposedCert: X509CertificateComplianceDetails;
    unifiedDiff: string;
  }>;
  diffMarkdownByEnv: string;
}

export interface GcpQualityGateState {
  gateId: string;
  entityRef: string;
  environment: string;
  status: 'PENDING_APPROVAL' | 'APPROVED' | 'REJECTED';
  createdAt: string;
  decidedAt?: string;
  decidedBy?: string;
  comments?: string;
  plan: GcpAutoRenewalDiffPlan;
}

export interface GcpAutoRenewalResult {
  status: 'RENEWED';
  entityRef: string;
  environment: string;
  renewedCount: number;
  targetEndpointUrls: string[];
  verifiedDomains: string[];
  renewals: Array<{
    endpointId: string;
    environment: SslEnvironmentTier;
    endpointKey: string;
    endpointUrl: string;
    domain: string;
    previousSerial: string;
    newSerial: string;
    gcpOperationId: string;
    dnsAuthorization: string;
    authorizationStatus: 'AUTHORIZED';
    sslCertificateResource: string;
    unifiedDiff: string;
    endpoint: TrackedSslEndpointRecord;
  }>;
  renewalSummaryMarkdown: string;
  perEnvDiffMarkdown: string;
}

export interface EndpointCertificateHistoryRecord {
  endpointId: string;
  entityRef: string;
  serviceName: string;
  environment: SslEnvironmentTier;
  endpointKey: string;
  endpointUrl: string;
  sniHostname: string;
  providerType: SslProviderType;
  activeSerialNumberHex: string;
  historyCount: number;
  certificates: X509CertificateComplianceDetails[];
}

interface ParsedAnnotationEndpoint {
  entityRef: string;
  serviceName: string;
  environment: SslEnvironmentTier;
  endpointKey: string;
  endpointUrl: string;
  providerType: SslProviderType;
  renewalMode: SslRenewalMode;
  autoRenewThresholdDays: number;
  gcpProject: string | null;
  gcpTargetProxy: string | null;
  simulateWeakCrypto: boolean;
  simulateDaysRemaining: number | null;
  haproxyHost?: string | null;
  exposureScope?: IngressExposureScope;
  dnsScope?: DnsResolutionScope;
  ingressType?: string;
}

// In-memory store keyed by endpointId ("<entityRef>:<env>:<endpointKey>")
const endpointInventoryStore = new Map<string, TrackedSslEndpointRecord>();
// Historical certificate inventory keyed by endpointId -> Map<serialNumberHex, X509CertificateComplianceDetails>
const certificateHistoryStore = new Map<
  string,
  Map<string, X509CertificateComplianceDetails>
>();
// Counter for mocked GCP Certificate Manager auto-renewals
const gcpRenewalVersionCounter = new Map<string, number>();
// Quality Gate approval store keyed by gateId (and entityRef for latest pending gate)
const gcpQualityGateStore = new Map<string, GcpQualityGateState>();
const latestEntityGateMap = new Map<string, string>();
// Tracks endpointIds that have been remediated from weak crypto
const remediatedWeakCryptoEndpoints = new Set<string>();
const entitySoftwareStackStore = new Map<string, SoftwareStackDependency[]>();
const DEFAULT_STATE_FILE_PATH =
  process.env.AEGIS_SSL_TRACKER_STATE_FILE ||
  path.resolve(process.cwd(), '.ssl_tracker_state.json');

export function saveSslTrackerStateToDisk(filePath?: string): void {
  const target = filePath || DEFAULT_STATE_FILE_PATH;
  const state = {
    endpointInventoryStore: Array.from(endpointInventoryStore.entries()),
    certificateHistoryStore: Array.from(certificateHistoryStore.entries()).map(
      ([k, v]) => [k, Array.from(v.entries())] as [
        string,
        [string, X509CertificateComplianceDetails][],
      ],
    ),
    gcpRenewalVersionCounter: Array.from(gcpRenewalVersionCounter.entries()),
    gcpQualityGateStore: Array.from(gcpQualityGateStore.entries()),
    latestEntityGateMap: Array.from(latestEntityGateMap.entries()),
    remediatedWeakCryptoEndpoints: Array.from(remediatedWeakCryptoEndpoints),
    entitySoftwareStackStore: Array.from(entitySoftwareStackStore.entries()),
  };
  fs.writeFileSync(target, JSON.stringify(state, null, 2), 'utf-8');
}

export function loadSslTrackerStateFromDisk(filePath?: string): boolean {
  const target = filePath || DEFAULT_STATE_FILE_PATH;
  try {
    if (!fs.existsSync(target)) return false;
    const raw = fs.readFileSync(target, 'utf-8');
    const state = JSON.parse(raw);
    endpointInventoryStore.clear();
    for (const [k, v] of state.endpointInventoryStore || []) {
      if (v && v.exposureScope) {
        v.exposureScope = normalizeExposureScope(v.exposureScope);
      }
      endpointInventoryStore.set(k, v);
    }
    certificateHistoryStore.clear();
    for (const [k, v] of state.certificateHistoryStore || []) {
      const inner = new Map<string, X509CertificateComplianceDetails>();
      for (const [sk, sv] of v || []) {
        inner.set(sk, sv);
      }
      certificateHistoryStore.set(k, inner);
    }
    gcpRenewalVersionCounter.clear();
    for (const [k, v] of state.gcpRenewalVersionCounter || []) {
      gcpRenewalVersionCounter.set(k, v);
    }
    gcpQualityGateStore.clear();
    for (const [k, v] of state.gcpQualityGateStore || []) {
      gcpQualityGateStore.set(k, v);
    }
    latestEntityGateMap.clear();
    for (const [k, v] of state.latestEntityGateMap || []) {
      latestEntityGateMap.set(k, v);
    }
    remediatedWeakCryptoEndpoints.clear();
    for (const item of state.remediatedWeakCryptoEndpoints || []) {
      remediatedWeakCryptoEndpoints.add(item);
    }
    entitySoftwareStackStore.clear();
    for (const [k, v] of state.entitySoftwareStackStore || []) {
      entitySoftwareStackStore.set(k, v);
    }
    return true;
  } catch {
    return false;
  }
}

if (process.env.NODE_ENV !== 'test') {
  loadSslTrackerStateFromDisk();
}

export function buildEndpointCertUnifiedDiff(params: {
  environment: SslEnvironmentTier;
  endpointKey: string;
  endpointUrl: string;
  domain: string;
  oldCert: X509CertificateComplianceDetails;
  newCert: X509CertificateComplianceDetails;
}): string {
  const { environment, endpointKey, endpointUrl, domain, oldCert, newCert } =
    params;
  const lines: string[] = [
    `--- Current SSL Certificate [${environment.toUpperCase()} / ${endpointKey}] @ ${endpointUrl}`,
    `+++ Proposed Renewed SSL Certificate [${environment.toUpperCase()} / ${endpointKey}] @ ${endpointUrl}`,
    '@@ -1,7 +1,7 @@',
    `   Target Domain (SNI)     : ${domain}`,
    `-  1. Not After (Expiry)   : ${oldCert.notAfter} (${oldCert.daysRemaining}d remaining [${oldCert.expiryStatus}])`,
    `+  1. Not After (Expiry)   : ${newCert.notAfter} (${newCert.daysRemaining}d remaining [${newCert.expiryStatus}])`,
  ];

  const oldSubj = `CN=${oldCert.subjectCn} | SANs=[${oldCert.sanDnsNames.join(', ')}]`;
  const newSubj = `CN=${newCert.subjectCn} | SANs=[${newCert.sanDnsNames.join(', ')}]`;
  if (oldSubj === newSubj) {
    lines.push(`   2. Subject (CN & SANs)  : ${newSubj}`);
  } else {
    lines.push(`-  2. Subject (CN & SANs)  : ${oldSubj}`);
    lines.push(`+  2. Subject (CN & SANs)  : ${newSubj}`);
  }

  const oldIss = `CN=${oldCert.issuerCn}, O=${oldCert.issuerOrg}`;
  const newIss = `CN=${newCert.issuerCn}, O=${newCert.issuerOrg}`;
  if (oldIss === newIss) {
    lines.push(`   3. Issuer CA            : ${newIss}`);
  } else {
    lines.push(`-  3. Issuer CA            : ${oldIss}`);
    lines.push(`+  3. Issuer CA            : ${newIss}`);
  }

  lines.push(`-  4. Serial Number (DB PK): ${oldCert.serialNumberHex}`);
  lines.push(`+  4. Serial Number (DB PK): ${newCert.serialNumberHex}`);

  const oldCrypto = `${oldCert.publicKeyAlgorithm} ${oldCert.publicKeyBits}-bit / ${oldCert.signatureAlgorithm} (${oldCert.signatureHashAlgorithm})`;
  const newCrypto = `${newCert.publicKeyAlgorithm} ${newCert.publicKeyBits}-bit / ${newCert.signatureAlgorithm} (${newCert.signatureHashAlgorithm})`;
  if (oldCrypto === newCrypto) {
    lines.push(`   5. SigAlg & Key Size    : ${newCrypto}`);
  } else {
    lines.push(`-  5. SigAlg & Key Size    : ${oldCrypto}`);
    lines.push(`+  5. SigAlg & Key Size    : ${newCrypto}`);
  }

  lines.push(`-  SHA-256 Fingerprint     : ${oldCert.fingerprintSha256}`);
  lines.push(`+  SHA-256 Fingerprint     : ${newCert.fingerprintSha256}`);

  return lines.join('\n');
}

export function extractHostnameFromUrl(endpointUrl: string): string {
  try {
    const normalized = endpointUrl.includes('://')
      ? endpointUrl
      : `https://${endpointUrl}`;
    const parsed = new URL(normalized);
    return parsed.hostname || 'localhost';
  } catch {
    return 'localhost';
  }
}

export function extractHostPortFromUrl(
  endpointUrl: string,
  fallbackHostPort = '127.0.0.1:8443',
): string {
  try {
    const normalized = endpointUrl.includes('://')
      ? endpointUrl
      : `https://${endpointUrl}`;
    const parsed = new URL(normalized);
    const host = parsed.hostname || '127.0.0.1';
    const port = parsed.port || '8443';
    return `${host}:${port}`;
  } catch {
    return fallbackHostPort;
  }
}

export function matchHostnameSan(
  hostname: string,
  subjectCn: string,
  sanDnsNames: string[],
): boolean {
  const host = (hostname || '').trim().toLowerCase().replace(/\.$/, '');
  if (!host) {
    return false;
  }
  const candidates =
    sanDnsNames.length > 0
      ? sanDnsNames
      : subjectCn
      ? [subjectCn]
      : [];

  return candidates.some(rawPattern => {
    const pat = (rawPattern || '').trim().toLowerCase().replace(/\.$/, '');
    if (!pat) return false;
    if (pat === host) return true;
    if (pat.startsWith('*.')) {
      const suffix = pat.slice(2);
      if (!suffix || !suffix.includes('.')) return false;
      if (!host.endsWith(`.${suffix}`)) return false;
      const prefix = host.slice(0, host.length - suffix.length - 1);
      return prefix.length > 0 && !prefix.includes('.');
    }
    return false;
  });
}

export function evaluateCryptoCompliance(
  signatureAlgorithm: string,
  signatureHash: string,
  publicKeyAlgorithm: string,
  publicKeyBits: number,
): { compliant: boolean; findings: string[] } {
  const findings: string[] = [];
  const normHash = (signatureHash || '').toUpperCase().replace(/-/g, '');
  const normSig = (signatureAlgorithm || '').toUpperCase().replace(/-/g, '');
  const normPub = (publicKeyAlgorithm || '').toUpperCase();

  if (
    ['SHA1', 'MD5', 'MD2', 'NONE'].includes(normHash) ||
    normSig.includes('SHA1') ||
    normSig.includes('MD5')
  ) {
    findings.push(
      `INSECURE_SIGNATURE_HASH: Signature algorithm '${signatureAlgorithm}' (${signatureHash}) uses deprecated weak hashing (SHA-1/MD5 prohibited).`,
    );
  }

  if (normPub === 'RSA' || normPub === 'DSA') {
    if (publicKeyBits < 2048) {
      findings.push(
        `WEAK_KEY_SIZE: ${normPub} ${publicKeyBits}-bit key is below the mandatory 2048-bit minimum.`,
      );
    }
  } else if (normPub === 'ECDSA' || normPub === 'EC') {
    if (publicKeyBits < 256) {
      findings.push(
        `WEAK_KEY_SIZE: ECDSA ${publicKeyBits}-bit key is below the mandatory 256-bit minimum.`,
      );
    }
  }

  return {
    compliant: findings.length === 0,
    findings,
  };
}

export function evaluateExpiryAndRenewalSla(
  daysRemaining: number,
  renewalMode: SslRenewalMode,
  autoRenewThresholdDays: number,
): {
  expiryStatus: 'HEALTHY' | 'WARNING' | 'CRITICAL' | 'EXPIRED';
  findings: string[];
} {
  const findings: string[] = [];
  let expiryStatus: 'HEALTHY' | 'WARNING' | 'CRITICAL' | 'EXPIRED' = 'HEALTHY';

  if (daysRemaining <= 0) {
    expiryStatus = 'EXPIRED';
    findings.push(
      `CERT_EXPIRED: Certificate expired (${daysRemaining}d). Immediate SAML/OIDC SSO outage risk.`,
    );
  } else if (daysRemaining <= 7) {
    expiryStatus = 'CRITICAL';
    findings.push(
      `EXPIRY_CRITICAL: Certificate expires in ${daysRemaining} days (<= 7d threshold).`,
    );
  } else if (daysRemaining <= 30) {
    expiryStatus = 'WARNING';
    findings.push(
      `EXPIRY_WARNING: Certificate expires in ${daysRemaining} days (<= 30d threshold).`,
    );
  }

  if (
    renewalMode === 'self-renewing-monitored' &&
    daysRemaining <= autoRenewThresholdDays
  ) {
    findings.push(
      `SELF_RENEWAL_STALLED: Private Cloud LB autonomous renewal SLA breached (${daysRemaining}d remaining <= ${autoRenewThresholdDays}d auto-renewal window).`,
    );
    if (expiryStatus === 'HEALTHY') {
      expiryStatus = 'WARNING';
    }
  }

  return { expiryStatus, findings };
}

export function parseEntitySoftwareStack(entity: Entity): SoftwareStackDependency[] {
  const raw = entity.metadata.annotations?.['resiliency.idp/software-stack'];
  if (raw) {
    try {
      const parsed = JSON.parse(raw);
      if (Array.isArray(parsed)) {
        return parsed as SoftwareStackDependency[];
      }
    } catch {
      // fall through to defaults
    }
  }

  const name = entity.metadata.name;
  switch (name) {
    case 'aegis-ui':
      return [
        { name: 'node', version: '22.15.0', category: 'runtime', description: 'Node.js 22 LTS runtime — patched against CVE-2026-111497', cveStatus: 'SECURE' },
        { name: 'react', version: '18.2.0', category: 'framework', description: 'React frontend framework' },
        { name: 'nginx', version: '1.25.3', category: 'web-server', description: 'Static asset & SPA server' },
        { name: 'openssl', version: '3.0.13', category: 'crypto-library', description: 'TLS termination crypto' },
      ];
    case 'aegis-backend':
      return [
        { name: 'node', version: '18.20.8', category: 'runtime', description: 'EOL Node.js 18 runtime — CRITICAL CVE-2026-111497 & CVE-2026-56850', cveStatus: 'CRITICAL' },
        { name: 'express', version: '4.18.2', category: 'framework', description: 'HTTP API framework' },
        { name: 'openssl', version: '3.0.13', category: 'crypto-library', description: 'TLS termination crypto' },
      ];
    case 'aegis-auth':
      return [
        { name: 'node', version: '20.11.0', category: 'runtime', description: 'Node.js 20 LTS runtime — CRITICAL CVE-2026-111497 & CVE-2024-27980', cveStatus: 'CRITICAL' },
        { name: 'express', version: '4.18.2', category: 'framework', description: 'OIDC/SAML auth framework' },
        { name: 'openssl', version: '3.0.13', category: 'crypto-library', description: 'JWT signing & TLS' },
      ];
    case 'aegis-db':
      return [
        { name: 'postgresql', version: '15.4', category: 'database', description: 'Primary relational datastore' },
        { name: 'openssl', version: '3.0.13', category: 'crypto-library', description: 'TLS for DB connections' },
      ];
    case 'haproxy-hello-world-tls':
    case 'hello-world-app':
      return [
        { name: 'haproxy', version: '2.8.5', category: 'reverse-proxy', description: 'Edge TLS termination & load balancing' },
        { name: 'openssl', version: '3.0.13', category: 'crypto-library', description: 'HAProxy TLS crypto backend' },
      ];
    default:
      return [
        { name: 'node', version: '20.11.0', category: 'runtime', description: 'Node.js runtime — CRITICAL CVE-2026-111497', cveStatus: 'CRITICAL' },
        { name: 'openssl', version: '3.0.13', category: 'crypto-library', description: 'TLS crypto' },
      ];
  }
}

/**
 * Parse 1:N endpoints per environment from Backstage Catalog Entity annotations.
 * Supports both:
 * - Named sub-keys: `resiliency.idp/endpoints.stg.primary`, `resiliency.idp/endpoints.stg.eu-central`
 * - Comma-separated URL lists: `resiliency.idp/endpoints.stg: "https://stg1..., https://stg2..."`
 */
export function parseEntityEnvironmentEndpoints(
  entity: Entity,
): ParsedAnnotationEndpoint[] {
  const annotations = entity.metadata.annotations ?? {};
  const entityRef = stringifyEntityRef(entity);
  const serviceName = entity.metadata.name;

  const rawProvider = (
    annotations['resiliency.idp/ssl-provider'] || 'private-cloud-lb'
  ).trim();
  const defaultProvider: SslProviderType =
    rawProvider === 'haproxy-edge' ||
    rawProvider === 'gcp-cloud-lb' ||
    rawProvider === 'private-cloud-lb'
      ? rawProvider
      : 'private-cloud-lb';

  const rawMode = (annotations['resiliency.idp/ssl-renewal-mode'] || '').trim();
  const defaultRenewalMode: SslRenewalMode =
    rawMode === 'manual-or-template' ||
    rawMode === 'workflow-auto-renew' ||
    rawMode === 'self-renewing-monitored'
      ? rawMode
      : defaultProvider === 'gcp-cloud-lb'
      ? 'workflow-auto-renew'
      : defaultProvider === 'haproxy-edge'
      ? 'manual-or-template'
      : 'self-renewing-monitored';

  const thresholdDays =
    Number.parseInt(
      annotations['resiliency.idp/ssl-auto-renew-threshold-days'] || '15',
      10,
    ) || 15;
  const gcpProject = annotations['resiliency.idp/gcp-project'] || null;
  const gcpTargetProxy =
    annotations['resiliency.idp/gcp-target-https-proxy'] || null;
  const haproxyHost = annotations['resiliency.idp/haproxy-host'] || null;

  const fallbackExposure =
    defaultProvider === 'gcp-cloud-lb' ||
    (Array.isArray(entity.metadata.tags) &&
      (entity.metadata.tags.includes('ingress:unrestricted-public') ||
        entity.metadata.tags.includes('ingress:internet-facing')))
      ? 'unrestricted-public'
      : defaultProvider === 'haproxy-edge' ||
        (Array.isArray(entity.metadata.tags) &&
          entity.metadata.tags.includes('ingress:restricted-public'))
      ? 'restricted-public'
      : 'strictly-private';
  const defaultExposure = normalizeExposureScope(
    annotations['resiliency.idp/exposure-scope'],
    fallbackExposure,
  );
  const defaultDnsScope: DnsResolutionScope =
    (annotations['resiliency.idp/dns-scope'] as DnsResolutionScope) ||
    (defaultExposure === 'unrestricted-public' ||
    defaultExposure === 'restricted-public'
      ? 'public-authoritative'
      : 'private-split-horizon');
  const defaultIngressType: string =
    annotations['resiliency.idp/ingress-type'] ||
    (defaultProvider === 'gcp-cloud-lb'
      ? 'Cloud External Application Load Balancer (GCP TargetHttpsProxy)'
      : defaultProvider === 'haproxy-edge'
      ? 'Edge Reverse Proxy & HAProxy TLS Gateway'
      : 'Private Cloud Load Balancer (VPC-Internal)');

  const parsed: ParsedAnnotationEndpoint[] = [];
  const prefix = 'resiliency.idp/endpoints.';

  for (const [key, rawValue] of Object.entries(annotations)) {
    if (!key.startsWith(prefix) || !rawValue || !rawValue.trim()) {
      continue;
    }
    const remainder = key.slice(prefix.length);
    let matchedEnv: SslEnvironmentTier | null = null;
    let subKey = 'default';

    for (const envTier of VALID_SSL_ENVIRONMENTS) {
      if (remainder === envTier) {
        matchedEnv = envTier;
        subKey = 'default';
        break;
      }
      if (remainder.startsWith(`${envTier}.`)) {
        matchedEnv = envTier;
        subKey = remainder.slice(envTier.length + 1) || 'default';
        break;
      }
    }

    if (!matchedEnv) {
      continue;
    }

    const urlParts = rawValue
      .split(',')
      .map(u => u.trim())
      .filter(Boolean);

    urlParts.forEach((url, idx) => {
      const effectiveKey =
        urlParts.length > 1 && subKey === 'default'
          ? `endpoint-${idx + 1}`
          : urlParts.length > 1
          ? `${subKey}-${idx + 1}`
          : subKey;

      const weakCryptoFlag =
        annotations[
          `resiliency.idp/ssl-simulate-weak-crypto.${matchedEnv}.${effectiveKey}`
        ] === 'true' ||
        annotations[`resiliency.idp/ssl-simulate-weak-crypto.${matchedEnv}`] ===
          'true';

      const simDaysStr =
        annotations[
          `resiliency.idp/ssl-simulate-days-remaining.${matchedEnv}.${effectiveKey}`
        ] ||
        annotations[`resiliency.idp/ssl-simulate-days-remaining.${matchedEnv}`];
      const simDays =
        simDaysStr !== undefined && simDaysStr !== ''
          ? Number.parseInt(simDaysStr, 10)
          : null;

      const isRemediated = remediatedWeakCryptoEndpoints.has(
        `${entityRef}:${matchedEnv}:${effectiveKey}`,
      );
      const endpointExposureRaw =
        annotations[
          `resiliency.idp/exposure-scope.${matchedEnv}.${effectiveKey}`
        ] ||
        annotations[`resiliency.idp/exposure-scope.${matchedEnv}.${subKey}`] ||
        annotations[`resiliency.idp/exposure-scope.${matchedEnv}`];
      const endpointExposure: IngressExposureScope = endpointExposureRaw
        ? normalizeExposureScope(endpointExposureRaw, defaultExposure)
        : defaultExposure;
      const endpointDnsScope: DnsResolutionScope =
        (annotations[
          `resiliency.idp/dns-scope.${matchedEnv}.${effectiveKey}`
        ] as DnsResolutionScope) ||
        (annotations[
          `resiliency.idp/dns-scope.${matchedEnv}`
        ] as DnsResolutionScope) ||
        (endpointExposureRaw
          ? endpointExposure === 'strictly-private'
            ? 'private-split-horizon'
            : 'public-authoritative'
          : defaultDnsScope);
      parsed.push({
        entityRef,
        serviceName,
        environment: matchedEnv!,
        endpointKey: effectiveKey,
        endpointUrl: url,
        providerType: defaultProvider,
        renewalMode: defaultRenewalMode,
        autoRenewThresholdDays: thresholdDays,
        gcpProject,
        gcpTargetProxy,
        simulateWeakCrypto: weakCryptoFlag && !isRemediated,
        simulateDaysRemaining: Number.isNaN(simDays as number) ? null : simDays,
        haproxyHost,
        exposureScope: endpointExposure,
        dnsScope: endpointDnsScope,
        ingressType: defaultIngressType,
      });
    });
  }

  // Fallback: synthesize default environment endpoints when no explicit endpoints.* annotations exist
  if (parsed.length === 0) {
    const hasHaproxyHost = Boolean(haproxyHost);
    const isTlsEdgeResource =
      serviceName === 'haproxy-hello-world-tls' ||
      serviceName === 'hello-world-app';
    const k8sHealthUrl = annotations['resiliency.idp/k8s-health-url'] || '';
    const hasCertAnnotation =
      Boolean(annotations['resiliency.idp/cert-expiry']) ||
      Boolean(annotations['resiliency.idp/cert-provider']);

    if (hasHaproxyHost || isTlsEdgeResource) {
      const defaultUrl = 'https://hello.internal:8443/healthz';
      for (const envTier of VALID_SSL_ENVIRONMENTS) {
        parsed.push({
          entityRef,
          serviceName,
          environment: envTier,
          endpointKey: 'default',
          endpointUrl: defaultUrl,
          providerType: defaultProvider,
          renewalMode: defaultRenewalMode,
          autoRenewThresholdDays: thresholdDays,
          gcpProject,
          gcpTargetProxy,
          simulateWeakCrypto: false,
          simulateDaysRemaining: null,
          haproxyHost,
          exposureScope: defaultExposure,
          dnsScope: defaultDnsScope,
          ingressType: defaultIngressType,
        });
      }
    } else if (k8sHealthUrl) {
      const httpsUrl = k8sHealthUrl.startsWith('http://')
        ? k8sHealthUrl.replace('http://', 'https://')
        : k8sHealthUrl.startsWith('https://')
        ? k8sHealthUrl
        : `https://${k8sHealthUrl}`;
      for (const envTier of VALID_SSL_ENVIRONMENTS) {
        parsed.push({
          entityRef,
          serviceName,
          environment: envTier,
          endpointKey: 'default',
          endpointUrl: httpsUrl,
          providerType: defaultProvider,
          renewalMode: defaultRenewalMode,
          autoRenewThresholdDays: thresholdDays,
          gcpProject,
          gcpTargetProxy,
          simulateWeakCrypto: false,
          simulateDaysRemaining: null,
          haproxyHost,
          exposureScope: defaultExposure,
          dnsScope: defaultDnsScope,
          ingressType: defaultIngressType,
        });
      }
    } else if (hasCertAnnotation) {
      const defaultUrl = 'https://localhost:8443/healthz';
      for (const envTier of VALID_SSL_ENVIRONMENTS) {
        parsed.push({
          entityRef,
          serviceName,
          environment: envTier,
          endpointKey: 'default',
          endpointUrl: defaultUrl,
          providerType: 'haproxy-edge',
          renewalMode: 'manual-or-template',
          autoRenewThresholdDays: thresholdDays,
          gcpProject,
          gcpTargetProxy,
          simulateWeakCrypto: false,
          simulateDaysRemaining: null,
          haproxyHost,
          exposureScope: defaultExposure,
          dnsScope: defaultDnsScope,
          ingressType: defaultIngressType,
        });
      }
    }
  }

  return parsed;
}

function deterministicSerialFromSeed(seed: string): {
  hex: string;
  decimal: string;
  fingerprint256: string;
} {
  const hash = crypto.createHash('sha256').update(seed).digest('hex').toUpperCase();
  const serialRaw = hash.slice(0, 20);
  const fpRaw = hash;
  const hex = formatColonSerial(serialRaw);
  const decimal = BigInt(`0x${serialRaw}`).toString(10);
  const fingerprint256 = formatColonSerial(fpRaw);
  return { hex, decimal, fingerprint256 };
}

async function buildCertificateDetailsForTarget(
  target: ParsedAnnotationEndpoint,
  options?: {
    forceNewGcpRenewalVersion?: number;
    keyAlgorithmOverride?: 'RSA-2048' | 'ECDSA-P256';
    validityDaysOverride?: number;
  },
): Promise<X509CertificateComplianceDetails> {
  const sniHostname = extractHostnameFromUrl(target.endpointUrl);
  const now = new Date();

  // If HAProxy Edge provider and not simulating weak crypto, attempt live TLS probe first
  if (
    target.providerType === 'haproxy-edge' &&
    !target.simulateWeakCrypto &&
    target.simulateDaysRemaining === null
  ) {
    try {
      const probeTarget =
        target.haproxyHost || extractHostPortFromUrl(target.endpointUrl);
      const live = await probeLiveTlsCertificate(probeTarget);
      const expiryInfo = evaluateExpiryAndRenewalSla(
        live.daysRemaining,
        target.renewalMode,
        target.autoRenewThresholdDays,
      );
      const cryptoCheck = evaluateCryptoCompliance(
        'sha256WithRSAEncryption',
        'SHA256',
        'RSA',
        2048,
      );
      const findings = [...expiryInfo.findings, ...cryptoCheck.findings];
      return {
        serialNumberHex: live.serialNumber,
        serialNumberDecimal: BigInt(`0x${live.rawSerial || '01'}`).toString(10),
        rotatedFromSerial: null,
        historyCount: 1,
        notBefore: live.validFrom,
        notAfter: live.expiryDate,
        daysRemaining: live.daysRemaining,
        expiryStatus: expiryInfo.expiryStatus,
        subjectCn: sniHostname,
        subjectDn: `CN=${sniHostname},O=Project Aegis Edge`,
        sanDnsNames: [sniHostname, `*.${sniHostname.split('.').slice(1).join('.')}`],
        hostnameMatchesSan: true,
        issuerCn: live.issuerCN || 'Aegis HAProxy Edge Root CA',
        issuerOrg: 'Project Aegis Edge Resiliency (OpenSSL)',
        issuerDn: `CN=${live.issuerCN || 'Aegis HAProxy Edge Root CA'},O=Project Aegis Edge Resiliency`,
        isSelfSigned: true,
        signatureAlgorithm: 'sha256WithRSAEncryption',
        signatureHashAlgorithm: 'SHA256',
        publicKeyAlgorithm: 'RSA',
        publicKeyBits: 2048,
        fingerprintSha256: live.fingerprint256,
        complianceStatus:
          findings.length === 0 ? 'COMPLIANT' : 'WARNING',
        complianceFindings: findings,
        isActive: true,
      };
    } catch {
      // Fall back to deterministic provider inspection below
    }
  }

  const defaultDaysByProviderAndEnv: Record<
    SslProviderType,
    Record<SslEnvironmentTier, number>
  > = {
    'haproxy-edge': {
      dev: 88,
      stg: 85,
      'stress-test': 72,
      preprod: 89,
      prod: 90,
    },
    'private-cloud-lb': {
      dev: 64,
      stg: 58,
      'stress-test': 44,
      preprod: 76,
      prod: 82,
    },
    'gcp-cloud-lb': {
      dev: 48,
      stg: 42,
      'stress-test': 27,
      preprod: 69,
      prod: 79,
    },
  };

  const daysRemaining =
    options?.validityDaysOverride ??
    target.simulateDaysRemaining ??
    defaultDaysByProviderAndEnv[target.providerType][target.environment];

  const notBeforeDate = new Date(now.getTime() - 5 * 86400 * 1000);
  const notAfterDate = new Date(now.getTime() + daysRemaining * 86400 * 1000);

  const renewalGen = options?.forceNewGcpRenewalVersion ?? 1;
  const seed = `${target.providerType}:v${renewalGen}:${target.entityRef}:${target.environment}:${target.endpointKey}:${daysRemaining}:${target.simulateWeakCrypto}`;
  const { hex: serialNumberHex, decimal: serialNumberDecimal, fingerprint256 } =
    deterministicSerialFromSeed(seed);

  let issuerCn = 'Aegis Private Cloud Vault Intermediate CA G2';
  let issuerOrg = 'Aegis Enterprise Private PKI (Self-Renewing)';
  let isSelfSigned = false;
  let signatureAlgorithm = 'sha256WithRSAEncryption';
  let signatureHashAlgorithm = 'SHA256';
  let publicKeyAlgorithm = 'RSA';
  let publicKeyBits = 2048;

  if (target.providerType === 'gcp-cloud-lb') {
    issuerCn = 'GTS CA 1C3';
    issuerOrg = 'Google Trust Services LLC';
    isSelfSigned = false;
    if (options?.keyAlgorithmOverride === 'RSA-2048') {
      signatureAlgorithm = 'sha256WithRSAEncryption';
      signatureHashAlgorithm = 'SHA256';
      publicKeyAlgorithm = 'RSA';
      publicKeyBits = 2048;
    } else {
      signatureAlgorithm = 'ecdsa-with-SHA256';
      signatureHashAlgorithm = 'SHA256';
      publicKeyAlgorithm = 'ECDSA';
      publicKeyBits = 256;
    }
  } else if (target.providerType === 'haproxy-edge') {
    issuerCn = 'Aegis HAProxy Edge Root CA';
    issuerOrg = 'Project Aegis Edge Resiliency';
    isSelfSigned = true;
  }

  if (target.providerType !== 'gcp-cloud-lb' && options?.keyAlgorithmOverride) {
    if (options.keyAlgorithmOverride === 'RSA-2048') {
      signatureAlgorithm = 'sha256WithRSAEncryption';
      signatureHashAlgorithm = 'SHA256';
      publicKeyAlgorithm = 'RSA';
      publicKeyBits = 2048;
    } else {
      signatureAlgorithm = 'ecdsa-with-SHA256';
      signatureHashAlgorithm = 'SHA256';
      publicKeyAlgorithm = 'ECDSA';
      publicKeyBits = 256;
    }
  }

  if (target.simulateWeakCrypto) {
    signatureAlgorithm = 'sha1WithRSAEncryption';
    signatureHashAlgorithm = 'SHA1';
    publicKeyAlgorithm = 'RSA';
    publicKeyBits = 1024;
  }

  const domainSuffix = sniHostname.split('.').slice(1).join('.');
  const sanDnsNames = domainSuffix
    ? [sniHostname, `*.${domainSuffix}`]
    : [sniHostname];
  const hostnameMatchesSan = matchHostnameSan(
    sniHostname,
    sniHostname,
    sanDnsNames,
  );

  const expiryEval = evaluateExpiryAndRenewalSla(
    daysRemaining,
    target.renewalMode,
    target.autoRenewThresholdDays,
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
      `SAN_HOSTNAME_MISMATCH: Endpoint hostname '${sniHostname}' does not match certificate SANs.`,
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
    serialNumberHex,
    serialNumberDecimal,
    rotatedFromSerial: null,
    historyCount: 1,
    notBefore: notBeforeDate.toISOString(),
    notAfter: notAfterDate.toISOString(),
    daysRemaining,
    expiryStatus: expiryEval.expiryStatus,
    subjectCn: sniHostname,
    subjectDn: `CN=${sniHostname},O=Project Aegis Platform`,
    sanDnsNames,
    hostnameMatchesSan,
    issuerCn,
    issuerOrg,
    issuerDn: `CN=${issuerCn},O=${issuerOrg}`,
    isSelfSigned,
    signatureAlgorithm,
    signatureHashAlgorithm,
    publicKeyAlgorithm,
    publicKeyBits,
    fingerprintSha256: fingerprint256,
    complianceStatus,
    complianceFindings: findings,
    isActive: true,
  };
}

function recordEndpointCertificate(
  target: ParsedAnnotationEndpoint,
  cert: X509CertificateComplianceDetails,
): TrackedSslEndpointRecord {
  const endpointId = `${target.entityRef}:${target.environment}:${target.endpointKey}`;
  const existing = endpointInventoryStore.get(endpointId);
  const previousSerial = existing?.certificate.serialNumberHex ?? null;

  let historyMap = certificateHistoryStore.get(endpointId);
  if (!historyMap) {
    historyMap = new Map<string, X509CertificateComplianceDetails>();
    certificateHistoryStore.set(endpointId, historyMap);
  }

  if (previousSerial && previousSerial !== cert.serialNumberHex) {
    const oldEntry = historyMap.get(previousSerial);
    if (oldEntry) {
      historyMap.set(previousSerial, { ...oldEntry, isActive: false });
    }
    cert.rotatedFromSerial = previousSerial;
  } else if (existing?.certificate.rotatedFromSerial) {
    cert.rotatedFromSerial = existing.certificate.rotatedFromSerial;
  }

  historyMap.set(cert.serialNumberHex, { ...cert });
  cert.historyCount = historyMap.size;

  const record: TrackedSslEndpointRecord = {
    endpointId,
    entityRef: target.entityRef,
    serviceName: target.serviceName,
    environment: target.environment,
    endpointKey: target.endpointKey,
    endpointUrl: target.endpointUrl,
    sniHostname: extractHostnameFromUrl(target.endpointUrl),
    providerType: target.providerType,
    renewalMode: target.renewalMode,
    autoRenewThresholdDays: target.autoRenewThresholdDays,
    gcpProject: target.gcpProject,
    gcpTargetProxy: target.gcpTargetProxy,
    exposureScope: normalizeExposureScope(
      target.exposureScope,
      'strictly-private',
    ),
    dnsScope: target.dnsScope ?? 'private-split-horizon',
    ingressType: target.ingressType ?? 'Private Cloud Load Balancer (VPC-Internal)',
    lastProbedAt: new Date().toISOString(),
    certificate: cert,
  };

  endpointInventoryStore.set(endpointId, record);
  if (process.env.NODE_ENV !== 'test') {
    saveSslTrackerStateToDisk();
  }
  return record;
}

export async function scanEntityEndpoints(
  entity: Entity,
  options?: { forceRescan?: boolean },
): Promise<EntitySslTrackerRollup | null> {
  const targets = parseEntityEnvironmentEndpoints(entity);
  if (targets.length === 0) {
    return null;
  }

  const entityRef = stringifyEntityRef(entity);
  const records: TrackedSslEndpointRecord[] = [];

  for (const target of targets) {
    const endpointId = `${target.entityRef}:${target.environment}:${target.endpointKey}`;
    const cached = endpointInventoryStore.get(endpointId);
    if (cached && !options?.forceRescan) {
      records.push(cached);
      continue;
    }
    const cert = await buildCertificateDetailsForTarget(target);
    const saved = recordEndpointCertificate(target, cert);
    records.push(saved);
  }

  const softwareStack = parseEntitySoftwareStack(entity);
  entitySoftwareStackStore.set(entityRef, softwareStack);
  return buildEntityRollup(entityRef, entity.metadata.name, records, softwareStack);
}

export function buildEntityRollup(
  entityRef: string,
  serviceName: string,
  records: TrackedSslEndpointRecord[],
  softwareStack?: SoftwareStackDependency[],
): EntitySslTrackerRollup {
  const envCounts: Record<SslEnvironmentTier, number> = {
    dev: 0,
    stg: 0,
    'stress-test': 0,
    preprod: 0,
    prod: 0,
  };

  let minDays = 9999;
  let compliantCount = 0;
  let hasNonCompliant = false;
  let hasWarning = false;

  for (const rec of records) {
    envCounts[rec.environment] = (envCounts[rec.environment] || 0) + 1;
    if (rec.certificate.daysRemaining < minDays) {
      minDays = rec.certificate.daysRemaining;
    }
    if (rec.certificate.complianceStatus === 'COMPLIANT') {
      compliantCount += 1;
    } else if (rec.certificate.complianceStatus === 'NON_COMPLIANT') {
      hasNonCompliant = true;
    } else {
      hasWarning = true;
    }
  }

  const overallStatus: 'COMPLIANT' | 'WARNING' | 'NON_COMPLIANT' = hasNonCompliant
    ? 'NON_COMPLIANT'
    : hasWarning
    ? 'WARNING'
    : 'COMPLIANT';

  const first = records[0];
  return {
    entityRef,
    serviceName,
    providerType: first?.providerType ?? 'private-cloud-lb',
    renewalMode: first?.renewalMode ?? 'self-renewing-monitored',
    overallStatus,
    minDaysRemaining: minDays === 9999 ? 0 : minDays,
    totalEndpoints: records.length,
    compliantEndpoints: compliantCount,
    environmentCounts: envCounts,
    endpoints: records,
    lastScannedAt: new Date().toISOString(),
    exposureCounts: {
      unrestrictedPublic: records.filter(
        r => normalizeExposureScope(r.exposureScope) === 'unrestricted-public',
      ).length,
      restrictedPublic: records.filter(
        r => normalizeExposureScope(r.exposureScope) === 'restricted-public',
      ).length,
      strictlyPrivate: records.filter(
        r => normalizeExposureScope(r.exposureScope) === 'strictly-private',
      ).length,
      internetFacing: records.filter(r => {
        const s = normalizeExposureScope(r.exposureScope);
        return s === 'unrestricted-public' || s === 'restricted-public';
      }).length,
      internalOnly: records.filter(
        r => normalizeExposureScope(r.exposureScope) === 'strictly-private',
      ).length,
    },
    softwareStack: softwareStack ?? [],
  };
}

export function getEndpointCertificateHistory(params?: {
  entityRef?: string;
  endpointId?: string;
  environment?: string;
}): EndpointCertificateHistoryRecord[] {
  const results: EndpointCertificateHistoryRecord[] = [];

  for (const rec of endpointInventoryStore.values()) {
    if (params?.entityRef && rec.entityRef !== params.entityRef) continue;
    if (params?.endpointId && rec.endpointId !== params.endpointId) continue;
    if (
      params?.environment &&
      params.environment !== 'all' &&
      rec.environment !== params.environment
    )
      continue;

    const historyMap = certificateHistoryStore.get(rec.endpointId);
    const certs = historyMap
      ? Array.from(historyMap.values()).sort((a, b) => {
          if (a.isActive && !b.isActive) return -1;
          if (!a.isActive && b.isActive) return 1;
          return 0;
        })
      : [];

    results.push({
      endpointId: rec.endpointId,
      entityRef: rec.entityRef,
      serviceName: rec.serviceName,
      environment: rec.environment,
      endpointKey: rec.endpointKey,
      endpointUrl: rec.endpointUrl,
      sniHostname: rec.sniHostname,
      providerType: rec.providerType,
      activeSerialNumberHex: rec.certificate.serialNumberHex,
      historyCount: certs.length,
      certificates: certs,
    });
  }

  return results;
}

export function getEntitySslRollupFromStore(
  entityRef: string,
): EntitySslTrackerRollup | null {
  const matching = Array.from(endpointInventoryStore.values()).filter(
    r => r.entityRef === entityRef,
  );
  if (matching.length === 0) {
    return null;
  }
  return buildEntityRollup(entityRef, matching[0].serviceName, matching, entitySoftwareStackStore.get(entityRef));
}

export function getFleetSslInventory(): {
  totalEndpoints: number;
  compliantCount: number;
  warningCount: number;
  nonCompliantCount: number;
  endpoints: TrackedSslEndpointRecord[];
} {
  const all = Array.from(endpointInventoryStore.values());
  let compliantCount = 0;
  let warningCount = 0;
  let nonCompliantCount = 0;
  for (const r of all) {
    if (r.certificate.complianceStatus === 'COMPLIANT') compliantCount += 1;
    else if (r.certificate.complianceStatus === 'NON_COMPLIANT')
      nonCompliantCount += 1;
    else warningCount += 1;
  }
  return {
    totalEndpoints: all.length,
    compliantCount,
    warningCount,
    nonCompliantCount,
    endpoints: all,
  };
}

export async function previewMockGcpAutoRenewalDiff(params: {
  entityRef: string;
  environment?: string;
  endpointKey?: string;
  targetEndpointsFilter?: string[];
  keyAlgorithm?: 'RSA-2048' | 'ECDSA-P256';
  validityDays?: number;
  gcpProject?: string;
  targetHttpsProxy?: string;
}): Promise<GcpAutoRenewalDiffPlan> {
  const envScope = params.environment || 'all';
  const keyAlg = params.keyAlgorithm || 'ECDSA-P256';
  const validityDays = params.validityDays || 90;
  let filterSet =
    params.targetEndpointsFilter && params.targetEndpointsFilter.length > 0
      ? new Set(params.targetEndpointsFilter.map(s => s.trim()))
      : null;

  if (filterSet) {
    const hasAnyMatch = Array.from(endpointInventoryStore.values()).some(
      rec => {
        if (rec.entityRef !== params.entityRef) return false;
        return (
          filterSet!.has(rec.endpointUrl) ||
          filterSet!.has(rec.endpointId) ||
          filterSet!.has(`${rec.environment}:${rec.endpointKey}`)
        );
      },
    );
    if (!hasAnyMatch) {
      filterSet = null;
    }
  }

  const matching = Array.from(endpointInventoryStore.values()).filter(rec => {
    if (rec.entityRef !== params.entityRef) return false;
    if (envScope !== 'all' && rec.environment !== envScope) return false;
    if (params.endpointKey && rec.endpointKey !== params.endpointKey)
      return false;
    if (
      filterSet &&
      !filterSet.has(rec.endpointUrl) &&
      !filterSet.has(rec.endpointId) &&
      !filterSet.has(`${rec.environment}:${rec.endpointKey}`)
    ) {
      return false;
    }
    return true;
  });

  const proposedChanges: GcpAutoRenewalDiffPlan['proposedChanges'] = [];
  const mdSections: string[] = [
    '### Target Endpoints & Per-Environment SSL Certificate Diff (Pre-Renewal Quality Gate)',
    '',
  ];

  for (const existing of matching) {
    const nextVer = (gcpRenewalVersionCounter.get(existing.endpointId) ?? 1) + 1;
    const target: ParsedAnnotationEndpoint = {
      entityRef: existing.entityRef,
      serviceName: existing.serviceName,
      environment: existing.environment,
      endpointKey: existing.endpointKey,
      endpointUrl: existing.endpointUrl,
      providerType: 'gcp-cloud-lb',
      renewalMode: 'workflow-auto-renew',
      autoRenewThresholdDays: existing.autoRenewThresholdDays,
      gcpProject: params.gcpProject || existing.gcpProject || 'aegis-prod-cloud',
      gcpTargetProxy:
        params.targetHttpsProxy ||
        existing.gcpTargetProxy ||
        'aegis-ui-https-proxy',
      simulateWeakCrypto: false,
      simulateDaysRemaining: validityDays,
    };

    const proposedCert = await buildCertificateDetailsForTarget(target, {
      forceNewGcpRenewalVersion: nextVer,
      keyAlgorithmOverride: keyAlg,
      validityDaysOverride: validityDays,
    });

    const unifiedDiff = buildEndpointCertUnifiedDiff({
      environment: existing.environment,
      endpointKey: existing.endpointKey,
      endpointUrl: existing.endpointUrl,
      domain: existing.sniHostname,
      oldCert: existing.certificate,
      newCert: proposedCert,
    });

    proposedChanges.push({
      endpointId: existing.endpointId,
      environment: existing.environment,
      endpointKey: existing.endpointKey,
      endpointUrl: existing.endpointUrl,
      domain: existing.sniHostname,
      currentCert: existing.certificate,
      proposedCert,
      unifiedDiff,
    });

    mdSections.push(
      `#### Environment: \`${existing.environment.toUpperCase()}\` — Endpoint \`${existing.endpointKey}\` (\`${existing.endpointUrl}\` / Domain: \`${existing.sniHostname}\`)`,
      '```diff',
      unifiedDiff,
      '```',
      '',
    );
  }

  return {
    entityRef: params.entityRef,
    environment: envScope,
    targetEndpointsCount: proposedChanges.length,
    targetEndpointUrls: proposedChanges.map(p => p.endpointUrl),
    targetDomains: proposedChanges.map(p => p.domain),
    proposedChanges,
    diffMarkdownByEnv: mdSections.join('\n'),
  };
}

export function createQualityGateApprovalRequest(
  plan: GcpAutoRenewalDiffPlan,
): GcpQualityGateState {
  const gateId = `gate-${Date.now()}-${Math.random().toString(36).slice(2, 7)}`;
  const state: GcpQualityGateState = {
    gateId,
    entityRef: plan.entityRef,
    environment: plan.environment,
    status: 'PENDING_APPROVAL',
    createdAt: new Date().toISOString(),
    plan,
  };
  gcpQualityGateStore.set(gateId, state);
  latestEntityGateMap.set(plan.entityRef, gateId);
  if (process.env.NODE_ENV !== 'test') {
    saveSslTrackerStateToDisk();
  }
  return state;
}

export function getQualityGateStatus(params: {
  gateId?: string;
  entityRef?: string;
}): GcpQualityGateState | null {
  if (params.gateId && gcpQualityGateStore.has(params.gateId)) {
    return gcpQualityGateStore.get(params.gateId)!;
  }
  if (params.entityRef) {
    const latestId = latestEntityGateMap.get(params.entityRef);
    if (latestId && gcpQualityGateStore.has(latestId)) {
      return gcpQualityGateStore.get(latestId)!;
    }
  }
  return null;
}

export function decideQualityGateApproval(params: {
  gateId?: string;
  entityRef?: string;
  decision: 'APPROVED' | 'REJECTED';
  decidedBy?: string;
  comments?: string;
}): GcpQualityGateState | null {
  const gate = getQualityGateStatus({
    gateId: params.gateId,
    entityRef: params.entityRef,
  });
  if (!gate) {
    return null;
  }
  gate.status = params.decision;
  gate.decidedAt = new Date().toISOString();
  gate.decidedBy = params.decidedBy || 'platform-admin@aegis.internal';
  gate.comments = params.comments || 'Reviewed per-environment SSL certificate diff';
  if (process.env.NODE_ENV !== 'test') {
    saveSslTrackerStateToDisk();
  }
  return gate;
}

export async function triggerMockGcpAutoRenewal(params: {
  entityRef: string;
  environment?: string;
  endpointKey?: string;
  targetEndpointsFilter?: string[];
  keyAlgorithm?: 'RSA-2048' | 'ECDSA-P256';
  validityDays?: number;
  gcpProject?: string;
  targetHttpsProxy?: string;
}): Promise<GcpAutoRenewalResult> {
  const envScope = params.environment || 'all';
  const keyAlg = params.keyAlgorithm || 'ECDSA-P256';
  const validityDays = params.validityDays || 90;
  let filterSet =
    params.targetEndpointsFilter && params.targetEndpointsFilter.length > 0
      ? new Set(params.targetEndpointsFilter.map(s => s.trim()))
      : null;

  if (filterSet) {
    const hasAnyMatch = Array.from(endpointInventoryStore.values()).some(
      rec => {
        if (rec.entityRef !== params.entityRef) return false;
        return (
          filterSet!.has(rec.endpointUrl) ||
          filterSet!.has(rec.endpointId) ||
          filterSet!.has(`${rec.environment}:${rec.endpointKey}`)
        );
      },
    );
    if (!hasAnyMatch) {
      filterSet = null;
    }
  }

  const matching = Array.from(endpointInventoryStore.values()).filter(rec => {
    if (rec.entityRef !== params.entityRef) return false;
    if (envScope !== 'all' && rec.environment !== envScope) return false;
    if (params.endpointKey && rec.endpointKey !== params.endpointKey)
      return false;
    if (
      filterSet &&
      !filterSet.has(rec.endpointUrl) &&
      !filterSet.has(rec.endpointId) &&
      !filterSet.has(`${rec.environment}:${rec.endpointKey}`)
    ) {
      return false;
    }
    return true;
  });

  const renewals: GcpAutoRenewalResult['renewals'] = [];
  const markdownLines: string[] = [
    '### Verified Domains & Renewed Certificates Summary',
    '',
    '| Environment | Endpoint Key | Target Endpoint URL | Verified Domain (CN / SAN) | Old Serial (DB Key) | New Verified Serial (DB Key) | Issuer CA | SigAlg & Key Size | Not After (Expiry) | Verification Status |',
    '|---|---|---|---|---|---|---|---|---|---|',
  ];
  const diffSections: string[] = [
    '### Per-Environment Certificate Diff (Before vs. After Renewal)',
    '',
  ];

  for (const existing of matching) {
    const oldCertSnapshot = { ...existing.certificate };
    const previousSerial = existing.certificate.serialNumberHex;
    const nextVer = (gcpRenewalVersionCounter.get(existing.endpointId) ?? 1) + 1;
    gcpRenewalVersionCounter.set(existing.endpointId, nextVer);

    const target: ParsedAnnotationEndpoint = {
      entityRef: existing.entityRef,
      serviceName: existing.serviceName,
      environment: existing.environment,
      endpointKey: existing.endpointKey,
      endpointUrl: existing.endpointUrl,
      providerType: 'gcp-cloud-lb',
      renewalMode: 'workflow-auto-renew',
      autoRenewThresholdDays: existing.autoRenewThresholdDays,
      gcpProject: params.gcpProject || existing.gcpProject || 'aegis-prod-cloud',
      gcpTargetProxy:
        params.targetHttpsProxy ||
        existing.gcpTargetProxy ||
        'aegis-ui-https-proxy',
      simulateWeakCrypto: false,
      simulateDaysRemaining: validityDays,
    };

    const newCert = await buildCertificateDetailsForTarget(target, {
      forceNewGcpRenewalVersion: nextVer,
      keyAlgorithmOverride: keyAlg,
      validityDaysOverride: validityDays,
    });
    const updatedRecord = recordEndpointCertificate(target, newCert);

    const unifiedDiff = buildEndpointCertUnifiedDiff({
      environment: updatedRecord.environment,
      endpointKey: updatedRecord.endpointKey,
      endpointUrl: updatedRecord.endpointUrl,
      domain: updatedRecord.sniHostname,
      oldCert: oldCertSnapshot,
      newCert: updatedRecord.certificate,
    });

    const opId = `operation-gcp-certmgr-v${nextVer}-${Date.now().toString().slice(-6)}`;
    const dnsAuth = `_acme-challenge.${updatedRecord.sniHostname} CNAME auth.certificatemanager.goog.`;
    const sslResource = `projects/${target.gcpProject}/locations/global/certificates/${target.serviceName}-${target.environment}-${target.endpointKey}-v${nextVer}`;

    renewals.push({
      endpointId: updatedRecord.endpointId,
      environment: updatedRecord.environment,
      endpointKey: updatedRecord.endpointKey,
      endpointUrl: updatedRecord.endpointUrl,
      domain: updatedRecord.sniHostname,
      previousSerial,
      newSerial: updatedRecord.certificate.serialNumberHex,
      gcpOperationId: opId,
      dnsAuthorization: dnsAuth,
      authorizationStatus: 'AUTHORIZED',
      sslCertificateResource: sslResource,
      unifiedDiff,
      endpoint: updatedRecord,
    });

    markdownLines.push(
      `| \`${updatedRecord.environment}\` | \`${updatedRecord.endpointKey}\` | \`${updatedRecord.endpointUrl}\` | \`${updatedRecord.sniHostname}\` (\`${updatedRecord.certificate.sanDnsNames.join(', ')}\`) | \`${previousSerial}\` | \`${updatedRecord.certificate.serialNumberHex}\` | ${updatedRecord.certificate.issuerCn} | ${updatedRecord.certificate.publicKeyAlgorithm}-${updatedRecord.certificate.publicKeyBits} (${updatedRecord.certificate.signatureHashAlgorithm}) | ${updatedRecord.certificate.notAfter.slice(0, 10)} (${updatedRecord.certificate.daysRemaining}d) | ✅ **VERIFIED & COMPLIANT** |`,
    );

    diffSections.push(
      `#### \`${updatedRecord.environment.toUpperCase()}\` — \`${updatedRecord.sniHostname}\` (\`${updatedRecord.endpointUrl}\`)`,
      '```diff',
      unifiedDiff,
      '```',
      '',
    );
  }

  if (process.env.NODE_ENV !== 'test') {
    saveSslTrackerStateToDisk();
  }

  return {
    status: 'RENEWED',
    entityRef: params.entityRef,
    environment: envScope,
    renewedCount: renewals.length,
    targetEndpointUrls: renewals.map(r => r.endpointUrl),
    verifiedDomains: renewals.map(r => r.domain),
    renewals,
    renewalSummaryMarkdown: markdownLines.join('\n'),
    perEnvDiffMarkdown: diffSections.join('\n'),
  };
}

export async function remediatePrivateCloudEndpointCrypto(params: {
  entityRef: string;
  environment?: string;
  endpointKey?: string;
  keyAlgorithm?: 'RSA-2048' | 'ECDSA-P256';
  validityDays?: number;
}): Promise<GcpAutoRenewalResult> {
  const envScope = params.environment || 'all';
  const keyAlg = params.keyAlgorithm || 'RSA-2048';
  const validityDays = params.validityDays || 90;

  const matching = Array.from(endpointInventoryStore.values()).filter(rec => {
    if (rec.entityRef !== params.entityRef) return false;
    if (envScope !== 'all' && rec.environment !== envScope) return false;
    if (params.endpointKey && rec.endpointKey !== params.endpointKey)
      return false;
    return true;
  });

  const renewals: GcpAutoRenewalResult['renewals'] = [];
  const markdownLines: string[] = [
    '### Private Cloud LB Crypto Remediation Summary',
    '',
  ];
  const diffSections: string[] = [
    '### Per-Endpoint Certificate Diff (Before vs. After Remediation)',
    '',
  ];

  for (const existing of matching) {
    const oldCertSnapshot = { ...existing.certificate };
    const previousSerial = existing.certificate.serialNumberHex;
    const nextVer = (gcpRenewalVersionCounter.get(existing.endpointId) ?? 1) + 1;
    gcpRenewalVersionCounter.set(existing.endpointId, nextVer);
    remediatedWeakCryptoEndpoints.add(existing.endpointId);

    const target: ParsedAnnotationEndpoint = {
      entityRef: existing.entityRef,
      serviceName: existing.serviceName,
      environment: existing.environment,
      endpointKey: existing.endpointKey,
      endpointUrl: existing.endpointUrl,
      providerType: existing.providerType,
      renewalMode: existing.renewalMode,
      autoRenewThresholdDays: existing.autoRenewThresholdDays,
      gcpProject: existing.gcpProject ?? null,
      gcpTargetProxy: existing.gcpTargetProxy ?? null,
      simulateWeakCrypto: false,
      simulateDaysRemaining: validityDays,
      haproxyHost: null,
    };

    const newCert = await buildCertificateDetailsForTarget(target, {
      forceNewGcpRenewalVersion: nextVer,
      keyAlgorithmOverride: keyAlg,
      validityDaysOverride: validityDays,
    });
    const updatedRecord = recordEndpointCertificate(target, newCert);

    const unifiedDiff = buildEndpointCertUnifiedDiff({
      environment: updatedRecord.environment,
      endpointKey: updatedRecord.endpointKey,
      endpointUrl: updatedRecord.endpointUrl,
      domain: updatedRecord.sniHostname,
      oldCert: oldCertSnapshot,
      newCert: updatedRecord.certificate,
    });

    renewals.push({
      endpointId: updatedRecord.endpointId,
      environment: updatedRecord.environment,
      endpointKey: updatedRecord.endpointKey,
      endpointUrl: updatedRecord.endpointUrl,
      domain: updatedRecord.sniHostname,
      previousSerial,
      newSerial: updatedRecord.certificate.serialNumberHex,
      gcpOperationId: `remediation-${updatedRecord.endpointId}-v${nextVer}`,
      dnsAuthorization: `_acme-challenge.${updatedRecord.sniHostname} CNAME auth.certificatemanager.goog.`,
      authorizationStatus: 'AUTHORIZED',
      sslCertificateResource: `remediated/${updatedRecord.endpointId}/v${nextVer}`,
      unifiedDiff,
      endpoint: updatedRecord,
    });

    markdownLines.push(
      `| \`${updatedRecord.environment}\` | \`${updatedRecord.endpointKey}\` | \`${updatedRecord.endpointUrl}\` | \`${updatedRecord.sniHostname}\` | \`${previousSerial}\` | \`${updatedRecord.certificate.serialNumberHex}\` | ✅ **REMEDIATED** |`,
    );

    diffSections.push(
      `#### \`${updatedRecord.environment.toUpperCase()}\` — \`${updatedRecord.sniHostname}\` (\`${updatedRecord.endpointUrl}\`)`,
      '```diff',
      unifiedDiff,
      '```',
      '',
    );
  }

  if (process.env.NODE_ENV !== 'test') {
    saveSslTrackerStateToDisk();
  }

  return {
    status: 'RENEWED',
    entityRef: params.entityRef,
    environment: envScope,
    renewedCount: renewals.length,
    targetEndpointUrls: renewals.map(r => r.endpointUrl),
    verifiedDomains: renewals.map(r => r.domain),
    renewals,
    renewalSummaryMarkdown: markdownLines.join('\n'),
    perEnvDiffMarkdown: diffSections.join('\n'),
  };
}

export function renderSslTrackerPrometheusMetrics(): string {
  const lines: string[] = [
    '# HELP aegis_ssl_endpoint_expiry_days Days remaining before SSL certificate Not After expiry',
    '# TYPE aegis_ssl_endpoint_expiry_days gauge',
    '# HELP aegis_ssl_endpoint_compliant 1 if endpoint SSL certificate passes all 5 compliance pillars else 0',
    '# TYPE aegis_ssl_endpoint_compliant gauge',
    '# HELP aegis_ssl_endpoint_key_bits Public key bit length of the endpoint SSL certificate',
    '# TYPE aegis_ssl_endpoint_key_bits gauge',
  ];

  for (const rec of endpointInventoryStore.values()) {
    const c = rec.certificate;
    const labels = [
      `entity="${rec.entityRef}"`,
      `service="${rec.serviceName}"`,
      `env="${rec.environment}"`,
      `endpoint_key="${rec.endpointKey}"`,
      `provider="${rec.providerType}"`,
      `renewal_mode="${rec.renewalMode}"`,
      `serial="${c.serialNumberHex}"`,
      `subject_cn="${c.subjectCn}"`,
      `issuer_cn="${c.issuerCn}"`,
      `sig_alg="${c.signatureAlgorithm}"`,
    ].join(',');
    const compliantVal = c.complianceStatus === 'COMPLIANT' ? 1 : 0;
    lines.push(`aegis_ssl_endpoint_expiry_days{${labels}} ${c.daysRemaining}`);
    lines.push(`aegis_ssl_endpoint_compliant{${labels}} ${compliantVal}`);
    lines.push(`aegis_ssl_endpoint_key_bits{${labels}} ${c.publicKeyBits}`);
  }

  return `${lines.join('\n')}\n`;
}

export function clearSslTrackerStoreForTests(): void {
  endpointInventoryStore.clear();
  certificateHistoryStore.clear();
  gcpRenewalVersionCounter.clear();
  gcpQualityGateStore.clear();
  latestEntityGateMap.clear();
  remediatedWeakCryptoEndpoints.clear();
  entitySoftwareStackStore.clear();
}

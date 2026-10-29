import { useCallback, useEffect, useMemo, useState } from 'react';
import { createFrontendModule } from '@backstage/frontend-plugin-api';
import {
  discoveryApiRef,
  fetchApiRef,
  identityApiRef,
  useApi,
} from '@backstage/core-plugin-api';
import { EntityCardBlueprint } from '@backstage/plugin-catalog-react/alpha';
import { useEntity } from '@backstage/plugin-catalog-react';
import { InfoCard, LinkButton } from '@backstage/core-components';
import { stringifyEntityRef } from '@backstage/catalog-model';

const DEFAULT_SSL_TRACKER_BASE_URL = 'http://localhost:7007/api/ssl-tracker';

function useSslTrackerBackendClient() {
  let discoveryApi: { getBaseUrl(pluginId: string): Promise<string> } | null =
    null;
  let fetchApi: { fetch: typeof fetch } | null = null;
  let identityApi: {
    getBackstageIdentity(): Promise<{ userEntityRef: string }>;
  } | null = null;

  try {
    // eslint-disable-next-line react-hooks/rules-of-hooks
    discoveryApi = useApi(discoveryApiRef);
  } catch {
    discoveryApi = null;
  }
  try {
    // eslint-disable-next-line react-hooks/rules-of-hooks
    fetchApi = useApi(fetchApiRef);
  } catch {
    fetchApi = null;
  }
  try {
    // eslint-disable-next-line react-hooks/rules-of-hooks
    identityApi = useApi(identityApiRef);
  } catch {
    identityApi = null;
  }

  const getBaseUrl = useCallback(async (): Promise<string> => {
    if (discoveryApi) {
      try {
        return await discoveryApi.getBaseUrl('ssl-tracker');
      } catch {
        return DEFAULT_SSL_TRACKER_BASE_URL;
      }
    }
    return DEFAULT_SSL_TRACKER_BASE_URL;
  }, [discoveryApi]);

  const apiFetch = useCallback(
    async (subPath: string, init?: RequestInit): Promise<Response> => {
      const base = await getBaseUrl();
      const normalizedPath = subPath.startsWith('/') ? subPath : `/${subPath}`;
      const url = `${base.replace(/\/$/, '')}${normalizedPath}`;
      if (fetchApi) {
        return fetchApi.fetch(url, init);
      }
      return fetch(url, init);
    },
    [fetchApi, getBaseUrl],
  );

  return { getBaseUrl, apiFetch, identityApi };
}

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

export function getExposureTierMeta(scope?: string | null) {
  const normalized = normalizeExposureScope(scope);
  if (normalized === 'unrestricted-public') {
    return {
      key: 'unrestricted-public' as const,
      tier: 'Tier 1: Unrestricted Public',
      shortBadge: '🌐 Unrestricted Public',
      analogy: '🏪 Retail Storefront (Open Doors)',
      businessTerm: 'Customer-Facing / Open Edge',
      whoCanReach: 'Anyone on the internet.',
      protection: 'WAF, DDoS mitigation, Bot protection, App-level Auth.',
      auditGoal:
        'Ensure edge hardening (WAF/Rate limits) is active and no internal data leaks here.',
      bg: '#e1f5fe',
      fg: '#01579b',
      border: '#0288d1',
    };
  }
  if (normalized === 'restricted-public') {
    return {
      key: 'restricted-public' as const,
      tier: 'Tier 2: Restricted Public (ACL-Gated)',
      shortBadge: '🛡️ Restricted Public (ACL-Gated)',
      analogy: '🏢 Office Lobby (Badge Scanner at Door)',
      businessTerm: 'Partner / B2B-Facing • Authenticated Edge',
      whoCanReach:
        'Anyone on the internet can see it; only approved IPs/identities pass the gate.',
      protection: 'Perimeter ACLs, IP Allowlists, Identity-Aware Proxy (IAP).',
      auditGoal:
        'The Audit Danger Zone: Verify why this is not Tier 3. Ensure ACLs are not overly permissive.',
      bg: '#fff3e0',
      fg: '#e65100',
      border: '#f57c00',
    };
  }
  return {
    key: 'strictly-private' as const,
    tier: 'Tier 3: Strictly Private (Internal)',
    shortBadge: '🔒 Strictly Private',
    analogy: '🏦 Underground Vault (Hidden Inside Compound)',
    businessTerm: 'Employee / System-Only • Private Core',
    whoCanReach:
      'Nobody from the outside; requires active VPN or internal network connection.',
    protection: 'Private DNS, VPC isolation, Zero Trust Network Access (ZTNA).',
    auditGoal:
      'Confirm zero public DNS resolution or accidental public routing.',
    bg: '#ede7f6',
    fg: '#4a148c',
    border: '#673ab3',
  };
}

export type DnsResolutionScope =
  | 'public-authoritative'
  | 'private-split-horizon';
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

const ENV_TIERS: readonly SslEnvironmentTier[] = [
  'dev',
  'stg',
  'stress-test',
  'preprod',
  'prod',
];

interface X509CertificateComplianceDetails {
  serialNumberHex: string;
  serialNumberDecimal: string;
  rotatedFromSerial: string | null;
  historyCount: number;
  notBefore: string;
  notAfter: string;
  daysRemaining: number;
  expiryStatus: 'HEALTHY' | 'WARNING' | 'CRITICAL' | 'EXPIRED';
  subjectCn: string;
  subjectDn: string;
  sanDnsNames: string[];
  hostnameMatchesSan: boolean;
  issuerCn: string;
  issuerOrg: string;
  issuerDn: string;
  isSelfSigned: boolean;
  signatureAlgorithm: string;
  signatureHashAlgorithm: string;
  publicKeyAlgorithm: string;
  publicKeyBits: number;
  fingerprintSha256: string;
  complianceStatus: 'COMPLIANT' | 'WARNING' | 'NON_COMPLIANT';
  complianceFindings: string[];
  isActive: boolean;
}

interface TrackedSslEndpointRecord {
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

interface EntitySslTrackerRollup {
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
  exposureCounts?: {
    unrestrictedPublic?: number;
    restrictedPublic?: number;
    strictlyPrivate?: number;
    internetFacing: number;
    internalOnly: number;
  };
  softwareStack?: SoftwareStackDependency[];
  lastScannedAt: string;
  qualityGate?: GcpQualityGateState | null;
}

interface GcpEndpointCertDiffEntry {
  endpointId: string;
  environment: SslEnvironmentTier;
  endpointKey: string;
  endpointUrl: string;
  domain: string;
  currentCert: X509CertificateComplianceDetails;
  proposedCert: X509CertificateComplianceDetails;
  unifiedDiff: string;
}

interface GcpAutoRenewalDiffPlan {
  entityRef: string;
  environment: string;
  targetEndpointsCount: number;
  targetEndpointUrls: string[];
  targetDomains: string[];
  proposedChanges: GcpEndpointCertDiffEntry[];
  diffMarkdownByEnv: string;
}

interface GcpQualityGateState {
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

interface VerifiedDomainCertRecord {
  domain: string;
  environment: SslEnvironmentTier;
  endpointKey: string;
  endpointUrl: string;
  subjectCn: string;
  sanDnsNames: string[];
  hostnameMatchesSan: boolean;
  issuerCn: string;
  previousSerialNumberHex: string;
  newSerialNumberHex: string;
  notAfter: string;
  daysRemaining: number;
  signatureAlgorithm: string;
  publicKeyAlgorithm: string;
  publicKeyBits: number;
  complianceStatus: 'COMPLIANT' | 'WARNING' | 'NON_COMPLIANT';
}

interface EndpointCertificateHistoryRecord {
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

function mapRenewalsToVerifiedDomainRecords(
  renewals: any[] | undefined,
): VerifiedDomainCertRecord[] {
  if (!Array.isArray(renewals)) return [];
  return renewals.map(r => {
    const cert: X509CertificateComplianceDetails = r.endpoint?.certificate || {};
    return {
      domain: r.domain,
      environment: r.environment,
      endpointKey: r.endpointKey,
      endpointUrl: r.endpointUrl,
      subjectCn: cert.subjectCn || r.domain,
      sanDnsNames: cert.sanDnsNames || [r.domain],
      hostnameMatchesSan: cert.hostnameMatchesSan ?? true,
      issuerCn: cert.issuerCn || 'GTS CA 1C3',
      previousSerialNumberHex: r.previousSerial,
      newSerialNumberHex: r.newSerial,
      notAfter: cert.notAfter || '',
      daysRemaining: cert.daysRemaining ?? 90,
      signatureAlgorithm: cert.signatureAlgorithm || 'ecdsa-with-SHA256',
      publicKeyAlgorithm: cert.publicKeyAlgorithm || 'ECDSA',
      publicKeyBits: cert.publicKeyBits ?? 256,
      complianceStatus: cert.complianceStatus || 'COMPLIANT',
    };
  });
}

function buildFallbackRollupFromEntity(entity: any): EntitySslTrackerRollup | null {
  const annotations: Record<string, string> = entity?.metadata?.annotations ?? {};
  const prefix = 'resiliency.idp/endpoints.';
  const rawProvider = (
    annotations['resiliency.idp/ssl-provider'] || 'private-cloud-lb'
  ).trim() as SslProviderType;
  const providerType: SslProviderType =
    rawProvider === 'haproxy-edge' ||
    rawProvider === 'gcp-cloud-lb' ||
    rawProvider === 'private-cloud-lb'
      ? rawProvider
      : 'private-cloud-lb';

  const renewalMode: SslRenewalMode =
    providerType === 'gcp-cloud-lb'
      ? 'workflow-auto-renew'
      : providerType === 'haproxy-edge'
      ? 'manual-or-template'
      : 'self-renewing-monitored';

  const entityRef = stringifyEntityRef(entity);
  const serviceName = entity?.metadata?.name || 'service';
  const exposureScope: IngressExposureScope = normalizeExposureScope(
    annotations['resiliency.idp/exposure-scope'],
    providerType === 'gcp-cloud-lb'
      ? 'unrestricted-public'
      : providerType === 'haproxy-edge'
      ? 'restricted-public'
      : 'strictly-private',
  );
  const dnsScope: DnsResolutionScope =
    (annotations['resiliency.idp/dns-scope'] as DnsResolutionScope) ||
    (exposureScope === 'strictly-private'
      ? 'private-split-horizon'
      : 'public-authoritative');
  const ingressType: string =
    annotations['resiliency.idp/ingress-type'] ||
    (providerType === 'gcp-cloud-lb'
      ? 'Cloud External Application Load Balancer (GCP TargetHttpsProxy)'
      : providerType === 'haproxy-edge'
      ? 'Edge Reverse Proxy & HAProxy TLS Gateway'
      : 'Private Cloud Load Balancer (VPC-Internal)');
  const softwareStack: SoftwareStackDependency[] = annotations[
    'resiliency.idp/software-stack'
  ]
    ? (JSON.parse(
        annotations['resiliency.idp/software-stack'],
      ) as SoftwareStackDependency[])
    : [
        {
          name: 'node',
          version: '18.17.0',
          category: 'runtime',
          description: 'Node.js Runtime',
          cveStatus: 'SECURE',
        },
        {
          name: 'nginx',
          version: '1.24.0',
          category: 'web-server',
          description: 'Nginx Web Server',
          cveStatus: 'SECURE',
        },
      ];
  const endpoints: TrackedSslEndpointRecord[] = [];
  const envCounts: Record<SslEnvironmentTier, number> = {
    dev: 0,
    stg: 0,
    'stress-test': 0,
    preprod: 0,
    prod: 0,
  };

  Object.entries(annotations).forEach(([key, rawVal]) => {
    if (!key.startsWith(prefix) || !rawVal) return;
    const rem = key.slice(prefix.length);
    let env: SslEnvironmentTier | null = null;
    let subKey = 'default';
    for (const tier of ENV_TIERS) {
      if (rem === tier) {
        env = tier;
        subKey = 'default';
        break;
      }
      if (rem.startsWith(`${tier}.`)) {
        env = tier;
        subKey = rem.slice(tier.length + 1) || 'default';
        break;
      }
    }
    if (!env) return;

    const urls = rawVal
      .split(',')
      .map(s => s.trim())
      .filter(Boolean);
    urls.forEach((url, idx) => {
      const epKey = urls.length > 1 ? `${subKey}-${idx + 1}` : subKey;
      envCounts[env!] = (envCounts[env!] || 0) + 1;
      let host = 'localhost';
      try {
        host = new URL(url.includes('://') ? url : `https://${url}`).hostname;
      } catch {
        host = 'localhost';
      }
      const isWeakSim =
        annotations[
          `resiliency.idp/ssl-simulate-weak-crypto.${env}.${epKey}`
        ] === 'true';
      const days = env === 'stress-test' ? 35 : 75;
      const notAfter = new Date(Date.now() + days * 86400 * 1000).toISOString();
      const serialHex = `4A:8F:${env!.toUpperCase().slice(0, 2)}:0${idx + 1}:9C:2E:71:B4`;

      const epExposureRaw =
        annotations[`resiliency.idp/exposure-scope.${env}.${epKey}`] ||
        annotations[`resiliency.idp/exposure-scope.${env}.${subKey}`] ||
        annotations[`resiliency.idp/exposure-scope.${env}`];
      const epExposure: IngressExposureScope = epExposureRaw
        ? normalizeExposureScope(epExposureRaw, exposureScope)
        : exposureScope;
      const epDnsScope: DnsResolutionScope = epExposureRaw
        ? epExposure === 'strictly-private'
          ? 'private-split-horizon'
          : 'public-authoritative'
        : dnsScope;

      endpoints.push({
        endpointId: `${entityRef}:${env}:${epKey}`,
        entityRef,
        serviceName,
        environment: env!,
        endpointKey: epKey,
        endpointUrl: url,
        sniHostname: host,
        providerType,
        renewalMode,
        exposureScope: epExposure,
        dnsScope: epDnsScope,
        ingressType,
        autoRenewThresholdDays: 15,
        gcpProject: annotations['resiliency.idp/gcp-project'] || null,
        gcpTargetProxy:
          annotations['resiliency.idp/gcp-target-https-proxy'] || null,
        lastProbedAt: new Date().toISOString(),
        certificate: {
          serialNumberHex: serialHex,
          serialNumberDecimal: '537261900129',
          rotatedFromSerial: null,
          historyCount: 1,
          notBefore: new Date(Date.now() - 5 * 86400 * 1000).toISOString(),
          notAfter,
          daysRemaining: days,
          expiryStatus: 'HEALTHY',
          subjectCn: host,
          subjectDn: `CN=${host},O=Project Aegis`,
          sanDnsNames: [host, `*.${host.split('.').slice(1).join('.')}`],
          hostnameMatchesSan: true,
          issuerCn:
            providerType === 'gcp-cloud-lb'
              ? 'GTS CA 1C3'
              : providerType === 'haproxy-edge'
              ? 'Aegis HAProxy Edge Root CA'
              : 'Aegis Private Cloud Vault Intermediate CA G2',
          issuerOrg:
            providerType === 'gcp-cloud-lb'
              ? 'Google Trust Services LLC'
              : 'Aegis Enterprise Private PKI',
          issuerDn: 'CN=CA,O=Aegis',
          isSelfSigned: providerType === 'haproxy-edge',
          signatureAlgorithm: isWeakSim
            ? 'sha1WithRSAEncryption'
            : providerType === 'gcp-cloud-lb'
            ? 'ecdsa-with-SHA256'
            : 'sha256WithRSAEncryption',
          signatureHashAlgorithm: isWeakSim ? 'SHA1' : 'SHA256',
          publicKeyAlgorithm:
            providerType === 'gcp-cloud-lb' && !isWeakSim ? 'ECDSA' : 'RSA',
          publicKeyBits: isWeakSim
            ? 1024
            : providerType === 'gcp-cloud-lb'
            ? 256
            : 2048,
          fingerprintSha256: 'AA:BB:CC:DD:EE:FF:00:11',
          complianceStatus: isWeakSim ? 'NON_COMPLIANT' : 'COMPLIANT',
          complianceFindings: isWeakSim
            ? [
                'INSECURE_SIGNATURE_HASH: sha1WithRSAEncryption (SHA1) prohibited',
                'WEAK_KEY_SIZE: RSA 1024-bit key < 2048-bit minimum',
              ]
            : [],
          isActive: true,
        },
      });
    });
  });

  if (endpoints.length === 0) {
    const hasHaproxyHost = Boolean(annotations['resiliency.idp/haproxy-host']);
    const isTlsEdgeResource =
      serviceName === 'haproxy-hello-world-tls' ||
      serviceName === 'hello-world-app';
    const k8sHealthUrl = annotations['resiliency.idp/k8s-health-url'];
    const hasCertAnnotation =
      Boolean(annotations['resiliency.idp/cert-expiry']) ||
      Boolean(annotations['resiliency.idp/cert-provider']);
    const hasSslMonitoredTag =
      Array.isArray(entity?.metadata?.tags) &&
      entity.metadata.tags.includes('ssl-monitored');

    if (
      hasHaproxyHost ||
      isTlsEdgeResource ||
      k8sHealthUrl ||
      hasCertAnnotation ||
      hasSslMonitoredTag
    ) {
      let fallbackUrl: string;
      let fallbackProvider: SslProviderType;

      if (hasHaproxyHost || isTlsEdgeResource) {
        fallbackUrl = 'https://hello.internal:8443/healthz';
        fallbackProvider = 'haproxy-edge';
      } else if (k8sHealthUrl) {
        fallbackUrl = k8sHealthUrl.startsWith('https://')
          ? k8sHealthUrl
          : k8sHealthUrl.replace(/^http:\/\//, 'https://');
        fallbackProvider = providerType;
      } else {
        fallbackUrl = `https://${serviceName}.internal/healthz`;
        fallbackProvider = providerType;
      }

      let fallbackHost = 'localhost';
      try {
        fallbackHost = new URL(fallbackUrl).hostname;
      } catch {
        fallbackHost = 'localhost';
      }

      const fallbackRenewalMode: SslRenewalMode =
        fallbackProvider === 'gcp-cloud-lb'
          ? 'workflow-auto-renew'
          : fallbackProvider === 'haproxy-edge'
          ? 'manual-or-template'
          : 'self-renewing-monitored';

      for (const tier of ENV_TIERS) {
        envCounts[tier] = (envCounts[tier] || 0) + 1;
        const days = tier === 'stress-test' ? 35 : 75;
        const notAfter = new Date(
          Date.now() + days * 86400 * 1000,
        ).toISOString();
        const serialHex = `4A:8F:${tier.toUpperCase().slice(0, 2)}:FB:9C:2E:71:B4`;

        endpoints.push({
          endpointId: `${entityRef}:${tier}:default`,
          entityRef,
          serviceName,
          environment: tier,
          endpointKey: 'default',
          endpointUrl: fallbackUrl,
          sniHostname: fallbackHost,
          providerType: fallbackProvider,
          renewalMode: fallbackRenewalMode,
          exposureScope,
          dnsScope,
          ingressType,
          autoRenewThresholdDays: 15,
          gcpProject: annotations['resiliency.idp/gcp-project'] || null,
          gcpTargetProxy:
            annotations['resiliency.idp/gcp-target-https-proxy'] || null,
          lastProbedAt: new Date().toISOString(),
          certificate: {
            serialNumberHex: serialHex,
            serialNumberDecimal: '537261900129',
            rotatedFromSerial: null,
            historyCount: 1,
            notBefore: new Date(Date.now() - 5 * 86400 * 1000).toISOString(),
            notAfter,
            daysRemaining: days,
            expiryStatus: 'HEALTHY',
            subjectCn: fallbackHost,
            subjectDn: `CN=${fallbackHost},O=Project Aegis`,
            sanDnsNames: [
              fallbackHost,
              `*.${fallbackHost.split('.').slice(1).join('.')}`,
            ],
            hostnameMatchesSan: true,
            issuerCn:
              fallbackProvider === 'gcp-cloud-lb'
                ? 'GTS CA 1C3'
                : fallbackProvider === 'haproxy-edge'
                ? 'Aegis HAProxy Edge Root CA'
                : 'Aegis Private Cloud Vault Intermediate CA G2',
            issuerOrg:
              fallbackProvider === 'gcp-cloud-lb'
                ? 'Google Trust Services LLC'
                : 'Aegis Enterprise Private PKI',
            issuerDn: 'CN=CA,O=Aegis',
            isSelfSigned: fallbackProvider === 'haproxy-edge',
            signatureAlgorithm:
              fallbackProvider === 'gcp-cloud-lb'
                ? 'ecdsa-with-SHA256'
                : 'sha256WithRSAEncryption',
            signatureHashAlgorithm: 'SHA256',
            publicKeyAlgorithm:
              fallbackProvider === 'gcp-cloud-lb' ? 'ECDSA' : 'RSA',
            publicKeyBits: fallbackProvider === 'gcp-cloud-lb' ? 256 : 2048,
            fingerprintSha256: 'AA:BB:CC:DD:EE:FF:00:11',
            complianceStatus: 'COMPLIANT',
            complianceFindings: [],
            isActive: true,
          },
        });
      }
    }
  }

  if (endpoints.length === 0) {
    return null;
  }

  const compliantEndpoints = endpoints.filter(
    e => e.certificate.complianceStatus === 'COMPLIANT',
  ).length;
  const hasNonCompliant = endpoints.some(
    e => e.certificate.complianceStatus === 'NON_COMPLIANT',
  );

  return {
    entityRef,
    serviceName,
    providerType,
    renewalMode,
    overallStatus: hasNonCompliant ? 'NON_COMPLIANT' : 'COMPLIANT',
    minDaysRemaining: Math.min(...endpoints.map(e => e.certificate.daysRemaining)),
    totalEndpoints: endpoints.length,
    compliantEndpoints,
    environmentCounts: envCounts,
    endpoints,
    exposureCounts: {
      unrestrictedPublic: endpoints.filter(
        e => normalizeExposureScope(e.exposureScope) === 'unrestricted-public',
      ).length,
      restrictedPublic: endpoints.filter(
        e => normalizeExposureScope(e.exposureScope) === 'restricted-public',
      ).length,
      strictlyPrivate: endpoints.filter(
        e => normalizeExposureScope(e.exposureScope) === 'strictly-private',
      ).length,
      internetFacing: endpoints.filter(e => {
        const s = normalizeExposureScope(e.exposureScope);
        return s === 'unrestricted-public' || s === 'restricted-public';
      }).length,
      internalOnly: endpoints.filter(
        e => normalizeExposureScope(e.exposureScope) === 'strictly-private',
      ).length,
    },
    softwareStack,
    lastScannedAt: new Date().toISOString(),
  };
}

function badgeStyle(status: string): {
  bg: string;
  fg: string;
  border: string;
} {
  if (status === 'COMPLIANT' || status === 'HEALTHY') {
    return { bg: '#e8f5e9', fg: '#1b5e20', border: '#4caf50' };
  }
  if (
    status === 'NON_COMPLIANT' ||
    status === 'EXPIRED' ||
    status === 'CRITICAL'
  ) {
    return { bg: '#ffebee', fg: '#b71c1c', border: '#f44336' };
  }
  return { bg: '#fff3e0', fg: '#e65100', border: '#ff9800' };
}

function providerLabel(providerType: SslProviderType): {
  title: string;
  subtitle: string;
  badgeBg: string;
  badgeFg: string;
} {
  if (providerType === 'gcp-cloud-lb') {
    return {
      title: 'Google Public Cloud Load Balancer (TargetHttpsProxy + Certificate Manager)',
      subtitle:
        'Workflow-Driven Auto-Renewal • Issues GTS CA 1C3 certificates via DNS-01 authorization',
      badgeBg: '#e3f2fd',
      badgeFg: '#0d47a1',
    };
  }
  if (providerType === 'haproxy-edge') {
    return {
      title: 'HAProxy Edge Load Balancer (Runtime Admin Socket)',
      subtitle:
        'Hitless PEM Hot-Reload • Monitored & rotated via HAProxy Scaffolder Workflow',
      badgeBg: '#f3e5f5',
      badgeFg: '#4a148c',
    };
  }
  return {
    title: 'Private Cloud Load Balancer (F5 BIG-IP / NSX-T / Vault PKI)',
    subtitle:
      'Autonomous Self-Renewing (Monitored-Only) • Alerts if certificate enters <= 15d SLA window without rotating',
    badgeBg: '#e0f2f1',
    badgeFg: '#004d40',
  };
}

export const EntityMultiEnvSslComplianceCard = () => {
  const { entity } = useEntity();
  const entityRef = stringifyEntityRef(entity);
  const { getBaseUrl, apiFetch, identityApi } = useSslTrackerBackendClient();
  const fallbackRollup = useMemo(
    () => buildFallbackRollupFromEntity(entity),
    [entity],
  );

  const [rollup, setRollup] = useState<EntitySslTrackerRollup | null>(
    fallbackRollup,
  );
  const [selectedEnv, setSelectedEnv] = useState<'ALL' | SslEnvironmentTier>(
    'ALL',
  );
  const [statusFilter, setStatusFilter] = useState<
    'ALL' | 'COMPLIANT' | 'WARNING' | 'NON_COMPLIANT'
  >('ALL');
  const [exposureFilter, setExposureFilter] = useState<
    | 'ALL'
    | 'unrestricted-public'
    | 'restricted-public'
    | 'strictly-private'
    | 'internet-facing'
    | 'internal-only'
  >('ALL');
  const [showAuditMatrix, setShowAuditMatrix] = useState<boolean>(true);
  const [searchQuery, setSearchQuery] = useState<string>('');
  const [isOfflineMode, setIsOfflineMode] = useState<boolean>(false);
  const [errorBanner, setErrorBanner] = useState<string | null>(null);
  const [showHistoryDrawer, setShowHistoryDrawer] = useState<boolean>(false);
  const [historyRecords, setHistoryRecords] = useState<
    EndpointCertificateHistoryRecord[] | null
  >(null);
  const [busyMessage, setBusyMessage] = useState<string | null>(null);
  const [gcpRenewalBanner, setGcpRenewalBanner] = useState<string | null>(null);
  const [qualityGate, setQualityGate] = useState<GcpQualityGateState | null>(
    null,
  );
  const [approverId, setApproverId] = useState<string>(
    'user:default/platform-sre',
  );
  const [metricsUrl, setMetricsUrl] = useState<string>(
    `${DEFAULT_SSL_TRACKER_BASE_URL}/metrics`,
  );
  const [verifiedDomainsSummary, setVerifiedDomainsSummary] = useState<
    VerifiedDomainCertRecord[] | null
  >(null);
  const [updatedTargetEndpoints, setUpdatedTargetEndpoints] = useState<
    string[]
  >([]);

  useEffect(() => {
    let mounted = true;
    getBaseUrl()
      .then(base => {
        if (mounted) {
          setMetricsUrl(`${base.replace(/\/$/, '')}/metrics`);
        }
      })
      .catch(() => {});
    if (identityApi) {
      identityApi
        .getBackstageIdentity()
        .then(identity => {
          if (mounted && identity?.userEntityRef) {
            setApproverId(identity.userEntityRef);
          }
        })
        .catch(() => {});
    }
    return () => {
      mounted = false;
    };
  }, [getBaseUrl, identityApi]);

  const fetchStatus = useCallback(() => {
    apiFetch(`/status?entityRef=${encodeURIComponent(entityRef)}`)
      .then(res => (res.ok ? res.json() : null))
      .then(data => {
        if (data && Array.isArray(data.endpoints)) {
          setRollup(data);
          setIsOfflineMode(false);
          setErrorBanner(null);
          if (data.qualityGate) {
            setQualityGate(data.qualityGate);
          }
        }
      })
      .catch(() => {
        // Keep annotation-derived fallback in offline/unit test environments
        setIsOfflineMode(true);
      });
  }, [apiFetch, entityRef]);

  useEffect(() => {
    setRollup(fallbackRollup);
    if (fallbackRollup) {
      fetchStatus();
    }
  }, [fallbackRollup, fetchStatus]);

  if (!rollup || rollup.endpoints.length === 0) {
    return null;
  }

  const handleRescan = async () => {
    setBusyMessage('Scanning live X.509 endpoints across environments...');
    try {
      const resp = await apiFetch('/scan', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ entityRef }),
      });
      if (resp.ok) {
        const updated = await resp.json();
        if (updated && Array.isArray(updated.endpoints)) {
          setRollup(updated);
          setIsOfflineMode(false);
          setErrorBanner(null);
        }
      }
    } catch {
      setIsOfflineMode(true);
      setErrorBanner(
        'Backend SSL Tracker API unreachable — displaying annotation-derived fallback telemetry.',
      );
    } finally {
      setBusyMessage(null);
    }
  };

  const handleToggleRotationHistory = async () => {
    if (showHistoryDrawer) {
      setShowHistoryDrawer(false);
      return;
    }
    setBusyMessage('Loading certificate rotation lineage & serial history...');
    try {
      const resp = await apiFetch(
        `/history?entityRef=${encodeURIComponent(entityRef)}`,
      );
      if (resp.ok) {
        const data = await resp.json();
        if (data && Array.isArray(data.endpoints)) {
          setHistoryRecords(data.endpoints);
          setShowHistoryDrawer(true);
          setIsOfflineMode(false);
          return;
        }
      }
      throw new Error('Fallback to local rollup history');
    } catch {
      const fallbackHistory: EndpointCertificateHistoryRecord[] =
        rollup.endpoints.map(ep => ({
          endpointId: ep.endpointId,
          entityRef: ep.entityRef,
          serviceName: ep.serviceName,
          environment: ep.environment,
          endpointKey: ep.endpointKey,
          endpointUrl: ep.endpointUrl,
          sniHostname: ep.sniHostname,
          providerType: ep.providerType,
          activeSerialNumberHex: ep.certificate.serialNumberHex,
          historyCount: ep.certificate.historyCount,
          certificates: [ep.certificate],
        }));
      setHistoryRecords(fallbackHistory);
      setShowHistoryDrawer(true);
    } finally {
      setBusyMessage(null);
    }
  };

  const handleRemediateWeakCrypto = async (
    targetEndpointKey?: string,
    targetEnvOverride?: SslEnvironmentTier,
  ) => {
    const envTarget =
      targetEnvOverride || (selectedEnv === 'ALL' ? 'all' : selectedEnv);
    setBusyMessage(
      `Remediating weak cryptography & rotating certificate via Private PKI (${envTarget}${
        targetEndpointKey ? ` / ${targetEndpointKey}` : ''
      })...`,
    );
    try {
      const resp = await apiFetch('/remediate-crypto', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          entityRef,
          environment: envTarget,
          endpointKey: targetEndpointKey,
          keyAlgorithm: 'RSA-2048',
          validityDays: 90,
        }),
      });
      if (resp.ok) {
        const body = await resp.json();
        if (body.rollup) {
          setRollup(body.rollup);
        }
        setVerifiedDomainsSummary(
          mapRenewalsToVerifiedDomainRecords(body.renewals),
        );
        if (Array.isArray(body.targetEndpointUrls)) {
          setUpdatedTargetEndpoints(body.targetEndpointUrls);
        }
        setGcpRenewalBanner(
          `✓ Cryptographic Remediation Completed: Rotated ${body.renewedCount} endpoint certificate(s) to RSA-2048 / SHA-256 (90d validity).`,
        );
        setIsOfflineMode(false);
        setErrorBanner(null);
      }
    } catch {
      setIsOfflineMode(true);
      setErrorBanner(
        'Backend API unreachable during remediation request — verify backend server status.',
      );
    } finally {
      setBusyMessage(null);
    }
  };

  const handlePreviewGcpDiffAndQualityGate = async () => {
    const envTarget = selectedEnv === 'ALL' ? 'all' : selectedEnv;
    setBusyMessage(
      `Generating Per-Environment Certificate Diff & opening Manual Approval Quality Gate (${envTarget})...`,
    );
    try {
      const resp = await apiFetch('/gcp-preview-diff', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          entityRef,
          environment: envTarget,
          keyAlgorithm: 'ECDSA-P256',
          validityDays: 90,
          openQualityGate: true,
        }),
      });
      if (resp.ok) {
        const body = await resp.json();
        const gateObj = body.qualityGate || body.gate;
        if (gateObj) {
          setQualityGate(gateObj);
        }
        setGcpRenewalBanner(
          `Quality Gate Pending Approval: Review the per-environment certificate diff for ${
            body.plan?.targetEndpointUrls?.length ??
            body.plan?.proposedChanges?.length ??
            0
          } target endpoint(s) below before applying new certificates.`,
        );
      }
    } catch {
      setIsOfflineMode(true);
    } finally {
      setBusyMessage(null);
    }
  };

  const handleDecideQualityGate = async (
    decision: 'APPROVED' | 'REJECTED',
  ) => {
    const envTarget =
      qualityGate?.plan?.environment ||
      (selectedEnv === 'ALL' ? 'all' : selectedEnv);
    const targetEndpoints = qualityGate?.plan?.targetEndpointUrls || [];

    setBusyMessage(
      decision === 'APPROVED'
        ? `Quality Gate Approved by ${approverId}: Provisioning new certificates & verifying all domains...`
        : `Rejecting Quality Gate for ${entityRef}...`,
    );
    try {
      // 1. Record Quality Gate decision (unblocks any paused Scaffolder workflow)
      const gateResp = await apiFetch('/quality-gate/decide', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          entityRef,
          gateId: qualityGate?.gateId,
          decision,
          decidedBy: approverId,
          comments:
            decision === 'APPROVED'
              ? 'Manual approval of per-environment certificate diff confirmed.'
              : 'Rejected during manual quality gate review.',
        }),
      });
      if (gateResp.ok) {
        const gateData = await gateResp.json();
        setQualityGate(gateData);
      }

      // 2. If approved, execute auto-renewal and populate verified domains result summary
      if (decision === 'APPROVED') {
        const renewResp = await apiFetch('/gcp-auto-renew', {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({
            entityRef,
            environment: envTarget,
            targetEndpoints,
            keyAlgorithm: 'ECDSA-P256',
            validityDays: 90,
          }),
        });
        if (renewResp.ok) {
          const body = await renewResp.json();
          if (body.rollup) {
            setRollup(body.rollup);
          }
          setVerifiedDomainsSummary(
            mapRenewalsToVerifiedDomainRecords(body.renewals),
          );
          if (Array.isArray(body.targetEndpointUrls)) {
            setUpdatedTargetEndpoints(body.targetEndpointUrls);
          }
          setGcpRenewalBanner(
            `✓ Quality Gate Approved (${approverId}) & Auto-Renewal Completed: Updated ${body.renewedCount} target endpoint(s) and verified all ${
              body.verifiedDomains?.length ?? body.renewedCount
            } domain(s) with fresh GTS CA 1C3 certificates.`,
          );
        }
      } else {
        setGcpRenewalBanner(
          `✗ Quality Gate Rejected by ${approverId}. No certificates were modified.`,
        );
      }
    } catch {
      setIsOfflineMode(true);
    } finally {
      setBusyMessage(null);
    }
  };

  const handleTriggerMockGcpAutoRenew = async () => {
    const envTarget = selectedEnv === 'ALL' ? 'all' : selectedEnv;
    setBusyMessage(
      `Executing Mock GCP Certificate Manager DNS-01 Authorization & TargetHttpsProxy binding (${envTarget})...`,
    );
    try {
      const resp = await apiFetch('/gcp-auto-renew', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          entityRef,
          environment: envTarget,
          keyAlgorithm: 'ECDSA-P256',
          validityDays: 90,
        }),
      });
      if (resp.ok) {
        const body = await resp.json();
        if (body.rollup) {
          setRollup(body.rollup);
        }
        setVerifiedDomainsSummary(
          mapRenewalsToVerifiedDomainRecords(body.renewals),
        );
        if (Array.isArray(body.targetEndpointUrls)) {
          setUpdatedTargetEndpoints(body.targetEndpointUrls);
        }
        setGcpRenewalBanner(
          `GCP Auto-Renewal Succeeded: Rotated ${body.renewedCount} endpoint certificate(s) in '${envTarget}' with fresh GTS CA 1C3 serial numbers.`,
        );
      }
    } catch {
      setIsOfflineMode(true);
    } finally {
      setBusyMessage(null);
    }
  };

  const visibleEndpoints = rollup.endpoints.filter(e => {
    if (selectedEnv !== 'ALL' && e.environment !== selectedEnv) {
      return false;
    }
    if (
      statusFilter !== 'ALL' &&
      e.certificate.complianceStatus !== statusFilter
    ) {
      return false;
    }
    if (
      exposureFilter !== 'ALL' &&
      normalizeExposureScope(e.exposureScope) !==
        normalizeExposureScope(exposureFilter)
    ) {
      return false;
    }
    if (searchQuery.trim()) {
      const q = searchQuery.trim().toLowerCase();
      const hay = [
        e.endpointKey,
        e.endpointUrl,
        e.sniHostname,
        e.certificate.serialNumberHex,
        e.certificate.issuerCn,
        e.environment,
      ]
        .join(' ')
        .toLowerCase();
      if (!hay.includes(q)) {
        return false;
      }
    }
    return true;
  });

  const overallColors = badgeStyle(rollup.overallStatus);
  const provMeta = providerLabel(rollup.providerType);

  return (
    <InfoCard
      title={`Multi-Environment SSL/TLS Endpoint & Compliance Tracker (${rollup.serviceName})`}
    >
      <div style={{ display: 'flex', flexDirection: 'column', gap: '14px' }}>
        {/* Provider Topology & Overall Compliance Header */}
        <div
          style={{
            display: 'flex',
            flexWrap: 'wrap',
            justifyContent: 'space-between',
            alignItems: 'center',
            gap: '10px',
            padding: '10px 12px',
            backgroundColor: provMeta.badgeBg,
            color: provMeta.badgeFg,
            borderRadius: '8px',
          }}
        >
          <div>
            <div style={{ fontWeight: 700, fontSize: '0.92rem' }}>
              Load Balancer Tier: {provMeta.title}
            </div>
            <div style={{ fontSize: '0.8rem', opacity: 0.9 }}>
              {provMeta.subtitle}
            </div>
          </div>
          <div style={{ display: 'flex', alignItems: 'center', gap: '8px' }}>
            <span
              style={{
                backgroundColor: overallColors.bg,
                color: overallColors.fg,
                border: `1px solid ${overallColors.border}`,
                borderRadius: '12px',
                padding: '4px 12px',
                fontWeight: 700,
                fontSize: '0.82rem',
              }}
            >
              {rollup.overallStatus} • {rollup.compliantEndpoints}/
              {rollup.totalEndpoints} Endpoints Compliant (Min{' '}
              {rollup.minDaysRemaining}d left)
            </span>
          </div>
        </div>

        {(isOfflineMode || errorBanner) && (
          <div
            style={{
              display: 'flex',
              justifyContent: 'space-between',
              alignItems: 'center',
              flexWrap: 'wrap',
              gap: '8px',
              padding: '8px 12px',
              backgroundColor: '#fff8e1',
              color: '#e65100',
              border: '1px solid #ffb74d',
              borderRadius: '6px',
              fontSize: '0.8rem',
              fontWeight: 600,
            }}
          >
            <span>
              ⚠{' '}
              {errorBanner ||
                'Simulated / Offline Fallback Mode: Displaying annotation-derived SSL telemetry.'}
            </span>
            <button
              type="button"
              onClick={handleRescan}
              style={{
                cursor: 'pointer',
                padding: '3px 10px',
                borderRadius: '4px',
                border: '1px solid #e65100',
                backgroundColor: '#fff',
                color: '#e65100',
                fontWeight: 700,
                fontSize: '0.75rem',
              }}
            >
              Retry Live Sync
            </button>
          </div>
        )}

        {gcpRenewalBanner && (
          <div
            style={{
              padding: '8px 12px',
              backgroundColor: '#e8f5e9',
              color: '#1b5e20',
              border: '1px solid #4caf50',
              borderRadius: '6px',
              fontSize: '0.83rem',
              fontWeight: 600,
            }}
          >
            {gcpRenewalBanner}
          </div>
        )}

        {/* Environment Filter Bar (supports 1:N endpoints per environment, e.g. STG (3)) */}
        <div
          style={{
            display: 'flex',
            flexWrap: 'wrap',
            gap: '8px',
            alignItems: 'center',
          }}
        >
          <span style={{ fontWeight: 700, fontSize: '0.82rem' }}>
            Environment Tags:
          </span>
          <button
            type="button"
            onClick={() => setSelectedEnv('ALL')}
            style={{
              cursor: 'pointer',
              padding: '4px 10px',
              borderRadius: '14px',
              border:
                selectedEnv === 'ALL' ? '2px solid #1976d2' : '1px solid #ccc',
              backgroundColor: selectedEnv === 'ALL' ? '#e3f2fd' : '#fafafa',
              fontWeight: selectedEnv === 'ALL' ? 700 : 500,
              fontSize: '0.78rem',
            }}
          >
            ALL ({rollup.totalEndpoints})
          </button>
          {ENV_TIERS.map(envTier => {
            const count = rollup.environmentCounts[envTier] || 0;
            const isSelected = selectedEnv === envTier;
            return (
              <button
                key={envTier}
                type="button"
                onClick={() => setSelectedEnv(envTier)}
                style={{
                  cursor: 'pointer',
                  padding: '4px 10px',
                  borderRadius: '14px',
                  border: isSelected ? '2px solid #1976d2' : '1px solid #ccc',
                  backgroundColor: isSelected ? '#e3f2fd' : '#fafafa',
                  fontWeight: isSelected ? 700 : 500,
                  fontSize: '0.78rem',
                }}
              >
                env:{envTier.toUpperCase()} ({count})
              </button>
            );
          })}
        </div>

        {/* 3-Tier Exposure Spectrum Filter & Executive Audit Matrix */}
        <div
          style={{
            display: 'flex',
            flexWrap: 'wrap',
            gap: '8px',
            alignItems: 'center',
          }}
        >
          <span style={{ fontWeight: 700, fontSize: '0.82rem' }}>
            3-Tier Exposure Spectrum:
          </span>
          <button
            type="button"
            onClick={() => setExposureFilter('ALL')}
            style={{
              cursor: 'pointer',
              padding: '4px 10px',
              borderRadius: '14px',
              border:
                exposureFilter === 'ALL'
                  ? '2px solid #1976d2'
                  : '1px solid #ccc',
              backgroundColor:
                exposureFilter === 'ALL' ? '#e3f2fd' : '#fafafa',
              fontWeight: exposureFilter === 'ALL' ? 700 : 500,
              fontSize: '0.78rem',
            }}
          >
            ALL ({rollup.totalEndpoints})
          </button>
          {(
            [
              'unrestricted-public',
              'restricted-public',
              'strictly-private',
            ] as const
          ).map(tierKey => {
            const meta = getExposureTierMeta(tierKey);
            const count =
              tierKey === 'unrestricted-public'
                ? rollup.exposureCounts?.unrestrictedPublic ??
                  rollup.endpoints.filter(
                    e =>
                      normalizeExposureScope(e.exposureScope) ===
                      'unrestricted-public',
                  ).length
                : tierKey === 'restricted-public'
                ? rollup.exposureCounts?.restrictedPublic ??
                  rollup.endpoints.filter(
                    e =>
                      normalizeExposureScope(e.exposureScope) ===
                      'restricted-public',
                  ).length
                : rollup.exposureCounts?.strictlyPrivate ??
                  rollup.endpoints.filter(
                    e =>
                      normalizeExposureScope(e.exposureScope) ===
                      'strictly-private',
                  ).length;
            const active =
              exposureFilter !== 'ALL' &&
              normalizeExposureScope(exposureFilter) === tierKey;
            return (
              <button
                key={tierKey}
                type="button"
                onClick={() =>
                  setExposureFilter(active ? 'ALL' : tierKey)
                }
                style={{
                  cursor: 'pointer',
                  padding: '4px 10px',
                  borderRadius: '14px',
                  border: active
                    ? `2px solid ${meta.border}`
                    : '1px solid #ccc',
                  backgroundColor: active ? meta.bg : '#fafafa',
                  color: active ? meta.fg : '#333',
                  fontWeight: active ? 700 : 500,
                  fontSize: '0.78rem',
                }}
              >
                {meta.shortBadge} ({count})
              </button>
            );
          })}
          <button
            type="button"
            onClick={() => setShowAuditMatrix(prev => !prev)}
            style={{
              cursor: 'pointer',
              marginLeft: 'auto',
              padding: '3px 10px',
              borderRadius: '12px',
              border: '1px solid #90a4ae',
              backgroundColor: showAuditMatrix ? '#eceff1' : '#fff',
              color: '#37474f',
              fontWeight: 600,
              fontSize: '0.74rem',
            }}
          >
            {showAuditMatrix
              ? 'Hide 3-Tier Audit Matrix'
              : 'Show 3-Tier Audit Matrix'}
          </button>
        </div>

        {showAuditMatrix && (
          <div
            style={{
              padding: '10px 12px',
              borderRadius: '8px',
              backgroundColor: '#fafafa',
              border: '1px solid #e0e0e0',
            }}
          >
            <div
              style={{
                fontSize: '0.76rem',
                color: '#37474f',
                marginBottom: '8px',
                fontStyle: 'italic',
                borderLeft: '3px solid #1976d2',
                paddingLeft: '8px',
              }}
            >
              &ldquo;Every domain we own belongs in one of three buckets:{' '}
              <strong>Unrestricted Public</strong> for our customers,{
                ' '}
              <strong>Restricted Public</strong> for external partners, and{
                ' '}
              <strong>Strictly Private</strong> for our internal teams. The goal
              of this audit is to catch internal tools that were accidentally
              deployed into the middle bucket—sitting on the public internet
              behind an ACL—and move them into the Strictly Private bucket where
              they belong.&rdquo;
            </div>
            <div
              style={{
                display: 'grid',
                gridTemplateColumns: 'repeat(auto-fit, minmax(230px, 1fr))',
                gap: '8px',
              }}
            >
              {(
                [
                  'unrestricted-public',
                  'restricted-public',
                  'strictly-private',
                ] as const
              ).map(tierKey => {
                const meta = getExposureTierMeta(tierKey);
                const count = rollup.endpoints.filter(
                  e => normalizeExposureScope(e.exposureScope) === tierKey,
                ).length;
                const active =
                  exposureFilter !== 'ALL' &&
                  normalizeExposureScope(exposureFilter) === tierKey;
                return (
                  <div
                    key={tierKey}
                    onClick={() =>
                      setExposureFilter(active ? 'ALL' : tierKey)
                    }
                    style={{
                      cursor: 'pointer',
                      padding: '8px 10px',
                      borderRadius: '6px',
                      backgroundColor: meta.bg,
                      color: meta.fg,
                      border: active
                        ? `2px solid ${meta.border}`
                        : `1px solid ${meta.border}`,
                      fontSize: '0.72rem',
                    }}
                  >
                    <div
                      style={{
                        display: 'flex',
                        justifyContent: 'space-between',
                        fontWeight: 700,
                        fontSize: '0.77rem',
                        marginBottom: '3px',
                      }}
                    >
                      <span>{meta.tier}</span>
                      <span>{count} ep</span>
                    </div>
                    <div style={{ fontWeight: 600, marginBottom: '2px' }}>
                      {meta.analogy} • {meta.businessTerm}
                    </div>
                    <div style={{ opacity: 0.92, marginBottom: '2px' }}>
                      <strong>Reach:</strong> {meta.whoCanReach}
                    </div>
                    <div style={{ opacity: 0.92, marginBottom: '2px' }}>
                      <strong>Protection:</strong> {meta.protection}
                    </div>
                    <div style={{ fontWeight: 600 }}>
                      <strong>Audit Goal:</strong> {meta.auditGoal}
                    </div>
                  </div>
                );
              })}
            </div>
          </div>
        )}

        {/* Compliance Status Filter Chips & Search Input */}
        <div
          style={{
            display: 'flex',
            flexWrap: 'wrap',
            gap: '8px',
            alignItems: 'center',
            justifyContent: 'space-between',
          }}
        >
          <div
            style={{
              display: 'flex',
              flexWrap: 'wrap',
              gap: '6px',
              alignItems: 'center',
            }}
          >
            <span style={{ fontWeight: 700, fontSize: '0.8rem' }}>
              Compliance Status:
            </span>
            {(
              ['ALL', 'COMPLIANT', 'WARNING', 'NON_COMPLIANT'] as const
            ).map(st => {
              const active = statusFilter === st;
              return (
                <button
                  key={st}
                  type="button"
                  onClick={() => setStatusFilter(st)}
                  style={{
                    cursor: 'pointer',
                    padding: '3px 9px',
                    borderRadius: '12px',
                    border: active ? '2px solid #1976d2' : '1px solid #ccc',
                    backgroundColor: active ? '#e3f2fd' : '#fafafa',
                    fontWeight: active ? 700 : 500,
                    fontSize: '0.75rem',
                  }}
                >
                  {st}
                </button>
              );
            })}
          </div>
          <input
            type="text"
            value={searchQuery}
            onChange={e => setSearchQuery(e.target.value)}
            placeholder="Filter by hostname, URL, serial, or endpoint key..."
            style={{
              padding: '4px 10px',
              borderRadius: '6px',
              border: '1px solid #ccc',
              fontSize: '0.78rem',
              minWidth: '260px',
            }}
          />
        </div>

        {/* 5-Pillar SSL Certificate Compliance Table */}
        <div style={{ overflowX: 'auto' }}>
          <table
            style={{
              width: '100%',
              borderCollapse: 'collapse',
              fontSize: '0.79rem',
            }}
          >
            <thead>
              <tr
                style={{
                  backgroundColor: '#f5f5f5',
                  textAlign: 'left',
                  borderBottom: '2px solid #ddd',
                }}
              >
                <th style={{ padding: '8px' }}>Env &amp; Endpoint (1:N)</th>
                <th style={{ padding: '8px' }}>
                  1. Not After (Expiry &amp; SSO Guard)
                </th>
                <th style={{ padding: '8px' }}>
                  2. Subject (Common Name &amp; SANs)
                </th>
                <th style={{ padding: '8px' }}>
                  3. Issuer (CA &amp; Renewal Path)
                </th>
                <th style={{ padding: '8px' }}>
                  4. Serial Number (Unique DB Key)
                </th>
                <th style={{ padding: '8px' }}>
                  5. Signature Algorithm &amp; Key Size
                </th>
              </tr>
            </thead>
            <tbody>
              {visibleEndpoints.map(item => {
                const c = item.certificate;
                const expColor = badgeStyle(c.expiryStatus);
                const compColor = badgeStyle(c.complianceStatus);
                return (
                  <tr
                    key={item.endpointId}
                    style={{ borderBottom: '1px solid #eee' }}
                  >
                    {/* Env & Endpoint */}
                    <td style={{ padding: '8px', verticalAlign: 'top' }}>
                      <div>
                        <span
                          style={{
                            display: 'inline-block',
                            padding: '1px 7px',
                            borderRadius: '10px',
                            backgroundColor: '#263238',
                            color: '#fff',
                            fontWeight: 700,
                            fontSize: '0.72rem',
                            marginRight: '6px',
                          }}
                        >
                          {item.environment.toUpperCase()}
                        </span>
                        <strong>{item.endpointKey}</strong>
                      </div>
                      <div style={{ marginTop: '3px' }}>
                        <code style={{ fontSize: '0.73rem' }}>
                          {item.endpointUrl}
                        </code>
                      </div>
                      <div style={{ marginTop: '3px' }}>
                        {(() => {
                          const expMeta = getExposureTierMeta(
                            item.exposureScope,
                          );
                          return (
                            <>
                              <span
                                style={{
                                  display: 'inline-block',
                                  padding: '1px 6px',
                                  borderRadius: '8px',
                                  backgroundColor: expMeta.bg,
                                  color: expMeta.fg,
                                  border: `1px solid ${expMeta.border}`,
                                  fontSize: '0.7rem',
                                  fontWeight: 700,
                                  marginTop: '2px',
                                }}
                              >
                                {expMeta.shortBadge}
                              </span>
                              <div
                                style={{
                                  fontSize: '0.67rem',
                                  color: expMeta.fg,
                                  fontWeight: 600,
                                  marginTop: '2px',
                                }}
                              >
                                {expMeta.analogy}
                              </div>
                            </>
                          );
                        })()}
                      </div>
                      {item.ingressType && (
                        <div
                          style={{
                            fontSize: '0.68rem',
                            color: '#555',
                            marginTop: '2px',
                          }}
                        >
                          {item.ingressType}
                        </div>
                      )}
                    </td>

                    {/* Pillar 1: Not After (Expiry Date) */}
                    <td style={{ padding: '8px', verticalAlign: 'top' }}>
                      <div>
                        <code>{c.notAfter.slice(0, 19)}Z</code>
                      </div>
                      <div style={{ marginTop: '4px' }}>
                        <span
                          style={{
                            backgroundColor: expColor.bg,
                            color: expColor.fg,
                            border: `1px solid ${expColor.border}`,
                            borderRadius: '10px',
                            padding: '1px 8px',
                            fontWeight: 700,
                            fontSize: '0.72rem',
                          }}
                        >
                          {c.expiryStatus} ({c.daysRemaining}d left)
                        </span>
                      </div>
                      {item.renewalMode === 'self-renewing-monitored' && (
                        <div
                          style={{
                            fontSize: '0.7rem',
                            color: '#00695c',
                            marginTop: '3px',
                          }}
                        >
                          Self-Renew SLA: &gt;{item.autoRenewThresholdDays}d
                        </div>
                      )}
                    </td>

                    {/* Pillar 2: Subject (CN & SAN) */}
                    <td style={{ padding: '8px', verticalAlign: 'top' }}>
                      <div>
                        <strong>CN:</strong> <code>{c.subjectCn}</code>
                      </div>
                      <div
                        style={{
                          fontSize: '0.72rem',
                          color: '#555',
                          marginTop: '2px',
                        }}
                      >
                        <strong>SANs:</strong> {c.sanDnsNames.join(', ')}
                      </div>
                      <div style={{ marginTop: '3px' }}>
                        <span
                          style={{
                            fontSize: '0.7rem',
                            fontWeight: 700,
                            color: c.hostnameMatchesSan ? '#2e7d32' : '#c62828',
                          }}
                        >
                          {c.hostnameMatchesSan
                            ? '✓ Hostname Matches SAN'
                            : '✗ SAN Mismatch'}
                        </span>
                      </div>
                    </td>

                    {/* Pillar 3: Issuer */}
                    <td style={{ padding: '8px', verticalAlign: 'top' }}>
                      <div style={{ fontWeight: 600 }}>{c.issuerCn}</div>
                      <div style={{ fontSize: '0.72rem', color: '#555' }}>
                        {c.issuerOrg}
                      </div>
                      <div style={{ fontSize: '0.7rem', marginTop: '2px' }}>
                        {c.isSelfSigned ? (
                          <span style={{ color: '#e65100', fontWeight: 600 }}>
                            Self-Signed Edge Cert
                          </span>
                        ) : (
                          <span style={{ color: '#1565c0', fontWeight: 600 }}>
                            Managed CA Chain
                          </span>
                        )}
                      </div>
                    </td>

                    {/* Pillar 4: Serial Number (Unique DB Key) */}
                    <td style={{ padding: '8px', verticalAlign: 'top' }}>
                      <div>
                        <code
                          style={{
                            fontSize: '0.73rem',
                            backgroundColor: '#f0f4c3',
                            padding: '2px 4px',
                            borderRadius: '4px',
                          }}
                        >
                          {c.serialNumberHex}
                        </code>
                      </div>
                      {c.rotatedFromSerial && (
                        <div
                          onClick={handleToggleRotationHistory}
                          style={{
                            cursor: 'pointer',
                            fontSize: '0.7rem',
                            color: '#1b5e20',
                            fontWeight: 600,
                            marginTop: '3px',
                            textDecoration: 'underline',
                          }}
                        >
                          ↻ Rotated from {c.rotatedFromSerial.slice(0, 11)}… (
                          {c.historyCount} versions in DB)
                        </div>
                      )}
                    </td>

                    {/* Pillar 5: Signature Algorithm & Key Size */}
                    <td style={{ padding: '8px', verticalAlign: 'top' }}>
                      <div>
                        <code>
                          {c.publicKeyAlgorithm} {c.publicKeyBits}-bit
                        </code>{' '}
                        • <code>{c.signatureAlgorithm}</code>
                      </div>
                      <div style={{ marginTop: '4px' }}>
                        <span
                          style={{
                            backgroundColor: compColor.bg,
                            color: compColor.fg,
                            border: `1px solid ${compColor.border}`,
                            borderRadius: '10px',
                            padding: '1px 8px',
                            fontWeight: 700,
                            fontSize: '0.72rem',
                          }}
                        >
                          {c.complianceStatus}
                        </span>
                      </div>
                      {c.complianceFindings.length > 0 && (
                        <div
                          style={{
                            marginTop: '4px',
                            fontSize: '0.7rem',
                            color: '#b71c1c',
                            fontWeight: 600,
                          }}
                        >
                          {c.complianceFindings.map((f, i) => (
                            <div key={i}>⚠ {f}</div>
                          ))}
                        </div>
                      )}
                      {c.complianceStatus === 'NON_COMPLIANT' && (
                        <div style={{ marginTop: '6px' }}>
                          <button
                            type="button"
                            onClick={() =>
                              handleRemediateWeakCrypto(
                                item.endpointKey,
                                item.environment,
                              )
                            }
                            style={{
                              cursor: 'pointer',
                              padding: '3px 8px',
                              borderRadius: '4px',
                              border: '1px solid #b71c1c',
                              backgroundColor: '#c62828',
                              color: '#fff',
                              fontWeight: 700,
                              fontSize: '0.7rem',
                            }}
                          >
                            ⚡ Remediate Weak Crypto (RSA-2048)
                          </button>
                        </div>
                      )}
                    </td>
                  </tr>
                );
              })}
            </tbody>
          </table>
        </div>

        {/* Software & Runtime Stack Inventory (SBOM) */}
        {rollup.softwareStack && rollup.softwareStack.length > 0 && (
          <div
            style={{
              marginTop: '8px',
              padding: '12px',
              borderRadius: '8px',
              border: '1px solid #78909c',
              backgroundColor: '#f5f5f5',
            }}
          >
            <div
              style={{
                fontWeight: 700,
                fontSize: '0.88rem',
                color: '#263238',
                marginBottom: '8px',
              }}
            >
              Software &amp; Runtime Stack Inventory (SBOM)
            </div>
            <div style={{ overflowX: 'auto' }}>
              <table
                style={{
                  width: '100%',
                  borderCollapse: 'collapse',
                  fontSize: '0.76rem',
                  backgroundColor: '#fff',
                }}
              >
                <thead>
                  <tr
                    style={{
                      backgroundColor: '#cfd8dc',
                      textAlign: 'left',
                      borderBottom: '2px solid #90a4ae',
                    }}
                  >
                    <th style={{ padding: '6px' }}>Package/Software</th>
                    <th style={{ padding: '6px' }}>Version</th>
                    <th style={{ padding: '6px' }}>Category</th>
                    <th style={{ padding: '6px' }}>Description</th>
                    <th style={{ padding: '6px' }}>CVE Status</th>
                  </tr>
                </thead>
                <tbody>
                  {rollup.softwareStack.map(dep => (
                    <tr
                      key={`${dep.name}-${dep.version}`}
                      style={{ borderBottom: '1px solid #e0e0e0' }}
                    >
                      <td style={{ padding: '6px', fontWeight: 700 }}>
                        {dep.name}
                      </td>
                      <td style={{ padding: '6px' }}>
                        <code>{dep.version}</code>
                      </td>
                      <td style={{ padding: '6px' }}>{dep.category}</td>
                      <td style={{ padding: '6px' }}>{dep.description}</td>
                      <td style={{ padding: '6px' }}>
                        {dep.cveStatus && (
                          <span
                            style={{
                              padding: '1px 6px',
                              borderRadius: '8px',
                              fontWeight: 700,
                              fontSize: '0.7rem',
                              backgroundColor:
                                dep.cveStatus === 'SECURE'
                                  ? '#e8f5e9'
                                  : dep.cveStatus === 'WARNING'
                                  ? '#fff3e0'
                                  : '#ffebee',
                              color:
                                dep.cveStatus === 'SECURE'
                                  ? '#1b5e20'
                                  : dep.cveStatus === 'WARNING'
                                  ? '#e65100'
                                  : '#b71c1c',
                            }}
                          >
                            {dep.cveStatus}
                          </span>
                        )}
                      </td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          </div>
        )}

        {/* Provider-Aware Lifecycle & Workflow Actions */}
        <div
          style={{
            display: 'flex',
            flexWrap: 'wrap',
            gap: '10px',
            alignItems: 'center',
            marginTop: '4px',
          }}
        >
          <button
            type="button"
            onClick={handleRescan}
            style={{
              cursor: 'pointer',
              padding: '6px 14px',
              borderRadius: '6px',
              border: '1px solid #1976d2',
              backgroundColor: '#fff',
              color: '#1976d2',
              fontWeight: 700,
              fontSize: '0.82rem',
            }}
          >
            Rescan All Environment Endpoints
          </button>

          <button
            type="button"
            onClick={handleToggleRotationHistory}
            style={{
              cursor: 'pointer',
              padding: '6px 14px',
              borderRadius: '6px',
              border: '1px solid #455a64',
              backgroundColor: showHistoryDrawer ? '#455a64' : '#eceff1',
              color: showHistoryDrawer ? '#fff' : '#263238',
              fontWeight: 700,
              fontSize: '0.82rem',
            }}
          >
            {showHistoryDrawer
              ? 'Hide Rotation History'
              : 'View Rotation History & Serial Lineage'}
          </button>

          {rollup.providerType === 'gcp-cloud-lb' && (
            <>
              <button
                type="button"
                onClick={handlePreviewGcpDiffAndQualityGate}
                style={{
                  cursor: 'pointer',
                  padding: '6px 14px',
                  borderRadius: '6px',
                  border: '1px solid #e65100',
                  backgroundColor: '#ef6c00',
                  color: '#fff',
                  fontWeight: 700,
                  fontSize: '0.82rem',
                }}
              >
                Review Cert Diff &amp; Quality Gate (
                {selectedEnv === 'ALL' ? 'All Envs' : selectedEnv.toUpperCase()}
                )
              </button>
              <button
                type="button"
                onClick={handleTriggerMockGcpAutoRenew}
                style={{
                  cursor: 'pointer',
                  padding: '6px 14px',
                  borderRadius: '6px',
                  border: '1px solid #0d47a1',
                  backgroundColor: '#1565c0',
                  color: '#fff',
                  fontWeight: 700,
                  fontSize: '0.82rem',
                }}
              >
                Trigger Mock GCP Auto-Renewal (
                {selectedEnv === 'ALL' ? 'All Envs' : selectedEnv.toUpperCase()}
                )
              </button>
              <LinkButton
                color="primary"
                variant="outlined"
                to={`/create/templates/default/renew-gcp-lb-tls-cert?formData=${encodeURIComponent(
                  JSON.stringify({
                    targetEntity: entityRef,
                    targetEnvironment:
                      selectedEnv === 'ALL' ? 'all' : selectedEnv,
                    targetEndpoints: visibleEndpoints.map(e => e.endpointUrl),
                  }),
                )}`}
              >
                Open GCP Auto-Renewal Workflow
              </LinkButton>
            </>
          )}

          {rollup.providerType === 'haproxy-edge' && (
            <LinkButton
              color="primary"
              variant="contained"
              to="/create/templates/default/update-haproxy-tls-cert?formData=%7B%22certEntity%22%3A%22resource%3Adefault%2Fhaproxy-hello-world-tls%22%7D"
            >
              Rotate HAProxy Certificate
            </LinkButton>
          )}

          {rollup.providerType === 'private-cloud-lb' && (
            <>
              <span
                style={{
                  fontSize: '0.8rem',
                  color: '#004d40',
                  backgroundColor: '#e0f2f1',
                  padding: '5px 10px',
                  borderRadius: '6px',
                  fontWeight: 600,
                }}
              >
                ✓ Private Cloud LB Self-Renewal Active (Monitored Across{' '}
                {rollup.totalEndpoints} Endpoints)
              </span>
              {rollup.overallStatus === 'NON_COMPLIANT' && (
                <button
                  type="button"
                  onClick={() => handleRemediateWeakCrypto()}
                  style={{
                    cursor: 'pointer',
                    padding: '6px 14px',
                    borderRadius: '6px',
                    border: '1px solid #b71c1c',
                    backgroundColor: '#c62828',
                    color: '#fff',
                    fontWeight: 700,
                    fontSize: '0.82rem',
                  }}
                >
                  ⚡ Remediate Weak Crypto / Force Vault Renewal
                </button>
              )}
            </>
          )}

          <a
            href={metricsUrl}
            target="_blank"
            rel="noopener noreferrer"
            style={{ fontSize: '0.82rem', fontWeight: 600, marginLeft: 'auto' }}
          >
            Prometheus SSL Compliance Metrics
          </a>
        </div>

        {/* Expandable Certificate Rotation History & Serial Lineage Drawer */}
        {showHistoryDrawer && historyRecords && (
          <div
            style={{
              marginTop: '6px',
              padding: '12px',
              borderRadius: '8px',
              border: '1px solid #90a4ae',
              backgroundColor: '#eceff1',
            }}
          >
            <div
              style={{
                fontWeight: 700,
                fontSize: '0.88rem',
                color: '#263238',
                marginBottom: '8px',
              }}
            >
              Certificate Rotation History &amp; Serial Lineage (
              {historyRecords.length} Tracked Endpoints)
            </div>
            <div style={{ overflowX: 'auto' }}>
              <table
                style={{
                  width: '100%',
                  borderCollapse: 'collapse',
                  fontSize: '0.75rem',
                  backgroundColor: '#fff',
                }}
              >
                <thead>
                  <tr
                    style={{
                      backgroundColor: '#cfd8dc',
                      textAlign: 'left',
                      borderBottom: '2px solid #90a4ae',
                    }}
                  >
                    <th style={{ padding: '6px' }}>Env / Endpoint</th>
                    <th style={{ padding: '6px' }}>State</th>
                    <th style={{ padding: '6px' }}>Serial Number (DB Key)</th>
                    <th style={{ padding: '6px' }}>Rotated From Serial</th>
                    <th style={{ padding: '6px' }}>Issuer CA</th>
                    <th style={{ padding: '6px' }}>Key &amp; Signature</th>
                    <th style={{ padding: '6px' }}>Not After (Expiry)</th>
                    <th style={{ padding: '6px' }}>Compliance</th>
                  </tr>
                </thead>
                <tbody>
                  {historyRecords.flatMap(rec =>
                    rec.certificates.map(cert => (
                      <tr
                        key={`${rec.endpointId}-${cert.serialNumberHex}`}
                        style={{
                          borderBottom: '1px solid #e0e0e0',
                          opacity: cert.isActive ? 1 : 0.72,
                        }}
                      >
                        <td style={{ padding: '6px', fontWeight: 700 }}>
                          {rec.environment.toUpperCase()} / {rec.endpointKey}
                        </td>
                        <td style={{ padding: '6px' }}>
                          <span
                            style={{
                              padding: '1px 6px',
                              borderRadius: '8px',
                              fontWeight: 700,
                              fontSize: '0.7rem',
                              backgroundColor: cert.isActive
                                ? '#e8f5e9'
                                : '#eeeeee',
                              color: cert.isActive ? '#1b5e20' : '#616161',
                            }}
                          >
                            {cert.isActive ? 'ACTIVE' : 'ROTATED'}
                          </span>
                        </td>
                        <td style={{ padding: '6px' }}>
                          <code>{cert.serialNumberHex}</code>
                        </td>
                        <td style={{ padding: '6px' }}>
                          <code>{cert.rotatedFromSerial || '— (Initial)'}</code>
                        </td>
                        <td style={{ padding: '6px' }}>{cert.issuerCn}</td>
                        <td style={{ padding: '6px' }}>
                          <code>
                            {cert.publicKeyAlgorithm} {cert.publicKeyBits}-bit /{' '}
                            {cert.signatureAlgorithm}
                          </code>
                        </td>
                        <td style={{ padding: '6px' }}>
                          <code>{cert.notAfter.slice(0, 10)}</code> (
                          {cert.daysRemaining}d)
                        </td>
                        <td style={{ padding: '6px', fontWeight: 700 }}>
                          {cert.complianceStatus}
                        </td>
                      </tr>
                    )),
                  )}
                </tbody>
              </table>
            </div>
          </div>
        )}

        {/* Quality Gate — Manual Approval of Per-Environment Certificate Diff */}
        {qualityGate && qualityGate.plan && (
          <div
            style={{
              marginTop: '8px',
              padding: '14px',
              borderRadius: '8px',
              border:
                qualityGate.status === 'APPROVED'
                  ? '2px solid #2e7d32'
                  : qualityGate.status === 'REJECTED'
                  ? '2px solid #c62828'
                  : '2px solid #ef6c00',
              backgroundColor:
                qualityGate.status === 'APPROVED'
                  ? '#f1f8e9'
                  : qualityGate.status === 'REJECTED'
                  ? '#ffebee'
                  : '#fff8e1',
            }}
          >
            <div
              style={{
                display: 'flex',
                flexWrap: 'wrap',
                justifyContent: 'space-between',
                alignItems: 'center',
                gap: '8px',
                marginBottom: '10px',
              }}
            >
              <div>
                <div style={{ fontWeight: 700, fontSize: '0.92rem' }}>
                  Quality Gate — Manual Approval &amp; Per-Environment
                  Certificate Diff ({qualityGate.gateId})
                </div>
                <div style={{ fontSize: '0.78rem', color: '#444' }}>
                  Status: <strong>{qualityGate.status}</strong>
                  {qualityGate.decidedBy
                    ? ` • Decided by ${qualityGate.decidedBy} at ${qualityGate.decidedAt}`
                    : ' • Awaiting manual review of target endpoints and certificate diff before updating load balancer bindings'}
                </div>
              </div>
              {qualityGate.status === 'PENDING_APPROVAL' && (
                <div
                  style={{
                    display: 'flex',
                    alignItems: 'center',
                    gap: '8px',
                    flexWrap: 'wrap',
                  }}
                >
                  <label style={{ fontSize: '0.78rem', fontWeight: 600 }}>
                    Approver:{' '}
                    <input
                      type="text"
                      value={approverId}
                      onChange={e => setApproverId(e.target.value)}
                      style={{
                        padding: '4px 8px',
                        borderRadius: '4px',
                        border: '1px solid #ccc',
                        fontSize: '0.78rem',
                      }}
                    />
                  </label>
                  <button
                    type="button"
                    onClick={() => handleDecideQualityGate('APPROVED')}
                    style={{
                      cursor: 'pointer',
                      padding: '6px 12px',
                      borderRadius: '6px',
                      border: '1px solid #1b5e20',
                      backgroundColor: '#2e7d32',
                      color: '#fff',
                      fontWeight: 700,
                      fontSize: '0.8rem',
                    }}
                  >
                    ✓ Approve Quality Gate &amp; Update Certs
                  </button>
                  <button
                    type="button"
                    onClick={() => handleDecideQualityGate('REJECTED')}
                    style={{
                      cursor: 'pointer',
                      padding: '6px 12px',
                      borderRadius: '6px',
                      border: '1px solid #b71c1c',
                      backgroundColor: '#c62828',
                      color: '#fff',
                      fontWeight: 700,
                      fontSize: '0.8rem',
                    }}
                  >
                    ✗ Reject
                  </button>
                </div>
              )}
            </div>

            {/* Target Endpoints Where Certificates Will Be Updated */}
            <div
              style={{
                marginBottom: '10px',
                padding: '8px 10px',
                backgroundColor: '#fff',
                borderRadius: '6px',
                border: '1px solid #ddd',
              }}
            >
              <div
                style={{
                  fontWeight: 700,
                  fontSize: '0.8rem',
                  marginBottom: '4px',
                }}
              >
                Target Endpoints Where Certificates Will Be Updated (
                {qualityGate.plan.proposedChanges.length}):
              </div>
              <div
                style={{
                  display: 'flex',
                  flexWrap: 'wrap',
                  gap: '6px',
                }}
              >
                {qualityGate.plan.proposedChanges.map(entry => (
                  <code
                    key={entry.endpointId}
                    style={{
                      fontSize: '0.74rem',
                      backgroundColor: '#e3f2fd',
                      color: '#0d47a1',
                      padding: '2px 8px',
                      borderRadius: '4px',
                      border: '1px solid #90caf9',
                    }}
                  >
                    [{entry.environment.toUpperCase()}/{entry.endpointKey}]{' '}
                    {entry.endpointUrl} ({entry.domain})
                  </code>
                ))}
              </div>
            </div>

            {/* Per-Environment Certificate Unified Diff */}
            <div
              style={{
                display: 'flex',
                flexDirection: 'column',
                gap: '8px',
              }}
            >
              {qualityGate.plan.proposedChanges.map(entry => (
                <div
                  key={entry.endpointId}
                  style={{
                    backgroundColor: '#1e1e1e',
                    color: '#e0e0e0',
                    borderRadius: '6px',
                    padding: '10px',
                    overflowX: 'auto',
                  }}
                >
                  <div
                    style={{
                      fontWeight: 700,
                      fontSize: '0.78rem',
                      color: '#90caf9',
                      marginBottom: '6px',
                    }}
                  >
                    Environment Certificate Diff: env:
                    {entry.environment.toUpperCase()} / {entry.endpointKey} (
                    {entry.endpointUrl})
                  </div>
                  <pre
                    style={{
                      margin: 0,
                      fontSize: '0.73rem',
                      lineHeight: 1.45,
                      fontFamily: 'monospace',
                    }}
                  >
                    {entry.unifiedDiff.split('\n').map((line, i) => {
                      let lineColor = '#e0e0e0';
                      if (line.startsWith('---') || line.startsWith('- ')) {
                        lineColor = '#ff8a80';
                      } else if (
                        line.startsWith('+++') ||
                        line.startsWith('+ ')
                      ) {
                        lineColor = '#b9f6ca';
                      } else if (line.startsWith('@@')) {
                        lineColor = '#80d8ff';
                      }
                      return (
                        <div key={i} style={{ color: lineColor }}>
                          {line}
                        </div>
                      );
                    })}
                  </pre>
                </div>
              ))}
            </div>
          </div>
        )}

        {/* Result Summary — All Verified Domains with New Certificates */}
        {verifiedDomainsSummary && verifiedDomainsSummary.length > 0 && (
          <div
            style={{
              marginTop: '8px',
              padding: '12px',
              borderRadius: '8px',
              border: '2px solid #2e7d32',
              backgroundColor: '#e8f5e9',
            }}
          >
            <div
              style={{
                fontWeight: 700,
                fontSize: '0.9rem',
                color: '#1b5e20',
                marginBottom: '6px',
              }}
            >
              ✓ Workflow Result Summary — All Verified Domains &amp; New
              Certificates ({verifiedDomainsSummary.length} Domains Verified)
            </div>
            {updatedTargetEndpoints.length > 0 && (
              <div
                style={{
                  fontSize: '0.77rem',
                  color: '#2e7d32',
                  marginBottom: '8px',
                }}
              >
                <strong>Updated Target Endpoints:</strong>{' '}
                {updatedTargetEndpoints.join(' • ')}
              </div>
            )}
            <div style={{ overflowX: 'auto' }}>
              <table
                style={{
                  width: '100%',
                  borderCollapse: 'collapse',
                  fontSize: '0.76rem',
                  backgroundColor: '#fff',
                }}
              >
                <thead>
                  <tr
                    style={{
                      backgroundColor: '#c8e6c9',
                      textAlign: 'left',
                      borderBottom: '2px solid #81c784',
                    }}
                  >
                    <th style={{ padding: '6px' }}>Environment</th>
                    <th style={{ padding: '6px' }}>Target Endpoint Updated</th>
                    <th style={{ padding: '6px' }}>Verified Domain (SNI)</th>
                    <th style={{ padding: '6px' }}>Subject CN &amp; SAN</th>
                    <th style={{ padding: '6px' }}>Issuer CA</th>
                    <th style={{ padding: '6px' }}>
                      Previous → New Serial Number
                    </th>
                    <th style={{ padding: '6px' }}>New Not After (Expiry)</th>
                    <th style={{ padding: '6px' }}>Key &amp; Signature</th>
                    <th style={{ padding: '6px' }}>Verification</th>
                  </tr>
                </thead>
                <tbody>
                  {verifiedDomainsSummary.map(vd => (
                    <tr
                      key={`${vd.environment}-${vd.endpointKey}-${vd.domain}`}
                      style={{ borderBottom: '1px solid #e0e0e0' }}
                    >
                      <td style={{ padding: '6px', fontWeight: 700 }}>
                        {vd.environment.toUpperCase()} ({vd.endpointKey})
                      </td>
                      <td style={{ padding: '6px' }}>
                        <code>{vd.endpointUrl}</code>
                      </td>
                      <td style={{ padding: '6px', fontWeight: 700 }}>
                        <code>{vd.domain}</code>
                      </td>
                      <td style={{ padding: '6px' }}>
                        <code>{vd.subjectCn}</code> (
                        {vd.hostnameMatchesSan ? '✓ SAN Match' : '✗ Mismatch'})
                      </td>
                      <td style={{ padding: '6px' }}>{vd.issuerCn}</td>
                      <td style={{ padding: '6px' }}>
                        <code>{vd.previousSerialNumberHex.slice(0, 11)}…</code>{' '}
                        →{' '}
                        <code
                          style={{
                            backgroundColor: '#e8f5e9',
                            fontWeight: 700,
                            color: '#1b5e20',
                          }}
                        >
                          {vd.newSerialNumberHex}
                        </code>
                      </td>
                      <td style={{ padding: '6px' }}>
                        <code>{vd.notAfter.slice(0, 19)}Z</code> (
                        {vd.daysRemaining}d)
                      </td>
                      <td style={{ padding: '6px' }}>
                        <code>
                          {vd.publicKeyAlgorithm} {vd.publicKeyBits}-bit /{' '}
                          {vd.signatureAlgorithm}
                        </code>
                      </td>
                      <td
                        style={{
                          padding: '6px',
                          fontWeight: 700,
                          color: '#1b5e20',
                        }}
                      >
                        ✓ {vd.complianceStatus}
                      </td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          </div>
        )}

        {busyMessage && (
          <div
            style={{
              fontSize: '0.8rem',
              color: '#1565c0',
              fontStyle: 'italic',
            }}
          >
            {busyMessage}
          </div>
        )}
      </div>
    </InfoCard>
  );
};

const sslTrackerEntityCard = EntityCardBlueprint.make({
  name: 'multi-env-ssl-compliance-card',
  params: {
    filter: 'kind:component,resource',
    loader: async () => <EntityMultiEnvSslComplianceCard />,
  },
});

export const sslTrackerModule = createFrontendModule({
  pluginId: 'catalog',
  extensions: [sslTrackerEntityCard],
});

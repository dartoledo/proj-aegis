export type ReachabilityState = 'REACHABLE_HOT_PATH' | 'LOADED_NOT_INVOKED' | 'UNREACHABLE_DEAD_CODE';
export type VexStatus = 'AFFECTED' | 'NOT_AFFECTED_VEX' | 'FIXED';
export type VexJustification = 'none' | 'vulnerable_code_not_in_execute_path' | 'inline_mitigations_already_exist' | 'component_not_present';

export interface ContextualCveSeed {
  cveId: string;
  title: string;
  affectedPackage: string;
  installedVersion: string;
  fixedVersion: string;
  cvssScore: number;
  epssScore: number;
  epssPercentile: number;
  isCisaKev: boolean;
  kevDueDate?: string;
  ransomwareCampaignUse: boolean;
  reachability: ReachabilityState;
  callGraphSymbol: string;
  vexStatus: VexStatus;
  vexJustification: VexJustification;
  attackPathSteps: string[];
}

export interface ContextualCveRecord extends ContextualCveSeed {
  acrsScore: number;
  priorityTier: 'P0_IMMEDIATE_24H' | 'P1_HIGH_7D' | 'P2_SCHEDULED_30D' | 'DEFERRED_VEX';
  slaHoursRemaining: number;
}

export interface EntityCveIntelligenceReport {
  entityRef: string;
  serviceName: string;
  exposureTier: 'unrestricted-public' | 'restricted-public' | 'strictly-private';
  maxAcrsScore: number;
  cisaKevCount: number;
  p0ImmediateCount: number;
  rawCriticalHighCount: number;
  noiseReductionPercent: number;
  cves: ContextualCveRecord[];
  evaluatedAt: string;
}

export interface FleetCvePrioritizationSummary {
  totalServices: number;
  totalRawCves: number;
  totalActionableP0: number;
  totalCisaKev: number;
  fleetNoiseReductionPercent: number;
  reports: EntityCveIntelligenceReport[];
}

export function computeAcrsScore(input: {
  cvssScore: number;
  epssScore: number;
  isCisaKev: boolean;
  exposureTier: 'unrestricted-public' | 'restricted-public' | 'strictly-private';
  reachability: ReachabilityState;
  vexStatus: VexStatus;
}): number {
  if (input.vexStatus === 'NOT_AFFECTED_VEX' || input.vexStatus === 'FIXED') {
    return 0;
  }
  const base = input.cvssScore * 3.5 + input.epssScore * 30 + (input.isCisaKev ? 20 : 0);
  const wExp = input.exposureTier === 'unrestricted-public' ? 1.25 : input.exposureTier === 'restricted-public' ? 1.0 : 0.75;
  const wReach = input.reachability === 'REACHABLE_HOT_PATH' ? 1.2 : input.reachability === 'LOADED_NOT_INVOKED' ? 0.8 : 0.25;
  return Math.min(100, Math.max(1, Math.round(base * wExp * wReach)));
}

export const CVE_INTEL_SEEDS: Record<string, { serviceName: string; exposureTier: 'unrestricted-public' | 'restricted-public' | 'strictly-private'; cves: ContextualCveSeed[] }> = {
  'aegis-ui': {
    serviceName: 'aegis-ui',
    exposureTier: 'unrestricted-public',
    cves: [
      {
        cveId: 'CVE-2026-31042',
        title: 'React DOM SSR Hydration Memory Corruption',
        affectedPackage: 'react-dom',
        installedVersion: '18.3.1',
        fixedVersion: '18.3.2',
        cvssScore: 7.5,
        epssScore: 0.42,
        epssPercentile: 91.4,
        isCisaKev: false,
        ransomwareCampaignUse: false,
        reachability: 'REACHABLE_HOT_PATH',
        callGraphSymbol: 'ReactDOMServer.renderToPipeableStream',
        vexStatus: 'AFFECTED',
        vexJustification: 'none',
        attackPathSteps: [
          'Internet Storefront (prod.ui.aegis.cloud.goog)',
          'SSR Hydration Endpoint',
          'ReactDOMServer.renderToPipeableStream',
        ],
      },
      {
        cveId: 'CVE-2024-6119',
        title: 'OpenSSL X509_check_purpose Use-After-Free',
        affectedPackage: 'openssl-libcrypto3',
        installedVersion: '3.3.2-r0',
        fixedVersion: '3.3.2-r1',
        cvssScore: 7.5,
        epssScore: 0.08,
        epssPercentile: 44.2,
        isCisaKev: false,
        ransomwareCampaignUse: false,
        reachability: 'UNREACHABLE_DEAD_CODE',
        callGraphSymbol: 'X509_check_purpose (unused)',
        vexStatus: 'NOT_AFFECTED_VEX',
        vexJustification: 'vulnerable_code_not_in_execute_path',
        attackPathSteps: ['Blocked at static NGINX layer'],
      },
    ],
  },
  'aegis-backend': {
    serviceName: 'aegis-backend',
    exposureTier: 'strictly-private',
    cves: [
      {
        cveId: 'CVE-2026-111497',
        title: 'Node.js HTTP/2 AsyncContext Heap Corruption RCE',
        affectedPackage: 'nodejs',
        installedVersion: '18.20.8',
        fixedVersion: '22.15.0',
        cvssScore: 9.8,
        epssScore: 0.964,
        epssPercentile: 99.8,
        isCisaKev: true,
        kevDueDate: '2026-11-05',
        ransomwareCampaignUse: true,
        reachability: 'REACHABLE_HOT_PATH',
        callGraphSymbol: 'http2.Http2ServerRequest._onStreamFrame -> AsyncLocalStorage',
        vexStatus: 'AFFECTED',
        vexJustification: 'none',
        attackPathSteps: [
          'Drifted Staging Webhook (stg.backend.api.aegis.cloud.goog)',
          'HTTP/2 Frame Multiplexer',
          'Node.js 18 AsyncContext Heap Corruption (CVE-2026-111497)',
          'GCE Metadata Token Exfiltration',
        ],
      },
      {
        cveId: 'CVE-2026-41092',
        title: 'Linux Kernel netfilter nf_tables Container Escape',
        affectedPackage: 'linux-image-cloud-amd64',
        installedVersion: '6.1.106-3',
        fixedVersion: '6.1.112-1',
        cvssScore: 7.8,
        epssScore: 0.61,
        epssPercentile: 95.1,
        isCisaKev: true,
        kevDueDate: '2026-11-10',
        ransomwareCampaignUse: false,
        reachability: 'LOADED_NOT_INVOKED',
        callGraphSymbol: 'netfilter nf_tables (pending reboot)',
        vexStatus: 'AFFECTED',
        vexJustification: 'none',
        attackPathSteps: ['Container Escape Attempt', 'Host Kernel 6.1.106 netfilter'],
      },
      {
        cveId: 'CVE-2024-0727',
        title: 'OpenSSL PKCS12_parse Buffer Overflow',
        affectedPackage: 'openssl',
        installedVersion: '1.1.1w-r1',
        fixedVersion: '3.3.2-r1',
        cvssScore: 7.5,
        epssScore: 0.04,
        epssPercentile: 31.0,
        isCisaKev: false,
        ransomwareCampaignUse: false,
        reachability: 'UNREACHABLE_DEAD_CODE',
        callGraphSymbol: 'PKCS12_parse (never imported)',
        vexStatus: 'AFFECTED',
        vexJustification: 'none',
        attackPathSteps: ['Dead code path in Alpine 3.17 libcrypto'],
      },
    ],
  },
  'aegis-auth': {
    serviceName: 'aegis-auth',
    exposureTier: 'strictly-private',
    cves: [
      {
        cveId: 'CVE-2026-111497',
        title: 'Node.js HTTP/2 AsyncContext Heap Corruption RCE',
        affectedPackage: 'nodejs',
        installedVersion: '20.11.0',
        fixedVersion: '22.15.0',
        cvssScore: 9.8,
        epssScore: 0.964,
        epssPercentile: 99.8,
        isCisaKev: true,
        kevDueDate: '2026-11-05',
        ransomwareCampaignUse: true,
        reachability: 'REACHABLE_HOT_PATH',
        callGraphSymbol: 'oidcProvider.tokenEndpoint -> http2stream',
        vexStatus: 'AFFECTED',
        vexJustification: 'none',
        attackPathSteps: [
          'Internal mTLS Mesh',
          'OIDC /oauth2/token Handler',
          'Node.js 20 CVE-2026-111497 RCE',
        ],
      },
    ],
  },
  'aegis-db': {
    serviceName: 'aegis-db',
    exposureTier: 'strictly-private',
    cves: [
      {
        cveId: 'CVE-2024-10979',
        title: 'PostgreSQL PL/Perl Trusted Extension RCE',
        affectedPackage: 'postgresql-15',
        installedVersion: '15.8',
        fixedVersion: '15.9',
        cvssScore: 8.8,
        epssScore: 0.19,
        epssPercentile: 78.5,
        isCisaKev: false,
        ransomwareCampaignUse: false,
        reachability: 'UNREACHABLE_DEAD_CODE',
        callGraphSymbol: 'plperl_trusted_init (extension disabled)',
        vexStatus: 'NOT_AFFECTED_VEX',
        vexJustification: 'component_not_present',
        attackPathSteps: ['PL/Perl extension disabled in postgresql.conf'],
      },
    ],
  },
  'hello-world-app': {
    serviceName: 'hello-world-app',
    exposureTier: 'restricted-public',
    cves: [
      {
        cveId: 'CVE-2023-40225',
        title: 'HAProxy HTTP/2 Content-Length Validation DoS',
        affectedPackage: 'haproxy',
        installedVersion: '3.0.0-r0',
        fixedVersion: '3.0.8-r0',
        cvssScore: 7.5,
        epssScore: 0.34,
        epssPercentile: 88.0,
        isCisaKev: false,
        ransomwareCampaignUse: false,
        reachability: 'LOADED_NOT_INVOKED',
        callGraphSymbol: 'h2_process_demux (Content-Length validation)',
        vexStatus: 'AFFECTED',
        vexJustification: 'none',
        attackPathSteps: ['Restricted Public Edge (:8443)', 'HAProxy TLS Termination'],
      },
    ],
  },
};

const VEX_OVERRIDES = new Map<string, { vexStatus: VexStatus; vexJustification: VexJustification }>();

export function resetCveVexAttestations(): void {
  VEX_OVERRIDES.clear();
}

export function resolveCveServiceKey(entityRef: string): string {
  const raw = entityRef.split('/').pop()?.split(':').pop() || 'aegis-ui';
  if (raw === 'haproxy-hello-world-tls') {
    return 'hello-world-app';
  }
  return CVE_INTEL_SEEDS[raw] ? raw : 'aegis-ui';
}

export async function getEntityCveIntelligenceReport(entityRef: string): Promise<EntityCveIntelligenceReport> {
  const key = resolveCveServiceKey(entityRef);
  const seed = CVE_INTEL_SEEDS[key];

  const cves: ContextualCveRecord[] = seed.cves.map((c) => {
    const override = VEX_OVERRIDES.get(`${key}:${c.cveId}`);
    const vexStatus = override ? override.vexStatus : c.vexStatus;
    const vexJustification = override ? override.vexJustification : c.vexJustification;
    const acrsScore = computeAcrsScore({
      cvssScore: c.cvssScore,
      epssScore: c.epssScore,
      isCisaKev: c.isCisaKev,
      exposureTier: seed.exposureTier,
      reachability: c.reachability,
      vexStatus,
    });

    let priorityTier: ContextualCveRecord['priorityTier'];
    if (vexStatus !== 'AFFECTED') {
      priorityTier = 'DEFERRED_VEX';
    } else if (acrsScore >= 75 || c.isCisaKev) {
      priorityTier = 'P0_IMMEDIATE_24H';
    } else if (acrsScore >= 50) {
      priorityTier = 'P1_HIGH_7D';
    } else {
      priorityTier = 'P2_SCHEDULED_30D';
    }

    let slaHoursRemaining: number;
    if (priorityTier === 'P0_IMMEDIATE_24H') {
      slaHoursRemaining = 24;
    } else if (priorityTier === 'P1_HIGH_7D') {
      slaHoursRemaining = 168;
    } else if (priorityTier === 'P2_SCHEDULED_30D') {
      slaHoursRemaining = 720;
    } else {
      slaHoursRemaining = 0;
    }

    return {
      ...c,
      vexStatus,
      vexJustification,
      acrsScore,
      priorityTier,
      slaHoursRemaining,
    };
  });

  cves.sort((a, b) => b.acrsScore - a.acrsScore);

  const maxAcrsScore = cves.reduce((m, c) => Math.max(m, c.acrsScore), 0);
  const cisaKevCount = cves.filter((c) => c.isCisaKev && c.vexStatus === 'AFFECTED').length;
  const p0ImmediateCount = cves.filter((c) => c.priorityTier === 'P0_IMMEDIATE_24H').length;
  const rawCriticalHighCount = cves.filter((c) => c.cvssScore >= 7.0).length;
  const noiseReductionPercent = rawCriticalHighCount > 0 ? Math.round(((rawCriticalHighCount - p0ImmediateCount) / rawCriticalHighCount) * 100) : 0;

  return {
    entityRef: `component:default/${key}`,
    serviceName: seed.serviceName,
    exposureTier: seed.exposureTier,
    maxAcrsScore,
    cisaKevCount,
    p0ImmediateCount,
    rawCriticalHighCount,
    noiseReductionPercent,
    cves,
    evaluatedAt: new Date().toISOString(),
  };
}

export async function getFleetCvePriorities(): Promise<FleetCvePrioritizationSummary> {
  const reports = await Promise.all(
    Object.keys(CVE_INTEL_SEEDS).map((k) => getEntityCveIntelligenceReport(k)),
  );

  const totalRawCves = reports.reduce((s, r) => s + r.rawCriticalHighCount, 0);
  const totalActionableP0 = reports.reduce((s, r) => s + r.p0ImmediateCount, 0);
  const totalCisaKev = reports.reduce((s, r) => s + r.cisaKevCount, 0);
  const fleetNoiseReductionPercent = totalRawCves > 0 ? Math.round(((totalRawCves - totalActionableP0) / totalRawCves) * 100) : 0;

  return {
    totalServices: reports.length,
    totalRawCves,
    totalActionableP0,
    totalCisaKev,
    fleetNoiseReductionPercent,
    reports,
  };
}

export async function issueVexAttestation(entityRef: string, cveId: string, justification: VexJustification): Promise<EntityCveIntelligenceReport> {
  const key = resolveCveServiceKey(entityRef);
  VEX_OVERRIDES.set(`${key}:${cveId}`, {
    vexStatus: justification === 'none' ? 'AFFECTED' : 'NOT_AFFECTED_VEX',
    vexJustification: justification,
  });
  return getEntityCveIntelligenceReport(key);
}

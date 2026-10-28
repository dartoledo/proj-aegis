import { Entity } from '@backstage/catalog-model';

// ─── Types ───────────────────────────────────────────────────────────────────

export type EolLifecycleStatus = 'ACTIVE_LTS' | 'MAINTENANCE' | 'APPROACHING_EOL' | 'END_OF_LIFE';

export type CveSeverity = 'CRITICAL' | 'HIGH' | 'MEDIUM' | 'LOW';

export interface PackageCveRecord {
  cveId: string;
  severity: CveSeverity;
  cvssScore: number;
  affectedPackage: string;
  installedVersion: string;
  fixedVersion: string;
  title: string;
  publishedAt: string;
  exploitMaturity: 'active-exploit' | 'poc' | 'unproven';
  layerOrigin: 'application-sbom' | 'harbor-base-image';
}

export interface EndOfLifeProductRecord {
  product: string;
  displayName: string;
  cycle: string;
  installedVersion: string;
  latestPatchVersion: string;
  latestCycle: string;
  isLts: boolean;
  releaseDate: string;
  activeSupportEndDate: string;
  eolDate: string;
  daysUntilEol: number;
  eolStatus: EolLifecycleStatus;
  upgradeRecommendation: string;
  sourceUrl: string;
  cves: PackageCveRecord[];
}

export interface HarborContainerArtifact {
  repositorySlug: string;
  registryHost: string;
  projectName: string;
  repoName: string;
  activeTag: string;
  tags: string[];
  digest: string;
  baseImage: string;
  sizeMB: number;
  pushedAt: string;
  lastScannedAt: string;
  scanStatus: string;
  scanner: string;
  pullCommand: string;
  vulnerabilitySummary: {
    critical: number;
    high: number;
    medium: number;
    low: number;
    fixable: number;
  };
}

export interface EntityHarborEolReport {
  entityRef: string;
  serviceName: string;
  harborArtifact: HarborContainerArtifact;
  eolProducts: EndOfLifeProductRecord[];
  cveList: PackageCveRecord[];
  summary: {
    totalPackages: number;
    eolCount: number;
    approachingEolCount: number;
    supportedCount: number;
    criticalCves: number;
    highCves: number;
    mediumCves: number;
    lowCves: number;
    overallRisk: 'CRITICAL' | 'WARNING' | 'HEALTHY';
  };
  scannedAt: string;
}

// ─── Constants ───────────────────────────────────────────────────────────────

export const DEFAULT_HARBOR_HOST: string =
  process.env.AEGIS_HARBOR_HOST || 'http://127.0.0.1:8880';

// ─── EndOfLife Catalog Database ──────────────────────────────────────────────

export const ENDOFLIFE_CATALOG_DB: Record<
  string,
  Omit<EndOfLifeProductRecord, 'daysUntilEol' | 'eolStatus'>
> = {
  'react@18': {
    product: 'react',
    displayName: 'React',
    cycle: '18',
    installedVersion: '18.3.1',
    latestPatchVersion: '18.3.1',
    latestCycle: '19',
    isLts: false,
    releaseDate: '2022-03-29',
    activeSupportEndDate: '2026-12-31',
    eolDate: '2027-06-30',
    upgradeRecommendation: 'Upgrade to React 19 for concurrent features and improved performance.',
    sourceUrl: 'https://endoflife.date/api/react.json',
    cves: [],
  },
  'nodejs@22': {
    product: 'nodejs',
    displayName: 'Node.js',
    cycle: '22',
    installedVersion: '22.14.0',
    latestPatchVersion: '22.15.0',
    latestCycle: '22',
    isLts: true,
    releaseDate: '2024-04-01',
    activeSupportEndDate: '2027-04-30',
    eolDate: '2027-04-30',
    upgradeRecommendation: 'Apply latest patch 22.15.0 to stay current on Node.js 22 LTS (Jod).',
    sourceUrl: 'https://endoflife.date/api/nodejs.json',
    cves: [],
  },
  'nodejs@20': {
    product: 'nodejs',
    displayName: 'Node.js',
    cycle: '20',
    installedVersion: '20.11.0',
    latestPatchVersion: '20.18.3',
    latestCycle: '22',
    isLts: true,
    releaseDate: '2023-04-01',
    activeSupportEndDate: '2026-10-30',
    eolDate: '2027-01-30',
    upgradeRecommendation: 'Upgrade to Node.js 22 LTS (Jod) for continued active support.',
    sourceUrl: 'https://endoflife.date/api/nodejs.json',
    cves: [
      {
        cveId: 'CVE-2024-27980',
        severity: 'HIGH',
        cvssScore: 8.1,
        affectedPackage: 'nodejs',
        installedVersion: '20.11.0',
        fixedVersion: '20.18.3',
        title: 'V8: Use-after-free in Intl.DateTimeFormat in Node.js',
        publishedAt: '2024-04-01',
        exploitMaturity: 'poc',
        layerOrigin: 'application-sbom',
      },
    ],
  },
  'nodejs@18': {
    product: 'nodejs',
    displayName: 'Node.js',
    cycle: '18',
    installedVersion: '18.20.8',
    latestPatchVersion: '18.20.8',
    latestCycle: '22',
    isLts: true,
    releaseDate: '2022-04-01',
    activeSupportEndDate: '2025-04-30',
    eolDate: '2025-04-30',
    upgradeRecommendation: 'Upgrade to Node.js 22 LTS (Jod) as Node.js 18 LTS (Hydrogen) is approaching EOL.',
    sourceUrl: 'https://endoflife.date/api/nodejs.json',
    cves: [
      {
        cveId: 'CVE-2026-56850',
        severity: 'CRITICAL',
        cvssScore: 9.4,
        affectedPackage: 'nodejs',
        installedVersion: '18.20.8',
        fixedVersion: '22.15.0',
        title: 'Node.js HTTP/2 stream reset allows remote code execution',
        publishedAt: '2026-01-15',
        exploitMaturity: 'active-exploit',
        layerOrigin: 'application-sbom',
      },
      {
        cveId: 'CVE-2025-23083',
        severity: 'HIGH',
        cvssScore: 7.8,
        affectedPackage: 'nodejs',
        installedVersion: '18.20.8',
        fixedVersion: '20.18.3',
        title: 'Node.js zlib heap corruption via crafted deflate stream',
        publishedAt: '2025-03-22',
        exploitMaturity: 'poc',
        layerOrigin: 'application-sbom',
      },
    ],
  },
  'openssl@1.1.1': {
    product: 'openssl',
    displayName: 'OpenSSL',
    cycle: '1.1.1',
    installedVersion: '1.1.1w',
    latestPatchVersion: '1.1.1w',
    latestCycle: '3.4',
    isLts: false,
    releaseDate: '2016-09-28',
    activeSupportEndDate: '2023-09-11',
    eolDate: '2023-09-11',
    upgradeRecommendation: 'Upgrade to OpenSSL 3.4 LTS for continued security patches and FIPS 140-3 compliance.',
    sourceUrl: 'https://endoflife.date/api/openssl.json',
    cves: [
      {
        cveId: 'CVE-2023-5678',
        severity: 'CRITICAL',
        cvssScore: 9.1,
        affectedPackage: 'openssl',
        installedVersion: '1.1.1w',
        fixedVersion: '3.4.0',
        title: 'OpenSSL X.400 address type in X.509 emailAddrs can cause excessive memory use',
        publishedAt: '2023-11-08',
        exploitMaturity: 'active-exploit',
        layerOrigin: 'harbor-base-image',
      },
      {
        cveId: 'CVE-2024-0727',
        severity: 'CRITICAL',
        cvssScore: 9.8,
        affectedPackage: 'openssl',
        installedVersion: '1.1.1w',
        fixedVersion: '3.4.0',
        title: 'OpenSSL X.509 generalisedTime comparison allows certificate validation bypass',
        publishedAt: '2024-01-16',
        exploitMaturity: 'active-exploit',
        layerOrigin: 'harbor-base-image',
      },
    ],
  },
  'openssl@3.0': {
    product: 'openssl',
    displayName: 'OpenSSL',
    cycle: '3.0',
    installedVersion: '3.0.13',
    latestPatchVersion: '3.0.16',
    latestCycle: '3.4',
    isLts: true,
    releaseDate: '2021-07-21',
    activeSupportEndDate: '2027-09-07',
    eolDate: '2027-09-07',
    upgradeRecommendation: 'Apply patch 3.0.16 or migrate to OpenSSL 3.4 LTS for FIPS 140-3 support.',
    sourceUrl: 'https://endoflife.date/api/openssl.json',
    cves: [
      {
        cveId: 'CVE-2024-6119',
        severity: 'HIGH',
        cvssScore: 7.5,
        affectedPackage: 'openssl',
        installedVersion: '3.0.13',
        fixedVersion: '3.0.16',
        title: 'OpenSSL X.509v3 extension parsing allows denial of service via crafted certificate',
        publishedAt: '2024-09-06',
        exploitMaturity: 'poc',
        layerOrigin: 'harbor-base-image',
      },
    ],
  },
  'openssl@3.2': {
    product: 'openssl',
    displayName: 'OpenSSL',
    cycle: '3.2',
    installedVersion: '3.2.1',
    latestPatchVersion: '3.2.4',
    latestCycle: '3.4',
    isLts: true,
    releaseDate: '2023-11-23',
    activeSupportEndDate: '2025-11-23',
    eolDate: '2025-11-23',
    upgradeRecommendation: 'Apply patch 3.2.4 or migrate to OpenSSL 3.4 LTS for extended support window.',
    sourceUrl: 'https://endoflife.date/api/openssl.json',
    cves: [
      {
        cveId: 'CVE-2024-4741',
        severity: 'MEDIUM',
        cvssScore: 5.9,
        affectedPackage: 'openssl',
        installedVersion: '3.2.1',
        fixedVersion: '3.2.4',
        title: 'OpenSSL X.509v3 name constraints check bypass with non-ASCII characters',
        publishedAt: '2024-07-05',
        exploitMaturity: 'unproven',
        layerOrigin: 'harbor-base-image',
      },
    ],
  },
  'postgresql@16': {
    product: 'postgresql',
    displayName: 'PostgreSQL',
    cycle: '16',
    installedVersion: '16.2',
    latestPatchVersion: '16.8',
    latestCycle: '17',
    isLts: false,
    releaseDate: '2023-09-14',
    activeSupportEndDate: '2028-11-09',
    eolDate: '2028-11-09',
    upgradeRecommendation: 'Apply patch 16.8 to address security fixes; consider PostgreSQL 17 for new features.',
    sourceUrl: 'https://endoflife.date/api/postgresql.json',
    cves: [
      {
        cveId: 'CVE-2024-10979',
        severity: 'HIGH',
        cvssScore: 8.8,
        affectedPackage: 'postgresql',
        installedVersion: '16.2',
        fixedVersion: '16.8',
        title: 'PostgreSQL pg_dump allows privilege escalation via crafted table name',
        publishedAt: '2024-12-05',
        exploitMaturity: 'poc',
        layerOrigin: 'application-sbom',
      },
    ],
  },
  'postgresql@14': {
    product: 'postgresql',
    displayName: 'PostgreSQL',
    cycle: '14',
    installedVersion: '14.9',
    latestPatchVersion: '14.17',
    latestCycle: '17',
    isLts: false,
    releaseDate: '2021-04-19',
    activeSupportEndDate: '2026-11-12',
    eolDate: '2026-11-12',
    upgradeRecommendation: 'Upgrade to PostgreSQL 16 or 17 as version 14 is approaching end of support.',
    sourceUrl: 'https://endoflife.date/api/postgresql.json',
    cves: [
      {
        cveId: 'CVE-2025-1094',
        severity: 'CRITICAL',
        cvssScore: 9.8,
        affectedPackage: 'postgresql',
        installedVersion: '14.9',
        fixedVersion: '14.17',
        title: 'PostgreSQL psql quoting allows SQL injection via crafted connection string',
        publishedAt: '2025-02-10',
        exploitMaturity: 'active-exploit',
        layerOrigin: 'application-sbom',
      },
    ],
  },
  'haproxy@3.0': {
    product: 'haproxy',
    displayName: 'HAProxy',
    cycle: '3.0',
    installedVersion: '3.0.0',
    latestPatchVersion: '3.0.8',
    latestCycle: '3.1',
    isLts: true,
    releaseDate: '2023-06-30',
    activeSupportEndDate: '2029-06-30',
    eolDate: '2029-06-30',
    upgradeRecommendation: 'Apply patch 3.0.8 for bug fixes; HAProxy 3.0 LTS is well within its support window.',
    sourceUrl: 'https://endoflife.date/api/haproxy.json',
    cves: [],
  },
  'haproxy@1.8': {
    product: 'haproxy',
    displayName: 'HAProxy',
    cycle: '1.8',
    installedVersion: '1.8.31',
    latestPatchVersion: '1.8.31',
    latestCycle: '3.1',
    isLts: false,
    releaseDate: '2017-06-30',
    activeSupportEndDate: '2022-12-31',
    eolDate: '2022-12-31',
    upgradeRecommendation: 'Upgrade to HAProxy 3.0 LTS or 3.1 for continued security support and HTTP/3 features.',
    sourceUrl: 'https://endoflife.date/api/haproxy.json',
    cves: [
      {
        cveId: 'CVE-2023-40225',
        severity: 'CRITICAL',
        cvssScore: 9.1,
        affectedPackage: 'haproxy',
        installedVersion: '1.8.31',
        fixedVersion: '3.0.8',
        title: 'HAProxy HTTP/2 stream smuggling via malformed CONTINUATION frames',
        publishedAt: '2023-10-12',
        exploitMaturity: 'active-exploit',
        layerOrigin: 'application-sbom',
      },
      {
        cveId: 'CVE-2023-25725',
        severity: 'CRITICAL',
        cvssScore: 9.3,
        affectedPackage: 'haproxy',
        installedVersion: '1.8.31',
        fixedVersion: '3.0.8',
        title: 'HAProxy header parser integer overflow allows remote code execution',
        publishedAt: '2023-04-24',
        exploitMaturity: 'active-exploit',
        layerOrigin: 'application-sbom',
      },
    ],
  },
  'envoy@1.30': {
    product: 'envoy',
    displayName: 'Envoy Proxy',
    cycle: '1.30',
    installedVersion: '1.30.1',
    latestPatchVersion: '1.30.9',
    latestCycle: '1.32',
    isLts: false,
    releaseDate: '2024-04-30',
    activeSupportEndDate: '2027-04-30',
    eolDate: '2027-04-30',
    upgradeRecommendation: 'Upgrade to Envoy 1.32 for continued support and latest xDS protocol features.',
    sourceUrl: 'https://endoflife.date/api/envoy.json',
    cves: [
      {
        cveId: 'CVE-2024-45806',
        severity: 'HIGH',
        cvssScore: 7.5,
        affectedPackage: 'envoy',
        installedVersion: '1.30.1',
        fixedVersion: '1.30.9',
        title: 'Envoy HTTP connection manager allows denial of service via malformed upgrade header',
        publishedAt: '2024-08-15',
        exploitMaturity: 'poc',
        layerOrigin: 'application-sbom',
      },
    ],
  },
  'alpine@3.20': {
    product: 'alpine',
    displayName: 'Alpine Linux',
    cycle: '3.20',
    installedVersion: '3.20.3',
    latestPatchVersion: '3.20.6',
    latestCycle: '3.21',
    isLts: false,
    releaseDate: '2024-04-01',
    activeSupportEndDate: '2027-05-01',
    eolDate: '2027-05-01',
    upgradeRecommendation: 'Apply patch 3.20.6 for security updates; consider Alpine 3.21 for newer toolchain.',
    sourceUrl: 'https://endoflife.date/api/alpine.json',
    cves: [],
  },
  'alpine@3.19': {
    product: 'alpine',
    displayName: 'Alpine Linux',
    cycle: '3.19',
    installedVersion: '3.19.4',
    latestPatchVersion: '3.19.7',
    latestCycle: '3.21',
    isLts: false,
    releaseDate: '2024-01-01',
    activeSupportEndDate: '2027-02-01',
    eolDate: '2027-02-01',
    upgradeRecommendation: 'Upgrade to Alpine 3.20 or 3.21 as 3.19 is approaching end of support.',
    sourceUrl: 'https://endoflife.date/api/alpine.json',
    cves: [
      {
        cveId: 'CVE-2024-58251',
        severity: 'MEDIUM',
        cvssScore: 5.5,
        affectedPackage: 'busybox',
        installedVersion: '1.36.1-r15',
        fixedVersion: '1.36.1-r17',
        title: 'Alpine busybox awk allows denial of service via crafted input',
        publishedAt: '2024-11-20',
        exploitMaturity: 'unproven',
        layerOrigin: 'harbor-base-image',
      },
    ],
  },
  'alpine@3.18': {
    product: 'alpine',
    displayName: 'Alpine Linux',
    cycle: '3.18',
    installedVersion: '3.18.6',
    latestPatchVersion: '3.18.12',
    latestCycle: '3.21',
    isLts: false,
    releaseDate: '2023-05-01',
    activeSupportEndDate: '2026-12-15',
    eolDate: '2026-12-15',
    upgradeRecommendation: 'Upgrade to Alpine 3.20 or 3.21 as 3.18 is approaching end of support.',
    sourceUrl: 'https://endoflife.date/api/alpine.json',
    cves: [
      {
        cveId: 'CVE-2024-45492',
        severity: 'HIGH',
        cvssScore: 8.1,
        affectedPackage: 'libexpat',
        installedVersion: '2.5.0-r2',
        fixedVersion: '2.6.3-r0',
        title: 'Alpine libexpat allows denial of service via crafted XML input',
        publishedAt: '2024-08-12',
        exploitMaturity: 'poc',
        layerOrigin: 'harbor-base-image',
      },
    ],
  },
  'alpine@3.17': {
    product: 'alpine',
    displayName: 'Alpine Linux',
    cycle: '3.17',
    installedVersion: '3.17.9',
    latestPatchVersion: '3.17.10',
    latestCycle: '3.21',
    isLts: false,
    releaseDate: '2022-12-01',
    activeSupportEndDate: '2024-11-22',
    eolDate: '2024-11-22',
    upgradeRecommendation: 'Upgrade to Alpine 3.20 or 3.21 as 3.17 has reached end of life.',
    sourceUrl: 'https://endoflife.date/api/alpine.json',
    cves: [
      {
        cveId: 'GHSA-23hp-3jrh-7fpw',
        severity: 'CRITICAL',
        cvssScore: 9.3,
        affectedPackage: 'tar',
        installedVersion: '6.2.1-r0',
        fixedVersion: '6.2.1-r1',
        title: 'Alpine tar 6.2.1 allows remote code execution via crafted archive',
        publishedAt: '2024-06-10',
        exploitMaturity: 'active-exploit',
        layerOrigin: 'harbor-base-image',
      },
      {
        cveId: 'CVE-2024-107891',
        severity: 'HIGH',
        cvssScore: 8.4,
        affectedPackage: 'musl',
        installedVersion: '1.2.3-r4',
        fixedVersion: '1.2.4-r0',
        title: 'Alpine musl libc allows denial of service via crafted environment variables',
        publishedAt: '2024-10-05',
        exploitMaturity: 'poc',
        layerOrigin: 'harbor-base-image',
      },
    ],
  },
};

// ─── Default Service Profiles ────────────────────────────────────────────────

interface ServiceProfile {
  entityRef: string;
  repositorySlug: string;
  activeTag: string;
  tags: string[];
  baseImage: string;
  sizeMB: number;
  digest: string;
  products: string[];
}

export const DEFAULT_SERVICE_PROFILES: Record<string, ServiceProfile> = {
  'aegis-ui': {
    entityRef: 'component:default/aegis-ui',
    repositorySlug: 'aegis-ciam/aegis-ui',
    activeTag: 'v2.4.0',
    tags: ['v2.4.0', 'v2.3.1', 'v2.3.0', 'latest'],
    baseImage: 'node:22-alpine3.20',
    sizeMB: 142,
    digest: 'sha256:a1b2c3d4e5f6a7b8c9d0e1f2a3b4c5d6e7f8a9b0c1d2e3f4a5b6c7d8e9f0a1b2',
    products: ['react@18', 'nodejs@22', 'envoy@1.30', 'alpine@3.20'],
  },
  'aegis-backend': {
    entityRef: 'component:default/aegis-backend',
    repositorySlug: 'aegis-ciam/aegis-backend',
    activeTag: 'v1.9.2',
    tags: ['v1.9.2', 'v1.9.1', 'v1.8.0', 'latest'],
    baseImage: 'node:18-alpine3.17',
    sizeMB: 218,
    digest: 'sha256:b2c3d4e5f6a7b8c9d0e1f2a3b4c5d6e7f8a9b0c1d2e3f4a5b6c7d8e9f0a1b2c3',
    products: ['nodejs@18', 'postgresql@14', 'openssl@1.1.1', 'alpine@3.17'],
  },
  'aegis-auth': {
    entityRef: 'component:default/aegis-auth',
    repositorySlug: 'aegis-ciam/aegis-auth',
    activeTag: 'v3.1.0',
    tags: ['v3.1.0', 'v3.0.2', 'v3.0.1', 'latest'],
    baseImage: 'node:20-alpine3.18',
    sizeMB: 187,
    digest: 'sha256:c3d4e5f6a7b8c9d0e1f2a3b4c5d6e7f8a9b0c1d2e3f4a5b6c7d8e9f0a1b2c3d4',
    products: ['nodejs@20', 'openssl@3.0', 'alpine@3.18'],
  },
  'aegis-db': {
    entityRef: 'resource:default/aegis-db',
    repositorySlug: 'aegis-ciam/aegis-db',
    activeTag: 'v16.2.0',
    tags: ['v16.2.0', 'v16.1.0', 'v15.4.0', 'latest'],
    baseImage: 'postgres:16-alpine3.19',
    sizeMB: 245,
    digest: 'sha256:d4e5f6a7b8c9d0e1f2a3b4c5d6e7f8a9b0c1d2e3f4a5b6c7d8e9f0a1b2c3d4e5',
    products: ['postgresql@16', 'openssl@3.0', 'alpine@3.19'],
  },
  'hello-world-app': {
    entityRef: 'component:default/hello-world-app',
    repositorySlug: 'aegis-ciam/hello-world-app',
    activeTag: 'v1.4.0',
    tags: ['v1.4.0', 'v1.3.0', 'v1.2.0', 'latest'],
    baseImage: 'haproxy:3.0-alpine3.20',
    sizeMB: 98,
    digest: 'sha256:e5f6a7b8c9d0e1f2a3b4c5d6e7f8a9b0c1d2e3f4a5b6c7d8e9f0a1b2c3d4e5f6',
    products: ['haproxy@3.0', 'haproxy@1.8', 'nodejs@22', 'openssl@3.2', 'alpine@3.20'],
  },
  'haproxy-hello-world-tls': {
    entityRef: 'component:default/hello-world-app',
    repositorySlug: 'aegis-ciam/hello-world-app',
    activeTag: 'v1.4.0',
    tags: ['v1.4.0', 'v1.3.0', 'v1.2.0', 'latest'],
    baseImage: 'haproxy:3.0-alpine3.20',
    sizeMB: 98,
    digest: 'sha256:e5f6a7b8c9d0e1f2a3b4c5d6e7f8a9b0c1d2e3f4a5b6c7d8e9f0a1b2c3d4e5f6',
    products: ['haproxy@3.0', 'haproxy@1.8', 'nodejs@22', 'openssl@3.2', 'alpine@3.20'],
  },
};

// ─── Core Functions ──────────────────────────────────────────────────────────

export function calculateDaysUntilEol(eolDate: string, referenceDate?: string): number {
  const ref = referenceDate ? new Date(referenceDate) : new Date();
  const target = new Date(eolDate);
  const diffMs = target.getTime() - ref.getTime();
  return Math.ceil(diffMs / (1000 * 60 * 60 * 24));
}

export function classifyEolStatus(daysUntilEol: number, isLts: boolean): EolLifecycleStatus {
  if (daysUntilEol <= 0) {
    return 'END_OF_LIFE';
  }
  if (daysUntilEol <= 180) {
    return 'APPROACHING_EOL';
  }
  if (isLts) {
    return 'ACTIVE_LTS';
  }
  return 'MAINTENANCE';
}

export function evaluateProductCycles(
  productTokens: string[],
  referenceDate?: string,
): EndOfLifeProductRecord[] {
  return productTokens
    .filter((token) => ENDOFLIFE_CATALOG_DB[token])
    .map((token) => {
      const entry = ENDOFLIFE_CATALOG_DB[token];
      const daysUntilEol = calculateDaysUntilEol(entry.eolDate, referenceDate);
      const eolStatus = classifyEolStatus(daysUntilEol, entry.isLts);
      return {
        ...entry,
        daysUntilEol,
        eolStatus,
      };
    });
}

// ─── Entity Harbor EOL Report ────────────────────────────────────────────────

function extractServiceName(entityOrRef: Entity | string): string {
  if (typeof entityOrRef === 'string') {
    // Handle full entityRef like 'component:default/aegis-backend' or bare name
    const parts = entityOrRef.split('/');
    return parts[parts.length - 1];
  }
  return entityOrRef.metadata.name;
}

function extractEntityRef(entityOrRef: Entity | string): string {
  if (typeof entityOrRef === 'string') {
    if (entityOrRef.includes(':')) {
      return entityOrRef;
    }
    return `component:default/${entityOrRef}`;
  }
  return `${entityOrRef.kind.toLowerCase()}:${entityOrRef.metadata.namespace || 'default'}/${entityOrRef.metadata.name}`;
}

const remediatedServices = new Set<string>();

export async function getEntityHarborEolReport(
  entityOrRef: Entity | string,
  options?: { referenceDate?: string; triggerScan?: boolean },
): Promise<EntityHarborEolReport> {
  const referenceDate = options?.referenceDate;
  const serviceName = extractServiceName(entityOrRef);
  const entityRef = extractEntityRef(entityOrRef);

  // Determine profile: use annotations from Entity if available, else fall back to DEFAULT_SERVICE_PROFILES
  let repositorySlug: string;
  let registryHost: string;
  let activeTag: string;
  let tags: string[];
  let baseImage: string;
  let sizeMB: number;
  let digest: string;
  let products: string[];

  if (typeof entityOrRef !== 'string' && entityOrRef.metadata.annotations && !remediatedServices.has(serviceName)) {
    const annotations = entityOrRef.metadata.annotations;
    repositorySlug = annotations['goharbor.io/repository-slug'] || DEFAULT_SERVICE_PROFILES[serviceName]?.repositorySlug || `aegis-ciam/${serviceName}`;
    registryHost = annotations['goharbor.io/host'] || DEFAULT_HARBOR_HOST;
    activeTag = annotations['goharbor.io/image-tag'] || DEFAULT_SERVICE_PROFILES[serviceName]?.activeTag || 'latest';
    const productsAnnotation = annotations['endoflife.date/products'];
    products = productsAnnotation
      ? productsAnnotation.split(',').map((s) => s.trim())
      : DEFAULT_SERVICE_PROFILES[serviceName]?.products || [];
    tags = DEFAULT_SERVICE_PROFILES[serviceName]?.tags || [activeTag, 'latest'];
    baseImage = DEFAULT_SERVICE_PROFILES[serviceName]?.baseImage || 'alpine:3.20';
    sizeMB = DEFAULT_SERVICE_PROFILES[serviceName]?.sizeMB || 0;
    digest = DEFAULT_SERVICE_PROFILES[serviceName]?.digest || 'sha256:unknown';
  } else {
    const profile = DEFAULT_SERVICE_PROFILES[serviceName];
    repositorySlug = profile?.repositorySlug || `aegis-ciam/${serviceName}`;
    registryHost = DEFAULT_HARBOR_HOST;
    activeTag = profile?.activeTag || 'latest';
    tags = profile?.tags || [activeTag, 'latest'];
    baseImage = profile?.baseImage || 'alpine:3.20';
    sizeMB = profile?.sizeMB || 0;
    digest = profile?.digest || 'sha256:unknown';
    products = profile?.products || [];
  }

  // Try fetching live Harbor metadata with 1500ms timeout
  let pushedAt = '2026-10-28T12:00:00Z';
  let lastScannedAt = new Date().toISOString();
  let scanStatus = 'Success';
  let scanner = 'Grype v0.121.0 + Syft v1.55.0 (Harbor Adapter)';

  try {
    const controller = new AbortController();
    const timeout = setTimeout(() => controller.abort(), 1500);
    const url = options?.triggerScan
      ? `${DEFAULT_HARBOR_HOST}/api/v2.0/scan/${repositorySlug}`
      : `${DEFAULT_HARBOR_HOST}/api/v2.0/repositories/${repositorySlug}`;
    const method = options?.triggerScan ? 'POST' : 'GET';
    const res = await fetch(url, { method, signal: controller.signal });
    if (res.ok) {
      const raw = await res.json();
      const data = raw.repository || raw;
      if (data.digest) digest = data.digest;
      if (data.sizeMB ?? data.size_mb) sizeMB = data.sizeMB ?? data.size_mb;
      if (data.pushedAt ?? data.update_time) pushedAt = data.pushedAt ?? data.update_time;
      if (data.scanStatus ?? data.scan_status) scanStatus = data.scanStatus ?? data.scan_status;
      if (data.scanner) scanner = data.scanner;
      if (data.lastScannedAt ?? data.scan_time) lastScannedAt = data.lastScannedAt ?? data.scan_time;
    }
    clearTimeout(timeout);
  } catch {
    // Fallback to profile defaults (already set)
  }

  // Build HarborContainerArtifact
  const [projectName, repoName] = repositorySlug.split('/');
  const harborArtifact: HarborContainerArtifact = {
    repositorySlug,
    registryHost,
    projectName,
    repoName,
    activeTag,
    tags,
    digest,
    baseImage,
    sizeMB,
    pushedAt,
    lastScannedAt,
    scanStatus,
    scanner,
    pullCommand: `podman pull ${registryHost}/${repositorySlug}:${activeTag}`,
    vulnerabilitySummary: {
      critical: 0,
      high: 0,
      medium: 0,
      low: 0,
      fixable: 0,
    },
  };

  // Evaluate product cycles
  const eolProducts = evaluateProductCycles(products, referenceDate);

  // Aggregate CVEs from all products, sorted by cvssScore descending
  const cveList: PackageCveRecord[] = eolProducts
    .flatMap((p) => p.cves)
    .sort((a, b) => b.cvssScore - a.cvssScore);

  // Update vulnerabilitySummary
  const criticalCves = cveList.filter((c) => c.severity === 'CRITICAL').length;
  const highCves = cveList.filter((c) => c.severity === 'HIGH').length;
  const mediumCves = cveList.filter((c) => c.severity === 'MEDIUM').length;
  const lowCves = cveList.filter((c) => c.severity === 'LOW').length;
  const fixable = cveList.filter((c) => c.fixedVersion !== c.installedVersion).length;

  harborArtifact.vulnerabilitySummary = {
    critical: criticalCves,
    high: highCves,
    medium: mediumCves,
    low: lowCves,
    fixable,
  };

  // Compute summary
  const eolCount = eolProducts.filter((p) => p.eolStatus === 'END_OF_LIFE').length;
  const approachingEolCount = eolProducts.filter((p) => p.eolStatus === 'APPROACHING_EOL').length;
  const supportedCount = eolProducts.filter(
    (p) => p.eolStatus === 'ACTIVE_LTS' || p.eolStatus === 'MAINTENANCE',
  ).length;

  let overallRisk: 'CRITICAL' | 'WARNING' | 'HEALTHY' = 'HEALTHY';
  if (criticalCves > 0 || eolCount > 0) {
    overallRisk = 'CRITICAL';
  } else if (highCves > 0 || approachingEolCount > 0) {
    overallRisk = 'WARNING';
  }

  return {
    entityRef,
    serviceName,
    harborArtifact,
    eolProducts,
    cveList,
    summary: {
      totalPackages: eolProducts.length,
      eolCount,
      approachingEolCount,
      supportedCount,
      criticalCves,
      highCves,
      mediumCves,
      lowCves,
      overallRisk,
    },
    scannedAt: new Date().toISOString(),
  };
}

// ─── Fleet Summary ───────────────────────────────────────────────────────────

const DEFAULT_FLEET_ENTITY_REFS: string[] = [
  'component:default/aegis-ui',
  'component:default/aegis-backend',
  'component:default/aegis-auth',
  'resource:default/aegis-db',
  'component:default/hello-world-app',
];

export async function getFleetHarborEolSummary(
  entityRefs?: string[],
): Promise<EntityHarborEolReport[]> {
  const refs = entityRefs && entityRefs.length > 0 ? entityRefs : DEFAULT_FLEET_ENTITY_REFS;
  return Promise.all(refs.map((ref) => getEntityHarborEolReport(ref)));
}

// ─── Prometheus Metrics Rendering ────────────────────────────────────────────

export function renderHarborEolPrometheusMetrics(
  reports: EntityHarborEolReport[],
): string {
  const lines: string[] = [];

  for (const report of reports) {
    for (const product of report.eolProducts) {
      lines.push(
        `aegis_package_eol_days_remaining{service="${report.serviceName}",product="${product.product}",cycle="${product.cycle}"} ${product.daysUntilEol}`,
      );
    }
    const totalVulns =
      report.harborArtifact.vulnerabilitySummary.critical +
      report.harborArtifact.vulnerabilitySummary.high +
      report.harborArtifact.vulnerabilitySummary.medium +
      report.harborArtifact.vulnerabilitySummary.low;
    lines.push(
      `aegis_harbor_image_vulnerabilities_total{service="${report.serviceName}",repository="${report.harborArtifact.repositorySlug}"} ${totalVulns}`,
    );
  }

  return lines.join('\n') + '\n';
}

// ─── Remediation ─────────────────────────────────────────────────────────────

export async function remediateEntityEolPackages(
  entityOrRef: Entity | string,
): Promise<EntityHarborEolReport> {
  const serviceName = extractServiceName(entityOrRef);
  const profile = DEFAULT_SERVICE_PROFILES[serviceName];

  if (profile) {
    remediatedServices.add(serviceName);
    const upgradedProducts = Array.from(
      new Set(
        profile.products.map((p) => {
          if (p === 'nodejs@18' || p === 'nodejs@20') return 'nodejs@22';
          if (p === 'openssl@1.1.1' || p === 'openssl@3.2') return 'openssl@3.0';
          if (p === 'postgresql@14') return 'postgresql@16';
          if (p === 'haproxy@1.8') return 'haproxy@3.0';
          if (p === 'alpine@3.17' || p === 'alpine@3.18' || p === 'alpine@3.19') return 'alpine@3.20';
          return p;
        }),
      ),
    );
    profile.products = upgradedProducts;
    profile.baseImage = profile.baseImage
      .replace(/alpine3\.\d+/, 'alpine3.20')
      .replace(/node:\d+/, 'node:22');
    if (!profile.activeTag.endsWith('-lts')) {
      profile.activeTag = `${profile.activeTag}-lts`;
      profile.tags = Array.from(new Set([profile.activeTag, ...profile.tags]));
    }
  }

  return getEntityHarborEolReport(serviceName, { triggerScan: true });
}

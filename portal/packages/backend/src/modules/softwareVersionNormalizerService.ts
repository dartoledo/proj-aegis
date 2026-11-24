export type EolCycleStrategy =
  | 'MAJOR'
  | 'MAJOR_MINOR'
  | 'MAJOR_MINOR_PATCH'
  | 'DISTRO_CODENAME';

export type SoftwareEcosystem =
  | 'npm'
  | 'pypi'
  | 'maven'
  | 'golang'
  | 'cargo'
  | 'nuget'
  | 'apk'
  | 'deb'
  | 'rpm'
  | 'oci'
  | 'generic';

export type SemverSortTuple = [number, number, number, number, number, number, number];

export interface NormalizedSoftwareVersionRecord {
  productName: string;
  rawVersion: string;
  ecosystem: SoftwareEcosystem;

  // Canonical External Identity Anchors (PURL + CPE 2.3)
  purl: string;
  cpe23Uri: string;

  // External EOL Data Source Fields (endoflife.date API v1 + vendor lifecycle feeds)
  eolProductSlug: string;
  eolCycleKey: string;
  eolCycleStrategy: EolCycleStrategy;
  eolApiUrl: string;
  vendorLifecycleStream: string;

  // External CVE & Vulnerability Data Source Fields (OSV.dev, NVD CPE, GHSA, Distro SecDB, CISA KEV / EPSS)
  osvEcosystem: string;
  osvPackageName: string;
  nvdCpeMatchString: string;
  ghsaEcosystem: string | null;
  distroAdvisoryNamespace: string | null;

  // Decomposed Version Tuple & SQL Sort Array
  upstreamVersion: string;
  epoch: number;
  major: number;
  minor: number;
  patch: number;
  letterPatchNum: number;
  prereleaseStageRank: number;
  prereleaseNum: number;
  distroRevision: string | null;
  semverSortTuple: SemverSortTuple;
}

export interface PublicEolCycleReference {
  eolProductSlug: string;
  cycle: string;
  isLts: boolean;
  releaseDate: string;
  activeSupportEndDate: string;
  eolDate: string;
  latestPatchVersion: string;
}

export interface PublicCveRangeReference {
  cveId: string;
  ghsaId?: string;
  title: string;
  eolProductSlug: string;
  osvEcosystem: string;
  osvPackageName: string;
  nvdCpeMatchString: string;
  distroAdvisoryNamespace: string | null;
  introducedVersion: string;
  fixedVersion: string | null;
  cvssV3Score: number;
  epssScore: number;
  isCisaKev: boolean;
  advisorySource: 'OSV_DEV' | 'NVD_CPE' | 'ALPINE_SECDB' | 'DEBIAN_TRACKER' | 'GITHUB_GHSA';
}

export interface VersionCrossCheckResult {
  normalized: NormalizedSoftwareVersionRecord;
  eolMatch: {
    matchedCycle: PublicEolCycleReference | null;
    isEol: boolean;
    isApproachingEol: boolean;
    isOutdatedPatchOnCycle: boolean;
    latestPatchVersionOnCycle: string | null;
    daysUntilEol: number | null;
  };
  cveMatches: PublicCveRangeReference[];
  highestCvssScore: number;
  highestEpssScore: number;
  hasReachableCisaKev: boolean;
}

interface ProductCatalogRule {
  canonicalName: string;
  eolProductSlug: string;
  eolCycleStrategy: EolCycleStrategy;
  defaultEcosystem: SoftwareEcosystem;
  purlNamespace?: string;
  purlName: string;
  cpeVendor: string;
  cpeProduct: string;
  osvEcosystem: string;
  osvPackageName: string;
  ghsaEcosystem: string | null;
  vendorLifecycleStream: string;
}

const PRODUCT_CATALOG_RULES: Record<string, ProductCatalogRule> = {
  nodejs: {
    canonicalName: 'Node.js',
    eolProductSlug: 'nodejs',
    eolCycleStrategy: 'MAJOR',
    defaultEcosystem: 'generic',
    purlName: 'nodejs',
    cpeVendor: 'nodejs',
    cpeProduct: 'node.js',
    osvEcosystem: 'Bitnami',
    osvPackageName: 'node',
    ghsaEcosystem: 'npm',
    vendorLifecycleStream: 'openjs-nodejs-release-schedule',
  },
  openssl: {
    canonicalName: 'OpenSSL',
    eolProductSlug: 'openssl',
    eolCycleStrategy: 'MAJOR_MINOR',
    defaultEcosystem: 'generic',
    purlName: 'openssl',
    cpeVendor: 'openssl',
    cpeProduct: 'openssl',
    osvEcosystem: 'OSS-Fuzz',
    osvPackageName: 'openssl',
    ghsaEcosystem: null,
    vendorLifecycleStream: 'openssl-security-strategy',
  },
  postgresql: {
    canonicalName: 'PostgreSQL',
    eolProductSlug: 'postgresql',
    eolCycleStrategy: 'MAJOR',
    defaultEcosystem: 'generic',
    purlName: 'postgresql',
    cpeVendor: 'postgresql',
    cpeProduct: 'postgresql',
    osvEcosystem: 'Bitnami',
    osvPackageName: 'postgresql',
    ghsaEcosystem: null,
    vendorLifecycleStream: 'pgdg-version-policy',
  },
  alpine: {
    canonicalName: 'Alpine Linux',
    eolProductSlug: 'alpine',
    eolCycleStrategy: 'MAJOR_MINOR',
    defaultEcosystem: 'apk',
    purlNamespace: 'alpine',
    purlName: 'alpine-baselayout',
    cpeVendor: 'alpinelinux',
    cpeProduct: 'alpine_linux',
    osvEcosystem: 'Alpine',
    osvPackageName: 'alpine-baselayout',
    ghsaEcosystem: null,
    vendorLifecycleStream: 'alpinelinux-releases',
  },
  ubuntu: {
    canonicalName: 'Ubuntu Linux',
    eolProductSlug: 'ubuntu',
    eolCycleStrategy: 'MAJOR_MINOR',
    defaultEcosystem: 'deb',
    purlNamespace: 'ubuntu',
    purlName: 'ubuntu-base',
    cpeVendor: 'canonical',
    cpeProduct: 'ubuntu_linux',
    osvEcosystem: 'Ubuntu',
    osvPackageName: 'linux',
    ghsaEcosystem: null,
    vendorLifecycleStream: 'canonical-ubuntu-lts',
  },
  react: {
    canonicalName: 'React',
    eolProductSlug: 'react',
    eolCycleStrategy: 'MAJOR',
    defaultEcosystem: 'npm',
    purlName: 'react',
    cpeVendor: 'facebook',
    cpeProduct: 'react',
    osvEcosystem: 'npm',
    osvPackageName: 'react',
    ghsaEcosystem: 'npm',
    vendorLifecycleStream: 'meta-react-major-cycles',
  },
  'react-dom': {
    canonicalName: 'React DOM',
    eolProductSlug: 'react',
    eolCycleStrategy: 'MAJOR',
    defaultEcosystem: 'npm',
    purlName: 'react-dom',
    cpeVendor: 'facebook',
    cpeProduct: 'react',
    osvEcosystem: 'npm',
    osvPackageName: 'react-dom',
    ghsaEcosystem: 'npm',
    vendorLifecycleStream: 'meta-react-major-cycles',
  },
  haproxy: {
    canonicalName: 'HAProxy',
    eolProductSlug: 'haproxy',
    eolCycleStrategy: 'MAJOR_MINOR',
    defaultEcosystem: 'generic',
    purlName: 'haproxy',
    cpeVendor: 'haproxy',
    cpeProduct: 'haproxy',
    osvEcosystem: 'Alpine',
    osvPackageName: 'haproxy',
    ghsaEcosystem: null,
    vendorLifecycleStream: 'haproxy-lts-branches',
  },
  envoy: {
    canonicalName: 'Envoy Proxy',
    eolProductSlug: 'envoy',
    eolCycleStrategy: 'MAJOR_MINOR',
    defaultEcosystem: 'generic',
    purlName: 'envoy',
    cpeVendor: 'envoyproxy',
    cpeProduct: 'envoy',
    osvEcosystem: 'OSS-Fuzz',
    osvPackageName: 'envoy',
    ghsaEcosystem: null,
    vendorLifecycleStream: 'cncf-envoy-releases',
  },
  express: {
    canonicalName: 'Express',
    eolProductSlug: 'express',
    eolCycleStrategy: 'MAJOR',
    defaultEcosystem: 'npm',
    purlName: 'express',
    cpeVendor: 'expressjs',
    cpeProduct: 'express',
    osvEcosystem: 'npm',
    osvPackageName: 'express',
    ghsaEcosystem: 'npm',
    vendorLifecycleStream: 'openjs-express-lts',
  },
  typeorm: {
    canonicalName: 'TypeORM',
    eolProductSlug: 'typeorm',
    eolCycleStrategy: 'MAJOR_MINOR',
    defaultEcosystem: 'npm',
    purlName: 'typeorm',
    cpeVendor: 'typeorm',
    cpeProduct: 'typeorm',
    osvEcosystem: 'npm',
    osvPackageName: 'typeorm',
    ghsaEcosystem: 'npm',
    vendorLifecycleStream: 'npm-typeorm-releases',
  },
};

export const PUBLIC_EOL_CYCLE_REFERENCE_DB: PublicEolCycleReference[] = [
  {
    eolProductSlug: 'nodejs',
    cycle: '18',
    isLts: true,
    releaseDate: '2022-04-19',
    activeSupportEndDate: '2023-10-18',
    eolDate: '2025-04-30',
    latestPatchVersion: '18.20.8',
  },
  {
    eolProductSlug: 'nodejs',
    cycle: '20',
    isLts: true,
    releaseDate: '2023-04-18',
    activeSupportEndDate: '2024-10-22',
    eolDate: '2026-04-30',
    latestPatchVersion: '20.19.0',
  },
  {
    eolProductSlug: 'nodejs',
    cycle: '22',
    isLts: true,
    releaseDate: '2024-04-24',
    activeSupportEndDate: '2025-10-21',
    eolDate: '2027-04-30',
    latestPatchVersion: '22.15.0',
  },
  {
    eolProductSlug: 'openssl',
    cycle: '1.1.1',
    isLts: true,
    releaseDate: '2018-09-11',
    activeSupportEndDate: '2021-09-11',
    eolDate: '2023-09-11',
    latestPatchVersion: '1.1.1w',
  },
  {
    eolProductSlug: 'openssl',
    cycle: '3.0',
    isLts: true,
    releaseDate: '2021-09-07',
    activeSupportEndDate: '2024-09-07',
    eolDate: '2026-09-07',
    latestPatchVersion: '3.0.16',
  },
  {
    eolProductSlug: 'openssl',
    cycle: '3.2',
    isLts: false,
    releaseDate: '2023-11-23',
    activeSupportEndDate: '2025-05-23',
    eolDate: '2025-11-23',
    latestPatchVersion: '3.2.4',
  },
  {
    eolProductSlug: 'postgresql',
    cycle: '16',
    isLts: true,
    releaseDate: '2023-09-14',
    activeSupportEndDate: '2027-11-11',
    eolDate: '2028-11-09',
    latestPatchVersion: '16.8.0',
  },
  {
    eolProductSlug: 'alpine',
    cycle: '3.19',
    isLts: false,
    releaseDate: '2023-12-07',
    activeSupportEndDate: '2025-05-01',
    eolDate: '2025-11-01',
    latestPatchVersion: '3.19.7',
  },
  {
    eolProductSlug: 'alpine',
    cycle: '3.20',
    isLts: false,
    releaseDate: '2024-05-22',
    activeSupportEndDate: '2025-11-01',
    eolDate: '2026-04-01',
    latestPatchVersion: '3.20.6',
  },
  {
    eolProductSlug: 'react',
    cycle: '18',
    isLts: true,
    releaseDate: '2022-03-29',
    activeSupportEndDate: '2024-12-05',
    eolDate: '2027-12-31',
    latestPatchVersion: '18.3.2',
  },
  {
    eolProductSlug: 'haproxy',
    cycle: '3.0',
    isLts: true,
    releaseDate: '2024-05-29',
    activeSupportEndDate: '2028-06-30',
    eolDate: '2029-06-30',
    latestPatchVersion: '3.0.8',
  },
];

export const PUBLIC_CVE_RANGE_REFERENCE_DB: PublicCveRangeReference[] = [
  {
    cveId: 'CVE-2026-111497',
    ghsaId: 'GHSA-v8rce-node-1149',
    title: 'Node.js V8 & HTTP/2 AsyncContext Heap Corruption RCE',
    eolProductSlug: 'nodejs',
    osvEcosystem: 'Bitnami',
    osvPackageName: 'node',
    nvdCpeMatchString: 'cpe:2.3:a:nodejs:node.js',
    distroAdvisoryNamespace: null,
    introducedVersion: '18.0.0',
    fixedVersion: '22.15.0',
    cvssV3Score: 9.8,
    epssScore: 0.964,
    isCisaKev: true,
    advisorySource: 'NVD_CPE',
  },
  {
    cveId: 'CVE-2024-0727',
    title: 'OpenSSL PKCS12_parse Null Pointer Dereference & Buffer Overflow',
    eolProductSlug: 'openssl',
    osvEcosystem: 'OSS-Fuzz',
    osvPackageName: 'openssl',
    nvdCpeMatchString: 'cpe:2.3:a:openssl:openssl',
    distroAdvisoryNamespace: null,
    introducedVersion: '1.1.1a',
    fixedVersion: '3.0.14',
    cvssV3Score: 7.5,
    epssScore: 0.04,
    isCisaKev: false,
    advisorySource: 'NVD_CPE',
  },
  {
    cveId: 'CVE-2024-6119',
    title: 'OpenSSL X509_check_purpose Use-After-Free in Certificate Chain Validation',
    eolProductSlug: 'openssl',
    osvEcosystem: 'OSS-Fuzz',
    osvPackageName: 'openssl',
    nvdCpeMatchString: 'cpe:2.3:a:openssl:openssl',
    distroAdvisoryNamespace: null,
    introducedVersion: '3.0.0',
    fixedVersion: '3.0.15',
    cvssV3Score: 7.5,
    epssScore: 0.08,
    isCisaKev: false,
    advisorySource: 'OSV_DEV',
  },
  {
    cveId: 'CVE-2024-6119',
    title: 'OpenSSL X509_check_purpose Use-After-Free (Alpine 3.19 Backport)',
    eolProductSlug: 'openssl',
    osvEcosystem: 'Alpine:v3.19',
    osvPackageName: 'openssl',
    nvdCpeMatchString: 'cpe:2.3:a:openssl:openssl',
    distroAdvisoryNamespace: 'alpine:3.19',
    introducedVersion: '3.0.0',
    fixedVersion: '3.0.13-r1',
    cvssV3Score: 7.5,
    epssScore: 0.08,
    isCisaKev: false,
    advisorySource: 'ALPINE_SECDB',
  },
  {
    cveId: 'CVE-2026-31042',
    ghsaId: 'GHSA-react-ssr-3104',
    title: 'React DOM SSR Hydration Stream Memory Corruption',
    eolProductSlug: 'react',
    osvEcosystem: 'npm',
    osvPackageName: 'react',
    nvdCpeMatchString: 'cpe:2.3:a:facebook:react',
    distroAdvisoryNamespace: null,
    introducedVersion: '18.0.0',
    fixedVersion: '18.3.2',
    cvssV3Score: 7.5,
    epssScore: 0.42,
    isCisaKev: false,
    advisorySource: 'GITHUB_GHSA',
  },
  {
    cveId: 'CVE-2023-40225',
    title: 'HAProxy HTTP/2 Content-Length Header Validation DoS',
    eolProductSlug: 'haproxy',
    osvEcosystem: 'Alpine',
    osvPackageName: 'haproxy',
    nvdCpeMatchString: 'cpe:2.3:a:haproxy:haproxy',
    distroAdvisoryNamespace: null,
    introducedVersion: '3.0.0',
    fixedVersion: '3.0.8',
    cvssV3Score: 7.5,
    epssScore: 0.34,
    isCisaKev: false,
    advisorySource: 'OSV_DEV',
  },
];

function resolveProductRule(rawName: string): ProductCatalogRule {
  const cleaned = rawName.trim().toLowerCase();
  if (cleaned.includes('node')) return PRODUCT_CATALOG_RULES.nodejs;
  if (cleaned.includes('openssl')) return PRODUCT_CATALOG_RULES.openssl;
  if (cleaned.includes('postgres')) return PRODUCT_CATALOG_RULES.postgresql;
  if (cleaned.includes('alpine')) return PRODUCT_CATALOG_RULES.alpine;
  if (cleaned.includes('ubuntu')) return PRODUCT_CATALOG_RULES.ubuntu;
  if (cleaned === 'react-dom') return PRODUCT_CATALOG_RULES['react-dom'];
  if (cleaned.includes('react')) return PRODUCT_CATALOG_RULES.react;
  if (cleaned.includes('haproxy')) return PRODUCT_CATALOG_RULES.haproxy;
  if (cleaned.includes('envoy')) return PRODUCT_CATALOG_RULES.envoy;
  if (cleaned.includes('express')) return PRODUCT_CATALOG_RULES.express;
  if (cleaned.includes('typeorm')) return PRODUCT_CATALOG_RULES.typeorm;

  const slug = cleaned.replace(/[^a-z0-9-]+/g, '-').replace(/^-|-$/g, '') || 'unknown';
  return {
    canonicalName: rawName.trim(),
    eolProductSlug: slug,
    eolCycleStrategy: 'MAJOR_MINOR',
    defaultEcosystem: 'generic',
    purlName: slug,
    cpeVendor: slug,
    cpeProduct: slug,
    osvEcosystem: 'OSS-Fuzz',
    osvPackageName: slug,
    ghsaEcosystem: null,
    vendorLifecycleStream: `${slug}-upstream-releases`,
  };
}

function encodeLetterPatch(letters: string): number {
  if (!letters) return 0;
  const lower = letters.toLowerCase();
  let acc = 0;
  for (let i = 0; i < lower.length; i++) {
    const code = lower.charCodeAt(i) - 96;
    if (code >= 1 && code <= 26) {
      acc = acc * 26 + code;
    }
  }
  return acc;
}

function parsePrereleaseRank(prereleaseToken: string | null): { rank: number; num: number } {
  if (!prereleaseToken) {
    return { rank: 999, num: 0 };
  }
  const lower = prereleaseToken.toLowerCase();
  const numMatch = lower.match(/(\d+)/);
  const num = numMatch ? parseInt(numMatch[1], 10) : 0;

  if (lower.startsWith('alpha') || lower.startsWith('a')) {
    return { rank: 10, num };
  }
  if (lower.startsWith('beta') || lower.startsWith('b')) {
    return { rank: 20, num };
  }
  if (lower.startsWith('rc') || lower.startsWith('pre')) {
    return { rank: 30, num };
  }
  return { rank: 50, num };
}

export function decomposeRawVersion(rawVersion: string): {
  upstreamVersion: string;
  epoch: number;
  major: number;
  minor: number;
  patch: number;
  letterPatchNum: number;
  prereleaseStageRank: number;
  prereleaseNum: number;
  distroRevision: string | null;
  semverSortTuple: SemverSortTuple;
} {
  let working = (rawVersion || '0.0.0').trim().replace(/^v/i, '');

  // 1. Extract optional Debian/RPM Epoch (e.g. "1:3.0.13-1~deb12u1")
  let epoch = 0;
  const epochMatch = working.match(/^(\d+):(.+)$/);
  if (epochMatch) {
    epoch = parseInt(epochMatch[1], 10);
    working = epochMatch[2];
  }

  // 2. Separate Distro Revision or Prerelease suffix
  let distroRevision: string | null = null;
  let prereleaseToken: string | null = null;

  // Match Alpine "-r0", Debian "-1~deb12u1", Ubuntu "-1ubuntu2.1"
  const distroRevMatch = working.match(/^([^-]+)-((?:r\d+)|(?:\d+[~+a-zA-Z0-9._-]*))$/);
  if (distroRevMatch && !/^rc\d+/i.test(distroRevMatch[2])) {
    working = distroRevMatch[1];
    distroRevision = distroRevMatch[2];
  } else {
    const prereleaseMatch = working.match(/^([^-]+)-([a-zA-Z0-9._-]+)$/);
    if (prereleaseMatch) {
      working = prereleaseMatch[1];
      prereleaseToken = prereleaseMatch[2];
    }
  }

  const upstreamVersion = working;
  const parts = upstreamVersion.split('.');
  const major = parseInt(parts[0] || '0', 10) || 0;
  const minor = parseInt(parts[1] || '0', 10) || 0;

  let patch = 0;
  let letterPatchNum = 0;
  if (parts[2]) {
    const patchMatch = parts[2].match(/^(\d+)([a-zA-Z]+)?$/);
    if (patchMatch) {
      patch = parseInt(patchMatch[1], 10) || 0;
      letterPatchNum = encodeLetterPatch(patchMatch[2] || '');
    } else {
      patch = parseInt(parts[2], 10) || 0;
    }
  }

  const { rank: prereleaseStageRank, num: prereleaseNum } = parsePrereleaseRank(prereleaseToken);

  const semverSortTuple: SemverSortTuple = [
    epoch,
    major,
    minor,
    patch,
    letterPatchNum,
    prereleaseStageRank,
    prereleaseNum,
  ];

  return {
    upstreamVersion,
    epoch,
    major,
    minor,
    patch,
    letterPatchNum,
    prereleaseStageRank,
    prereleaseNum,
    distroRevision,
    semverSortTuple,
  };
}

export function parseAndNormalizeSoftwareVersion(input: {
  productName: string;
  rawVersion: string;
  ecosystem?: SoftwareEcosystem;
  distroQualifier?: string | null;
}): NormalizedSoftwareVersionRecord {
  const rule = resolveProductRule(input.productName);
  const decomposed = decomposeRawVersion(input.rawVersion);

  const ecosystem: SoftwareEcosystem =
    input.ecosystem ||
    (input.distroQualifier?.startsWith('alpine')
      ? 'apk'
      : input.distroQualifier?.startsWith('debian') || input.distroQualifier?.startsWith('ubuntu')
        ? 'deb'
        : rule.defaultEcosystem);

  // Compute EOL Cycle Key based on product strategy (with OpenSSL 1.1.1 legacy exception)
  let eolCycleStrategy = rule.eolCycleStrategy;
  let eolCycleKey: string;
  if (rule.eolProductSlug === 'openssl' && decomposed.major === 1 && decomposed.minor === 1) {
    eolCycleStrategy = 'MAJOR_MINOR_PATCH';
    eolCycleKey = `${decomposed.major}.${decomposed.minor}.${decomposed.patch}`;
  } else if (eolCycleStrategy === 'MAJOR') {
    eolCycleKey = `${decomposed.major}`;
  } else if (eolCycleStrategy === 'MAJOR_MINOR_PATCH') {
    eolCycleKey = `${decomposed.major}.${decomposed.minor}.${decomposed.patch}`;
  } else {
    eolCycleKey = `${decomposed.major}.${decomposed.minor}`;
  }

  const distroAdvisoryNamespace = input.distroQualifier || null;
  const purlNamespacePart =
    ecosystem === 'apk'
      ? 'alpine/'
      : ecosystem === 'deb'
        ? `${(distroAdvisoryNamespace || 'debian').split(':')[0]}/`
        : rule.purlNamespace
          ? `${rule.purlNamespace}/`
          : '';
  const purlQualifier = distroAdvisoryNamespace
    ? `?distro=${encodeURIComponent(distroAdvisoryNamespace.replace(':', '-'))}`
    : '';
  const purl = `pkg:${ecosystem}/${purlNamespacePart}${rule.purlName}@${input.rawVersion.trim()}${purlQualifier}`;

  const nvdCpeMatchString = `cpe:2.3:a:${rule.cpeVendor}:${rule.cpeProduct}`;
  const cpe23Uri = `${nvdCpeMatchString}:${decomposed.upstreamVersion}:*:*:*:*:*:*:*`;

  const osvEcosystem = distroAdvisoryNamespace
    ? distroAdvisoryNamespace.startsWith('alpine:')
      ? `Alpine:v${distroAdvisoryNamespace.split(':')[1]}`
      : distroAdvisoryNamespace.startsWith('debian:')
        ? `Debian:${distroAdvisoryNamespace.split(':')[1]}`
        : rule.osvEcosystem
    : rule.osvEcosystem;

  return {
    productName: rule.canonicalName,
    rawVersion: input.rawVersion.trim(),
    ecosystem,
    purl,
    cpe23Uri,
    eolProductSlug: rule.eolProductSlug,
    eolCycleKey,
    eolCycleStrategy,
    eolApiUrl: `https://endoflife.date/api/v1/products/${rule.eolProductSlug}/releases/${eolCycleKey}`,
    vendorLifecycleStream: rule.vendorLifecycleStream,
    osvEcosystem,
    osvPackageName: rule.osvPackageName,
    nvdCpeMatchString,
    ghsaEcosystem: rule.ghsaEcosystem,
    distroAdvisoryNamespace,
    ...decomposed,
  };
}

export function compareNormalizedSortTuples(a: SemverSortTuple, b: SemverSortTuple): number {
  for (let i = 0; i < a.length; i++) {
    if (a[i] < b[i]) return -1;
    if (a[i] > b[i]) return 1;
  }
  return 0;
}

function parseDistroRevisionNum(distroRevision: string | null): number {
  if (!distroRevision) return 0;
  const m = distroRevision.match(/(\d+)/);
  return m ? parseInt(m[1], 10) : 0;
}

export function isVersionInCveRange(
  record: NormalizedSoftwareVersionRecord,
  cveRange: PublicCveRangeReference,
): boolean {
  if (record.eolProductSlug !== cveRange.eolProductSlug) {
    return false;
  }

  // If record has a distro qualifier and there is a distro-specific advisory, enforce distro isolation
  if (cveRange.distroAdvisoryNamespace && cveRange.distroAdvisoryNamespace !== record.distroAdvisoryNamespace) {
    return false;
  }

  const introDecomposed = decomposeRawVersion(cveRange.introducedVersion);
  if (compareNormalizedSortTuples(record.semverSortTuple, introDecomposed.semverSortTuple) < 0) {
    return false;
  }

  if (!cveRange.fixedVersion) {
    return true;
  }

  const fixedDecomposed = decomposeRawVersion(cveRange.fixedVersion);
  const upstreamCmp = compareNormalizedSortTuples(record.semverSortTuple, fixedDecomposed.semverSortTuple);
  if (upstreamCmp < 0) {
    return true;
  }
  if (upstreamCmp > 0) {
    return false;
  }

  // Equal upstream version: compare distro revision if fixedVersion specifies one (e.g., 3.0.13-r0 vs 3.0.13-r1)
  if (fixedDecomposed.distroRevision) {
    return parseDistroRevisionNum(record.distroRevision) < parseDistroRevisionNum(fixedDecomposed.distroRevision);
  }

  return false;
}

export function crossCheckSoftwareVersion(
  input: {
    productName: string;
    rawVersion: string;
    ecosystem?: SoftwareEcosystem;
    distroQualifier?: string | null;
  },
  referenceDateIso = '2026-11-24',
): VersionCrossCheckResult {
  const normalized = parseAndNormalizeSoftwareVersion(input);
  const refTime = new Date(referenceDateIso).getTime();

  const matchedCycle =
    PUBLIC_EOL_CYCLE_REFERENCE_DB.find(
      c => c.eolProductSlug === normalized.eolProductSlug && c.cycle === normalized.eolCycleKey,
    ) || null;

  let isEol = false;
  let isApproachingEol = false;
  let isOutdatedPatchOnCycle = false;
  let daysUntilEol: number | null = null;

  if (matchedCycle) {
    const eolTime = new Date(matchedCycle.eolDate).getTime();
    daysUntilEol = Math.round((eolTime - refTime) / (1000 * 60 * 60 * 24));
    isEol = daysUntilEol <= 0;
    isApproachingEol = !isEol && daysUntilEol <= 180;

    const latestDecomposed = decomposeRawVersion(matchedCycle.latestPatchVersion);
    isOutdatedPatchOnCycle =
      compareNormalizedSortTuples(normalized.semverSortTuple, latestDecomposed.semverSortTuple) < 0;
  }

  // Prefer distro-specific CVE ranges when distroAdvisoryNamespace is set to avoid upstream backport false positives
  const candidateCves = PUBLIC_CVE_RANGE_REFERENCE_DB.filter(
    c => c.eolProductSlug === normalized.eolProductSlug,
  );
  const distroSpecificCves = normalized.distroAdvisoryNamespace
    ? candidateCves.filter(c => c.distroAdvisoryNamespace === normalized.distroAdvisoryNamespace)
    : [];
  const effectivePool =
    distroSpecificCves.length > 0
      ? [
          ...distroSpecificCves,
          ...candidateCves.filter(
            c =>
              !c.distroAdvisoryNamespace &&
              !distroSpecificCves.some(d => d.cveId === c.cveId),
          ),
        ]
      : candidateCves.filter(c => !c.distroAdvisoryNamespace);

  const cveMatches = effectivePool.filter(cve => isVersionInCveRange(normalized, cve));
  const highestCvssScore = cveMatches.reduce((max, c) => Math.max(max, c.cvssV3Score), 0);
  const highestEpssScore = cveMatches.reduce((max, c) => Math.max(max, c.epssScore), 0);
  const hasReachableCisaKev = cveMatches.some(c => c.isCisaKev);

  return {
    normalized,
    eolMatch: {
      matchedCycle,
      isEol,
      isApproachingEol,
      isOutdatedPatchOnCycle,
      latestPatchVersionOnCycle: matchedCycle ? matchedCycle.latestPatchVersion : null,
      daysUntilEol,
    },
    cveMatches,
    highestCvssScore,
    highestEpssScore,
    hasReachableCisaKev,
  };
}

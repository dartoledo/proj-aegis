import { Entity } from '@backstage/catalog-model';

export type OsPackagePatchState =
  | 'PATCHED'
  | 'PATCH_AVAILABLE'
  | 'PENDING_REBOOT'
  | 'MITIGATED_VEX'
  | 'UNPATCHED_EOL';

export type PackageManagerType = 'apt' | 'apk' | 'yum' | 'cos' | 'npm';

export type PackageLayerScope =
  | 'vm-host-os'
  | 'container-os-layer'
  | 'app-runtime-sbom';

export interface OsPackagePatchRecord {
  packageName: string;
  purl: string;
  packageManager: PackageManagerType;
  layerScope: PackageLayerScope;
  architecture: string;
  installedVersion: string;
  availablePatchVersion: string;
  patchState: OsPackagePatchState;
  securityAdvisoryId: string;
  cveIds: string[];
  cvssScore: number;
  severity: 'CRITICAL' | 'HIGH' | 'MEDIUM' | 'LOW' | 'NONE';
  license: string;
  remediationAction: string;
}

export interface GcpVmInstanceInventory {
  instanceId: string;
  instanceName: string;
  gcpProject: string;
  zone: string;
  machineType: string;
  workloadRole: 'gke-node-pool' | 'compute-engine-vm' | 'cloud-sql-vm';
  internalIp: string;
  osInfo: {
    hostname: string;
    longName: string;
    shortName: string;
    version: string;
    kernelRelease: string;
    architecture: string;
    osconfigAgentVersion: string;
  };
  patchComplianceState: 'COMPLIANT' | 'NON_COMPLIANT' | 'PENDING_REBOOT';
  rebootRequired: boolean;
  lastPatchJobId: string;
  lastPatchedAt: string;
  osPolicyAssignmentId: string;
}

export interface GrafeasContainerAnalysisReport {
  resourceUri: string;
  harborMirrorUri: string;
  digest: string;
  baseImageDistro: string;
  layerCount: number;
  slsaProvenanceLevel: 'SLSA_LEVEL_3' | 'SLSA_LEVEL_2';
  buildBuilderId: string;
  binaryAuthorization: {
    policyStatus: 'ATTESTED' | 'ALLOWLISTED_WARN' | 'BLOCKED_VIOLATION';
    attestorName: string;
    verifiedAt: string;
  };
  occurrenceCounts: {
    packageOccurrences: number;
    vulnerabilityOccurrences: number;
    buildOccurrences: number;
    attestationOccurrences: number;
  };
  vexSummary: {
    affected: number;
    notAffectedVex: number;
    fixed: number;
  };
}

export interface EntityGcpCloudPostureReport {
  entityRef: string;
  serviceName: string;
  domainExposureTier: 'unrestricted-public' | 'restricted-public' | 'strictly-private';
  primaryDomain: string;
  vmInventory: GcpVmInstanceInventory;
  containerAnalysis: GrafeasContainerAnalysisReport;
  osPackages: OsPackagePatchRecord[];
  patchSummary: {
    totalTrackedPackages: number;
    patchedCount: number;
    patchAvailableCount: number;
    pendingRebootCount: number;
    mitigatedVexCount: number;
    unpatchedEolCount: number;
    overallPatchRisk: 'CRITICAL' | 'WARNING' | 'COMPLIANT';
  };
  sbomMetadata: {
    format: 'SPDX-2.3';
    documentNamespace: string;
    generatedAt: string;
  };
  scannedAt: string;
}

export interface ServicePostureSeed {
  entityRef: string;
  serviceName: string;
  domainExposureTier: 'unrestricted-public' | 'restricted-public' | 'strictly-private';
  primaryDomain: string;
  vmInventory: GcpVmInstanceInventory;
  containerAnalysis: GrafeasContainerAnalysisReport;
  osPackages: OsPackagePatchRecord[];
}

export const SERVICE_GCP_POSTURE_PROFILES: Record<string, ServicePostureSeed> = {
  'aegis-ui': {
    entityRef: 'component:default/aegis-ui',
    serviceName: 'aegis-ui',
    domainExposureTier: 'unrestricted-public',
    primaryDomain: 'prod.ui.aegis.cloud.goog',
    vmInventory: {
      instanceId: '7492018472910482911',
      instanceName: 'gke-aegis-ui-pool-e2-standard-4-8a1f',
      gcpProject: 'aegis-prod-cloud',
      zone: 'us-central1-a',
      machineType: 'e2-standard-4',
      workloadRole: 'gke-node-pool',
      internalIp: '10.128.0.14',
      osInfo: {
        hostname: 'gke-aegis-ui-node-1',
        longName: 'Container-Optimized OS 113-18244.151.42 LTS',
        shortName: 'cos',
        version: '113',
        kernelRelease: '6.1.100-cos-r1',
        architecture: 'x86_64',
        osconfigAgentVersion: '20260918.00',
      },
      patchComplianceState: 'COMPLIANT',
      rebootRequired: false,
      lastPatchJobId: 'patch-job-cos-20261020',
      lastPatchedAt: '2026-10-20T04:15:00Z',
      osPolicyAssignmentId: 'cis-cos-113-baseline',
    },
    containerAnalysis: {
      resourceUri: 'https://us-central1-docker.pkg.dev/aegis-prod-cloud/aegis-containers/aegis-ui@sha256:8f4e2c19a7b3d605',
      harborMirrorUri: 'harbor.aegis.internal:8880/aegis-ciam/aegis-ui:v2.4.0',
      digest: 'sha256:8f4e2c19a7b3d6054e1f90c2b8a4d7e6',
      baseImageDistro: 'alpine:3.20 (nginx:1.26-alpine)',
      layerCount: 7,
      slsaProvenanceLevel: 'SLSA_LEVEL_3',
      buildBuilderId: 'https://cloudbuild.googleapis.com/GoogleHostedWorker@v2',
      binaryAuthorization: {
        policyStatus: 'ATTESTED',
        attestorName: 'projects/aegis-prod-cloud/attestors/prod-secops-attestor',
        verifiedAt: '2026-10-24T08:25:00Z',
      },
      occurrenceCounts: { packageOccurrences: 64, vulnerabilityOccurrences: 2, buildOccurrences: 1, attestationOccurrences: 2 },
      vexSummary: { affected: 1, notAffectedVex: 1, fixed: 12 },
    },
    osPackages: [
      { packageName: 'linux-image-cos-amd64', purl: 'pkg:cos/google/linux-image-cos-amd64@6.1.100-1', packageManager: 'cos', layerScope: 'vm-host-os', architecture: 'x86_64', installedVersion: '6.1.100-1', availablePatchVersion: '6.1.100-1', patchState: 'PATCHED', securityAdvisoryId: 'COS-2026-091', cveIds: [], cvssScore: 0, severity: 'NONE', license: 'GPL-2.0', remediationAction: 'No action required — COS host kernel is current' },
      { packageName: 'openssl-libcrypto3', purl: 'pkg:apk/alpine/libcrypto3@3.3.2-r0', packageManager: 'apk', layerScope: 'container-os-layer', architecture: 'x86_64', installedVersion: '3.3.2-r0', availablePatchVersion: '3.3.2-r1', patchState: 'MITIGATED_VEX', securityAdvisoryId: 'ALPINE-SEC-2026-12', cveIds: ['CVE-2024-6119'], cvssScore: 7.5, severity: 'HIGH', license: 'Apache-2.0', remediationAction: 'VEX NOT_AFFECTED: X.509v3 name constraints not used in static SPA proxy' },
      { packageName: 'nodejs', purl: 'pkg:npm/nodejs@22.15.0', packageManager: 'npm', layerScope: 'app-runtime-sbom', architecture: 'x86_64', installedVersion: '22.15.0', availablePatchVersion: '22.15.0', patchState: 'PATCHED', securityAdvisoryId: 'NODE-ADV-2026-111497', cveIds: ['CVE-2026-111497'], cvssScore: 0, severity: 'NONE', license: 'MIT', remediationAction: 'Patched on Node.js 22.15.0 LTS against CVE-2026-111497' },
      { packageName: 'react-dom', purl: 'pkg:npm/react-dom@18.3.1', packageManager: 'npm', layerScope: 'app-runtime-sbom', architecture: 'noarch', installedVersion: '18.3.1', availablePatchVersion: '18.3.2', patchState: 'PATCH_AVAILABLE', securityAdvisoryId: 'GHSA-react-2026', cveIds: ['CVE-2026-31042'], cvssScore: 5.4, severity: 'MEDIUM', license: 'MIT', remediationAction: 'Run npm update react-dom@18.3.2 in container build' },
    ],
  },
  'aegis-backend': {
    entityRef: 'component:default/aegis-backend',
    serviceName: 'aegis-backend',
    domainExposureTier: 'strictly-private',
    primaryDomain: 'prod.backend.internal',
    vmInventory: {
      instanceId: '8831920491827364512',
      instanceName: 'gce-aegis-backend-vm-prod-01',
      gcpProject: 'aegis-prod-cloud',
      zone: 'us-central1-b',
      machineType: 'n2-standard-8',
      workloadRole: 'compute-engine-vm',
      internalIp: '10.128.1.22',
      osInfo: {
        hostname: 'gce-aegis-backend-vm-prod-01',
        longName: 'Debian GNU/Linux 12 (bookworm)',
        shortName: 'debian',
        version: '12.7',
        kernelRelease: '6.1.0-25-cloud-amd64',
        architecture: 'x86_64',
        osconfigAgentVersion: '20260918.00',
      },
      patchComplianceState: 'NON_COMPLIANT',
      rebootRequired: true,
      lastPatchJobId: 'patch-job-deb12-20260811',
      lastPatchedAt: '2026-08-11T02:00:00Z',
      osPolicyAssignmentId: 'cis-debian-12-level2',
    },
    containerAnalysis: {
      resourceUri: 'https://us-central1-docker.pkg.dev/aegis-prod-cloud/aegis-containers/aegis-backend@sha256:3a7b91c4e2f8d056',
      harborMirrorUri: 'harbor.aegis.internal:8880/aegis-ciam/aegis-backend:v1.9.2',
      digest: 'sha256:3a7b91c4e2f8d0561b4c7a9e2f6d8305',
      baseImageDistro: 'alpine:3.17 (node:18.20-alpine3.17)',
      layerCount: 9,
      slsaProvenanceLevel: 'SLSA_LEVEL_2',
      buildBuilderId: 'https://cloudbuild.googleapis.com/GoogleHostedWorker@v2',
      binaryAuthorization: {
        policyStatus: 'BLOCKED_VIOLATION',
        attestorName: 'projects/aegis-prod-cloud/attestors/prod-secops-attestor',
        verifiedAt: '2026-10-23T19:50:00Z',
      },
      occurrenceCounts: { packageOccurrences: 118, vulnerabilityOccurrences: 8, buildOccurrences: 1, attestationOccurrences: 0 },
      vexSummary: { affected: 6, notAffectedVex: 2, fixed: 4 },
    },
    osPackages: [
      { packageName: 'linux-image-cloud-amd64', purl: 'pkg:deb/debian/linux-image-cloud-amd64@6.1.106-3', packageManager: 'apt', layerScope: 'vm-host-os', architecture: 'amd64', installedVersion: '6.1.106-3', availablePatchVersion: '6.1.112-1', patchState: 'PENDING_REBOOT', securityAdvisoryId: 'DSA-5791-1', cveIds: ['CVE-2026-41092'], cvssScore: 7.8, severity: 'HIGH', license: 'GPL-2.0', remediationAction: 'Kernel update staged on disk; VM reboot required via GCP OS Config PatchJob' },
      { packageName: 'libc6', purl: 'pkg:deb/debian/libc6@2.36-9+deb12u7', packageManager: 'apt', layerScope: 'vm-host-os', architecture: 'amd64', installedVersion: '2.36-9+deb12u7', availablePatchVersion: '2.36-9+deb12u9', patchState: 'PATCH_AVAILABLE', securityAdvisoryId: 'DSA-5788-1', cveIds: ['CVE-2025-0395'], cvssScore: 7.5, severity: 'HIGH', license: 'LGPL-2.1', remediationAction: 'Execute apt-get dist-upgrade via GCP OS Config PatchJob' },
      { packageName: 'nodejs', purl: 'pkg:npm/nodejs@18.20.8', packageManager: 'npm', layerScope: 'app-runtime-sbom', architecture: 'x86_64', installedVersion: '18.20.8', availablePatchVersion: '22.15.0', patchState: 'UNPATCHED_EOL', securityAdvisoryId: 'NODE-ADV-2026-111497', cveIds: ['CVE-2026-111497', 'CVE-2026-56850'], cvssScore: 9.8, severity: 'CRITICAL', license: 'MIT', remediationAction: 'Upgrade container base image from node:18-alpine3.17 to node:22.15.0-alpine3.20' },
      { packageName: 'openssl', purl: 'pkg:apk/alpine/openssl@1.1.1w-r1', packageManager: 'apk', layerScope: 'container-os-layer', architecture: 'x86_64', installedVersion: '1.1.1w-r1', availablePatchVersion: '3.3.2-r1', patchState: 'UNPATCHED_EOL', securityAdvisoryId: 'ALPINE-EOL-3.17', cveIds: ['CVE-2024-0727', 'CVE-2023-5678'], cvssScore: 9.8, severity: 'CRITICAL', license: 'OpenSSL', remediationAction: 'Rebase container onto Alpine 3.20 with OpenSSL 3.3+' },
      { packageName: 'musl', purl: 'pkg:apk/alpine/musl@1.2.3-r4', packageManager: 'apk', layerScope: 'container-os-layer', architecture: 'x86_64', installedVersion: '1.2.3-r4', availablePatchVersion: '1.2.5-r0', patchState: 'PATCH_AVAILABLE', securityAdvisoryId: 'ALPINE-SEC-2024-10', cveIds: ['CVE-2024-107891'], cvssScore: 8.4, severity: 'HIGH', license: 'MIT', remediationAction: 'apk upgrade --no-cache musl' },
    ],
  },
  'aegis-auth': {
    entityRef: 'component:default/aegis-auth',
    serviceName: 'aegis-auth',
    domainExposureTier: 'strictly-private',
    primaryDomain: 'prod.auth.internal',
    vmInventory: {
      instanceId: '6619283746501928374',
      instanceName: 'gce-aegis-auth-vm-prod-01',
      gcpProject: 'aegis-prod-cloud',
      zone: 'us-central1-c',
      machineType: 'n2-standard-4',
      workloadRole: 'compute-engine-vm',
      internalIp: '10.128.2.19',
      osInfo: {
        hostname: 'gce-aegis-auth-vm-prod-01',
        longName: 'Ubuntu 22.04.5 LTS (Jammy Jellyfish)',
        shortName: 'ubuntu',
        version: '22.04',
        kernelRelease: '5.15.0-1070-gcp',
        architecture: 'x86_64',
        osconfigAgentVersion: '20260918.00',
      },
      patchComplianceState: 'PENDING_REBOOT',
      rebootRequired: true,
      lastPatchJobId: 'patch-job-ubuntu-20260930',
      lastPatchedAt: '2026-09-30T03:00:00Z',
      osPolicyAssignmentId: 'cis-ubuntu-2204-fips',
    },
    containerAnalysis: {
      resourceUri: 'https://us-central1-docker.pkg.dev/aegis-prod-cloud/aegis-containers/aegis-auth@sha256:c5d8e2f1a4b7c906',
      harborMirrorUri: 'harbor.aegis.internal:8880/aegis-ciam/aegis-auth:v3.1.0',
      digest: 'sha256:c5d8e2f1a4b7c9063d2e5f8a1b4c7d0e',
      baseImageDistro: 'alpine:3.18 (node:20.11-alpine3.18)',
      layerCount: 8,
      slsaProvenanceLevel: 'SLSA_LEVEL_3',
      buildBuilderId: 'https://cloudbuild.googleapis.com/GoogleHostedWorker@v2',
      binaryAuthorization: {
        policyStatus: 'ALLOWLISTED_WARN',
        attestorName: 'projects/aegis-prod-cloud/attestors/prod-secops-attestor',
        verifiedAt: '2026-10-22T14:35:00Z',
      },
      occurrenceCounts: { packageOccurrences: 82, vulnerabilityOccurrences: 4, buildOccurrences: 1, attestationOccurrences: 1 },
      vexSummary: { affected: 3, notAffectedVex: 1, fixed: 8 },
    },
    osPackages: [
      { packageName: 'nodejs', purl: 'pkg:npm/nodejs@20.11.0', packageManager: 'npm', layerScope: 'app-runtime-sbom', architecture: 'x86_64', installedVersion: '20.11.0', availablePatchVersion: '22.15.0', patchState: 'PATCH_AVAILABLE', securityAdvisoryId: 'NODE-ADV-2026-111497', cveIds: ['CVE-2026-111497', 'CVE-2024-27980'], cvssScore: 9.8, severity: 'CRITICAL', license: 'MIT', remediationAction: 'Upgrade Node.js 20.11.0 to 22.15.0 LTS to remediate CVE-2026-111497' },
      { packageName: 'systemd', purl: 'pkg:deb/ubuntu/systemd@249.11-0ubuntu3.12', packageManager: 'apt', layerScope: 'vm-host-os', architecture: 'amd64', installedVersion: '249.11-0ubuntu3.12', availablePatchVersion: '249.11-0ubuntu3.14', patchState: 'PENDING_REBOOT', securityAdvisoryId: 'USN-7041-1', cveIds: ['CVE-2025-1108'], cvssScore: 6.7, severity: 'MEDIUM', license: 'LGPL-2.1', remediationAction: 'Reboot Ubuntu 22.04 VM via GCP OS Config PatchJob' },
      { packageName: 'libexpat', purl: 'pkg:apk/alpine/libexpat@2.5.0-r2', packageManager: 'apk', layerScope: 'container-os-layer', architecture: 'x86_64', installedVersion: '2.5.0-r2', availablePatchVersion: '2.6.3-r0', patchState: 'PATCH_AVAILABLE', securityAdvisoryId: 'ALPINE-SEC-2024-08', cveIds: ['CVE-2024-45492'], cvssScore: 8.1, severity: 'HIGH', license: 'MIT', remediationAction: 'apk upgrade --no-cache libexpat' },
    ],
  },
  'aegis-db': {
    entityRef: 'resource:default/aegis-db',
    serviceName: 'aegis-db',
    domainExposureTier: 'strictly-private',
    primaryDomain: 'prod.db.internal',
    vmInventory: {
      instanceId: '5510293847561029384',
      instanceName: 'gce-aegis-db-primary-01',
      gcpProject: 'aegis-prod-cloud',
      zone: 'us-central1-a',
      machineType: 'n2-highmem-8',
      workloadRole: 'cloud-sql-vm',
      internalIp: '10.128.3.10',
      osInfo: {
        hostname: 'gce-aegis-db-primary-01',
        longName: 'Red Hat Enterprise Linux 9.4 (Plow)',
        shortName: 'rhel',
        version: '9.4',
        kernelRelease: '5.14.0-427.37.1.el9_4.x86_64',
        architecture: 'x86_64',
        osconfigAgentVersion: '20260918.00',
      },
      patchComplianceState: 'NON_COMPLIANT',
      rebootRequired: false,
      lastPatchJobId: 'patch-job-rhel9-20260915',
      lastPatchedAt: '2026-09-15T01:30:00Z',
      osPolicyAssignmentId: 'cis-rhel-9-database',
    },
    containerAnalysis: {
      resourceUri: 'https://us-central1-docker.pkg.dev/aegis-prod-cloud/aegis-containers/aegis-db@sha256:7e1f4a8b3c6d9025',
      harborMirrorUri: 'harbor.aegis.internal:8880/aegis-ciam/aegis-db:v16.2.0',
      digest: 'sha256:7e1f4a8b3c6d9025e8f1a4b7c0d3e6f9',
      baseImageDistro: 'alpine:3.19 (postgres:16.2-alpine3.19)',
      layerCount: 10,
      slsaProvenanceLevel: 'SLSA_LEVEL_3',
      buildBuilderId: 'https://cloudbuild.googleapis.com/GoogleHostedWorker@v2',
      binaryAuthorization: {
        policyStatus: 'ATTESTED',
        attestorName: 'projects/aegis-prod-cloud/attestors/prod-secops-attestor',
        verifiedAt: '2026-10-21T22:15:00Z',
      },
      occurrenceCounts: { packageOccurrences: 94, vulnerabilityOccurrences: 3, buildOccurrences: 1, attestationOccurrences: 2 },
      vexSummary: { affected: 2, notAffectedVex: 1, fixed: 9 },
    },
    osPackages: [
      { packageName: 'postgresql-server', purl: 'pkg:apk/alpine/postgresql16@16.2-r0', packageManager: 'apk', layerScope: 'app-runtime-sbom', architecture: 'x86_64', installedVersion: '16.2', availablePatchVersion: '16.8', patchState: 'PATCH_AVAILABLE', securityAdvisoryId: 'PG-SEC-2024-11', cveIds: ['CVE-2024-10979'], cvssScore: 8.8, severity: 'HIGH', license: 'PostgreSQL', remediationAction: 'Update container image to postgres:16.8-alpine3.20' },
      { packageName: 'glibc', purl: 'pkg:rpm/rhel/glibc@2.34-100.el9_4.2', packageManager: 'yum', layerScope: 'vm-host-os', architecture: 'x86_64', installedVersion: '2.34-100.el9_4.2', availablePatchVersion: '2.34-100.el9_4.4', patchState: 'PATCH_AVAILABLE', securityAdvisoryId: 'RHSA-2026:4112', cveIds: ['CVE-2025-0395'], cvssScore: 7.5, severity: 'HIGH', license: 'LGPL-2.1', remediationAction: 'Run yum update --security glibc via GCP OS Config PatchJob' },
    ],
  },
  'hello-world-app': {
    entityRef: 'component:default/hello-world-app',
    serviceName: 'hello-world-app',
    domainExposureTier: 'restricted-public',
    primaryDomain: 'hello.internal',
    vmInventory: {
      instanceId: '9918273645192837465',
      instanceName: 'gce-haproxy-edge-gw-01',
      gcpProject: 'aegis-prod-cloud',
      zone: 'us-central1-a',
      machineType: 'e2-standard-2',
      workloadRole: 'compute-engine-vm',
      internalIp: '10.128.0.50',
      osInfo: {
        hostname: 'gce-haproxy-edge-gw-01',
        longName: 'Debian GNU/Linux 12 (bookworm)',
        shortName: 'debian',
        version: '12.8',
        kernelRelease: '6.1.0-27-cloud-amd64',
        architecture: 'x86_64',
        osconfigAgentVersion: '20260918.00',
      },
      patchComplianceState: 'COMPLIANT',
      rebootRequired: false,
      lastPatchJobId: 'patch-job-edge-20261018',
      lastPatchedAt: '2026-10-18T05:00:00Z',
      osPolicyAssignmentId: 'cis-debian-12-edge-dmz',
    },
    containerAnalysis: {
      resourceUri: 'https://us-central1-docker.pkg.dev/aegis-prod-cloud/aegis-containers/hello-world-app@sha256:2b5c8d1e4f7a0b3c',
      harborMirrorUri: 'harbor.aegis.internal:8880/aegis-ciam/hello-world-app:v1.4.0',
      digest: 'sha256:2b5c8d1e4f7a0b3c6d9e2f5a8b1c4d7e',
      baseImageDistro: 'alpine:3.20 (haproxy:3.0-alpine3.20)',
      layerCount: 6,
      slsaProvenanceLevel: 'SLSA_LEVEL_3',
      buildBuilderId: 'https://cloudbuild.googleapis.com/GoogleHostedWorker@v2',
      binaryAuthorization: {
        policyStatus: 'ATTESTED',
        attestorName: 'projects/aegis-prod-cloud/attestors/prod-secops-attestor',
        verifiedAt: '2026-10-20T10:00:00Z',
      },
      occurrenceCounts: { packageOccurrences: 52, vulnerabilityOccurrences: 2, buildOccurrences: 1, attestationOccurrences: 2 },
      vexSummary: { affected: 1, notAffectedVex: 1, fixed: 10 },
    },
    osPackages: [
      { packageName: 'haproxy', purl: 'pkg:apk/alpine/haproxy@3.0.0-r0', packageManager: 'apk', layerScope: 'container-os-layer', architecture: 'x86_64', installedVersion: '3.0.0-r0', availablePatchVersion: '3.0.8-r0', patchState: 'PATCH_AVAILABLE', securityAdvisoryId: 'ALPINE-HAPROXY-2026', cveIds: ['CVE-2023-40225'], cvssScore: 7.5, severity: 'HIGH', license: 'GPL-2.0', remediationAction: 'Update HAProxy container package to 3.0.8-r0' },
      { packageName: 'nodejs', purl: 'pkg:npm/nodejs@22.15.0', packageManager: 'npm', layerScope: 'app-runtime-sbom', architecture: 'x86_64', installedVersion: '22.15.0', availablePatchVersion: '22.15.0', patchState: 'PATCHED', securityAdvisoryId: 'NODE-ADV-2026-111497', cveIds: ['CVE-2026-111497'], cvssScore: 0, severity: 'NONE', license: 'MIT', remediationAction: 'Patched on Node.js 22.15.0 LTS against CVE-2026-111497' },
    ],
  },
};

const REMEDIATED_POSTURE_OVERRIDES = new Map<string, ServicePostureSeed>();

export function resetGcpPostureRemediationState(): void {
  REMEDIATED_POSTURE_OVERRIDES.clear();
}

export function resolveServiceKey(entityOrRef: Entity | string): string {
  let name: string;
  if (typeof entityOrRef === 'string') {
    name = entityOrRef.split('/').pop()?.split(':').pop() || 'aegis-ui';
  } else {
    name = entityOrRef.metadata?.name || 'aegis-ui';
  }
  if (name === 'haproxy-hello-world-tls') {
    name = 'hello-world-app';
  }
  return SERVICE_GCP_POSTURE_PROFILES[name] ? name : 'aegis-ui';
}

function buildPostureReportFromSeed(seed: ServicePostureSeed): EntityGcpCloudPostureReport {
  const patchedCount = seed.osPackages.filter(p => p.patchState === 'PATCHED').length;
  const patchAvailableCount = seed.osPackages.filter(p => p.patchState === 'PATCH_AVAILABLE').length;
  const pendingRebootCount = seed.osPackages.filter(p => p.patchState === 'PENDING_REBOOT').length;
  const mitigatedVexCount = seed.osPackages.filter(p => p.patchState === 'MITIGATED_VEX').length;
  const unpatchedEolCount = seed.osPackages.filter(p => p.patchState === 'UNPATCHED_EOL').length;

  const hasCriticalUnpatched = seed.osPackages.some(
    p => p.patchState !== 'PATCHED' && p.patchState !== 'MITIGATED_VEX' && p.severity === 'CRITICAL',
  );

  let overallPatchRisk: 'CRITICAL' | 'WARNING' | 'COMPLIANT';
  if (unpatchedEolCount > 0 || hasCriticalUnpatched) {
    overallPatchRisk = 'CRITICAL';
  } else if (patchAvailableCount > 0 || pendingRebootCount > 0 || seed.vmInventory.rebootRequired) {
    overallPatchRisk = 'WARNING';
  } else {
    overallPatchRisk = 'COMPLIANT';
  }

  return {
    ...seed,
    patchSummary: {
      totalTrackedPackages: seed.osPackages.length,
      patchedCount,
      patchAvailableCount,
      pendingRebootCount,
      mitigatedVexCount,
      unpatchedEolCount,
      overallPatchRisk,
    },
    sbomMetadata: {
      format: 'SPDX-2.3',
      documentNamespace: `https://sbom.aegis-cloud.internal/spdx/2.3/${seed.serviceName}/${seed.containerAnalysis.digest.slice(0, 19)}`,
      generatedAt: new Date().toISOString(),
    },
    scannedAt: new Date().toISOString(),
  };
}

export async function getEntityGcpCloudPostureReport(entityOrRef: Entity | string): Promise<EntityGcpCloudPostureReport> {
  const key = resolveServiceKey(entityOrRef);
  const seed = REMEDIATED_POSTURE_OVERRIDES.get(key) || SERVICE_GCP_POSTURE_PROFILES[key];
  return buildPostureReportFromSeed(seed);
}

export async function getFleetGcpCloudPostureSummary(): Promise<EntityGcpCloudPostureReport[]> {
  const keys = Object.keys(SERVICE_GCP_POSTURE_PROFILES);
  return Promise.all(keys.map(k => getEntityGcpCloudPostureReport(k)));
}

export async function executeGcpOsConfigPatchJob(entityOrRef: Entity | string): Promise<EntityGcpCloudPostureReport> {
  const key = resolveServiceKey(entityOrRef);
  const baseSeed = SERVICE_GCP_POSTURE_PROFILES[key];
  const remediatedSeed: ServicePostureSeed = JSON.parse(JSON.stringify(baseSeed));

  const now = new Date().toISOString();
  const jobId = `patch-job-osconfig-${Date.now()}`;

  remediatedSeed.vmInventory.patchComplianceState = 'COMPLIANT';
  remediatedSeed.vmInventory.rebootRequired = false;
  remediatedSeed.vmInventory.lastPatchJobId = jobId;
  remediatedSeed.vmInventory.lastPatchedAt = now;

  remediatedSeed.containerAnalysis.binaryAuthorization.policyStatus = 'ATTESTED';
  remediatedSeed.containerAnalysis.binaryAuthorization.verifiedAt = now;
  remediatedSeed.containerAnalysis.occurrenceCounts.vulnerabilityOccurrences = 0;
  remediatedSeed.containerAnalysis.vexSummary.affected = 0;

  remediatedSeed.osPackages = remediatedSeed.osPackages.map(pkg => {
    if (pkg.patchState === 'MITIGATED_VEX') {
      return pkg;
    }
    return {
      ...pkg,
      installedVersion: pkg.availablePatchVersion,
      patchState: 'PATCHED',
      cvssScore: 0,
      severity: 'NONE',
      remediationAction: `Remediated via GCP OS Config PatchJob (${jobId}) & Cloud Build base image refresh`,
    };
  });

  REMEDIATED_POSTURE_OVERRIDES.set(key, remediatedSeed);
  return buildPostureReportFromSeed(remediatedSeed);
}

export async function generateEntitySpdxSbomDocument(entityOrRef: Entity | string): Promise<Record<string, unknown>> {
  const report = await getEntityGcpCloudPostureReport(entityOrRef);
  return {
    spdxVersion: 'SPDX-2.3',
    dataLicense: 'CC0-1.0',
    SPDXID: 'SPDXRef-DOCUMENT',
    name: `aegis-sbom-${report.serviceName}`,
    documentNamespace: report.sbomMetadata.documentNamespace,
    creationInfo: {
      created: report.sbomMetadata.generatedAt,
      creators: ['Tool: gcp-container-analysis-grafeas-v1', 'Tool: gcp-osconfig-vm-inventory-v1'],
    },
    packages: report.osPackages.map((p, idx) => ({
      SPDXID: `SPDXRef-Package-${idx + 1}`,
      name: p.packageName,
      versionInfo: p.installedVersion,
      licenseConcluded: p.license,
      externalRefs: [{ referenceCategory: 'PACKAGE-MANAGER', referenceType: 'purl', referenceLocator: p.purl }],
      annotations: [{ annotator: 'Tool: aegis-gcp-posture', annotationType: 'REVIEW', annotationComment: `layer=${p.layerScope};patchState=${p.patchState};advisory=${p.securityAdvisoryId}` }],
    })),
  };
}

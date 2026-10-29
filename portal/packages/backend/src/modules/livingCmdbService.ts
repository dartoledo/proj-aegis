export type DriftCategory = 'EXPOSURE_DRIFT' | 'IMMUTABILITY_DRIFT' | 'CAPACITY_DRIFT' | 'SHADOW_RESOURCE';
export type DriftSeverity = 'CRITICAL' | 'HIGH' | 'MEDIUM' | 'LOW';

export interface CmdbDriftItem {
  driftId: string;
  category: DriftCategory;
  severity: DriftSeverity;
  fieldPath: string;
  gitDeclaredValue: string;
  liveObservedValue: string;
  detectedSource: string;
  detectedAt: string;
  status: 'ACTIVE_DRIFT' | 'RECONCILED_TO_GIT' | 'ENFORCED_FROM_GIT';
  remediationHint: string;
}

export interface BlastRadiusNode {
  entityRef: string;
  serviceName: string;
  relation: 'UPSTREAM_DEPENDENCY' | 'DOWNSTREAM_CONSUMER';
  hopDistance: number;
  exposureTier: 'unrestricted-public' | 'restricted-public' | 'strictly-private';
  impactSeverity: 'CRITICAL' | 'HIGH' | 'MEDIUM';
  failurePropagationSummary: string;
}

export interface EntityCmdbSnapshot {
  entityRef: string;
  serviceName: string;
  ciId: string;
  ownerTeam: string;
  declaredExposureTier: 'unrestricted-public' | 'restricted-public' | 'strictly-private';
  observedExposureTier: 'unrestricted-public' | 'restricted-public' | 'strictly-private';
  declaredReplicas: number;
  observedReplicas: number;
  declaredImageDigest: string;
  observedImageDigest: string;
  driftStatus: 'IN_SYNC' | 'DRIFT_DETECTED';
  activeDriftCount: number;
  driftItems: CmdbDriftItem[];
  blastRadius: BlastRadiusNode[];
  lastReconciledAt: string;
}

export interface FleetCmdbTopologyReport {
  totalConfigurationItems: number;
  driftedServicesCount: number;
  totalActiveDrifts: number;
  shadowResourcesDetected: number;
  snapshots: EntityCmdbSnapshot[];
  directedEdges: Array<{ from: string; to: string; protocol: string }>;
}

export const CMDB_SERVICE_SEEDS: Record<string, Omit<EntityCmdbSnapshot, 'driftStatus' | 'activeDriftCount' | 'lastReconciledAt'>> = {
  'aegis-ui': {
    entityRef: 'aegis-ui',
    serviceName: 'aegis-ui',
    ciId: 'CI-AEGIS-1001',
    ownerTeam: 'platform-experience',
    declaredExposureTier: 'unrestricted-public',
    observedExposureTier: 'unrestricted-public',
    declaredReplicas: 3,
    observedReplicas: 3,
    declaredImageDigest: 'sha256:8f4e2c19a7b3d605',
    observedImageDigest: 'sha256:8f4e2c19a7b3d605',
    driftItems: [
      {
        driftId: 'drift-ui-cdn-ttl',
        category: 'CAPACITY_DRIFT',
        severity: 'MEDIUM',
        fieldPath: 'spec.cdn.maxTtlSeconds',
        gitDeclaredValue: '3600',
        liveObservedValue: '300',
        detectedSource: 'GCP Cloud CDN Probe',
        detectedAt: '2025-06-14T08:22:00Z',
        status: 'ACTIVE_DRIFT',
        remediationHint: 'Align CDN maxTtlSeconds in Git with live GCP Cloud CDN configuration',
      },
    ],
    blastRadius: [
      {
        entityRef: 'aegis-backend',
        serviceName: 'aegis-backend',
        relation: 'UPSTREAM_DEPENDENCY',
        hopDistance: 1,
        exposureTier: 'strictly-private',
        impactSeverity: 'CRITICAL',
        failurePropagationSummary: 'UI cannot render API responses if backend is down',
      },
      {
        entityRef: 'aegis-auth',
        serviceName: 'aegis-auth',
        relation: 'UPSTREAM_DEPENDENCY',
        hopDistance: 1,
        exposureTier: 'strictly-private',
        impactSeverity: 'HIGH',
        failurePropagationSummary: 'Session validation fails; users see 401 on all authenticated routes',
      },
    ],
  },
  'aegis-backend': {
    entityRef: 'aegis-backend',
    serviceName: 'aegis-backend',
    ciId: 'CI-AEGIS-1002',
    ownerTeam: 'core-services',
    declaredExposureTier: 'strictly-private',
    observedExposureTier: 'restricted-public',
    declaredReplicas: 3,
    observedReplicas: 5,
    declaredImageDigest: 'sha256:3a7b91c4e2f8d056',
    observedImageDigest: 'sha256:9f00deadbeef1122',
    driftItems: [
      {
        driftId: 'drift-backend-exposure',
        category: 'EXPOSURE_DRIFT',
        severity: 'CRITICAL',
        fieldPath: 'metadata.annotations[resiliency.idp/exposure-scope]',
        gitDeclaredValue: 'strictly-private',
        liveObservedValue: 'restricted-public (stg.backend.api.aegis.cloud.goog)',
        detectedSource: 'SSL & DNS Exposure Probe',
        detectedAt: '2025-06-14T07:15:00Z',
        status: 'ACTIVE_DRIFT',
        remediationHint: 'Remove public DNS A-record or move staging webhook behind Cloud IAP',
      },
      {
        driftId: 'drift-backend-digest',
        category: 'IMMUTABILITY_DRIFT',
        severity: 'HIGH',
        fieldPath: 'spec.template.spec.containers[0].image',
        gitDeclaredValue: 'sha256:3a7b91c4e2f8d056',
        liveObservedValue: 'sha256:9f00deadbeef1122',
        detectedSource: 'GKE / Harbor Digest Reconciler',
        detectedAt: '2025-06-14T06:45:00Z',
        status: 'ACTIVE_DRIFT',
        remediationHint: 'Roll out attested Harbor image digest to GKE workload',
      },
      {
        driftId: 'drift-backend-replicas',
        category: 'CAPACITY_DRIFT',
        severity: 'MEDIUM',
        fieldPath: 'spec.replicas',
        gitDeclaredValue: '3',
        liveObservedValue: '5',
        detectedSource: 'K8s Day-2 Live Probe',
        detectedAt: '2025-06-14T05:30:00Z',
        status: 'ACTIVE_DRIFT',
        remediationHint: 'Sync emergency 5-replica scale event back to Git catalog-info.yaml',
      },
    ],
    blastRadius: [
      {
        entityRef: 'aegis-ui',
        serviceName: 'aegis-ui',
        relation: 'DOWNSTREAM_CONSUMER',
        hopDistance: 1,
        exposureTier: 'unrestricted-public',
        impactSeverity: 'CRITICAL',
        failurePropagationSummary: 'All end-user API calls fail; UI shows error states',
      },
      {
        entityRef: 'aegis-db',
        serviceName: 'aegis-db',
        relation: 'UPSTREAM_DEPENDENCY',
        hopDistance: 1,
        exposureTier: 'strictly-private',
        impactSeverity: 'CRITICAL',
        failurePropagationSummary: 'Data layer unavailable; all CRUD operations time out',
      },
      {
        entityRef: 'aegis-auth',
        serviceName: 'aegis-auth',
        relation: 'UPSTREAM_DEPENDENCY',
        hopDistance: 1,
        exposureTier: 'strictly-private',
        impactSeverity: 'HIGH',
        failurePropagationSummary: 'Token validation fails; requests rejected at gateway',
      },
    ],
  },
  'aegis-auth': {
    entityRef: 'aegis-auth',
    serviceName: 'aegis-auth',
    ciId: 'CI-AEGIS-1003',
    ownerTeam: 'secops-iam',
    declaredExposureTier: 'strictly-private',
    observedExposureTier: 'strictly-private',
    declaredReplicas: 2,
    observedReplicas: 2,
    declaredImageDigest: 'sha256:c5d8e2f1a4b7c906',
    observedImageDigest: 'sha256:c5d8e2f1a4b7c906',
    driftItems: [
      {
        driftId: 'drift-auth-shadow-redis',
        category: 'SHADOW_RESOURCE',
        severity: 'HIGH',
        fieldPath: 'gcp.compute.subnetwork/shadow-vm',
        gitDeclaredValue: 'none',
        liveObservedValue: 'gce-auth-redis-ephemeral-02 (10.128.2.99)',
        detectedSource: 'GCP Cloud Asset Inventory',
        detectedAt: '2025-06-14T04:10:00Z',
        status: 'ACTIVE_DRIFT',
        remediationHint: 'Import shadow VM into Terraform/Backstage catalog or terminate instance',
      },
    ],
    blastRadius: [
      {
        entityRef: 'aegis-backend',
        serviceName: 'aegis-backend',
        relation: 'DOWNSTREAM_CONSUMER',
        hopDistance: 1,
        exposureTier: 'strictly-private',
        impactSeverity: 'HIGH',
        failurePropagationSummary: 'Backend cannot validate JWTs; all API requests return 401',
      },
      {
        entityRef: 'aegis-ui',
        serviceName: 'aegis-ui',
        relation: 'DOWNSTREAM_CONSUMER',
        hopDistance: 2,
        exposureTier: 'unrestricted-public',
        impactSeverity: 'MEDIUM',
        failurePropagationSummary: 'Indirect impact via backend; UI sessions expire and users must re-authenticate',
      },
    ],
  },
  'aegis-db': {
    entityRef: 'aegis-db',
    serviceName: 'aegis-db',
    ciId: 'CI-AEGIS-1004',
    ownerTeam: 'data-platform',
    declaredExposureTier: 'strictly-private',
    observedExposureTier: 'strictly-private',
    declaredReplicas: 2,
    observedReplicas: 2,
    declaredImageDigest: 'sha256:9a1b4c7d0e3f6a82',
    observedImageDigest: 'sha256:9a1b4c7d0e3f6a82',
    driftItems: [],
    blastRadius: [
      {
        entityRef: 'aegis-backend',
        serviceName: 'aegis-backend',
        relation: 'DOWNSTREAM_CONSUMER',
        hopDistance: 1,
        exposureTier: 'strictly-private',
        impactSeverity: 'CRITICAL',
        failurePropagationSummary: 'All data operations fail; backend returns 503 to consumers',
      },
      {
        entityRef: 'aegis-ui',
        serviceName: 'aegis-ui',
        relation: 'DOWNSTREAM_CONSUMER',
        hopDistance: 2,
        exposureTier: 'unrestricted-public',
        impactSeverity: 'HIGH',
        failurePropagationSummary: 'Indirect impact via backend; UI data fetches fail and show stale cache',
      },
    ],
  },
  'hello-world-app': {
    entityRef: 'hello-world-app',
    serviceName: 'hello-world-app',
    ciId: 'CI-AEGIS-1005',
    ownerTeam: 'edge-platform',
    declaredExposureTier: 'restricted-public',
    observedExposureTier: 'restricted-public',
    declaredReplicas: 2,
    observedReplicas: 2,
    declaredImageDigest: 'sha256:2b5c8d1e4f7a0b3c',
    observedImageDigest: 'sha256:2b5c8d1e4f7a0b3c',
    driftItems: [],
    blastRadius: [
      {
        entityRef: 'aegis-ui',
        serviceName: 'aegis-ui',
        relation: 'DOWNSTREAM_CONSUMER',
        hopDistance: 1,
        exposureTier: 'unrestricted-public',
        impactSeverity: 'MEDIUM',
        failurePropagationSummary: 'Edge feature degradation; UI falls back to default rendering',
      },
    ],
  },
};

const RECONCILED_CMDB_STATE = new Map<string, Omit<EntityCmdbSnapshot, 'driftStatus' | 'activeDriftCount' | 'lastReconciledAt'>>();

export function resetCmdbReconciliationState(): void {
  RECONCILED_CMDB_STATE.clear();
}

export function resolveCmdbServiceKey(entityOrRef: string): string {
  const raw = entityOrRef.split('/').pop()?.split(':').pop() || 'aegis-ui';
  if (raw === 'haproxy-hello-world-tls') {
    return 'hello-world-app';
  }
  return CMDB_SERVICE_SEEDS[raw] ? raw : 'aegis-ui';
}

function buildCmdbSnapshot(seed: Omit<EntityCmdbSnapshot, 'driftStatus' | 'activeDriftCount' | 'lastReconciledAt'>): EntityCmdbSnapshot {
  const activeDriftCount = seed.driftItems.filter(d => d.status === 'ACTIVE_DRIFT').length;
  return {
    ...seed,
    driftStatus: activeDriftCount > 0 ? 'DRIFT_DETECTED' : 'IN_SYNC',
    activeDriftCount,
    lastReconciledAt: new Date().toISOString(),
  };
}

export async function getEntityCmdbSnapshot(entityRef: string): Promise<EntityCmdbSnapshot> {
  const key = resolveCmdbServiceKey(entityRef);
  const seed = RECONCILED_CMDB_STATE.get(key) || CMDB_SERVICE_SEEDS[key];
  return buildCmdbSnapshot(seed);
}

export async function getFleetCmdbTopology(): Promise<FleetCmdbTopologyReport> {
  const keys = Object.keys(CMDB_SERVICE_SEEDS);
  const snapshots = await Promise.all(keys.map(k => getEntityCmdbSnapshot(k)));
  const driftedServicesCount = snapshots.filter(s => s.activeDriftCount > 0).length;
  const totalActiveDrifts = snapshots.reduce((sum, s) => sum + s.activeDriftCount, 0);
  const shadowResourcesDetected = snapshots.reduce((sum, s) => sum + s.driftItems.filter(d => d.status === 'ACTIVE_DRIFT' && d.category === 'SHADOW_RESOURCE').length, 0);
  return {
    totalConfigurationItems: snapshots.length,
    driftedServicesCount,
    totalActiveDrifts,
    shadowResourcesDetected,
    snapshots,
    directedEdges: [
      { from: 'hello-world-app', to: 'aegis-ui', protocol: 'HTTPS/TLS-1.3' },
      { from: 'aegis-ui', to: 'aegis-backend', protocol: 'REST/JSON-mTLS' },
      { from: 'aegis-ui', to: 'aegis-auth', protocol: 'OIDC/JWT' },
      { from: 'aegis-backend', to: 'aegis-auth', protocol: 'gRPC/Introspect' },
      { from: 'aegis-backend', to: 'aegis-db', protocol: 'PostgreSQL/TLS' },
    ],
  };
}

export async function reconcileCmdbDrift(entityRef: string, action: 'sync-to-git' | 'enforce-git-state', driftId?: string): Promise<EntityCmdbSnapshot> {
  const key = resolveCmdbServiceKey(entityRef);
  const current = JSON.parse(JSON.stringify(RECONCILED_CMDB_STATE.get(key) || CMDB_SERVICE_SEEDS[key]));
  current.driftItems = current.driftItems.map((item: CmdbDriftItem) => {
    if (driftId && item.driftId !== driftId) return item;
    return {
      ...item,
      status: action === 'sync-to-git' ? 'RECONCILED_TO_GIT' : 'ENFORCED_FROM_GIT',
      gitDeclaredValue: action === 'sync-to-git' ? item.liveObservedValue : item.gitDeclaredValue,
      liveObservedValue: action === 'enforce-git-state' ? item.gitDeclaredValue : item.liveObservedValue,
    };
  });
  if (!driftId || current.driftItems.every((d: CmdbDriftItem) => d.status !== 'ACTIVE_DRIFT')) {
    if (action === 'sync-to-git') {
      current.declaredReplicas = current.observedReplicas;
      current.declaredImageDigest = current.observedImageDigest;
      current.declaredExposureTier = current.observedExposureTier;
    } else {
      current.observedReplicas = current.declaredReplicas;
      current.observedImageDigest = current.declaredImageDigest;
      current.observedExposureTier = current.declaredExposureTier;
    }
  }
  RECONCILED_CMDB_STATE.set(key, current);
  return buildCmdbSnapshot(current);
}

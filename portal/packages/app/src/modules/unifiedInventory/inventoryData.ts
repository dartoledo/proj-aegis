export interface UnifiedEndpointItem {
  endpointId: string;
  serviceName: string;
  entityRef: string;
  environment: 'dev' | 'stg' | 'stress-test' | 'preprod' | 'prod';
  endpointUrl: string;
  sniHostname: string;
  exposureScope: 'unrestricted-public' | 'restricted-public' | 'strictly-private';
  dnsScope: 'public-authoritative' | 'private-split-horizon';
  providerType: 'gcp-cloud-lb' | 'haproxy-edge' | 'private-cloud-lb';
  issuerCn: string;
  algorithm: string;
  serialNumberHex: string;
  daysRemaining: number;
  complianceStatus: 'COMPLIANT' | 'WARNING' | 'NON_COMPLIANT';
  ownerTeam: string;
}

export interface UnifiedComponentItem {
  componentId: string;
  serviceName: string;
  entityRef: string;
  name: string;
  versionOrIdentifier: string;
  domain: 'INFRASTRUCTURE' | 'SOFTWARE';
  layerId?: string;
  layerLabel?: string;
  categoryType: string;
  categoryLabel: string;
  icon: string;
  status: 'HEALTHY' | 'DRIFTED' | 'WARNING' | 'CRITICAL';
  ownerTeamId: 'app-team' | 'sre-team';
  ownerTeamName: string;
  serviceSquad: string;
  purl?: string;
  cpe23Uri?: string;
  eolSlug?: string;
  eolStatus?: string;
  cveCount?: number;
  notes?: string;
}

export interface UnifiedDriftRecord {
  driftId: string;
  serviceName: string;
  entityRef: string;
  category: string;
  severity: string;
  fieldPath: string;
  gitDeclaredValue: string;
  liveObservedValue: string;
  detectedSource: string;
  status: string;
}

export interface UnifiedTeamRecord {
  teamId: string;
  teamName: string;
  teamType: 'GOVERNANCE_DOMAIN' | 'SERVICE_SQUAD';
  email: string;
  slackChannel: string;
  responsibilityScope: string;
  ownedServices: string[];
  totalComponents: number;
  softwareCount: number;
  infrastructureCount: number;
  endpointCount: number;
  driftedOrCriticalCount: number;
}

export interface UnifiedInventoryPayload {
  endpoints: UnifiedEndpointItem[];
  software: UnifiedComponentItem[];
  infrastructure: UnifiedComponentItem[];
  drifts: UnifiedDriftRecord[];
  teams: UnifiedTeamRecord[];
  isLiveBackend: boolean;
}

export const FALLBACK_ENDPOINTS: UnifiedEndpointItem[] = [
  {
    endpointId: 'ep-aegis-ui-prod-001',
    serviceName: 'aegis-ui',
    entityRef: 'svc-aegis-ui',
    environment: 'prod',
    endpointUrl: 'https://aegis-ui.prod.aegisplatform.io',
    sniHostname: 'aegis-ui.prod.aegisplatform.io',
    exposureScope: 'unrestricted-public',
    dnsScope: 'public-authoritative',
    providerType: 'gcp-cloud-lb',
    issuerCn: 'GCP Managed Cert - aegisplatform.io',
    algorithm: 'ECDSA P-256',
    serialNumberHex: 'A3F1B2C4D5E6F708192A3B4C5D6E7F80',
    daysRemaining: 42,
    complianceStatus: 'COMPLIANT',
    ownerTeam: 'App Team',
  },
  {
    endpointId: 'ep-aegis-ui-stg-002',
    serviceName: 'aegis-ui',
    entityRef: 'svc-aegis-ui',
    environment: 'stg',
    endpointUrl: 'https://aegis-ui.stg.aegisplatform.io',
    sniHostname: 'aegis-ui.stg.aegisplatform.io',
    exposureScope: 'restricted-public',
    dnsScope: 'public-authoritative',
    providerType: 'haproxy-edge',
    issuerCn: 'Let\'s Encrypt R3',
    algorithm: 'RSA 2048',
    serialNumberHex: 'B4C2D3E5F6A7B8192C3D4E5F6A7B8C90',
    daysRemaining: 18,
    complianceStatus: 'WARNING',
    ownerTeam: 'App Team',
  },
  {
    endpointId: 'ep-aegis-backend-prod-003',
    serviceName: 'aegis-backend',
    entityRef: 'svc-aegis-backend',
    environment: 'prod',
    endpointUrl: 'https://api.aegisplatform.io',
    sniHostname: 'api.aegisplatform.io',
    exposureScope: 'restricted-public',
    dnsScope: 'public-authoritative',
    providerType: 'gcp-cloud-lb',
    issuerCn: 'GCP Managed Cert - aegisplatform.io',
    algorithm: 'ECDSA P-256',
    serialNumberHex: 'C5D3E4F6A7B8C9203D4E5F6A7B8C9D01',
    daysRemaining: 61,
    complianceStatus: 'COMPLIANT',
    ownerTeam: 'App Team',
  },
  {
    endpointId: 'ep-aegis-backend-stress-004',
    serviceName: 'aegis-backend',
    entityRef: 'svc-aegis-backend',
    environment: 'stress-test',
    endpointUrl: 'https://api-stress.aegisplatform.io',
    sniHostname: 'api-stress.aegisplatform.io',
    exposureScope: 'strictly-private',
    dnsScope: 'private-split-horizon',
    providerType: 'private-cloud-lb',
    issuerCn: 'Internal CA - aegis-stress',
    algorithm: 'RSA 4096',
    serialNumberHex: 'D6E4F5A7B8C9D0314E5F6A7B8C9D0E12',
    daysRemaining: 90,
    complianceStatus: 'COMPLIANT',
    ownerTeam: 'SRE Team',
  },
  {
    endpointId: 'ep-aegis-auth-preprod-005',
    serviceName: 'aegis-auth',
    entityRef: 'svc-aegis-auth',
    environment: 'preprod',
    endpointUrl: 'https://auth.preprod.aegisplatform.io',
    sniHostname: 'auth.preprod.aegisplatform.io',
    exposureScope: 'restricted-public',
    dnsScope: 'public-authoritative',
    providerType: 'gcp-cloud-lb',
    issuerCn: 'GCP Managed Cert - aegisplatform.io',
    algorithm: 'ECDSA P-256',
    serialNumberHex: 'E7F5A6B8C9D0E1425F6A7B8C9D0E1F23',
    daysRemaining: 33,
    complianceStatus: 'COMPLIANT',
    ownerTeam: 'SRE Team',
  },
  {
    endpointId: 'ep-aegis-auth-dev-006',
    serviceName: 'aegis-auth',
    entityRef: 'svc-aegis-auth',
    environment: 'dev',
    endpointUrl: 'https://auth.dev.aegisplatform.io',
    sniHostname: 'auth.dev.aegisplatform.io',
    exposureScope: 'strictly-private',
    dnsScope: 'private-split-horizon',
    providerType: 'private-cloud-lb',
    issuerCn: 'Internal CA - aegis-dev',
    algorithm: 'RSA 2048',
    serialNumberHex: 'F8A6B7C9D0E1F2536A7B8C9D0E1F2A34',
    daysRemaining: 12,
    complianceStatus: 'NON_COMPLIANT',
    ownerTeam: 'SRE Team',
  },
  {
    endpointId: 'ep-aegis-db-prod-007',
    serviceName: 'aegis-db',
    entityRef: 'svc-aegis-db',
    environment: 'prod',
    endpointUrl: 'https://db.aegisplatform.io:5432',
    sniHostname: 'db.aegisplatform.io',
    exposureScope: 'strictly-private',
    dnsScope: 'private-split-horizon',
    providerType: 'private-cloud-lb',
    issuerCn: 'Internal CA - aegis-db',
    algorithm: 'ECDSA P-384',
    serialNumberHex: 'A9B7C8D0E1F2A3647B8C9D0E1F2A3B45',
    daysRemaining: 75,
    complianceStatus: 'COMPLIANT',
    ownerTeam: 'SRE Team',
  },
  {
    endpointId: 'ep-hello-world-dev-008',
    serviceName: 'hello-world-app',
    entityRef: 'svc-hello-world',
    environment: 'dev',
    endpointUrl: 'https://hello-world.dev.aegisplatform.io',
    sniHostname: 'hello-world.dev.aegisplatform.io',
    exposureScope: 'unrestricted-public',
    dnsScope: 'public-authoritative',
    providerType: 'haproxy-edge',
    issuerCn: 'Let\'s Encrypt R3',
    algorithm: 'RSA 2048',
    serialNumberHex: 'B0C8D9E1F2A3B4758C9D0E1F2A3B4C56',
    daysRemaining: 27,
    complianceStatus: 'COMPLIANT',
    ownerTeam: 'App Team',
  },
];

export const FALLBACK_COMPONENTS: UnifiedComponentItem[] = [
  // SOFTWARE (6)
  {
    componentId: 'sw-001',
    serviceName: 'aegis-backend',
    entityRef: 'svc-aegis-backend',
    name: 'Ubuntu',
    versionOrIdentifier: '22.04.4 LTS',
    domain: 'SOFTWARE',
    layerId: 'layer-os',
    layerLabel: 'Operating System',
    categoryType: 'operating-system',
    categoryLabel: 'Operating System',
    icon: '🖥️',
    status: 'HEALTHY',
    ownerTeamId: 'sre-team',
    ownerTeamName: 'SRE Team',
    serviceSquad: 'core-services',
    purl: 'pkg:deb/ubuntu/ubuntu@22.04.4?arch=amd64',
    cpe23Uri: 'cpe:2.3:o:canonical:ubuntu_linux:22.04.4',
    eolSlug: 'ubuntu-22-04-lts',
    eolStatus: 'SUPPORTED',
    cveCount: 3,
    notes: 'Base image for all aegis-backend containers',
  },
  {
    componentId: 'sw-002',
    serviceName: 'aegis-backend',
    entityRef: 'svc-aegis-backend',
    name: 'Node.js',
    versionOrIdentifier: '18.20.8',
    domain: 'SOFTWARE',
    layerId: 'layer-runtime',
    layerLabel: 'Platform Runtime Environment',
    categoryType: 'runtime',
    categoryLabel: 'Platform Runtime Environment',
    icon: '⚡',
    status: 'CRITICAL',
    ownerTeamId: 'app-team',
    ownerTeamName: 'App Team',
    serviceSquad: 'core-services',
    purl: 'pkg:npm/node@18.20.8',
    cpe23Uri: 'cpe:2.3:a:nodejs:node.js:18.20.8',
    eolSlug: 'nodejs-18',
    eolStatus: 'EOL',
    cveCount: 14,
    notes: 'Node.js 18 reached EOL on 2024-04-30. Upgrade to 20.x or 22.x required.',
  },
  {
    componentId: 'sw-003',
    serviceName: 'aegis-backend',
    entityRef: 'svc-aegis-backend',
    name: 'Express',
    versionOrIdentifier: '4.18.2',
    domain: 'SOFTWARE',
    layerId: 'layer-framework',
    layerLabel: 'Library / Framework',
    categoryType: 'framework',
    categoryLabel: 'Library / Framework',
    icon: '📦',
    status: 'HEALTHY',
    ownerTeamId: 'app-team',
    ownerTeamName: 'App Team',
    serviceSquad: 'core-services',
    purl: 'pkg:npm/express@4.18.2',
    cpe23Uri: 'cpe:2.3:a:expressjs:express:4.18.2',
    eolSlug: 'express-4',
    eolStatus: 'SUPPORTED',
    cveCount: 1,
    notes: 'Primary HTTP framework for aegis-backend REST API',
  },
  {
    componentId: 'sw-004',
    serviceName: 'aegis-auth',
    entityRef: 'svc-aegis-auth',
    name: 'Keycloak',
    versionOrIdentifier: '21.1.2',
    domain: 'SOFTWARE',
    layerId: 'layer-security',
    layerLabel: 'Security & Identity Software',
    categoryType: 'identity',
    categoryLabel: 'Security & Identity Software',
    icon: '🔐',
    status: 'WARNING',
    ownerTeamId: 'sre-team',
    ownerTeamName: 'SRE Team',
    serviceSquad: 'secops-iam',
    purl: 'pkg:maven/org.keycloak/keycloak@21.1.2',
    cpe23Uri: 'cpe:2.3:a:keycloak:keycloak:21.1.2',
    eolSlug: 'keycloak-21',
    eolStatus: 'SUPPORTED',
    cveCount: 5,
    notes: 'OAuth2/OIDC provider. 2 known CVEs in dependency tree.',
  },
  {
    componentId: 'sw-005',
    serviceName: 'aegis-db',
    entityRef: 'svc-aegis-db',
    name: 'Prisma',
    versionOrIdentifier: '5.10.0',
    domain: 'SOFTWARE',
    layerId: 'layer-data-access',
    layerLabel: 'Data Access / ORM',
    categoryType: 'orm',
    categoryLabel: 'Data Access / ORM',
    icon: '🗄️',
    status: 'HEALTHY',
    ownerTeamId: 'app-team',
    ownerTeamName: 'App Team',
    serviceSquad: 'data-platform',
    purl: 'pkg:npm/prisma@5.10.0',
    cpe23Uri: 'cpe:2.3:a:prisma:prisma:5.10.0',
    eolSlug: 'prisma-5',
    eolStatus: 'SUPPORTED',
    cveCount: 0,
    notes: 'ORM layer for PostgreSQL data access in aegis-backend',
  },
  {
    componentId: 'sw-006',
    serviceName: 'aegis-backend',
    entityRef: 'svc-aegis-backend',
    name: 'aegis-backend',
    versionOrIdentifier: '2.4.1',
    domain: 'SOFTWARE',
    layerId: 'layer-app-core',
    layerLabel: 'Application Core',
    categoryType: 'application',
    categoryLabel: 'Application Core',
    icon: '🏗️',
    status: 'HEALTHY',
    ownerTeamId: 'app-team',
    ownerTeamName: 'App Team',
    serviceSquad: 'core-services',
    purl: 'pkg:npm/@aegis/backend@2.4.1',
    cpe23Uri: 'cpe:2.3:a:aegis:aegis-backend:2.4.1',
    eolSlug: 'aegis-backend-2',
    eolStatus: 'SUPPORTED',
    cveCount: 0,
    notes: 'Core business logic service',
  },
  // INFRASTRUCTURE (6)
  {
    componentId: 'infra-001',
    serviceName: 'aegis-ui',
    entityRef: 'svc-aegis-ui',
    name: 'Cloudflare CDN',
    versionOrIdentifier: 'cf-zone-aegisplatform',
    domain: 'INFRASTRUCTURE',
    layerId: 'layer-edge',
    layerLabel: 'Edge & External Security',
    categoryType: 'cdn',
    categoryLabel: 'Edge & External Security',
    icon: '🌐',
    status: 'DRIFTED',
    ownerTeamId: 'sre-team',
    ownerTeamName: 'SRE Team',
    serviceSquad: 'edge-platform',
    notes: 'Cache TTL drifted from 300s (declared) to 600s (observed).',
  },
  {
    componentId: 'infra-002',
    serviceName: 'aegis-backend',
    entityRef: 'svc-aegis-backend',
    name: 'HAProxy',
    versionOrIdentifier: '2.8.5',
    domain: 'INFRASTRUCTURE',
    layerId: 'layer-ingress',
    layerLabel: 'Ingress & Traffic Routing',
    categoryType: 'load-balancer',
    categoryLabel: 'Ingress & Traffic Routing',
    icon: '🔀',
    status: 'HEALTHY',
    ownerTeamId: 'sre-team',
    ownerTeamName: 'SRE Team',
    serviceSquad: 'edge-platform',
    notes: 'Edge load balancer for aegisplatform.io traffic',
  },
  {
    componentId: 'infra-003',
    serviceName: 'aegis-db',
    entityRef: 'svc-aegis-db',
    name: 'GCP IAM Policy',
    versionOrIdentifier: 'proj-aegis-prod-iam-v14',
    domain: 'INFRASTRUCTURE',
    layerId: 'layer-governance',
    layerLabel: 'Cloud Governance',
    categoryType: 'iam-policy',
    categoryLabel: 'Cloud Governance',
    icon: '📋',
    status: 'HEALTHY',
    ownerTeamId: 'sre-team',
    ownerTeamName: 'SRE Team',
    serviceSquad: 'platform-experience',
    notes: 'GCP project-level IAM bindings for aegis-prod',
  },
  {
    componentId: 'infra-004',
    serviceName: 'aegis-backend',
    entityRef: 'svc-aegis-backend',
    name: 'K8s Deployment aegis-backend',
    versionOrIdentifier: 'deploy-aegis-backend-prod',
    domain: 'INFRASTRUCTURE',
    layerId: 'layer-orchestration',
    layerLabel: 'Orchestration & Compute',
    categoryType: 'k8s-deployment',
    categoryLabel: 'Orchestration & Compute',
    icon: '☸️',
    status: 'DRIFTED',
    ownerTeamId: 'sre-team',
    ownerTeamName: 'SRE Team',
    serviceSquad: 'core-services',
    notes: 'Replica count drifted: 3 declared in GitOps, 5 observed in cluster.',
  },
  {
    componentId: 'infra-005',
    serviceName: 'aegis-auth',
    entityRef: 'svc-aegis-auth',
    name: 'gce-auth-redis-ephemeral-02',
    versionOrIdentifier: 'vm-4f8a2c1d',
    domain: 'INFRASTRUCTURE',
    layerId: 'layer-hosts',
    layerLabel: 'Dedicated Hosts',
    categoryType: 'vm',
    categoryLabel: 'Dedicated Hosts',
    icon: '🖳',
    status: 'DRIFTED',
    ownerTeamId: 'sre-team',
    ownerTeamName: 'SRE Team',
    serviceSquad: 'secops-iam',
    notes: 'Shadow VM not tracked in IaC. Running Redis 7.2 for auth session cache.',
  },
  {
    componentId: 'infra-006',
    serviceName: 'aegis-auth',
    entityRef: 'svc-aegis-auth',
    name: 'Redis',
    versionOrIdentifier: '7.2.4',
    domain: 'INFRASTRUCTURE',
    layerId: 'layer-cache',
    layerLabel: 'Data Cache & State',
    categoryType: 'cache',
    categoryLabel: 'Data Cache & State',
    icon: '⚡',
    status: 'HEALTHY',
    ownerTeamId: 'sre-team',
    ownerTeamName: 'SRE Team',
    serviceSquad: 'data-platform',
    notes: 'Session and token cache for aegis-auth',
  },
];

export const FALLBACK_DRIFTS: UnifiedDriftRecord[] = [
  {
    driftId: 'drift-001',
    serviceName: 'aegis-ui',
    entityRef: 'svc-aegis-ui',
    category: 'CDN Configuration',
    severity: 'MEDIUM',
    fieldPath: 'cloudflare.cache_ttl',
    gitDeclaredValue: '300',
    liveObservedValue: '600',
    detectedSource: 'cloudflare-api-poll',
    status: 'OPEN',
  },
  {
    driftId: 'drift-002',
    serviceName: 'aegis-backend',
    entityRef: 'svc-aegis-backend',
    category: 'K8s Replica Count',
    severity: 'HIGH',
    fieldPath: 'spec.replicas',
    gitDeclaredValue: '3',
    liveObservedValue: '5',
    detectedSource: 'k8s-cluster-sync',
    status: 'OPEN',
  },
  {
    driftId: 'drift-003',
    serviceName: 'aegis-auth',
    entityRef: 'svc-aegis-auth',
    category: 'Shadow Resource',
    severity: 'HIGH',
    fieldPath: 'gcp.compute.instances.gce-auth-redis-ephemeral-02',
    gitDeclaredValue: 'not-found',
    liveObservedValue: 'RUNNING',
    detectedSource: 'gcp-inventory-scan',
    status: 'OPEN',
  },
  {
    driftId: 'drift-004',
    serviceName: 'aegis-auth',
    entityRef: 'svc-aegis-auth',
    category: 'Cache Version',
    severity: 'LOW',
    fieldPath: 'redis.version',
    gitDeclaredValue: '7.2.3',
    liveObservedValue: '7.2.4',
    detectedSource: 'redis-health-check',
    status: 'ACKNOWLEDGED',
  },
];

export const FALLBACK_TEAMS: UnifiedTeamRecord[] = [
  {
    teamId: 'app-team',
    teamName: 'App Team',
    teamType: 'SERVICE_SQUAD',
    email: 'app-team@aegisplatform.io',
    slackChannel: '#aegis-app-team',
    responsibilityScope: 'Application development, feature delivery, and software component ownership',
    ownedServices: ['aegis-ui', 'aegis-backend', 'hello-world-app'],
    totalComponents: 5,
    softwareCount: 4,
    infrastructureCount: 1,
    endpointCount: 4,
    driftedOrCriticalCount: 1,
  },
  {
    teamId: 'sre-team',
    teamName: 'SRE Team',
    teamType: 'SERVICE_SQUAD',
    email: 'sre-team@aegisplatform.io',
    slackChannel: '#aegis-sre',
    responsibilityScope: 'Infrastructure reliability, observability, and operational excellence',
    ownedServices: ['aegis-auth', 'aegis-db'],
    totalComponents: 7,
    softwareCount: 2,
    infrastructureCount: 5,
    endpointCount: 4,
    driftedOrCriticalCount: 3,
  },
  {
    teamId: 'platform-experience',
    teamName: 'platform-experience',
    teamType: 'GOVERNANCE_DOMAIN',
    email: 'platform-experience@aegisplatform.io',
    slackChannel: '#governance-platform-experience',
    responsibilityScope: 'Cloud governance, IAM policy management, and platform standards',
    ownedServices: ['aegis-db'],
    totalComponents: 1,
    softwareCount: 0,
    infrastructureCount: 1,
    endpointCount: 0,
    driftedOrCriticalCount: 0,
  },
  {
    teamId: 'core-services',
    teamName: 'core-services',
    teamType: 'GOVERNANCE_DOMAIN',
    email: 'core-services@aegisplatform.io',
    slackChannel: '#governance-core-services',
    responsibilityScope: 'Core backend services, data access layers, and orchestration',
    ownedServices: ['aegis-backend'],
    totalComponents: 4,
    softwareCount: 3,
    infrastructureCount: 1,
    endpointCount: 2,
    driftedOrCriticalCount: 2,
  },
  {
    teamId: 'secops-iam',
    teamName: 'secops-iam',
    teamType: 'GOVERNANCE_DOMAIN',
    email: 'secops-iam@aegisplatform.io',
    slackChannel: '#governance-secops-iam',
    responsibilityScope: 'Security operations, identity and access management, and auth infrastructure',
    ownedServices: ['aegis-auth'],
    totalComponents: 3,
    softwareCount: 1,
    infrastructureCount: 2,
    endpointCount: 2,
    driftedOrCriticalCount: 1,
  },
  {
    teamId: 'data-platform',
    teamName: 'data-platform',
    teamType: 'GOVERNANCE_DOMAIN',
    email: 'data-platform@aegisplatform.io',
    slackChannel: '#governance-data-platform',
    responsibilityScope: 'Data infrastructure, caching, and state management',
    ownedServices: ['aegis-db', 'aegis-auth'],
    totalComponents: 2,
    softwareCount: 1,
    infrastructureCount: 1,
    endpointCount: 0,
    driftedOrCriticalCount: 0,
  },
  {
    teamId: 'edge-platform',
    teamName: 'edge-platform',
    teamType: 'GOVERNANCE_DOMAIN',
    email: 'edge-platform@aegisplatform.io',
    slackChannel: '#governance-edge-platform',
    responsibilityScope: 'Edge security, CDN management, and ingress traffic routing',
    ownedServices: ['aegis-ui', 'aegis-backend'],
    totalComponents: 2,
    softwareCount: 0,
    infrastructureCount: 2,
    endpointCount: 2,
    driftedOrCriticalCount: 1,
  },
];

export async function fetchUnifiedInventoryData(): Promise<UnifiedInventoryPayload> {
  try {
    const [cmdbRes, sslRes] = await Promise.all([
      fetch('http://localhost:7007/api/living-cmdb/fleet-graph'),
      fetch('http://localhost:7007/api/ssl-tracker/fleet'),
    ]);

    let software: UnifiedComponentItem[] = [];
    let infrastructure: UnifiedComponentItem[] = [];
    let drifts: UnifiedDriftRecord[] = [];
    let endpoints: UnifiedEndpointItem[] = FALLBACK_ENDPOINTS;
    let anySucceeded = false;

    if (cmdbRes.ok) {
      const cmdbJson = await cmdbRes.json();
      if (Array.isArray(cmdbJson?.snapshots) && cmdbJson.snapshots.length > 0) {
        anySucceeded = true;
        for (const snap of cmdbJson.snapshots) {
          if (Array.isArray(snap.componentInventory)) {
            for (const node of snap.componentInventory) {
              const item: UnifiedComponentItem = {
                componentId: node.componentId,
                serviceName: snap.serviceName,
                entityRef: snap.entityRef,
                name: node.name,
                versionOrIdentifier: node.versionOrIdentifier,
                domain: node.domain,
                layerId: node.layerId,
                layerLabel: node.layerLabel || node.categoryLabel,
                categoryType: node.categoryType,
                categoryLabel: node.categoryLabel,
                icon: node.icon || '📦',
                status: node.status || 'HEALTHY',
                ownerTeamId: node.ownerTeamId || (node.domain === 'INFRASTRUCTURE' ? 'sre-team' : 'app-team'),
                ownerTeamName: node.ownerTeamName || (node.domain === 'INFRASTRUCTURE' ? 'SRE Team' : 'App Team'),
                serviceSquad: snap.ownerTeam || 'core-services',
                purl: node.normalizedVersion?.purl,
                cpe23Uri: node.normalizedVersion?.cpe23Uri,
                eolSlug: node.normalizedVersion ? `${node.normalizedVersion.eolProductSlug}@${node.normalizedVersion.eolCycleKey}` : undefined,
                eolStatus: node.versionCrossCheck?.eolMatch?.status || (node.status === 'CRITICAL' ? 'EOL' : 'SUPPORTED'),
                cveCount: Array.isArray(node.versionCrossCheck?.cves) ? node.versionCrossCheck.cves.length : 0,
                notes: node.notes,
              };
              if (node.domain === 'INFRASTRUCTURE') {
                infrastructure.push(item);
              } else {
                software.push(item);
              }
            }
          }
          if (Array.isArray(snap.driftItems)) {
            for (const item of snap.driftItems) {
              drifts.push({
                driftId: item.driftId || item.id,
                serviceName: snap.serviceName,
                entityRef: snap.entityRef,
                category: item.category,
                severity: item.severity,
                fieldPath: item.fieldPath,
                gitDeclaredValue: item.gitDeclaredValue || item.gitDeclared,
                liveObservedValue: item.liveObservedValue || item.liveObserved,
                detectedSource: item.detectedSource || item.source,
                status: item.status,
              });
            }
          }
        }
      }
    }

    if (sslRes.ok) {
      const sslJson = await sslRes.json();
      const rawEndpoints = sslJson?.endpoints || (Array.isArray(sslJson?.rollups) ? sslJson.rollups.flatMap((r: any) => r.endpoints || []) : []);
      if (rawEndpoints.length > 0) {
        anySucceeded = true;
        endpoints = rawEndpoints.map((ep: any) => ({
          endpointId: ep.endpointId,
          serviceName: ep.serviceName,
          entityRef: ep.entityRef,
          environment: ep.environment,
          endpointUrl: ep.endpointUrl,
          sniHostname: ep.sniHostname,
          exposureScope: ep.exposureScope || 'strictly-private',
          dnsScope: ep.dnsScope || (ep.exposureScope === 'strictly-private' ? 'private-split-horizon' : 'public-authoritative'),
          providerType: ep.providerType || 'private-cloud-lb',
          issuerCn: ep.certificate?.issuerCn || ep.issuerCn || 'GCP Managed CA',
          algorithm: ep.algorithm || (ep.certificate ? `${ep.certificate.publicKeyAlgorithm} ${ep.certificate.publicKeyBits}` : 'ECDSA P-256'),
          serialNumberHex: ep.certificate?.serialNumberHex || ep.serialNumberHex || 'N/A',
          daysRemaining: ep.certificate?.daysRemaining ?? ep.daysRemaining ?? 75,
          complianceStatus: ep.certificate?.complianceStatus || ep.complianceStatus || 'COMPLIANT',
          ownerTeam: ep.ownerTeam || (ep.providerType === 'private-cloud-lb' ? 'SRE Team' : 'App Team'),
        }));
      }
    }

    if (anySucceeded) {
      return {
        endpoints,
        software: software.length > 0 ? software : FALLBACK_COMPONENTS.filter((c) => c.domain === 'SOFTWARE'),
        infrastructure: infrastructure.length > 0 ? infrastructure : FALLBACK_COMPONENTS.filter((c) => c.domain === 'INFRASTRUCTURE'),
        drifts: drifts.length > 0 ? drifts : FALLBACK_DRIFTS,
        teams: FALLBACK_TEAMS,
        isLiveBackend: true,
      };
    }

    return {
      endpoints: FALLBACK_ENDPOINTS,
      software: FALLBACK_COMPONENTS.filter((c) => c.domain === 'SOFTWARE'),
      infrastructure: FALLBACK_COMPONENTS.filter((c) => c.domain === 'INFRASTRUCTURE'),
      drifts: FALLBACK_DRIFTS,
      teams: FALLBACK_TEAMS,
      isLiveBackend: false,
    };
  } catch {
    return {
      endpoints: FALLBACK_ENDPOINTS,
      software: FALLBACK_COMPONENTS.filter((c) => c.domain === 'SOFTWARE'),
      infrastructure: FALLBACK_COMPONENTS.filter((c) => c.domain === 'INFRASTRUCTURE'),
      drifts: FALLBACK_DRIFTS,
      teams: FALLBACK_TEAMS,
      isLiveBackend: false,
    };
  }
}

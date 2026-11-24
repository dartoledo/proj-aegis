export type AttackGraphNodeType =
  | 'EXPOSED_HTTPS_DOMAIN'
  | 'SSL_TLS_CERTIFICATE'
  | 'COMPUTE_HOST_OR_POD'
  | 'EOL_RUNTIME_OR_OS'
  | 'SBOM_PACKAGE'
  | 'CVE_VULNERABILITY'
  | 'LATERAL_SERVICE_OR_DATA_STORE';

export type AttackGraphEdgeType =
  | 'EXPOSES_INGRESS'
  | 'TERMINATES_TLS_WITH'
  | 'ROUTES_TO_WORKLOAD'
  | 'EXECUTES_ON_RUNTIME'
  | 'IMPORTS_SBOM_PACKAGE'
  | 'AFFECTED_BY_CVE'
  | 'REACHABLE_HOT_PATH_TO'
  | 'LATERAL_MOVEMENT_TO_DATA';

export interface AttackGraphNode {
  nodeId: string;
  nodeType: AttackGraphNodeType;
  label: string;
  taxonomyCategory: string;
  severity: 'CRITICAL' | 'HIGH' | 'MEDIUM' | 'HEALTHY';
  metadata: Record<string, string | number | boolean>;
}

export interface AttackGraphEdge {
  edgeId: string;
  fromNodeId: string;
  toNodeId: string;
  edgeType: AttackGraphEdgeType;
  protocolOrMechanism: string;
  isExploitableReachable: boolean;
  hopWeight: number;
}

export interface NHopAttackPathChain {
  pathId: string;
  title: string;
  hopCount: number;
  orderedNodeIds: string[];
  orderedEdgeTypes: AttackGraphEdgeType[];
  entryDomain: string;
  tlsPosture: string;
  eolRuntimeInChain: string;
  exploitableCveId: string;
  targetDataOrServiceAsset: string;
  chainRiskScore: number;
  blastRadiusSeverity: 'CRITICAL' | 'HIGH' | 'MEDIUM' | 'LOW';
  aiMcpRemediationPrompt: string;
}

export interface InfrahubTechInsightsFacts {
  serviceKey: string;
  infrahubBranch: string;
  infrahubTemporalCommitAt: string;
  exposed_domain_count: number;
  non_compliant_ssl_count: number;
  eol_package_count: number;
  reachable_kev_cve_count: number;
  reachable_lateral_data_paths_count: number;
  attack_path_risk_score: number;
}

export interface TechInsightsScorecardCheck {
  checkId: string;
  checkName: string;
  factName: keyof Pick<
    InfrahubTechInsightsFacts,
    | 'exposed_domain_count'
    | 'non_compliant_ssl_count'
    | 'eol_package_count'
    | 'reachable_kev_cve_count'
    | 'reachable_lateral_data_paths_count'
    | 'attack_path_risk_score'
  >;
  operator: 'lessThanOrEqual' | 'equals';
  thresholdValue: number;
  actualValue: number;
  result: 'PASS' | 'FAIL';
  description: string;
  remediationGuidance: string;
}

export interface EntityAttackGraphScorecardReport {
  entityRef: string;
  serviceName: string;
  infrahubGraphQlQuery: string;
  infrahubDeepLinkUrl: string;
  infrahubMcpAgentUri: string;
  infrahubMcpPrompt: string;
  facts: InfrahubTechInsightsFacts;
  scorecardStatus: 'PASS' | 'WARN' | 'FAIL';
  passedChecksCount: number;
  totalChecksCount: number;
  scorecardChecks: TechInsightsScorecardCheck[];
  nodes: AttackGraphNode[];
  edges: AttackGraphEdge[];
  attackPaths: NHopAttackPathChain[];
}

export interface FleetAttackGraphSummary {
  totalServicesEvaluated: number;
  failingScorecardsCount: number;
  totalReachableKevCves: number;
  totalEolPackagesInPaths: number;
  highestRiskService: string;
  reports: EntityAttackGraphScorecardReport[];
}

export const INFRAHUB_GRAPHQL_FACTS_QUERY = `query TechInsightsFacts($serviceKey: String!) {
  service(key: $serviceKey) {
    key
    name
    exposedDomains {
      count
    }
    sslCertificates {
      nonCompliantCount
    }
    sbomPackages {
      eolCount
    }
    cveVulnerabilities {
      reachableKevCount
    }
    lateralDataPaths {
      reachableCount
    }
    attackPathRiskScore
  }
  attackGraphEdges(serviceKey: $serviceKey) {
    edgeId
    fromNodeId
    toNodeId
    edgeType
    protocolOrMechanism
    isExploitableReachable
    hopWeight
  }
}`;

export interface InfrahubServiceGraphSeed {
  facts: InfrahubTechInsightsFacts;
  nodes: AttackGraphNode[];
  edges: AttackGraphEdge[];
  attackPaths: NHopAttackPathChain[];
}

export const INFRAHUB_ATTACK_GRAPH_SEEDS: Record<string, InfrahubServiceGraphSeed> = {
  'aegis-backend': {
    facts: {
      serviceKey: 'aegis-backend',
      infrahubBranch: 'main',
      infrahubTemporalCommitAt: '2026-01-15T08:00:00Z',
      exposed_domain_count: 2,
      non_compliant_ssl_count: 1,
      eol_package_count: 2,
      reachable_kev_cve_count: 2,
      reachable_lateral_data_paths_count: 2,
      attack_path_risk_score: 92,
    },
    nodes: [
      {
        nodeId: 'aegis-backend-domain-1',
        nodeType: 'EXPOSED_HTTPS_DOMAIN',
        label: 'stg.backend.api.aegis.cloud.goog',
        taxonomyCategory: 'network.ingress',
        severity: 'MEDIUM',
        metadata: { domain: 'stg.backend.api.aegis.cloud.goog', environment: 'staging' },
      },
      {
        nodeId: 'aegis-backend-cert-1',
        nodeType: 'SSL_TLS_CERTIFICATE',
        label: 'TLS-1.2 Expiring Cert',
        taxonomyCategory: 'security.tls',
        severity: 'HIGH',
        metadata: { protocol: 'TLS-1.2', daysToExpiry: 14, issuer: 'GCP Managed' },
      },
      {
        nodeId: 'aegis-backend-pod-1',
        nodeType: 'COMPUTE_HOST_OR_POD',
        label: 'aegis-backend-pod',
        taxonomyCategory: 'compute.workload',
        severity: 'MEDIUM',
        metadata: { cluster: 'aegis-stg', namespace: 'backend', replicas: 3 },
      },
      {
        nodeId: 'aegis-backend-runtime-1',
        nodeType: 'EOL_RUNTIME_OR_OS',
        label: 'Node.js 18.20.8 (EOL)',
        taxonomyCategory: 'runtime.eol',
        severity: 'HIGH',
        metadata: { version: '18.20.8', eolDate: '2025-10-15', majorVersion: 18 },
      },
      {
        nodeId: 'aegis-backend-sbom-1',
        nodeType: 'SBOM_PACKAGE',
        label: 'OpenSSL 1.1.1w',
        taxonomyCategory: 'sbom.native',
        severity: 'HIGH',
        metadata: { packageName: 'openssl', version: '1.1.1w', eol: true },
      },
      {
        nodeId: 'aegis-backend-cve-1',
        nodeType: 'CVE_VULNERABILITY',
        label: 'CVE-2026-111497 (V8 RCE KEV)',
        taxonomyCategory: 'vulnerability.kev',
        severity: 'CRITICAL',
        metadata: { cveId: 'CVE-2026-111497', kevListed: true, cvssScore: 9.1 },
      },
      {
        nodeId: 'aegis-backend-db-1',
        nodeType: 'LATERAL_SERVICE_OR_DATA_STORE',
        label: 'aegis-db (PostgreSQL 16.2)',
        taxonomyCategory: 'data.store',
        severity: 'CRITICAL',
        metadata: { engine: 'PostgreSQL', version: '16.2', dataClass: 'pii' },
      },
    ],
    edges: [
      {
        edgeId: 'aegis-backend-edge-1',
        fromNodeId: 'aegis-backend-domain-1',
        toNodeId: 'aegis-backend-cert-1',
        edgeType: 'EXPOSES_INGRESS',
        protocolOrMechanism: 'HTTPS/443',
        isExploitableReachable: true,
        hopWeight: 1,
      },
      {
        edgeId: 'aegis-backend-edge-2',
        fromNodeId: 'aegis-backend-cert-1',
        toNodeId: 'aegis-backend-pod-1',
        edgeType: 'TERMINATES_TLS_WITH',
        protocolOrMechanism: 'TLS-1.2',
        isExploitableReachable: true,
        hopWeight: 1,
      },
      {
        edgeId: 'aegis-backend-edge-3',
        fromNodeId: 'aegis-backend-pod-1',
        toNodeId: 'aegis-backend-runtime-1',
        edgeType: 'EXECUTES_ON_RUNTIME',
        protocolOrMechanism: 'Node.js 18.20.8',
        isExploitableReachable: true,
        hopWeight: 1,
      },
      {
        edgeId: 'aegis-backend-edge-4',
        fromNodeId: 'aegis-backend-runtime-1',
        toNodeId: 'aegis-backend-sbom-1',
        edgeType: 'IMPORTS_SBOM_PACKAGE',
        protocolOrMechanism: 'native binding',
        isExploitableReachable: true,
        hopWeight: 1,
      },
      {
        edgeId: 'aegis-backend-edge-5',
        fromNodeId: 'aegis-backend-sbom-1',
        toNodeId: 'aegis-backend-cve-1',
        edgeType: 'AFFECTED_BY_CVE',
        protocolOrMechanism: 'V8 RCE',
        isExploitableReachable: true,
        hopWeight: 1,
      },
      {
        edgeId: 'aegis-backend-edge-6',
        fromNodeId: 'aegis-backend-cve-1',
        toNodeId: 'aegis-backend-db-1',
        edgeType: 'REACHABLE_HOT_PATH_TO',
        protocolOrMechanism: 'lateral data path',
        isExploitableReachable: true,
        hopWeight: 1,
      },
    ],
    attackPaths: [
      {
        pathId: 'aegis-backend-path-1',
        title: '5-hop CRITICAL: stg.backend.api.aegis.cloud.goog to aegis-db via V8 RCE KEV',
        hopCount: 5,
        orderedNodeIds: [
          'aegis-backend-domain-1',
          'aegis-backend-pod-1',
          'aegis-backend-runtime-1',
          'aegis-backend-sbom-1',
          'aegis-backend-cve-1',
          'aegis-backend-db-1',
        ],
        orderedEdgeTypes: [
          'ROUTES_TO_WORKLOAD',
          'EXECUTES_ON_RUNTIME',
          'IMPORTS_SBOM_PACKAGE',
          'AFFECTED_BY_CVE',
          'REACHABLE_HOT_PATH_TO',
        ],
        entryDomain: 'stg.backend.api.aegis.cloud.goog',
        tlsPosture: 'TLS-1.2 Expiring',
        eolRuntimeInChain: 'Node.js 18.20.8',
        exploitableCveId: 'CVE-2026-111497',
        targetDataOrServiceAsset: 'aegis-db (PostgreSQL 16.2)',
        chainRiskScore: 92,
        blastRadiusSeverity: 'CRITICAL',
        aiMcpRemediationPrompt:
          'Upgrade Node.js runtime from 18.20.8 to 20.x LTS and patch OpenSSL to 1.1.1w+ to eliminate V8 RCE KEV exposure on aegis-backend.',
      },
    ],
  },
  'aegis-ui': {
    facts: {
      serviceKey: 'aegis-ui',
      infrahubBranch: 'main',
      infrahubTemporalCommitAt: '2026-01-15T08:00:00Z',
      exposed_domain_count: 3,
      non_compliant_ssl_count: 1,
      eol_package_count: 0,
      reachable_kev_cve_count: 0,
      reachable_lateral_data_paths_count: 1,
      attack_path_risk_score: 48,
    },
    nodes: [
      {
        nodeId: 'aegis-ui-domain-1',
        nodeType: 'EXPOSED_HTTPS_DOMAIN',
        label: 'stg.ui.aegis.cloud.goog',
        taxonomyCategory: 'network.ingress',
        severity: 'MEDIUM',
        metadata: { domain: 'stg.ui.aegis.cloud.goog', environment: 'staging' },
      },
      {
        nodeId: 'aegis-ui-cert-1',
        nodeType: 'SSL_TLS_CERTIFICATE',
        label: 'TLS-1.3 Valid Cert',
        taxonomyCategory: 'security.tls',
        severity: 'HEALTHY',
        metadata: { protocol: 'TLS-1.3', daysToExpiry: 210, issuer: 'GCP Managed' },
      },
      {
        nodeId: 'aegis-ui-pod-1',
        nodeType: 'COMPUTE_HOST_OR_POD',
        label: 'aegis-ui-pod',
        taxonomyCategory: 'compute.workload',
        severity: 'HEALTHY',
        metadata: { cluster: 'aegis-stg', namespace: 'frontend', replicas: 2 },
      },
      {
        nodeId: 'aegis-ui-sbom-1',
        nodeType: 'SBOM_PACKAGE',
        label: 'React 18.2.0',
        taxonomyCategory: 'sbom.javascript',
        severity: 'HEALTHY',
        metadata: { packageName: 'react', version: '18.2.0', eol: false },
      },
      {
        nodeId: 'aegis-ui-cdn-1',
        nodeType: 'LATERAL_SERVICE_OR_DATA_STORE',
        label: 'aegis-cdn (CloudFront)',
        taxonomyCategory: 'data.cdn',
        severity: 'MEDIUM',
        metadata: {
          provider: 'CloudFront',
          distribution: 'aegis-ui-dist',
          dataClass: 'static-assets',
        },
      },
    ],
    edges: [
      {
        edgeId: 'aegis-ui-edge-1',
        fromNodeId: 'aegis-ui-domain-1',
        toNodeId: 'aegis-ui-cert-1',
        edgeType: 'EXPOSES_INGRESS',
        protocolOrMechanism: 'HTTPS/443',
        isExploitableReachable: true,
        hopWeight: 1,
      },
      {
        edgeId: 'aegis-ui-edge-2',
        fromNodeId: 'aegis-ui-cert-1',
        toNodeId: 'aegis-ui-pod-1',
        edgeType: 'TERMINATES_TLS_WITH',
        protocolOrMechanism: 'TLS-1.3',
        isExploitableReachable: true,
        hopWeight: 1,
      },
      {
        edgeId: 'aegis-ui-edge-3',
        fromNodeId: 'aegis-ui-pod-1',
        toNodeId: 'aegis-ui-sbom-1',
        edgeType: 'IMPORTS_SBOM_PACKAGE',
        protocolOrMechanism: 'npm dependency',
        isExploitableReachable: true,
        hopWeight: 1,
      },
      {
        edgeId: 'aegis-ui-edge-4',
        fromNodeId: 'aegis-ui-sbom-1',
        toNodeId: 'aegis-ui-cdn-1',
        edgeType: 'REACHABLE_HOT_PATH_TO',
        protocolOrMechanism: 'asset delivery path',
        isExploitableReachable: true,
        hopWeight: 1,
      },
    ],
    attackPaths: [
      {
        pathId: 'aegis-ui-path-1',
        title: '4-hop MEDIUM: stg.ui.aegis.cloud.goog to aegis-cdn via asset delivery',
        hopCount: 4,
        orderedNodeIds: [
          'aegis-ui-domain-1',
          'aegis-ui-cert-1',
          'aegis-ui-pod-1',
          'aegis-ui-sbom-1',
          'aegis-ui-cdn-1',
        ],
        orderedEdgeTypes: [
          'EXPOSES_INGRESS',
          'TERMINATES_TLS_WITH',
          'IMPORTS_SBOM_PACKAGE',
          'REACHABLE_HOT_PATH_TO',
        ],
        entryDomain: 'stg.ui.aegis.cloud.goog',
        tlsPosture: 'TLS-1.3 Valid',
        eolRuntimeInChain: 'none',
        exploitableCveId: 'none',
        targetDataOrServiceAsset: 'aegis-cdn (CloudFront)',
        chainRiskScore: 48,
        blastRadiusSeverity: 'MEDIUM',
        aiMcpRemediationPrompt:
          'Review CloudFront distribution configuration for aegis-ui to ensure asset integrity and minimize lateral exposure surface.',
      },
    ],
  },
  'aegis-auth': {
    facts: {
      serviceKey: 'aegis-auth',
      infrahubBranch: 'main',
      infrahubTemporalCommitAt: '2026-01-15T08:00:00Z',
      exposed_domain_count: 1,
      non_compliant_ssl_count: 0,
      eol_package_count: 0,
      reachable_kev_cve_count: 1,
      reachable_lateral_data_paths_count: 1,
      attack_path_risk_score: 68,
    },
    nodes: [
      {
        nodeId: 'aegis-auth-domain-1',
        nodeType: 'EXPOSED_HTTPS_DOMAIN',
        label: 'auth.aegis.cloud.goog',
        taxonomyCategory: 'network.ingress',
        severity: 'MEDIUM',
        metadata: { domain: 'auth.aegis.cloud.goog', environment: 'production' },
      },
      {
        nodeId: 'aegis-auth-runtime-1',
        nodeType: 'EOL_RUNTIME_OR_OS',
        label: 'Node.js 20.11.0',
        taxonomyCategory: 'runtime.eol',
        severity: 'HIGH',
        metadata: { version: '20.11.0', eolDate: '2026-04-30', majorVersion: 20 },
      },
      {
        nodeId: 'aegis-auth-cve-1',
        nodeType: 'CVE_VULNERABILITY',
        label: 'CVE-2026-111497',
        taxonomyCategory: 'vulnerability.kev',
        severity: 'CRITICAL',
        metadata: { cveId: 'CVE-2026-111497', kevListed: true, cvssScore: 9.1 },
      },
      {
        nodeId: 'aegis-auth-lateral-1',
        nodeType: 'LATERAL_SERVICE_OR_DATA_STORE',
        label: 'gce-auth-redis-ephemeral-02',
        taxonomyCategory: 'data.store',
        severity: 'HIGH',
        metadata: { engine: 'Redis', version: '7.2', dataClass: 'session-tokens' },
      },
    ],
    edges: [
      {
        edgeId: 'aegis-auth-edge-1',
        fromNodeId: 'aegis-auth-domain-1',
        toNodeId: 'aegis-auth-runtime-1',
        edgeType: 'EXECUTES_ON_RUNTIME',
        protocolOrMechanism: 'Node.js 20.11.0',
        isExploitableReachable: true,
        hopWeight: 1,
      },
      {
        edgeId: 'aegis-auth-edge-2',
        fromNodeId: 'aegis-auth-runtime-1',
        toNodeId: 'aegis-auth-cve-1',
        edgeType: 'AFFECTED_BY_CVE',
        protocolOrMechanism: 'V8 RCE',
        isExploitableReachable: true,
        hopWeight: 1,
      },
      {
        edgeId: 'aegis-auth-edge-3',
        fromNodeId: 'aegis-auth-cve-1',
        toNodeId: 'aegis-auth-lateral-1',
        edgeType: 'REACHABLE_HOT_PATH_TO',
        protocolOrMechanism: 'lateral data path',
        isExploitableReachable: true,
        hopWeight: 1,
      },
    ],
    attackPaths: [
      {
        pathId: 'aegis-auth-path-1',
        title: '3-hop HIGH: auth.aegis.cloud.goog to gce-auth-redis-ephemeral-02 via V8 RCE KEV',
        hopCount: 3,
        orderedNodeIds: [
          'aegis-auth-domain-1',
          'aegis-auth-runtime-1',
          'aegis-auth-cve-1',
          'aegis-auth-lateral-1',
        ],
        orderedEdgeTypes: [
          'EXECUTES_ON_RUNTIME',
          'AFFECTED_BY_CVE',
          'REACHABLE_HOT_PATH_TO',
        ],
        entryDomain: 'auth.aegis.cloud.goog',
        tlsPosture: 'TLS-1.3 Valid',
        eolRuntimeInChain: 'Node.js 20.11.0',
        exploitableCveId: 'CVE-2026-111497',
        targetDataOrServiceAsset: 'gce-auth-redis-ephemeral-02',
        chainRiskScore: 68,
        blastRadiusSeverity: 'HIGH',
        aiMcpRemediationPrompt:
          'Upgrade Node.js runtime from 20.11.0 to 22.x LTS and patch V8 to eliminate CVE-2026-111497 KEV exposure on aegis-auth.',
      },
    ],
  },
  'aegis-db': {
    facts: {
      serviceKey: 'aegis-db',
      infrahubBranch: 'main',
      infrahubTemporalCommitAt: '2026-01-15T08:00:00Z',
      exposed_domain_count: 0,
      non_compliant_ssl_count: 0,
      eol_package_count: 0,
      reachable_kev_cve_count: 0,
      reachable_lateral_data_paths_count: 0,
      attack_path_risk_score: 12,
    },
    nodes: [
      {
        nodeId: 'aegis-db-pod-1',
        nodeType: 'COMPUTE_HOST_OR_POD',
        label: 'aegis-db-pod',
        taxonomyCategory: 'compute.workload',
        severity: 'HEALTHY',
        metadata: { cluster: 'aegis-prod', namespace: 'data', replicas: 2 },
      },
      {
        nodeId: 'aegis-db-store-1',
        nodeType: 'LATERAL_SERVICE_OR_DATA_STORE',
        label: 'PostgreSQL 16.2',
        taxonomyCategory: 'data.store',
        severity: 'HEALTHY',
        metadata: { engine: 'PostgreSQL', version: '16.2', dataClass: 'pii' },
      },
    ],
    edges: [
      {
        edgeId: 'aegis-db-edge-1',
        fromNodeId: 'aegis-db-pod-1',
        toNodeId: 'aegis-db-store-1',
        edgeType: 'LATERAL_MOVEMENT_TO_DATA',
        protocolOrMechanism: 'TCP/5432',
        isExploitableReachable: false,
        hopWeight: 1,
      },
    ],
    attackPaths: [],
  },
  'hello-world-app': {
    facts: {
      serviceKey: 'hello-world-app',
      infrahubBranch: 'main',
      infrahubTemporalCommitAt: '2026-01-15T08:00:00Z',
      exposed_domain_count: 1,
      non_compliant_ssl_count: 0,
      eol_package_count: 0,
      reachable_kev_cve_count: 0,
      reachable_lateral_data_paths_count: 0,
      attack_path_risk_score: 15,
    },
    nodes: [
      {
        nodeId: 'hello-world-domain-1',
        nodeType: 'EXPOSED_HTTPS_DOMAIN',
        label: 'hello.aegis.cloud.goog',
        taxonomyCategory: 'network.ingress',
        severity: 'HEALTHY',
        metadata: { domain: 'hello.aegis.cloud.goog', environment: 'production' },
      },
      {
        nodeId: 'hello-world-cert-1',
        nodeType: 'SSL_TLS_CERTIFICATE',
        label: 'HAProxy 3.0 TLS 1.3',
        taxonomyCategory: 'security.tls',
        severity: 'HEALTHY',
        metadata: { protocol: 'TLS-1.3', daysToExpiry: 300, issuer: 'GCP Managed' },
      },
      {
        nodeId: 'hello-world-runtime-1',
        nodeType: 'SBOM_PACKAGE',
        label: 'Node.js 22.15.0',
        taxonomyCategory: 'runtime.current',
        severity: 'HEALTHY',
        metadata: { version: '22.15.0', eol: false, majorVersion: 22 },
      },
    ],
    edges: [
      {
        edgeId: 'hello-world-edge-1',
        fromNodeId: 'hello-world-domain-1',
        toNodeId: 'hello-world-cert-1',
        edgeType: 'EXPOSES_INGRESS',
        protocolOrMechanism: 'HTTPS/443',
        isExploitableReachable: true,
        hopWeight: 1,
      },
      {
        edgeId: 'hello-world-edge-2',
        fromNodeId: 'hello-world-cert-1',
        toNodeId: 'hello-world-runtime-1',
        edgeType: 'TERMINATES_TLS_WITH',
        protocolOrMechanism: 'TLS-1.3',
        isExploitableReachable: true,
        hopWeight: 1,
      },
    ],
    attackPaths: [
      {
        pathId: 'hello-world-path-1',
        title: '2-hop LOW: hello.aegis.cloud.goog to Node.js 22.15.0 via HAProxy TLS termination',
        hopCount: 2,
        orderedNodeIds: [
          'hello-world-domain-1',
          'hello-world-cert-1',
          'hello-world-runtime-1',
        ],
        orderedEdgeTypes: [
          'EXPOSES_INGRESS',
          'TERMINATES_TLS_WITH',
        ],
        entryDomain: 'hello.aegis.cloud.goog',
        tlsPosture: 'TLS-1.3 Valid',
        eolRuntimeInChain: 'none',
        exploitableCveId: 'none',
        targetDataOrServiceAsset: 'Node.js 22.15.0',
        chainRiskScore: 15,
        blastRadiusSeverity: 'LOW',
        aiMcpRemediationPrompt:
          'No action required. hello-world-app is healthy with valid TLS-1.3 and current Node.js runtime.',
      },
    ],
  },
};

const INFRAHUB_SIMULATION_OVERRIDES = new Map<string, InfrahubServiceGraphSeed>();

export function resetInfrahubSimulationState(): void {
  INFRAHUB_SIMULATION_OVERRIDES.clear();
}

export function resolveInfrahubServiceKey(entityOrRef: string): string {
  const raw = entityOrRef.split('/').pop()?.split(':').pop() || 'aegis-backend';
  const mapped = raw === 'haproxy-hello-world-tls' ? 'hello-world-app' : raw;
  return INFRAHUB_ATTACK_GRAPH_SEEDS[mapped] ? mapped : 'aegis-backend';
}

export async function executeInfrahubGraphQlFactsQuery(
  serviceKey: string
): Promise<InfrahubServiceGraphSeed> {
  const seed =
    INFRAHUB_SIMULATION_OVERRIDES.get(serviceKey) || INFRAHUB_ATTACK_GRAPH_SEEDS[serviceKey];
  return JSON.parse(JSON.stringify(seed));
}

export async function retrieveInfrahubTechInsightsFacts(
  entityOrRef: string
): Promise<InfrahubTechInsightsFacts> {
  const key = resolveInfrahubServiceKey(entityOrRef);
  const seed = await executeInfrahubGraphQlFactsQuery(key);
  return seed.facts;
}

export function evaluateTechInsightsScorecardChecks(
  facts: InfrahubTechInsightsFacts
): TechInsightsScorecardCheck[] {
  return [
    {
      checkId: 'ssl-tls-compliance',
      checkName: 'SSL/TLS Compliance',
      factName: 'non_compliant_ssl_count',
      operator: 'equals',
      thresholdValue: 0,
      actualValue: facts.non_compliant_ssl_count,
      result: facts.non_compliant_ssl_count === 0 ? 'PASS' : 'FAIL',
      description: 'All SSL/TLS certificates must be compliant.',
      remediationGuidance: 'Rotate or renew non-compliant SSL/TLS certificates.',
    },
    {
      checkId: 'eol-runtime-hygiene',
      checkName: 'EOL Runtime Hygiene',
      factName: 'eol_package_count',
      operator: 'equals',
      thresholdValue: 0,
      actualValue: facts.eol_package_count,
      result: facts.eol_package_count === 0 ? 'PASS' : 'FAIL',
      description: 'No end-of-life packages should be present in the dependency graph.',
      remediationGuidance: 'Upgrade EOL runtimes and packages to supported versions.',
    },
    {
      checkId: 'zero-reachable-kev-cves',
      checkName: 'Zero Reachable KEV CVEs',
      factName: 'reachable_kev_cve_count',
      operator: 'equals',
      thresholdValue: 0,
      actualValue: facts.reachable_kev_cve_count,
      result: facts.reachable_kev_cve_count === 0 ? 'PASS' : 'FAIL',
      description: 'No reachable Known Exploited Vulnerabilities should exist.',
      remediationGuidance: 'Patch all reachable KEV-listed CVEs.',
    },
    {
      checkId: 'lateral-data-path-isolation',
      checkName: 'Lateral Data Path Isolation',
      factName: 'reachable_lateral_data_paths_count',
      operator: 'lessThanOrEqual',
      thresholdValue: 1,
      actualValue: facts.reachable_lateral_data_paths_count,
      result: facts.reachable_lateral_data_paths_count <= 1 ? 'PASS' : 'FAIL',
      description: 'Reachable lateral data paths must be at most 1.',
      remediationGuidance: 'Isolate or remove excess lateral data paths.',
    },
    {
      checkId: 'exposed-domain-surface',
      checkName: 'Exposed Domain Surface',
      factName: 'exposed_domain_count',
      operator: 'lessThanOrEqual',
      thresholdValue: 3,
      actualValue: facts.exposed_domain_count,
      result: facts.exposed_domain_count <= 3 ? 'PASS' : 'FAIL',
      description: 'Exposed domain count must not exceed 3.',
      remediationGuidance: 'Reduce exposed domain surface by consolidating or removing unused domains.',
    },
    {
      checkId: 'attack-path-risk-ceiling',
      checkName: 'Attack Path Risk Ceiling',
      factName: 'attack_path_risk_score',
      operator: 'lessThanOrEqual',
      thresholdValue: 45,
      actualValue: facts.attack_path_risk_score,
      result: facts.attack_path_risk_score <= 45 ? 'PASS' : 'FAIL',
      description: 'Attack path risk score must not exceed 45.',
      remediationGuidance: 'Reduce attack path risk by remediating contributing factors.',
    },
  ];
}

export async function getEntityAttackGraphScorecard(
  entityOrRef: string
): Promise<EntityAttackGraphScorecardReport> {
  const key = resolveInfrahubServiceKey(entityOrRef);
  const seed = await executeInfrahubGraphQlFactsQuery(key);
  const checks = evaluateTechInsightsScorecardChecks(seed.facts);
  const passedChecksCount = checks.filter((c) => c.result === 'PASS').length;
  const totalChecksCount = checks.length;

  let scorecardStatus: 'PASS' | 'WARN' | 'FAIL';
  if (passedChecksCount === totalChecksCount) {
    scorecardStatus = 'PASS';
  } else if (
    seed.facts.reachable_kev_cve_count > 0 ||
    seed.facts.attack_path_risk_score > 65
  ) {
    scorecardStatus = 'FAIL';
  } else {
    scorecardStatus = 'WARN';
  }

  return {
    entityRef: entityOrRef,
    serviceName: key,
    infrahubGraphQlQuery: INFRAHUB_GRAPHQL_FACTS_QUERY,
    infrahubDeepLinkUrl: `https://infrahub.example.com/services/${key}`,
    infrahubMcpAgentUri: `mcp://infrahub/agents/${key}`,
    infrahubMcpPrompt: `Analyze attack graph for ${key} and recommend remediation.`,
    facts: seed.facts,
    scorecardStatus,
    passedChecksCount,
    totalChecksCount,
    scorecardChecks: checks,
    nodes: seed.nodes,
    edges: seed.edges,
    attackPaths: seed.attackPaths,
  };
}

export async function simulateInfrahubWhatIfRemediation(
  entityOrRef: string,
  action: 'rotate-ssl' | 'upgrade-eol-runtime' | 'patch-kev-cve' | 'isolate-lateral-path'
): Promise<EntityAttackGraphScorecardReport> {
  const key = resolveInfrahubServiceKey(entityOrRef);
  const currentSeed =
    INFRAHUB_SIMULATION_OVERRIDES.get(key) || INFRAHUB_ATTACK_GRAPH_SEEDS[key];
  const clonedSeed: InfrahubServiceGraphSeed = JSON.parse(JSON.stringify(currentSeed));

  switch (action) {
    case 'rotate-ssl':
      clonedSeed.facts.non_compliant_ssl_count = 0;
      break;
    case 'upgrade-eol-runtime':
      clonedSeed.facts.eol_package_count = 0;
      break;
    case 'patch-kev-cve':
      clonedSeed.facts.reachable_kev_cve_count = 0;
      break;
    case 'isolate-lateral-path':
      clonedSeed.facts.reachable_lateral_data_paths_count = 0;
      break;
  }

  const facts = clonedSeed.facts;
  clonedSeed.facts.attack_path_risk_score = Math.min(
    100,
    facts.exposed_domain_count * 5 +
      facts.non_compliant_ssl_count * 15 +
      facts.eol_package_count * 15 +
      facts.reachable_kev_cve_count * 25 +
      facts.reachable_lateral_data_paths_count * 10
  );

  INFRAHUB_SIMULATION_OVERRIDES.set(key, clonedSeed);

  return getEntityAttackGraphScorecard(key);
}

export async function getFleetAttackGraphSummary(): Promise<FleetAttackGraphSummary> {
  const keys = Object.keys(INFRAHUB_ATTACK_GRAPH_SEEDS);
  const reports: EntityAttackGraphScorecardReport[] = [];

  for (const key of keys) {
    reports.push(await getEntityAttackGraphScorecard(key));
  }

  const failingScorecardsCount = reports.filter(
    (r) => r.scorecardStatus === 'FAIL'
  ).length;
  const totalReachableKevCves = reports.reduce(
    (sum, r) => sum + r.facts.reachable_kev_cve_count,
    0
  );
  const totalEolPackagesInPaths = reports.reduce(
    (sum, r) => sum + r.facts.eol_package_count,
    0
  );
  const highestRiskService = reports.reduce((max, r) =>
    r.facts.attack_path_risk_score >
    (reports.find((x) => x.serviceName === max)?.facts.attack_path_risk_score ?? 0)
      ? r.serviceName
      : max
  , reports[0]?.serviceName ?? '');

  return {
    totalServicesEvaluated: reports.length,
    failingScorecardsCount,
    totalReachableKevCves,
    totalEolPackagesInPaths,
    highestRiskService,
    reports,
  };
}

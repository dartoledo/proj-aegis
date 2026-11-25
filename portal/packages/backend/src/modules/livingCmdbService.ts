import {
  crossCheckSoftwareVersion,
  NormalizedSoftwareVersionRecord,
  VersionCrossCheckResult,
} from './softwareVersionNormalizerService';
import { queryEntityCmdbSnapshotFromPostgres, queryFleetCmdbTopologyFromPostgres } from './aegisPostgresStore';

export type DriftCategory = 'EXPOSURE_DRIFT' | 'IMMUTABILITY_DRIFT' | 'CAPACITY_DRIFT' | 'SHADOW_RESOURCE';
export type DriftSeverity = 'CRITICAL' | 'HIGH' | 'MEDIUM' | 'LOW';
export type TaxonomyDomain = 'INFRASTRUCTURE' | 'SOFTWARE';
export type InfrastructureLayerId =
  | 'EDGE_EXTERNAL_SECURITY'
  | 'INGRESS_TRAFFIC_ROUTING'
  | 'CLOUD_GOVERNANCE_BOUNDARIES'
  | 'ORCHESTRATION_COMPUTE_UNITS'
  | 'DEDICATED_HOSTS_TRADITIONAL_COMPUTE'
  | 'DATA_CACHE_STATE'
  | 'OBSERVABILITY_TELEMETRY_PLATFORM';
export type InfrastructureComponentType =
  | 'DOMAIN_ENDPOINT'
  | 'WAF_EDGE_PROTECTION'
  | 'CDN'
  | 'LOAD_BALANCER'
  | 'INGRESS_CONTROLLER'
  | 'SERVICE_MESH'
  | 'GCP_PROJECT_CLOUD_ACCOUNT'
  | 'IAM_SECRETS_MANAGEMENT'
  | 'NAMESPACE'
  | 'K8S_CLUSTER'
  | 'K8S_DEPLOYMENT'
  | 'POD'
  | 'CONTAINER'
  | 'VM_SERVER'
  | 'BAREMETAL_SERVER'
  | 'BATCH_SERVER_EVENT_WORKERS'
  | 'DATABASE_INFRA_INSTANCE'
  | 'DISTRIBUTED_CACHE'
  | 'OBJECT_STORAGE'
  | 'METRICS_LOGGING_ENGINES';
export type SoftwareComponentCategory =
  | 'OPERATING_SYSTEM'
  | 'PLATFORM_RUNTIME_ENVIRONMENT'
  | 'LIBRARY_FRAMEWORK'
  | 'SECURITY_IDENTITY_SOFTWARE'
  | 'MIDDLEWARE_INTEGRATION_SOFTWARE'
  | 'DATA_ACCESS_ORM'
  | 'CONFIGURATION_FEATURE_FLAG_SOFTWARE'
  | 'APPLICATION_CORE'
  | 'OBSERVABILITY_SOFTWARE'
  | 'EXTERNAL_API'
  | 'TESTING_SOFTWARE'
  | 'CONTAINERIZATION_SOFTWARE'
  | 'DEVELOPMENT_TOOLS_SCM';

export type TeamOwnerId = 'app-team' | 'sre-team';

export interface TeamOwnerRecord {
  teamId: TeamOwnerId;
  teamName: 'App Team' | 'SRE Team';
  email: string;
  slackChannel: string;
  responsibilityScope: string;
}

export const AEGIS_TEAM_OWNERS_TABLE: TeamOwnerRecord[] = [
  { teamId: 'app-team', teamName: 'App Team', email: 'app-team@aegis.idp', slackChannel: '#aegis-app-team', responsibilityScope: 'Application software components including runtimes, frameworks, business logic, and development tooling' },
  { teamId: 'sre-team', teamName: 'SRE Team', email: 'sre-team@aegis.idp', slackChannel: '#aegis-sre-team', responsibilityScope: 'All infrastructure components, operating systems, and containerization software' },
];

export function resolveComponentOwnerTeam(
  domain: TaxonomyDomain,
  categoryType: InfrastructureComponentType | SoftwareComponentCategory
): TeamOwnerRecord {
  if (domain === 'INFRASTRUCTURE' || categoryType === 'OPERATING_SYSTEM' || categoryType === 'CONTAINERIZATION_SOFTWARE') {
    return AEGIS_TEAM_OWNERS_TABLE[1];
  }
  return AEGIS_TEAM_OWNERS_TABLE[0];
}

export interface ComponentTaxonomyCategoryMeta {
  id: InfrastructureComponentType | SoftwareComponentCategory;
  domain: TaxonomyDomain;
  layerId?: InfrastructureLayerId;
  layerOrder?: number;
  layerLabel?: string;
  icon: string;
  label: string;
  definition: string;
  examples: string[];
  defaultOwnerTeamId?: TeamOwnerId;
}

export interface CmdbComponentNode {
  componentId: string;
  name: string;
  versionOrIdentifier: string;
  domain: TaxonomyDomain;
  layerId?: InfrastructureLayerId;
  layerLabel?: string;
  categoryType: InfrastructureComponentType | SoftwareComponentCategory;
  categoryLabel: string;
  icon: string;
  status: 'HEALTHY' | 'DRIFTED' | 'WARNING' | 'CRITICAL';
  notes?: string;
  normalizedVersion?: NormalizedSoftwareVersionRecord;
  versionCrossCheck?: VersionCrossCheckResult;
  ownerTeamId?: TeamOwnerId;
  ownerTeamName?: 'App Team' | 'SRE Team';
}

export const AEGIS_COMPONENT_TAXONOMY_CATALOG: ComponentTaxonomyCategoryMeta[] = [
  { id: 'DOMAIN_ENDPOINT', domain: 'INFRASTRUCTURE', layerId: 'EDGE_EXTERNAL_SECURITY', layerOrder: 1, layerLabel: 'Edge & External Security', icon: '🌐', label: 'Domain Endpoint', definition: 'A publicly resolvable DNS hostname or FQDN that serves as the external entry point for a service or application.', examples: ['api.aegis.cloud.goog', 'stg.backend.api.aegis.cloud.goog', 'cdn.aegis.cloud.goog'] },
  { id: 'WAF_EDGE_PROTECTION', domain: 'INFRASTRUCTURE', layerId: 'EDGE_EXTERNAL_SECURITY', layerOrder: 1, layerLabel: 'Edge & External Security', icon: '🛡️', label: 'WAF Edge Protection', definition: 'A Web Application Firewall deployed at the network edge to inspect and filter HTTP/HTTPS traffic before it reaches origin servers.', examples: ['GCP Cloud WAF', 'AWS WAF', 'Cloudflare WAF'] },
  { id: 'CDN', domain: 'INFRASTRUCTURE', layerId: 'EDGE_EXTERNAL_SECURITY', layerOrder: 1, layerLabel: 'Edge & External Security', icon: '🚀', label: 'Content Delivery Network', definition: 'A distributed network of edge caches that deliver static and dynamic content to end-users with low latency.', examples: ['GCP Cloud CDN', 'Cloudflare CDN', 'Fastly'] },
  { id: 'LOAD_BALANCER', domain: 'INFRASTRUCTURE', layerId: 'INGRESS_TRAFFIC_ROUTING', layerOrder: 2, layerLabel: 'Ingress & Traffic Routing', icon: '🔀', label: 'Load Balancer', definition: 'A network device or service that distributes inbound traffic across multiple backend targets to ensure no single target is overwhelmed.', examples: ['GCP Global External LB', 'HAProxy', 'NGINX Load Balancer'] },
  { id: 'INGRESS_CONTROLLER', domain: 'INFRASTRUCTURE', layerId: 'INGRESS_TRAFFIC_ROUTING', layerOrder: 2, layerLabel: 'Ingress & Traffic Routing', icon: '🚪', label: 'Ingress Controller', definition: 'A Kubernetes controller that manages external HTTP(S) access to services within the cluster via Ingress resources.', examples: ['NGINX Ingress Controller', 'GKE Ingress', 'Traefik Ingress'] },
  { id: 'SERVICE_MESH', domain: 'INFRASTRUCTURE', layerId: 'INGRESS_TRAFFIC_ROUTING', layerOrder: 2, layerLabel: 'Ingress & Traffic Routing', icon: '🕸️', label: 'Service Mesh', definition: 'A dedicated infrastructure layer that handles service-to-service communication, providing observability, traffic management, and policy enforcement.', examples: ['Istio', 'Linkerd', 'Consul Connect'] },
  { id: 'GCP_PROJECT_CLOUD_ACCOUNT', domain: 'INFRASTRUCTURE', layerId: 'CLOUD_GOVERNANCE_BOUNDARIES', layerOrder: 3, layerLabel: 'Cloud Governance & Logical Boundaries', icon: '☁️', label: 'GCP Project / Cloud Account', definition: 'A top-level organizational boundary in a cloud provider that groups resources, enforces billing, and scopes IAM permissions.', examples: ['gcp-project-aegis-prod', 'gcp-project-aegis-staging', 'aws-account-123456789012'] },
  { id: 'IAM_SECRETS_MANAGEMENT', domain: 'INFRASTRUCTURE', layerId: 'CLOUD_GOVERNANCE_BOUNDARIES', layerOrder: 3, layerLabel: 'Cloud Governance & Logical Boundaries', icon: '🔒', label: 'IAM & Secrets Management', definition: 'The set of identity, access control, and secret storage systems that govern who can access what and protect sensitive credentials.', examples: ['GCP Cloud IAM', 'HashiCorp Vault', 'AWS Secrets Manager'] },
  { id: 'NAMESPACE', domain: 'INFRASTRUCTURE', layerId: 'CLOUD_GOVERNANCE_BOUNDARIES', layerOrder: 3, layerLabel: 'Cloud Governance & Logical Boundaries', icon: '🛡️', label: 'Namespace', definition: 'A logical partition within a cluster or platform that isolates resources, enforces quotas, and scopes RBAC policies.', examples: ['aegis-prod', 'aegis-staging', 'kube-system'] },
  { id: 'K8S_CLUSTER', domain: 'INFRASTRUCTURE', layerId: 'ORCHESTRATION_COMPUTE_UNITS', layerOrder: 4, layerLabel: 'Orchestration & Compute Units', icon: '☸️', label: 'Kubernetes Cluster', definition: 'A group of worker nodes and control-plane components managed as a single unit for deploying and orchestrating containerized workloads.', examples: ['gke-aegis-prod-us-central1', 'eks-aegis-staging'] },
  { id: 'K8S_DEPLOYMENT', domain: 'INFRASTRUCTURE', layerId: 'ORCHESTRATION_COMPUTE_UNITS', layerOrder: 4, layerLabel: 'Orchestration & Compute Units', icon: '📜', label: 'Kubernetes Deployment', definition: 'A declarative API object that manages a set of identical Pods and provides rolling updates, rollbacks, and replica management.', examples: ['aegis-backend-deployment', 'aegis-ui-deployment'] },
  { id: 'POD', domain: 'INFRASTRUCTURE', layerId: 'ORCHESTRATION_COMPUTE_UNITS', layerOrder: 4, layerLabel: 'Orchestration & Compute Units', icon: '🌱', label: 'Pod', definition: 'The smallest deployable unit in Kubernetes; one or more containers that share network and storage namespaces.', examples: ['aegis-backend-7d4f8c9b6-abc12', 'aegis-ui-5f6g7h8i9-def34'] },
  { id: 'CONTAINER', domain: 'INFRASTRUCTURE', layerId: 'ORCHESTRATION_COMPUTE_UNITS', layerOrder: 4, layerLabel: 'Orchestration & Compute Units', icon: '🐳', label: 'Container', definition: 'A lightweight, isolated runtime process packaged with its dependencies, running within a Pod or on a host.', examples: ['aegis-backend:sha256:3a7b91c4e2f8d056', 'aegis-ui:sha256:8f4e2c19a7b3d605'] },
  { id: 'VM_SERVER', domain: 'INFRASTRUCTURE', layerId: 'DEDICATED_HOSTS_TRADITIONAL_COMPUTE', layerOrder: 5, layerLabel: 'Dedicated Hosts & Traditional Compute', icon: '🖥️', label: 'VM Server', definition: 'A virtualized compute instance running a full operating system, provisioned from a cloud provider or on-premises hypervisor.', examples: ['gce-aegis-batch-worker-01', 'ec2-aegis-legacy-app'] },
  { id: 'BAREMETAL_SERVER', domain: 'INFRASTRUCTURE', layerId: 'DEDICATED_HOSTS_TRADITIONAL_COMPUTE', layerOrder: 5, layerLabel: 'Dedicated Hosts & Traditional Compute', icon: '🧱', label: 'Baremetal Server', definition: 'A physical compute node without virtualization overhead, often used for latency-sensitive or GPU-accelerated workloads.', examples: ['bm-aegis-gpu-node-01', 'bm-aegis-db-primary'] },
  { id: 'BATCH_SERVER_EVENT_WORKERS', domain: 'INFRASTRUCTURE', layerId: 'DEDICATED_HOSTS_TRADITIONAL_COMPUTE', layerOrder: 5, layerLabel: 'Dedicated Hosts & Traditional Compute', icon: '⏱️', label: 'Batch Server / Event Workers', definition: 'Dedicated compute instances or serverless functions that process asynchronous jobs, event streams, or scheduled batch workloads.', examples: ['aegis-event-processor', 'aegis-batch-etl-worker'] },
  { id: 'DATABASE_INFRA_INSTANCE', domain: 'INFRASTRUCTURE', layerId: 'DATA_CACHE_STATE', layerOrder: 6, layerLabel: 'Data, Cache & State', icon: '🗄️', label: 'Database Infrastructure Instance', definition: 'A managed or self-hosted relational, document, or NoSQL database engine instance that persists application state.', examples: ['CloudSQL aegis-prod-pg', 'MongoDB Atlas aegis-cluster'] },
  { id: 'DISTRIBUTED_CACHE', domain: 'INFRASTRUCTURE', layerId: 'DATA_CACHE_STATE', layerOrder: 6, layerLabel: 'Data, Cache & State', icon: '⚡', label: 'Distributed Cache', definition: 'An in-memory data store distributed across multiple nodes to provide sub-millisecond read/write latency for hot data.', examples: ['Redis Cluster aegis-cache', 'Memcached aegis-session'] },
  { id: 'OBJECT_STORAGE', domain: 'INFRASTRUCTURE', layerId: 'DATA_CACHE_STATE', layerOrder: 6, layerLabel: 'Data, Cache & State', icon: '📦', label: 'Object Storage', definition: 'A scalable, flat storage system that stores unstructured data as objects addressed by unique keys.', examples: ['GCS aegis-artifacts-bucket', 'S3 aegis-media-store'] },
  { id: 'METRICS_LOGGING_ENGINES', domain: 'INFRASTRUCTURE', layerId: 'OBSERVABILITY_TELEMETRY_PLATFORM', layerOrder: 7, layerLabel: 'Observability & Telemetry Platform', icon: '📊', label: 'Metrics & Logging Engines', definition: 'The collection of time-series databases, log aggregators, and tracing backends that power monitoring, alerting, and debugging.', examples: ['Prometheus + Grafana', 'GCP Cloud Logging', 'Jaeger Tracing'] },
  { id: 'OPERATING_SYSTEM', domain: 'SOFTWARE', icon: '💻', label: 'Operating System', definition: 'The core system software that manages hardware resources and provides a platform for running application software.', examples: ['Ubuntu 22.04 LTS', 'Alpine 3.19', 'Windows Server 2022'] },
  { id: 'PLATFORM_RUNTIME_ENVIRONMENT', domain: 'SOFTWARE', icon: '🚀', label: 'Platform Runtime Environment', definition: 'The language-specific runtime or virtual machine that executes application code (e.g., JVM, V8, .NET CLR).', examples: ['Node.js 20.x', 'OpenJDK 17', 'Python 3.12'] },
  { id: 'LIBRARY_FRAMEWORK', domain: 'SOFTWARE', icon: '📦', label: 'Library / Framework', definition: 'A reusable collection of code that provides abstractions, patterns, or utilities to accelerate application development.', examples: ['React 18', 'Spring Boot 3', 'Express.js 4'] },
  { id: 'SECURITY_IDENTITY_SOFTWARE', domain: 'SOFTWARE', icon: '🛡️', label: 'Security & Identity Software', definition: 'Software components responsible for authentication, authorization, token management, and identity federation.', examples: ['Keycloak', 'Auth0', 'aegis-auth service'] },
  { id: 'MIDDLEWARE_INTEGRATION_SOFTWARE', domain: 'SOFTWARE', icon: '🔄', label: 'Middleware / Integration Software', definition: 'Software that facilitates communication between disparate systems, protocols, or data formats (message brokers, ESBs, API gateways).', examples: ['Apache Kafka', 'RabbitMQ', 'Kong API Gateway'] },
  { id: 'DATA_ACCESS_ORM', domain: 'SOFTWARE', icon: '🗺️', label: 'Data Access / ORM', definition: 'Object-Relational Mapping or data access layer software that abstracts database interactions behind typed APIs.', examples: ['Prisma', 'TypeORM', 'Hibernate JPA'] },
  { id: 'CONFIGURATION_FEATURE_FLAG_SOFTWARE', domain: 'SOFTWARE', icon: '⚙️', label: 'Configuration & Feature Flag Software', definition: 'Systems that externalize application configuration and enable progressive delivery via feature flags and dynamic toggles.', examples: ['LaunchDarkly', 'Unleash', 'aegis-config-service'] },
  { id: 'APPLICATION_CORE', domain: 'SOFTWARE', icon: '🛠️', label: 'Application Core', definition: 'The primary business-logic codebase of a service or application, excluding infrastructure and platform concerns.', examples: ['aegis-backend core module', 'aegis-ui application shell'] },
  { id: 'OBSERVABILITY_SOFTWARE', domain: 'SOFTWARE', icon: '📊', label: 'Observability Software', definition: 'Agent, SDK, or library components embedded in applications to emit metrics, logs, and traces to the telemetry platform.', examples: ['OpenTelemetry SDK', 'Datadog Agent', 'Prometheus client_golang'] },
  { id: 'EXTERNAL_API', domain: 'SOFTWARE', icon: '🌐', label: 'External API', definition: 'A third-party or cross-organizational API endpoint consumed by the system for data retrieval or action execution.', examples: ['Stripe Payments API', 'Google Maps API', 'aegis-public-rest-api'] },
  { id: 'TESTING_SOFTWARE', domain: 'SOFTWARE', icon: '🧪', label: 'Testing Software', definition: 'Frameworks, tools, and infrastructure dedicated to automated testing including unit, integration, E2E, and load testing.', examples: ['Jest', 'Playwright', 'Gatling Load Tester'] },
  { id: 'CONTAINERIZATION_SOFTWARE', domain: 'SOFTWARE', icon: '🐳', label: 'Containerization Software', definition: 'Tools and runtimes used to build, package, and manage container images and their lifecycle.', examples: ['Docker Engine', 'containerd', 'BuildKit'] },
  { id: 'DEVELOPMENT_TOOLS_SCM', domain: 'SOFTWARE', icon: '🛠️', label: 'Development Tools & Source Control (SCM)', definition: 'The version-controlled storage, collaboration platforms, and metadata for tracking human-written source code.', examples: ['GitHub Repositories', 'GitLab Projects', 'Bitbucket Repos', 'Monorepos'] },
];

export function getComponentTaxonomyCatalog(): ComponentTaxonomyCategoryMeta[] {
  return AEGIS_COMPONENT_TAXONOMY_CATALOG.map(c => ({ ...c, defaultOwnerTeamId: resolveComponentOwnerTeam(c.domain, c.id).teamId }));
}

export interface CmdbDriftItem {
  driftId: string;
  category: DriftCategory;
  severity: DriftSeverity;
  fieldPath: string;
  gitDeclaredValue: string;
  liveObservedValue: string;
  detectedSource: string;
  detectedAt: string;
  status: 'ACTIVE_DRIFT';
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
  componentInventory?: CmdbComponentNode[];
}

export interface FleetCmdbTopologyReport {
  totalConfigurationItems: number;
  driftedServicesCount: number;
  totalActiveDrifts: number;
  shadowResourcesDetected: number;
  snapshots: EntityCmdbSnapshot[];
  directedEdges: Array<{ from: string; to: string; protocol: string }>;
  taxonomyCatalog?: ComponentTaxonomyCategoryMeta[];
  teamOwnersTable?: TeamOwnerRecord[];
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
    componentInventory: [
      { componentId: 'ui-domain-endpoint', name: 'ui.aegis.cloud.goog', versionOrIdentifier: 'FQDN', domain: 'INFRASTRUCTURE', layerId: 'EDGE_EXTERNAL_SECURITY', layerLabel: 'Edge & External Security', categoryType: 'DOMAIN_ENDPOINT', categoryLabel: 'Domain Endpoint', icon: '🌐', status: 'HEALTHY' },
      { componentId: 'ui-waf-edge', name: 'Cloud Armor Edge Policy', versionOrIdentifier: 'policy-v3', domain: 'INFRASTRUCTURE', layerId: 'EDGE_EXTERNAL_SECURITY', layerLabel: 'Edge & External Security', categoryType: 'WAF_EDGE_PROTECTION', categoryLabel: 'WAF Edge Protection', icon: '🛡️', status: 'HEALTHY' },
      { componentId: 'ui-cdn', name: 'GCP Cloud CDN (DRIFTED TTL)', versionOrIdentifier: 'maxTtl=300s (declared 3600s)', domain: 'INFRASTRUCTURE', layerId: 'EDGE_EXTERNAL_SECURITY', layerLabel: 'Edge & External Security', categoryType: 'CDN', categoryLabel: 'Content Delivery Network', icon: '🚀', status: 'DRIFTED', notes: 'Live TTL is 300s but Git declares 3600s' },
      { componentId: 'ui-load-balancer', name: 'GCP HTTPS Load Balancer', versionOrIdentifier: 'global-external-lb-v2', domain: 'INFRASTRUCTURE', layerId: 'INGRESS_TRAFFIC_ROUTING', layerLabel: 'Ingress & Traffic Routing', categoryType: 'LOAD_BALANCER', categoryLabel: 'Load Balancer', icon: '🔀', status: 'HEALTHY' },
      { componentId: 'ui-k8s-cluster', name: 'gke-aegis-prod', versionOrIdentifier: 'GKE 1.29', domain: 'INFRASTRUCTURE', layerId: 'ORCHESTRATION_COMPUTE_UNITS', layerLabel: 'Orchestration & Compute Units', categoryType: 'K8S_CLUSTER', categoryLabel: 'Kubernetes Cluster', icon: '☸️', status: 'HEALTHY' },
      { componentId: 'ui-k8s-deployment', name: 'aegis-ui-deployment', versionOrIdentifier: 'replicas=3', domain: 'INFRASTRUCTURE', layerId: 'ORCHESTRATION_COMPUTE_UNITS', layerLabel: 'Orchestration & Compute Units', categoryType: 'K8S_DEPLOYMENT', categoryLabel: 'Kubernetes Deployment', icon: '📜', status: 'HEALTHY' },
      { componentId: 'ui-metrics-logging', name: 'Prometheus / Cloud Logging', versionOrIdentifier: 'prometheus-2.51', domain: 'INFRASTRUCTURE', layerId: 'OBSERVABILITY_TELEMETRY_PLATFORM', layerLabel: 'Observability & Telemetry Platform', categoryType: 'METRICS_LOGGING_ENGINES', categoryLabel: 'Metrics & Logging Engines', icon: '📊', status: 'HEALTHY' },
      { componentId: 'ui-os', name: 'Alpine Linux 3.20', versionOrIdentifier: '3.20.0', domain: 'SOFTWARE', categoryType: 'OPERATING_SYSTEM', categoryLabel: 'Operating System', icon: '💻', status: 'HEALTHY' },
      { componentId: 'ui-runtime', name: 'Node.js 22.15.0', versionOrIdentifier: 'v22.15.0', domain: 'SOFTWARE', categoryType: 'PLATFORM_RUNTIME_ENVIRONMENT', categoryLabel: 'Platform Runtime Environment', icon: '🚀', status: 'HEALTHY' },
      { componentId: 'ui-framework', name: 'React 18.3.1 / Backstage 1.34', versionOrIdentifier: 'react@18.3.1 backstage@1.34.0', domain: 'SOFTWARE', categoryType: 'LIBRARY_FRAMEWORK', categoryLabel: 'Library / Framework', icon: '📦', status: 'HEALTHY' },
      { componentId: 'ui-feature-flags', name: 'LaunchDarkly SDK', versionOrIdentifier: 'ldclient-js@8.2.0', domain: 'SOFTWARE', categoryType: 'CONFIGURATION_FEATURE_FLAG_SOFTWARE', categoryLabel: 'Configuration & Feature Flag Software', icon: '⚙️', status: 'HEALTHY' },
      { componentId: 'ui-app-core', name: 'Aegis Portal Frontend Core', versionOrIdentifier: 'v2.14.0', domain: 'SOFTWARE', categoryType: 'APPLICATION_CORE', categoryLabel: 'Application Core', icon: '🛠️', status: 'HEALTHY' },
      { componentId: 'ui-containerization', name: 'OCI Image sha256:8f4e2c19a7b3d605', versionOrIdentifier: 'sha256:8f4e2c19a7b3d605', domain: 'SOFTWARE', categoryType: 'CONTAINERIZATION_SOFTWARE', categoryLabel: 'Containerization Software', icon: '🐳', status: 'HEALTHY' },
      { componentId: 'ui-sw-scm', name: 'Aegis GitOps Monorepo (GitHub)', versionOrIdentifier: 'github.com/aegis-idp/proj-aegis@main', domain: 'SOFTWARE', categoryType: 'DEVELOPMENT_TOOLS_SCM', categoryLabel: 'Development Tools & Source Control (SCM)', icon: '🛠️', status: 'HEALTHY', notes: 'Version-controlled GitOps source of truth and Backstage catalog definitions' },
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
    componentInventory: [
      { componentId: 'be-domain-endpoint', name: 'stg.backend.api.aegis.cloud.goog (DRIFTED)', versionOrIdentifier: 'FQDN', domain: 'INFRASTRUCTURE', layerId: 'EDGE_EXTERNAL_SECURITY', layerLabel: 'Edge & External Security', categoryType: 'DOMAIN_ENDPOINT', categoryLabel: 'Domain Endpoint', icon: '🌐', status: 'DRIFTED', notes: 'Public DNS A-record not declared in Git' },
      { componentId: 'be-ingress-controller', name: 'GKE Ingress Gateway', versionOrIdentifier: 'gke-ingress-v1', domain: 'INFRASTRUCTURE', layerId: 'INGRESS_TRAFFIC_ROUTING', layerLabel: 'Ingress & Traffic Routing', categoryType: 'INGRESS_CONTROLLER', categoryLabel: 'Ingress Controller', icon: '🚪', status: 'HEALTHY' },
      { componentId: 'be-service-mesh', name: 'Istio mTLS Sidecar', versionOrIdentifier: 'istio-1.21', domain: 'INFRASTRUCTURE', layerId: 'INGRESS_TRAFFIC_ROUTING', layerLabel: 'Ingress & Traffic Routing', categoryType: 'SERVICE_MESH', categoryLabel: 'Service Mesh', icon: '🕸️', status: 'HEALTHY' },
      { componentId: 'be-gcp-project', name: 'gcp-project-aegis-prod', versionOrIdentifier: 'project-id: aegis-prod', domain: 'INFRASTRUCTURE', layerId: 'CLOUD_GOVERNANCE_BOUNDARIES', layerLabel: 'Cloud Governance & Logical Boundaries', categoryType: 'GCP_PROJECT_CLOUD_ACCOUNT', categoryLabel: 'GCP Project / Cloud Account', icon: '☁️', status: 'HEALTHY' },
      { componentId: 'be-iam-secrets', name: 'GCP Secret Manager', versionOrIdentifier: 'secret-manager-v1', domain: 'INFRASTRUCTURE', layerId: 'CLOUD_GOVERNANCE_BOUNDARIES', layerLabel: 'Cloud Governance & Logical Boundaries', categoryType: 'IAM_SECRETS_MANAGEMENT', categoryLabel: 'IAM & Secrets Management', icon: '🔒', status: 'HEALTHY' },
      { componentId: 'be-namespace', name: 'aegis-prod', versionOrIdentifier: 'namespace: aegis-prod', domain: 'INFRASTRUCTURE', layerId: 'CLOUD_GOVERNANCE_BOUNDARIES', layerLabel: 'Cloud Governance & Logical Boundaries', categoryType: 'NAMESPACE', categoryLabel: 'Namespace', icon: '🛡️', status: 'HEALTHY' },
      { componentId: 'be-k8s-deployment', name: 'aegis-backend-deployment (DRIFTED 5 replicas)', versionOrIdentifier: 'replicas=5 (declared 3)', domain: 'INFRASTRUCTURE', layerId: 'ORCHESTRATION_COMPUTE_UNITS', layerLabel: 'Orchestration & Compute Units', categoryType: 'K8S_DEPLOYMENT', categoryLabel: 'Kubernetes Deployment', icon: '📜', status: 'DRIFTED', notes: 'Emergency scale to 5 replicas not synced to Git' },
      { componentId: 'be-container', name: 'aegis-backend container (DRIFTED digest)', versionOrIdentifier: 'sha256:9f00deadbeef1122 (declared sha256:3a7b91c4e2f8d056)', domain: 'INFRASTRUCTURE', layerId: 'ORCHESTRATION_COMPUTE_UNITS', layerLabel: 'Orchestration & Compute Units', categoryType: 'CONTAINER', categoryLabel: 'Container', icon: '🐳', status: 'DRIFTED', notes: 'Live image digest differs from Git-declared attested digest' },
      { componentId: 'be-os', name: 'Ubuntu 22.04 LTS', versionOrIdentifier: '22.04.4', domain: 'SOFTWARE', categoryType: 'OPERATING_SYSTEM', categoryLabel: 'Operating System', icon: '💻', status: 'HEALTHY' },
      { componentId: 'be-runtime', name: 'Node.js 18.20.8 (CRITICAL EOL)', versionOrIdentifier: 'v18.20.8', domain: 'SOFTWARE', categoryType: 'PLATFORM_RUNTIME_ENVIRONMENT', categoryLabel: 'Platform Runtime Environment', icon: '🚀', status: 'CRITICAL', notes: 'Node.js 18 reached EOL; upgrade to v20 or v22 required' },
      { componentId: 'be-framework', name: 'Express 4.21.2', versionOrIdentifier: 'express@4.21.2', domain: 'SOFTWARE', categoryType: 'LIBRARY_FRAMEWORK', categoryLabel: 'Library / Framework', icon: '📦', status: 'HEALTHY' },
      { componentId: 'be-orm', name: 'TypeORM 0.3.20', versionOrIdentifier: 'typeorm@0.3.20', domain: 'SOFTWARE', categoryType: 'DATA_ACCESS_ORM', categoryLabel: 'Data Access / ORM', icon: '🗺️', status: 'HEALTHY' },
      { componentId: 'be-app-core', name: 'Aegis Core REST API Engine', versionOrIdentifier: 'v3.8.1', domain: 'SOFTWARE', categoryType: 'APPLICATION_CORE', categoryLabel: 'Application Core', icon: '🛠️', status: 'HEALTHY' },
      { componentId: 'be-observability', name: 'OpenTelemetry SDK', versionOrIdentifier: '@opentelemetry/sdk-node@1.25.0', domain: 'SOFTWARE', categoryType: 'OBSERVABILITY_SOFTWARE', categoryLabel: 'Observability Software', icon: '📊', status: 'HEALTHY' },
      { componentId: 'be-external-api', name: 'Stripe & GCP Cloud Asset API', versionOrIdentifier: 'stripe-node@14.0.0 gcp-cloud-asset-v1', domain: 'SOFTWARE', categoryType: 'EXTERNAL_API', categoryLabel: 'External API', icon: '🌐', status: 'HEALTHY' },
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
    componentInventory: [
      { componentId: 'auth-iam-secrets', name: 'GCP Secret Manager Vault', versionOrIdentifier: 'secret-manager-v1', domain: 'INFRASTRUCTURE', layerId: 'CLOUD_GOVERNANCE_BOUNDARIES', layerLabel: 'Cloud Governance & Logical Boundaries', categoryType: 'IAM_SECRETS_MANAGEMENT', categoryLabel: 'IAM & Secrets Management', icon: '🔒', status: 'HEALTHY' },
      { componentId: 'auth-pod', name: 'aegis-auth-pod-01', versionOrIdentifier: 'pod: aegis-auth-7d4f8c9b6-x2k9m', domain: 'INFRASTRUCTURE', layerId: 'ORCHESTRATION_COMPUTE_UNITS', layerLabel: 'Orchestration & Compute Units', categoryType: 'POD', categoryLabel: 'Pod', icon: '🌱', status: 'HEALTHY' },
      { componentId: 'auth-vm-server', name: 'gce-auth-redis-ephemeral-02 (DRIFTED Shadow VM)', versionOrIdentifier: '10.128.2.99', domain: 'INFRASTRUCTURE', layerId: 'DEDICATED_HOSTS_TRADITIONAL_COMPUTE', layerLabel: 'Dedicated Hosts & Traditional Compute', categoryType: 'VM_SERVER', categoryLabel: 'VM Server', icon: '🖥️', status: 'DRIFTED', notes: 'Shadow VM not declared in Git; detected via GCP Cloud Asset Inventory' },
      { componentId: 'auth-distributed-cache', name: 'Memorystore Redis Session Cache', versionOrIdentifier: 'redis-7.2-cluster', domain: 'INFRASTRUCTURE', layerId: 'DATA_CACHE_STATE', layerLabel: 'Data, Cache & State', categoryType: 'DISTRIBUTED_CACHE', categoryLabel: 'Distributed Cache', icon: '⚡', status: 'HEALTHY' },
      { componentId: 'auth-security-identity', name: 'Jose / JWT 5.9.6 & Passport.js', versionOrIdentifier: 'jose@5.9.6 passport@0.7.0', domain: 'SOFTWARE', categoryType: 'SECURITY_IDENTITY_SOFTWARE', categoryLabel: 'Security & Identity Software', icon: '🛡️', status: 'HEALTHY' },
      { componentId: 'auth-runtime', name: 'Node.js 20.11.0', versionOrIdentifier: 'v20.11.0', domain: 'SOFTWARE', categoryType: 'PLATFORM_RUNTIME_ENVIRONMENT', categoryLabel: 'Platform Runtime Environment', icon: '🚀', status: 'HEALTHY' },
      { componentId: 'auth-app-core', name: 'Aegis Zero-Trust Identity Broker', versionOrIdentifier: 'v4.2.0', domain: 'SOFTWARE', categoryType: 'APPLICATION_CORE', categoryLabel: 'Application Core', icon: '🛠️', status: 'HEALTHY' },
      { componentId: 'auth-testing', name: 'Jest & SonarQube Security Scanner', versionOrIdentifier: 'jest@29.7.0 sonarqube-10.4', domain: 'SOFTWARE', categoryType: 'TESTING_SOFTWARE', categoryLabel: 'Testing Software', icon: '🧪', status: 'HEALTHY' },
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
    componentInventory: [
      { componentId: 'db-baremetal-server', name: 'bm-aegis-db-primary-01', versionOrIdentifier: 'physical-node: bm-01', domain: 'INFRASTRUCTURE', layerId: 'DEDICATED_HOSTS_TRADITIONAL_COMPUTE', layerLabel: 'Dedicated Hosts & Traditional Compute', categoryType: 'BAREMETAL_SERVER', categoryLabel: 'Baremetal Server', icon: '🧱', status: 'HEALTHY' },
      { componentId: 'db-batch-workers', name: 'aegis-db-wal-archiver-cron', versionOrIdentifier: 'cron: 0 */15 * * *', domain: 'INFRASTRUCTURE', layerId: 'DEDICATED_HOSTS_TRADITIONAL_COMPUTE', layerLabel: 'Dedicated Hosts & Traditional Compute', categoryType: 'BATCH_SERVER_EVENT_WORKERS', categoryLabel: 'Batch Server / Event Workers', icon: '⏱️', status: 'HEALTHY' },
      { componentId: 'db-database-instance', name: 'Cloud SQL / PostgreSQL 16.2 Cluster', versionOrIdentifier: 'pg-16.2-ha-cluster', domain: 'INFRASTRUCTURE', layerId: 'DATA_CACHE_STATE', layerLabel: 'Data, Cache & State', categoryType: 'DATABASE_INFRA_INSTANCE', categoryLabel: 'Database Infrastructure Instance', icon: '🗄️', status: 'HEALTHY' },
      { componentId: 'db-object-storage', name: 'GCS aegis-db-backups-bucket', versionOrIdentifier: 'gs://aegis-db-backups', domain: 'INFRASTRUCTURE', layerId: 'DATA_CACHE_STATE', layerLabel: 'Data, Cache & State', categoryType: 'OBJECT_STORAGE', categoryLabel: 'Object Storage', icon: '📦', status: 'HEALTHY' },
      { componentId: 'db-os', name: 'Alpine Linux 3.19.4', versionOrIdentifier: '3.19.4', domain: 'SOFTWARE', categoryType: 'OPERATING_SYSTEM', categoryLabel: 'Operating System', icon: '💻', status: 'HEALTHY' },
      { componentId: 'db-data-access-orm', name: 'PostGIS 3.4.2 & pg-pool', versionOrIdentifier: 'postgis@3.4.2 pg-pool@3.6.2', domain: 'SOFTWARE', categoryType: 'DATA_ACCESS_ORM', categoryLabel: 'Data Access / ORM', icon: '🗺️', status: 'HEALTHY' },
      { componentId: 'db-observability', name: 'Prometheus postgres_exporter', versionOrIdentifier: 'postgres_exporter@0.16.0', domain: 'SOFTWARE', categoryType: 'OBSERVABILITY_SOFTWARE', categoryLabel: 'Observability Software', icon: '📊', status: 'HEALTHY' },
      { componentId: 'db-containerization', name: 'Helm Chart aegis-postgres-ha 2.4.0', versionOrIdentifier: 'helm-chart@2.4.0', domain: 'SOFTWARE', categoryType: 'CONTAINERIZATION_SOFTWARE', categoryLabel: 'Containerization Software', icon: '🐳', status: 'HEALTHY' },
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
    componentInventory: [
      { componentId: 'hw-domain-endpoint', name: 'hello.aegis.cloud.goog', versionOrIdentifier: 'FQDN', domain: 'INFRASTRUCTURE', layerId: 'EDGE_EXTERNAL_SECURITY', layerLabel: 'Edge & External Security', categoryType: 'DOMAIN_ENDPOINT', categoryLabel: 'Domain Endpoint', icon: '🌐', status: 'HEALTHY' },
      { componentId: 'hw-load-balancer', name: 'HAProxy 3.0 Edge Terminator', versionOrIdentifier: 'haproxy-3.0', domain: 'INFRASTRUCTURE', layerId: 'INGRESS_TRAFFIC_ROUTING', layerLabel: 'Ingress & Traffic Routing', categoryType: 'LOAD_BALANCER', categoryLabel: 'Load Balancer', icon: '🔀', status: 'HEALTHY' },
      { componentId: 'hw-container', name: 'hello-world-app:sha256:2b5c8d1e4f7a0b3c', versionOrIdentifier: 'sha256:2b5c8d1e4f7a0b3c', domain: 'INFRASTRUCTURE', layerId: 'ORCHESTRATION_COMPUTE_UNITS', layerLabel: 'Orchestration & Compute Units', categoryType: 'CONTAINER', categoryLabel: 'Container', icon: '🐳', status: 'HEALTHY' },
      { componentId: 'hw-middleware', name: 'HAProxy Runtime Socket / Envoy Gateway', versionOrIdentifier: 'envoy-1.29', domain: 'SOFTWARE', categoryType: 'MIDDLEWARE_INTEGRATION_SOFTWARE', categoryLabel: 'Middleware / Integration Software', icon: '🔄', status: 'HEALTHY' },
      { componentId: 'hw-runtime', name: 'Node.js 22.15.0', versionOrIdentifier: 'v22.15.0', domain: 'SOFTWARE', categoryType: 'PLATFORM_RUNTIME_ENVIRONMENT', categoryLabel: 'Platform Runtime Environment', icon: '🚀', status: 'HEALTHY' },
      { componentId: 'hw-app-core', name: 'Hello World Edge Microservice', versionOrIdentifier: 'v1.0.0', domain: 'SOFTWARE', categoryType: 'APPLICATION_CORE', categoryLabel: 'Application Core', icon: '🛠️', status: 'HEALTHY' },
    ],
  },
};

export function resolveCmdbServiceKey(entityOrRef: string): string {
  const raw = entityOrRef.split('/').pop()?.split(':').pop() || 'aegis-ui';
  if (raw === 'haproxy-hello-world-tls') {
    return 'hello-world-app';
  }
  return CMDB_SERVICE_SEEDS[raw] ? raw : 'aegis-ui';
}

function buildCmdbSnapshot(seed: Omit<EntityCmdbSnapshot, 'driftStatus' | 'activeDriftCount' | 'lastReconciledAt'>): EntityCmdbSnapshot {
  const activeDriftCount = seed.driftItems.filter(d => d.status === 'ACTIVE_DRIFT').length;
  const componentInventory = seed.componentInventory?.map(node => {
    const owner = resolveComponentOwnerTeam(node.domain, node.categoryType);
    if (node.domain !== 'SOFTWARE') {
      return {
        ...node,
        ownerTeamId: owner.teamId,
        ownerTeamName: owner.teamName,
      };
    }
    const crossCheck = crossCheckSoftwareVersion({
      productName: node.name,
      rawVersion: node.versionOrIdentifier,
    });
    return {
      ...node,
      normalizedVersion: crossCheck.normalized,
      versionCrossCheck: crossCheck,
      ownerTeamId: owner.teamId,
      ownerTeamName: owner.teamName,
    };
  });
  return {
    ...seed,
    ...(componentInventory ? { componentInventory } : {}),
    driftStatus: activeDriftCount > 0 ? 'DRIFT_DETECTED' : 'IN_SYNC',
    activeDriftCount,
    lastReconciledAt: new Date().toISOString(),
  };
}

export async function getEntityCmdbSnapshot(entityRef: string, knex?: any): Promise<EntityCmdbSnapshot> {
  try {
    const fromDb = await queryEntityCmdbSnapshotFromPostgres(entityRef, knex);
    if (fromDb) {
      return fromDb;
    }
  } catch {
    // Fall back to seed snapshot when DB client is unavailable
  }
  const key = resolveCmdbServiceKey(entityRef);
  const seed = CMDB_SERVICE_SEEDS[key];
  return buildCmdbSnapshot(seed);
}

export async function getFleetCmdbTopology(knex?: any): Promise<FleetCmdbTopologyReport> {
  try {
    const fromDb = await queryFleetCmdbTopologyFromPostgres(knex);
    if (fromDb) {
      return fromDb;
    }
  } catch {
    // Fall back to seed topology when DB client is unavailable
  }
  const keys = Object.keys(CMDB_SERVICE_SEEDS);
  const snapshots = await Promise.all(keys.map(k => getEntityCmdbSnapshot(k, knex)));
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
    taxonomyCatalog: getComponentTaxonomyCatalog(),
    teamOwnersTable: AEGIS_TEAM_OWNERS_TABLE,
  };
}



import { execFileSync } from 'node:child_process';
import fs from 'node:fs';
import http from 'node:http';

export interface K8sPodSummary {
  name: string;
  phase: string;
  ready: boolean;
  podIP: string;
  restarts: number;
  startedAt: string;
  image: string;
}

export interface K8sDeploymentSnapshot {
  deploymentName: string;
  namespace: string;
  entityRef: string;
  desiredReplicas: number;
  readyReplicas: number;
  availableReplicas: number;
  generation: number;
  observedGeneration: number;
  strategy: string;
  restartedAt: string;
  pods: K8sPodSummary[];
  serviceHealthUrl?: string;
  serviceHttpStatus?: number;
  serviceHealthy: boolean;
  gitOpsReplicas?: number;
  capturedAt: string;
}

export interface WorkloadConfig {
  deploymentName: string;
  entityRef: string;
  namespace: string;
  baselineReplicas: number;
  minReplicas: number;
  maxReplicas: number;
  isStateful: boolean;
  healthUrl?: string;
  catalogInfoPath: string;
}

export interface PolicyValidationInput {
  entityRef: string;
  namespace?: string;
  operationType: 'scale' | 'rolling-restart';
  selectionMode?: 'Count' | 'Percentage';
  replicaValue?: number;
  reason?: string;
}

export interface PolicyValidationOutput {
  allowed: boolean;
  entityRef: string;
  deploymentName: string;
  namespace: string;
  operationType: 'scale' | 'rolling-restart';
  selectionMode: 'Count' | 'Percentage';
  baselineReplicas: number;
  minReplicas: number;
  maxReplicas: number;
  targetReplicas: number;
  isStateful: boolean;
  healthUrl?: string;
  policySummary: string;
}

export interface ExecuteDay2OpInput {
  entityRef?: string;
  deploymentName: string;
  namespace?: string;
  operationType: 'scale' | 'rolling-restart';
  targetReplicas?: number;
  syncGitOpsManifest?: boolean;
  reason?: string;
  waitTimeoutSeconds?: number;
  manifestPath?: string;
}

export interface K8sDay2OperationDiff {
  operationId: string;
  executedAt: string;
  entityRef: string;
  deploymentName: string;
  namespace: string;
  operationType: 'scale' | 'rolling-restart';
  reason: string;
  targetReplicas: number;
  gitOpsSynced: boolean;
  steadyStateVerified: boolean;
  serviceHealthVerified: boolean;
  previous: K8sDeploymentSnapshot;
  current: K8sDeploymentSnapshot;
  unifiedDiff: string;
  markdownDiff: string;
}

export const DEFAULT_MANIFEST_PATH =
  '/home/dartoledo/proj-aegis/demo/k8s/manifest.yaml';

export const WORKLOAD_CONFIGS: Record<string, WorkloadConfig> = {
  backend: {
    deploymentName: 'backend',
    entityRef: 'component:default/aegis-backend',
    namespace: 'default',
    baselineReplicas: 1,
    minReplicas: 1,
    maxReplicas: 10,
    isStateful: false,
    healthUrl: 'http://127.0.0.1:30002/items',
    catalogInfoPath: '/home/dartoledo/proj-aegis/demo/backend/catalog-info.yaml',
  },
  auth: {
    deploymentName: 'auth',
    entityRef: 'component:default/aegis-auth',
    namespace: 'default',
    baselineReplicas: 1,
    minReplicas: 1,
    maxReplicas: 10,
    isStateful: false,
    healthUrl: 'http://127.0.0.1:30001',
    catalogInfoPath: '/home/dartoledo/proj-aegis/demo/auth/catalog-info.yaml',
  },
  ui: {
    deploymentName: 'ui',
    entityRef: 'component:default/aegis-ui',
    namespace: 'default',
    baselineReplicas: 1,
    minReplicas: 1,
    maxReplicas: 10,
    isStateful: false,
    healthUrl: 'http://127.0.0.1:30080',
    catalogInfoPath: '/home/dartoledo/proj-aegis/demo/ui/catalog-info.yaml',
  },
  db: {
    deploymentName: 'db',
    entityRef: 'resource:default/aegis-db',
    namespace: 'default',
    baselineReplicas: 1,
    minReplicas: 1,
    maxReplicas: 1,
    isStateful: true,
    catalogInfoPath: '/home/dartoledo/proj-aegis/demo/db-init/catalog-info.yaml',
  },
};

const latestDiffsByDeployment: Record<string, K8sDay2OperationDiff> = {};
const operationHistory: K8sDay2OperationDiff[] = [];
const operationCounters: Record<string, number> = {
  'backend:scale': 0,
  'backend:rolling-restart': 0,
  'auth:scale': 0,
  'auth:rolling-restart': 0,
  'ui:scale': 0,
  'ui:rolling-restart': 0,
  'db:rolling-restart': 0,
};

export function getLatestK8sDay2Diffs(): Record<string, K8sDay2OperationDiff> {
  return { ...latestDiffsByDeployment };
}

export function getK8sDay2History(): K8sDay2OperationDiff[] {
  return [...operationHistory];
}

export function resolveWorkloadConfig(entityRefOrName: string): WorkloadConfig {
  const cleaned = (entityRefOrName || '')
    .trim()
    .toLowerCase()
    .replace(/^(component|resource):(default\/)?/, '')
    .replace(/^aegis-/, '');

  const config = WORKLOAD_CONFIGS[cleaned];
  if (!config) {
    throw new Error(
      `Unknown Kubernetes workload "${entityRefOrName}". Supported workloads: aegis-backend, aegis-auth, aegis-ui, aegis-db`,
    );
  }
  return config;
}

export function readGitOpsManifestReplicas(
  deploymentName: string,
  manifestPath = DEFAULT_MANIFEST_PATH,
): number | undefined {
  if (!fs.existsSync(manifestPath)) {
    return undefined;
  }
  const content = fs.readFileSync(manifestPath, 'utf8');
  const docs = content.split(/^---\s*$/m);
  for (const doc of docs) {
    if (
      /kind:\s*Deployment/.test(doc) &&
      new RegExp(`name:\\s*${deploymentName}\\b`).test(doc)
    ) {
      const match = doc.match(/^\s*replicas:\s*(\d+)/m);
      return match ? Number(match[1]) : 1;
    }
  }
  return undefined;
}

export function syncGitOpsManifestReplicas(
  deploymentName: string,
  replicas: number,
  manifestPath = DEFAULT_MANIFEST_PATH,
): boolean {
  if (!fs.existsSync(manifestPath)) {
    return false;
  }
  const content = fs.readFileSync(manifestPath, 'utf8');
  const docs = content.split(/^---\s*$/m);
  let updated = false;

  const updatedDocs = docs.map(doc => {
    if (
      /kind:\s*Deployment/.test(doc) &&
      new RegExp(`name:\\s*${deploymentName}\\b`).test(doc)
    ) {
      updated = true;
      if (/^\s*replicas:\s*\d+/m.test(doc)) {
        return doc.replace(
          /^(\s*replicas:\s*)\d+/m,
          `$1${replicas}`,
        );
      }
      return doc.replace(
        /^(\s*spec:\s*\n)/m,
        `$1  replicas: ${replicas}\n`,
      );
    }
    return doc;
  });

  if (updated) {
    fs.writeFileSync(manifestPath, updatedDocs.join('---'), 'utf8');
  }
  return updated;
}

async function probeServiceHttpHealth(
  url?: string,
): Promise<{ status: number; healthy: boolean }> {
  if (!url) {
    return { status: 200, healthy: true };
  }
  return new Promise(resolve => {
    const req = http.get(url, { timeout: 2500 }, res => {
      const code = res.statusCode ?? 0;
      res.resume();
      resolve({
        status: code,
        healthy: code >= 200 && code < 500,
      });
    });
    req.on('timeout', () => {
      req.destroy();
      resolve({ status: 0, healthy: false });
    });
    req.on('error', () => {
      req.destroy();
      resolve({ status: 0, healthy: false });
    });
  });
}

export async function inspectK8sDeployment(
  deploymentOrEntity: string,
  namespace = 'default',
  manifestPath = DEFAULT_MANIFEST_PATH,
): Promise<K8sDeploymentSnapshot> {
  const config = resolveWorkloadConfig(deploymentOrEntity);
  const depName = config.deploymentName;
  const ns = namespace || config.namespace;

  const depJsonStr = execFileSync(
    'kubectl',
    ['get', 'deployment', depName, '-n', ns, '-o', 'json'],
    { encoding: 'utf8', stdio: ['ignore', 'pipe', 'pipe'] },
  );
  const dep = JSON.parse(depJsonStr);

  const podsJsonStr = execFileSync(
    'kubectl',
    ['get', 'pods', '-n', ns, '-l', `app=${depName}`, '-o', 'json'],
    { encoding: 'utf8', stdio: ['ignore', 'pipe', 'pipe'] },
  );
  const podsList = JSON.parse(podsJsonStr);

  const activePods: K8sPodSummary[] = (podsList.items || [])
    .filter((pod: any) => !pod.metadata?.deletionTimestamp)
    .map((pod: any) => {
      const statuses = pod.status?.containerStatuses || [];
      const allReady =
        statuses.length > 0 && statuses.every((cs: any) => Boolean(cs.ready));
      const restarts = statuses.reduce(
        (sum: number, cs: any) => sum + Number(cs.restartCount || 0),
        0,
      );
      const image =
        pod.spec?.containers?.[0]?.image ||
        statuses[0]?.image ||
        'unknown';
      return {
        name: String(pod.metadata?.name || 'unknown'),
        phase: String(pod.status?.phase || 'Unknown'),
        ready: allReady,
        podIP: String(pod.status?.podIP || 'Pending'),
        restarts,
        startedAt: String(
          pod.status?.startTime || pod.metadata?.creationTimestamp || '',
        ),
        image: String(image),
      };
    });

  const desiredReplicas = Number(dep.spec?.replicas ?? 1);
  const readyReplicas = Number(dep.status?.readyReplicas ?? 0);
  const availableReplicas = Number(dep.status?.availableReplicas ?? 0);
  const generation = Number(dep.metadata?.generation ?? 1);
  const observedGeneration = Number(dep.status?.observedGeneration ?? 1);
  const strategy = String(dep.spec?.strategy?.type || 'RollingUpdate');
  const templateAnnotations = dep.spec?.template?.metadata?.annotations || {};
  const restartedAt = String(
    templateAnnotations['kubectl.kubernetes.io/restartedAt'] ||
      templateAnnotations['aegis.idp/restartedAt'] ||
      'initial',
  );

  const gitOpsReplicas = readGitOpsManifestReplicas(depName, manifestPath);
  const healthProbe = config.healthUrl
    ? await probeServiceHttpHealth(config.healthUrl)
    : { status: readyReplicas >= 1 ? 200 : 503, healthy: readyReplicas >= 1 };

  return {
    deploymentName: depName,
    namespace: ns,
    entityRef: config.entityRef,
    desiredReplicas,
    readyReplicas,
    availableReplicas,
    generation,
    observedGeneration,
    strategy,
    restartedAt,
    pods: activePods,
    serviceHealthUrl: config.healthUrl,
    serviceHttpStatus: healthProbe.status,
    serviceHealthy: healthProbe.healthy && readyReplicas >= 1,
    gitOpsReplicas,
    capturedAt: new Date().toISOString(),
  };
}

export async function evaluateK8sDay2Policy(
  input: PolicyValidationInput,
): Promise<PolicyValidationOutput> {
  const config = resolveWorkloadConfig(input.entityRef);
  const namespace = input.namespace || config.namespace;
  const reason = (input.reason || '').trim();

  if (!reason) {
    throw new Error(
      'OPA Policy Violation [AEGIS-K8S-000]: An audit reason / change ticket is required for all Kubernetes Day-2 operations.',
    );
  }

  const selectionMode: 'Count' | 'Percentage' =
    input.selectionMode === 'Percentage' ? 'Percentage' : 'Count';

  if (input.operationType === 'scale') {
    if (config.isStateful) {
      throw new Error(
        `OPA Policy Violation [AEGIS-K8S-001]: Scaling is prohibited on stateful database workload "${config.deploymentName}". Only rolling-restart is permitted.`,
      );
    }

    const rawVal = Number(input.replicaValue ?? config.baselineReplicas);
    if (!Number.isFinite(rawVal) || rawVal <= 0) {
      throw new Error(
        `OPA Policy Violation [AEGIS-K8S-002]: Requested replica value (${input.replicaValue}) must be a positive integer within [${config.minReplicas}..${config.maxReplicas}].`,
      );
    }

    const targetReplicas =
      selectionMode === 'Percentage'
        ? Math.max(1, Math.floor((config.baselineReplicas * rawVal) / 100))
        : Math.floor(rawVal);

    if (
      targetReplicas < config.minReplicas ||
      targetReplicas > config.maxReplicas
    ) {
      throw new Error(
        `OPA Policy Violation [AEGIS-K8S-002]: Requested replicas (${targetReplicas}) violates guardrail bounds [${config.minReplicas}..${config.maxReplicas}] for deployment/${config.deploymentName}`,
      );
    }

    return {
      allowed: true,
      entityRef: config.entityRef,
      deploymentName: config.deploymentName,
      namespace,
      operationType: 'scale',
      selectionMode,
      baselineReplicas: config.baselineReplicas,
      minReplicas: config.minReplicas,
      maxReplicas: config.maxReplicas,
      targetReplicas,
      isStateful: config.isStateful,
      healthUrl: config.healthUrl,
      policySummary: `[PASS] OPA Guardrail check passed for deployment/${config.deploymentName}: targetReplicas=${targetReplicas} (mode=${selectionMode}, bounds=[${config.minReplicas}..${config.maxReplicas}])`,
    };
  }

  // rolling-restart
  let currentDesired = config.baselineReplicas;
  try {
    const snap = await inspectK8sDeployment(config.deploymentName, namespace);
    currentDesired = snap.desiredReplicas;
  } catch {
    // Use baselineReplicas if live cluster is not reachable during dry-run
  }

  return {
    allowed: true,
    entityRef: config.entityRef,
    deploymentName: config.deploymentName,
    namespace,
    operationType: 'rolling-restart',
    selectionMode,
    baselineReplicas: config.baselineReplicas,
    minReplicas: config.minReplicas,
    maxReplicas: config.maxReplicas,
    targetReplicas: currentDesired,
    isStateful: config.isStateful,
    healthUrl: config.healthUrl,
    policySummary: `[PASS] OPA Guardrail check passed for zero-downtime rolling-restart of deployment/${config.deploymentName} (replicas=${currentDesired})`,
  };
}

function formatPodListCompact(pods: K8sPodSummary[]): string {
  if (!pods.length) {
    return 'none';
  }
  return pods
    .map(p => `${p.name}(${p.podIP}:${p.phase}${p.ready ? ':Ready' : ':NotReady'})`)
    .join(', ');
}

export function buildK8sDay2Diff(params: {
  operationType: 'scale' | 'rolling-restart';
  reason: string;
  targetReplicas: number;
  gitOpsSynced: boolean;
  previous: K8sDeploymentSnapshot;
  current: K8sDeploymentSnapshot;
}): K8sDay2OperationDiff {
  const {
    operationType,
    reason,
    targetReplicas,
    gitOpsSynced,
    previous,
    current,
  } = params;

  const steadyStateVerified =
    current.readyReplicas === targetReplicas &&
    current.desiredReplicas === targetReplicas &&
    current.observedGeneration >= current.generation;
  const serviceHealthVerified = current.serviceHealthy;

  const diffLines: string[] = [
    `--- Pre-Operation K8s Workload State (deployment/${previous.deploymentName} @ ns/${previous.namespace})`,
    `+++ Post-Operation K8s Workload State (deployment/${current.deploymentName} @ ns/${current.namespace})`,
    '@@ -1,8 +1,8 @@',
  ];

  const rows: Array<{ label: string; oldVal: string; newVal: string }> = [
    {
      label: 'Workload / Entity   ',
      oldVal: `${previous.deploymentName} (${previous.entityRef})`,
      newVal: `${current.deploymentName} (${current.entityRef})`,
    },
    {
      label: 'Desired Replicas    ',
      oldVal: String(previous.desiredReplicas),
      newVal: String(current.desiredReplicas),
    },
    {
      label: 'Ready Replicas      ',
      oldVal: `${previous.readyReplicas} / ${previous.desiredReplicas} Ready`,
      newVal: `${current.readyReplicas} / ${current.desiredReplicas} Ready`,
    },
    {
      label: 'K8s Generation      ',
      oldVal: `gen=${previous.generation} (observed=${previous.observedGeneration})`,
      newVal: `gen=${current.generation} (observed=${current.observedGeneration})`,
    },
    {
      label: 'Rollout RestartedAt ',
      oldVal: previous.restartedAt,
      newVal: current.restartedAt,
    },
    {
      label: 'GitOps Manifest Sync',
      oldVal: `replicas=${previous.gitOpsReplicas ?? 1}`,
      newVal: `replicas=${current.gitOpsReplicas ?? current.desiredReplicas} (${gitOpsSynced ? 'Synced' : 'Live-Only'})`,
    },
    {
      label: 'Active Pod Endpoints',
      oldVal: formatPodListCompact(previous.pods),
      newVal: formatPodListCompact(current.pods),
    },
    {
      label: 'Service Health Probe',
      oldVal: `HTTP ${previous.serviceHttpStatus ?? 200} (${previous.serviceHealthy ? 'HEALTHY' : 'DEGRADED'})`,
      newVal: `HTTP ${current.serviceHttpStatus ?? 200} (${current.serviceHealthy ? 'HEALTHY' : 'DEGRADED'})`,
    },
  ];

  for (const row of rows) {
    if (row.oldVal === row.newVal) {
      diffLines.push(`   ${row.label}: ${row.newVal}`);
    } else {
      diffLines.push(`-  ${row.label}: ${row.oldVal}`);
      diffLines.push(`+  ${row.label}: ${row.newVal}`);
    }
  }

  const unifiedDiff = diffLines.join('\n');

  const markdownDiff = [
    `### Kubernetes Day-2 Operation Verification (\`${operationType.toUpperCase()}\` on \`deployment/${current.deploymentName}\`)`,
    '',
    `- **Target Entity:** \`${current.entityRef}\` (\`namespace: ${current.namespace}\`)`,
    `- **Operation Type:** \`${operationType}\` (Reason: *${reason}*)`,
    `- **Steady-State Rollout Verified:** \`${steadyStateVerified ? `PASSED (${current.readyReplicas}/${current.desiredReplicas} Ready)` : `PENDING (${current.readyReplicas}/${current.desiredReplicas} Ready)`}\``,
    `- **End-to-End Service Health Probe:** \`${serviceHealthVerified ? `HEALTHY (HTTP ${current.serviceHttpStatus ?? 200})` : 'DEGRADED'}\``,
    `- **GitOps Manifest Sync (\`demo/k8s/manifest.yaml\`):** \`${gitOpsSynced ? `SYNCED (replicas: ${current.gitOpsReplicas ?? current.desiredReplicas})` : 'UNCHANGED'}\``,
    '',
    '| K8s Workload Attribute | Pre-Operation State (Before) | Post-Operation State (After) |',
    '| :--- | :--- | :--- |',
    `| **Desired Replicas** | \`${previous.desiredReplicas}\` | \`${current.desiredReplicas}\` |`,
    `| **Ready / Available** | \`${previous.readyReplicas} / ${previous.desiredReplicas} Ready\` | \`${current.readyReplicas} / ${current.desiredReplicas} Ready\` |`,
    `| **Deployment Generation** | \`${previous.generation}\` | \`${current.generation}\` |`,
    `| **Rollout RestartedAt** | \`${previous.restartedAt}\` | \`${current.restartedAt}\` |`,
    `| **GitOps Manifest Replicas** | \`${previous.gitOpsReplicas ?? 1}\` | \`${current.gitOpsReplicas ?? current.desiredReplicas}\` |`,
    `| **Active Pod Endpoints** | \`${formatPodListCompact(previous.pods)}\` | \`${formatPodListCompact(current.pods)}\` |`,
    `| **Service Health Check** | \`HTTP ${previous.serviceHttpStatus ?? 200}\` | \`HTTP ${current.serviceHttpStatus ?? 200}\` |`,
    '',
    '```diff',
    unifiedDiff,
    '```',
  ].join('\n');

  const diffObj: K8sDay2OperationDiff = {
    operationId: `k8s-day2-${current.deploymentName}-${Date.now()}`,
    executedAt: new Date().toISOString(),
    entityRef: current.entityRef,
    deploymentName: current.deploymentName,
    namespace: current.namespace,
    operationType,
    reason,
    targetReplicas,
    gitOpsSynced,
    steadyStateVerified,
    serviceHealthVerified,
    previous,
    current,
    unifiedDiff,
    markdownDiff,
  };

  latestDiffsByDeployment[current.deploymentName] = diffObj;
  operationHistory.unshift(diffObj);
  if (operationHistory.length > 25) {
    operationHistory.pop();
  }

  return diffObj;
}

export async function executeK8sDay2Operation(
  input: ExecuteDay2OpInput,
): Promise<{
  operationId: string;
  deploymentName: string;
  namespace: string;
  operationType: 'scale' | 'rolling-restart';
  targetReplicas: number;
  gitOpsSynced: boolean;
  restartedAt: string;
  previous: K8sDeploymentSnapshot;
  current: K8sDeploymentSnapshot;
  operationDiff: K8sDay2OperationDiff;
}> {
  const config = resolveWorkloadConfig(
    input.deploymentName || input.entityRef || 'backend',
  );
  const namespace = input.namespace || config.namespace;
  const manifestPath = input.manifestPath || DEFAULT_MANIFEST_PATH;
  const timeoutSec = Math.max(15, Number(input.waitTimeoutSeconds ?? 90));
  const reason = (input.reason || 'Day-2 automated operation').trim();

  // Enforce OPA policy guardrails before executing
  const policy = await evaluateK8sDay2Policy({
    entityRef: input.entityRef || config.entityRef,
    namespace,
    operationType: input.operationType,
    selectionMode: 'Count',
    replicaValue: input.targetReplicas,
    reason,
  });

  const previous = await inspectK8sDeployment(
    config.deploymentName,
    namespace,
    manifestPath,
  );

  let gitOpsSynced = false;
  const targetReplicas =
    input.operationType === 'scale'
      ? policy.targetReplicas
      : previous.desiredReplicas;

  if (input.operationType === 'scale') {
    execFileSync(
      'kubectl',
      [
        'scale',
        `deployment/${config.deploymentName}`,
        `--replicas=${targetReplicas}`,
        '-n',
        namespace,
      ],
      { encoding: 'utf8', stdio: ['ignore', 'pipe', 'pipe'] },
    );

    if (input.syncGitOpsManifest !== false) {
      gitOpsSynced = syncGitOpsManifestReplicas(
        config.deploymentName,
        targetReplicas,
        manifestPath,
      );
    }
  } else {
    execFileSync(
      'kubectl',
      [
        'rollout',
        'restart',
        `deployment/${config.deploymentName}`,
        '-n',
        namespace,
      ],
      { encoding: 'utf8', stdio: ['ignore', 'pipe', 'pipe'] },
    );
  }

  // Wait for Kubernetes rollout steady-state completion
  execFileSync(
    'kubectl',
    [
      'rollout',
      'status',
      `deployment/${config.deploymentName}`,
      '-n',
      namespace,
      `--timeout=${timeoutSec}s`,
    ],
    { encoding: 'utf8', stdio: ['ignore', 'pipe', 'pipe'] },
  );

  const counterKey = `${config.deploymentName}:${input.operationType}`;
  operationCounters[counterKey] = (operationCounters[counterKey] || 0) + 1;

  // Poll briefly until terminating pods are cleaned up and readyReplicas matches targetReplicas
  let current = await inspectK8sDeployment(
    config.deploymentName,
    namespace,
    manifestPath,
  );
  for (let attempt = 0; attempt < 6; attempt++) {
    if (
      current.readyReplicas === targetReplicas &&
      current.pods.length === targetReplicas &&
      current.pods.every(p => p.ready)
    ) {
      break;
    }
    await new Promise(r => setTimeout(r, 300));
    current = await inspectK8sDeployment(
      config.deploymentName,
      namespace,
      manifestPath,
    );
  }

  const operationDiff = buildK8sDay2Diff({
    operationType: input.operationType,
    reason,
    targetReplicas,
    gitOpsSynced,
    previous,
    current,
  });

  return {
    operationId: operationDiff.operationId,
    deploymentName: config.deploymentName,
    namespace,
    operationType: input.operationType,
    targetReplicas,
    gitOpsSynced,
    restartedAt: current.restartedAt,
    previous,
    current,
    operationDiff,
  };
}

export async function verifyK8sWorkloadAndBuildDiff(params: {
  deploymentName: string;
  namespace?: string;
  operationType: 'scale' | 'rolling-restart';
  expectedReplicas: number;
  previousSnapshot?: K8sDeploymentSnapshot;
  gitOpsSynced?: boolean;
  reason?: string;
  manifestPath?: string;
}): Promise<K8sDay2OperationDiff> {
  const config = resolveWorkloadConfig(params.deploymentName);
  const namespace = params.namespace || config.namespace;
  const manifestPath = params.manifestPath || DEFAULT_MANIFEST_PATH;

  let current = await inspectK8sDeployment(
    config.deploymentName,
    namespace,
    manifestPath,
  );

  for (let attempt = 0; attempt < 6; attempt++) {
    if (
      current.readyReplicas === params.expectedReplicas &&
      current.desiredReplicas === params.expectedReplicas &&
      current.serviceHealthy
    ) {
      break;
    }
    await new Promise(r => setTimeout(r, 300));
    current = await inspectK8sDeployment(
      config.deploymentName,
      namespace,
      manifestPath,
    );
  }

  if (current.readyReplicas !== params.expectedReplicas) {
    throw new Error(
      `K8s steady-state verification failed for deployment/${config.deploymentName}: expected ${params.expectedReplicas} ready replicas, got ${current.readyReplicas}`,
    );
  }

  const existingDiff = latestDiffsByDeployment[config.deploymentName];
  const previous =
    params.previousSnapshot || existingDiff?.previous || current;

  return buildK8sDay2Diff({
    operationType: params.operationType,
    reason:
      params.reason ||
      existingDiff?.reason ||
      'Verified Day-2 steady-state rollout',
    targetReplicas: params.expectedReplicas,
    gitOpsSynced: Boolean(params.gitOpsSynced ?? existingDiff?.gitOpsSynced),
    previous,
    current,
  });
}

export async function getAllK8sWorkloadsStatus(): Promise<{
  workloads: Record<string, K8sDeploymentSnapshot>;
  latestDiffs: Record<string, K8sDay2OperationDiff>;
  history: K8sDay2OperationDiff[];
}> {
  const workloads: Record<string, K8sDeploymentSnapshot> = {};
  for (const key of Object.keys(WORKLOAD_CONFIGS)) {
    try {
      workloads[key] = await inspectK8sDeployment(key);
    } catch {
      // Skip if unreachable
    }
  }
  return {
    workloads,
    latestDiffs: getLatestK8sDay2Diffs(),
    history: getK8sDay2History(),
  };
}

export async function renderK8sPrometheusMetrics(): Promise<string> {
  const status = await getAllK8sWorkloadsStatus();
  const lines: string[] = [
    '# HELP idp_k8s_deployment_desired_replicas Desired replica count for Kubernetes deployment',
    '# TYPE idp_k8s_deployment_desired_replicas gauge',
  ];

  for (const [name, snap] of Object.entries(status.workloads)) {
    lines.push(
      `idp_k8s_deployment_desired_replicas{deployment="${name}",namespace="${snap.namespace}",entity="${snap.entityRef}"} ${snap.desiredReplicas}`,
    );
  }

  lines.push(
    '# HELP idp_k8s_deployment_ready_replicas Ready replica count for Kubernetes deployment',
    '# TYPE idp_k8s_deployment_ready_replicas gauge',
  );
  for (const [name, snap] of Object.entries(status.workloads)) {
    lines.push(
      `idp_k8s_deployment_ready_replicas{deployment="${name}",namespace="${snap.namespace}",entity="${snap.entityRef}"} ${snap.readyReplicas}`,
    );
  }

  lines.push(
    '# HELP idp_k8s_deployment_generation Observed metadata generation for Kubernetes deployment',
    '# TYPE idp_k8s_deployment_generation gauge',
  );
  for (const [name, snap] of Object.entries(status.workloads)) {
    lines.push(
      `idp_k8s_deployment_generation{deployment="${name}",namespace="${snap.namespace}"} ${snap.generation}`,
    );
  }

  lines.push(
    '# HELP idp_k8s_day2_operations_total Total Day-2 Kubernetes operations executed via Backstage IDP',
    '# TYPE idp_k8s_day2_operations_total counter',
  );
  for (const [key, count] of Object.entries(operationCounters)) {
    const [dep, op] = key.split(':');
    lines.push(
      `idp_k8s_day2_operations_total{deployment="${dep}",operation="${op}"} ${count}`,
    );
  }

  lines.push('');
  return lines.join('\n');
}

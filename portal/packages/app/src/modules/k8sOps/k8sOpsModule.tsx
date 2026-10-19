import { useEffect, useState } from 'react';
import { createFrontendModule } from '@backstage/frontend-plugin-api';
import { EntityCardBlueprint } from '@backstage/plugin-catalog-react/alpha';
import { useEntity } from '@backstage/plugin-catalog-react';
import { InfoCard, LinkButton } from '@backstage/core-components';

interface K8sPodSummary {
  name: string;
  phase: string;
  ready: boolean;
  podIP: string;
  restarts: number;
  image: string;
}

interface K8sDeploymentSnapshot {
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
}

interface K8sDay2OperationDiff {
  operationId: string;
  executedAt: string;
  operationType: 'scale' | 'rolling-restart';
  reason: string;
  targetReplicas: number;
  gitOpsSynced: boolean;
  steadyStateVerified: boolean;
  serviceHealthVerified: boolean;
  unifiedDiff: string;
}

function buildDay2TemplateUrl(
  entityRef: string,
  operationType: 'scale' | 'rolling-restart',
): string {
  const formData = JSON.stringify({
    componentEntity: entityRef,
    namespace: 'default',
    operationType,
  });
  return `/create/templates/default/k8s-day2-operations?formData=${encodeURIComponent(
    formData,
  )}`;
}

const K8sDay2WorkloadCard = () => {
  const { entity } = useEntity();
  const [liveSnapshot, setLiveSnapshot] =
    useState<K8sDeploymentSnapshot | null>(null);
  const [latestDiff, setLatestDiff] = useState<K8sDay2OperationDiff | null>(
    null,
  );

  const annotations = entity.metadata.annotations ?? {};
  const depName = annotations['resiliency.idp/k8s-deployment'];

  useEffect(() => {
    if (!depName) {
      return;
    }
    let mounted = true;
    fetch('http://localhost:7007/api/resiliency-k8s/status')
      .then(res => (res.ok ? res.json() : null))
      .then(data => {
        if (!mounted || !data) {
          return;
        }
        if (data.workloads && data.workloads[depName]) {
          setLiveSnapshot(data.workloads[depName]);
        }
        if (data.latestDiffs && data.latestDiffs[depName]) {
          setLatestDiff(data.latestDiffs[depName]);
        }
      })
      .catch(() => {
        // Fallback to catalog annotations if backend API is unreachable in tests
      });
    return () => {
      mounted = false;
    };
  }, [depName]);

  if (!depName) {
    return null;
  }

  const kindLower = entity.kind.toLowerCase();
  const namespace = entity.metadata.namespace || 'default';
  const entityRef = `${kindLower}:${namespace}/${entity.metadata.name}`;
  const isStateful =
    annotations['resiliency.idp/k8s-stateful'] === 'true' || depName === 'db';

  const desiredReplicas =
    liveSnapshot?.desiredReplicas ??
    Number(
      annotations['resiliency.idp/k8s-desired-replicas'] ||
        annotations['resiliency.idp/k8s-baseline-replicas'] ||
        1,
    );
  const readyReplicas =
    liveSnapshot?.readyReplicas ??
    Number(annotations['resiliency.idp/k8s-ready-replicas'] || desiredReplicas);
  const minReplicas = annotations['resiliency.idp/k8s-min-replicas'] || '1';
  const maxReplicas =
    annotations['resiliency.idp/k8s-max-replicas'] ||
    (isStateful ? '1' : '10');
  const generation =
    liveSnapshot?.generation ??
    Number(annotations['resiliency.idp/k8s-generation'] || 1);
  const restartedAt =
    liveSnapshot?.restartedAt ||
    annotations['resiliency.idp/k8s-restarted-at'] ||
    'initial';
  const isHealthy =
    readyReplicas === desiredReplicas &&
    (liveSnapshot ? liveSnapshot.serviceHealthy : true);

  return (
    <InfoCard title="Kubernetes Day-2 Operations & Live K3s Workload Status">
      <div style={{ display: 'flex', flexDirection: 'column', gap: '10px' }}>
        <div
          style={{
            display: 'flex',
            alignItems: 'center',
            justifyContent: 'space-between',
          }}
        >
          <strong>Rollout &amp; Replica Status:</strong>
          <span
            style={{
              backgroundColor: isHealthy ? '#e8f5e9' : '#fff3e0',
              color: isHealthy ? '#1b5e20' : '#e65100',
              border: `1px solid ${isHealthy ? '#4caf50' : '#ff9800'}`,
              borderRadius: '12px',
              padding: '2px 10px',
              fontWeight: 700,
              fontSize: '0.85rem',
            }}
          >
            {isHealthy ? 'Healthy' : 'Scaling / Degraded'} ({readyReplicas} /{' '}
            {desiredReplicas} Pods Ready)
          </span>
        </div>

        <div>
          <strong>K3s Deployment:</strong>{' '}
          <code>
            deployment/{depName} (namespace: {liveSnapshot?.namespace || 'default'})
          </code>
        </div>
        <div>
          <strong>OPA Replica Guardrails:</strong>{' '}
          <code>
            min={minReplicas}, max={maxReplicas}
            {isStateful ? ' (Stateful DB — Scaling Locked)' : ' (Stateless Horizontal Scale)'}
          </code>
        </div>
        <div>
          <strong>Metadata Generation &amp; Strategy:</strong>{' '}
          <code>
            gen={generation} ({liveSnapshot?.strategy || 'RollingUpdate'}) | restartedAt={restartedAt}
          </code>
        </div>
        {liveSnapshot?.gitOpsReplicas !== undefined && (
          <div>
            <strong>GitOps Manifest (demo/k8s/manifest.yaml):</strong>{' '}
            <code>replicas: {liveSnapshot.gitOpsReplicas}</code>
          </div>
        )}
        {liveSnapshot?. pods && liveSnapshot.pods.length > 0 && (
          <div>
            <strong>Active K3s Pods:</strong>
            <div
              style={{
                display: 'flex',
                flexDirection: 'column',
                gap: '4px',
                marginTop: '4px',
              }}
            >
              {liveSnapshot.pods.map(pod => (
                <code
                  key={pod.name}
                  style={{
                    fontSize: '0.78rem',
                    padding: '3px 6px',
                    backgroundColor: 'rgba(128,128,128,0.12)',
                    borderRadius: '4px',
                  }}
                >
                  {pod.name} | IP: {pod.podIP} | {pod.phase} |{' '}
                  {pod.ready ? 'Ready' : 'NotReady'} (Restarts: {pod.restarts})
                </code>
              ))}
            </div>
          </div>
        )}

        {latestDiff && (
          <div
            style={{
              marginTop: '6px',
              padding: '10px',
              backgroundColor: '#1e1e1e',
              color: '#d4d4d4',
              borderRadius: '6px',
              fontSize: '0.78rem',
              overflowX: 'auto',
            }}
          >
            <div
              style={{
                fontWeight: 700,
                marginBottom: '6px',
                color: '#81c784',
              }}
            >
              Last Day-2 Operation Verified ({latestDiff.operationType.toUpperCase()}{' '}
              — {latestDiff.reason})
            </div>
            <pre style={{ margin: 0, fontFamily: 'monospace' }}>
              {latestDiff.unifiedDiff}
            </pre>
          </div>
        )}

        <div
          style={{
            display: 'flex',
            flexWrap: 'wrap',
            gap: '10px',
            marginTop: '8px',
            alignItems: 'center',
          }}
        >
          {!isStateful && (
            <LinkButton
              color="primary"
              variant="contained"
              to={buildDay2TemplateUrl(entityRef, 'scale')}
            >
              Scale Workload (Day-2)
            </LinkButton>
          )}
          <LinkButton
            color="primary"
            variant="outlined"
            to={buildDay2TemplateUrl(entityRef, 'rolling-restart')}
          >
            Rolling Restart (Day-2)
          </LinkButton>
          <a
            href="http://localhost:7007/api/resiliency-k8s/metrics"
            target="_blank"
            rel="noopener noreferrer"
            style={{ fontSize: '0.85rem', fontWeight: 600 }}
          >
            K8s Prometheus Metrics
          </a>
        </div>
      </div>
    </InfoCard>
  );
};

const k8sDay2Card = EntityCardBlueprint.make({
  name: 'k8s-day2-workload-card',
  params: {
    filter: 'kind:component,resource',
    loader: async () => <K8sDay2WorkloadCard />,
  },
});

export const k8sOpsModule = createFrontendModule({
  pluginId: 'catalog',
  extensions: [k8sDay2Card],
});

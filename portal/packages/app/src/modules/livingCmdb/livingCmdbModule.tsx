import { useEffect, useState } from 'react';
import { createFrontendModule } from '@backstage/frontend-plugin-api';
import { EntityCardBlueprint } from '@backstage/plugin-catalog-react/alpha';
import { useEntity } from '@backstage/plugin-catalog-react';
import { InfoCard } from '@backstage/core-components';

interface CmdbDriftItem {
  id: string;
  category: string;
  severity: string;
  fieldPath: string;
  gitDeclared: string;
  liveObserved: string;
  source: string;
  status: string;
}

interface BlastRadiusNode {
  node: string;
  relation: 'UPSTREAM_DEPENDENCY' | 'DOWNSTREAM_CONSUMER';
  hopDistance: number;
  exposureTier: string;
  impactSeverity: string;
  failurePropagationSummary: string;
}

interface EntityCmdbSnapshot {
  ciId: string;
  serviceName: string;
  ownerTeam: string;
  driftStatus: 'IN_SYNC' | 'DRIFT_DETECTED';
  declaredExposureTier: string;
  observedExposureTier: string;
  replicas: number;
  imageDigest: string;
  driftItems: CmdbDriftItem[];
  blastRadius: BlastRadiusNode[];
}

interface FleetCmdbTopologyReport {
  totalCis: number;
  driftedServices: number;
  shadowResourcesDetected: number;
  directedDependencyEdges: string[];
}

export const EntityLivingCmdbCard = () => {
  const { entity } = useEntity();
  const entityRef = `${entity.kind.toLowerCase()}:${entity.metadata.namespace || 'default'}/${entity.metadata.name}`;

  const [snapshot, setSnapshot] = useState<EntityCmdbSnapshot | null>(null);
  const [fleetGraph, setFleetGraph] = useState<FleetCmdbTopologyReport | null>(null);
  const [activeTab, setActiveTab] = useState<'drift' | 'blast' | 'topology'>('drift');
  const [loading, setLoading] = useState(true);

  const fetchData = async () => {
    setLoading(true);
    try {
      const [entityRes, fleetRes] = await Promise.all([
        fetch(`http://127.0.0.1:7007/api/living-cmdb/entity?entityRef=${encodeURIComponent(entityRef)}`),
        fetch(`http://127.0.0.1:7007/api/living-cmdb/fleet-graph`),
      ]);
      const entityData: EntityCmdbSnapshot = await entityRes.json();
      const fleetData: FleetCmdbTopologyReport = await fleetRes.json();
      setSnapshot(entityData);
      setFleetGraph(fleetData);
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    fetchData();
  }, [entityRef]);

  const handleReconcile = async (action: 'sync-to-git' | 'enforce-git-state', driftId?: string) => {
    const body: Record<string, string> = { entityRef, action };
    if (driftId) {
      body.driftId = driftId;
    }
    await fetch(`http://127.0.0.1:7007/api/living-cmdb/reconcile`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(body),
    });
    fetchData();
  };

  if (loading || !snapshot) {
    return <InfoCard title="🧭 Autonomous Living CMDB & Drift Reconciler">Loading…</InfoCard>;
  }

  const driftColor = snapshot.driftStatus === 'IN_SYNC' ? '#2e7d32' : '#d32f2f';

  return (
    <InfoCard
      title={`🧭 Autonomous Living CMDB & Drift Reconciler — ${snapshot.ciId} (${snapshot.serviceName})`}
    >
      <div style={{ marginBottom: 12 }}>
        <span style={{ marginRight: 16 }}>Owner Team: {snapshot.ownerTeam}</span>
        <span style={{ marginRight: 16 }}>
          Drift Status:{' '}
          <span style={{ color: driftColor, fontWeight: 'bold' }}>{snapshot.driftStatus}</span>
        </span>
        <span style={{ marginRight: 16 }}>
          Declared vs Observed Exposure Tier: {snapshot.declaredExposureTier} vs {snapshot.observedExposureTier}
        </span>
        <span style={{ marginRight: 16 }}>Replicas: {snapshot.replicas}</span>
        <span style={{ marginRight: 16 }}>Image Digest: {snapshot.imageDigest}</span>
      </div>
      <div style={{ marginBottom: 12 }}>
        <button
          style={{ marginRight: 8 }}
          onClick={() => handleReconcile('sync-to-git')}
        >
          ✅ Sync Runtime to Git
        </button>
        <button onClick={() => handleReconcile('enforce-git-state')}>🛡️ Enforce Git Intent</button>
      </div>
      <div style={{ marginBottom: 8 }}>
        <button
          style={{ marginRight: 8, fontWeight: activeTab === 'drift' ? 'bold' : 'normal' }}
          onClick={() => setActiveTab('drift')}
        >
          Drift
        </button>
        <button
          style={{ marginRight: 8, fontWeight: activeTab === 'blast' ? 'bold' : 'normal' }}
          onClick={() => setActiveTab('blast')}
        >
          Blast Radius
        </button>
        <button
          style={{ fontWeight: activeTab === 'topology' ? 'bold' : 'normal' }}
          onClick={() => setActiveTab('topology')}
        >
          Topology
        </button>
      </div>
      {activeTab === 'drift' && (
        <table style={{ width: '100%', borderCollapse: 'collapse' }}>
          <thead>
            <tr>
              <th>Category</th>
              <th>Severity</th>
              <th>Field Path</th>
              <th>Git Declared</th>
              <th>Live Observed</th>
              <th>Source</th>
              <th>Status</th>
              <th>Actions</th>
            </tr>
          </thead>
          <tbody>
            {snapshot.driftItems.map((item) => (
              <tr key={item.id}>
                <td>{item.category}</td>
                <td>{item.severity}</td>
                <td>{item.fieldPath}</td>
                <td>{item.gitDeclared}</td>
                <td>{item.liveObserved}</td>
                <td>{item.source}</td>
                <td>{item.status}</td>
                <td>
                  <button
                    style={{ marginRight: 4 }}
                    onClick={() => handleReconcile('sync-to-git', item.id)}
                  >
                    Sync to Git
                  </button>
                  <button onClick={() => handleReconcile('enforce-git-state', item.id)}>
                    Enforce Git
                  </button>
                </td>
              </tr>
            ))}
          </tbody>
        </table>
      )}
      {activeTab === 'blast' && (
        <table style={{ width: '100%', borderCollapse: 'collapse' }}>
          <thead>
            <tr>
              <th>Node</th>
              <th>Relation</th>
              <th>Hop Distance</th>
              <th>Exposure Tier</th>
              <th>Impact Severity</th>
              <th>Failure Propagation Summary</th>
            </tr>
          </thead>
          <tbody>
            {snapshot.blastRadius.map((node, idx) => (
              <tr key={idx}>
                <td>{node.node}</td>
                <td>{node.relation}</td>
                <td>{node.hopDistance}</td>
                <td>{node.exposureTier}</td>
                <td>{node.impactSeverity}</td>
                <td>{node.failurePropagationSummary}</td>
              </tr>
            ))}
          </tbody>
        </table>
      )}
      {activeTab === 'topology' && fleetGraph && (
        <div>
          <p>Fleet Configuration Items: {fleetGraph.totalCis}</p>
          <p>Drifted Services: {fleetGraph.driftedServices}</p>
          <p>Shadow Resources Detected: {fleetGraph.shadowResourcesDetected}</p>
          <p>Directed Dependency Edges:</p>
          <ul>
            {fleetGraph.directedDependencyEdges.map((edge, idx) => (
              <li key={idx}>{edge}</li>
            ))}
          </ul>
        </div>
      )}
    </InfoCard>
  );
};

const livingCmdbEntityCard = EntityCardBlueprint.make({
  name: 'living-cmdb-card',
  params: {
    filter: 'kind:component,resource',
    loader: async () => <EntityLivingCmdbCard />,
  },
});

export const livingCmdbModule = createFrontendModule({
  pluginId: 'catalog',
  extensions: [livingCmdbEntityCard],
});

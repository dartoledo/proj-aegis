import { useEffect, useState } from 'react';
import { createFrontendModule } from '@backstage/frontend-plugin-api';
import { EntityCardBlueprint } from '@backstage/plugin-catalog-react/alpha';
import { useEntity } from '@backstage/plugin-catalog-react';
import { InfoCard } from '@backstage/core-components';

interface ComponentTaxonomyCategoryMeta {
  id: string;
  domain: 'INFRASTRUCTURE' | 'SOFTWARE';
  layerId?: string;
  layerOrder?: number;
  layerLabel?: string;
  icon: string;
  label: string;
  definition: string;
  examples: string[];
}

interface CmdbComponentNode {
  componentId: string;
  name: string;
  versionOrIdentifier: string;
  domain: 'INFRASTRUCTURE' | 'SOFTWARE';
  layerId?: string;
  layerLabel?: string;
  categoryType: string;
  categoryLabel: string;
  icon: string;
  status: 'HEALTHY' | 'DRIFTED' | 'WARNING' | 'CRITICAL';
  notes?: string;
}

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
  componentInventory?: CmdbComponentNode[];
}

interface FleetCmdbTopologyReport {
  totalCis: number;
  driftedServices: number;
  shadowResourcesDetected: number;
  directedDependencyEdges: string[];
  taxonomyCatalog?: ComponentTaxonomyCategoryMeta[];
}

export const EntityLivingCmdbCard = () => {
  const { entity } = useEntity();
  const entityRef = `${entity.kind.toLowerCase()}:${entity.metadata.namespace || 'default'}/${entity.metadata.name}`;

  const [snapshot, setSnapshot] = useState<EntityCmdbSnapshot | null>(null);
  const [fleetGraph, setFleetGraph] = useState<FleetCmdbTopologyReport | null>(null);
  const [activeTab, setActiveTab] = useState<'drift' | 'blast' | 'topology' | 'taxonomy'>('drift');
  const [taxonomyDomainFilter, setTaxonomyDomainFilter] = useState<'ALL' | 'INFRASTRUCTURE' | 'SOFTWARE'>('ALL');
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

  if (loading || !snapshot) {
    return <InfoCard title="🧭 Autonomous Living CMDB & Drift Detection">Loading…</InfoCard>;
  }

  const driftColor = snapshot.driftStatus === 'IN_SYNC' ? '#2e7d32' : '#d32f2f';

  return (
    <InfoCard
      title={`🧭 Autonomous Living CMDB & Drift Detection — ${snapshot.ciId} (${snapshot.serviceName})`}
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
        <span style={{ marginRight: 16 }}>Replicas: {(snapshot as any).declaredReplicas ?? snapshot.replicas} vs {(snapshot as any).observedReplicas ?? snapshot.replicas}</span>
        <span style={{ marginRight: 16 }}>Image Digest: {snapshot.imageDigest ?? (snapshot as any).observedImageDigest}</span>
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
          style={{ marginRight: 8, fontWeight: activeTab === 'topology' ? 'bold' : 'normal' }}
          onClick={() => setActiveTab('topology')}
        >
          Topology
        </button>
        <button
          style={{ fontWeight: activeTab === 'taxonomy' ? 'bold' : 'normal' }}
          onClick={() => setActiveTab('taxonomy')}
        >
          Component Taxonomy
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
            </tr>
          </thead>
          <tbody>
            {snapshot.driftItems.map((item) => (
              <tr key={item.id ?? (item as any).driftId}>
                <td>{item.category}</td>
                <td>{item.severity}</td>
                <td>{item.fieldPath}</td>
                <td>{item.gitDeclared ?? (item as any).gitDeclaredValue}</td>
                <td>{item.liveObserved ?? (item as any).liveObservedValue}</td>
                <td>{item.source ?? (item as any).detectedSource}</td>
                <td>{item.status ?? (item as any).reconciliationStatus}</td>
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
                <td>{node.node ?? (node as any).entityRef}</td>
                <td>{node.relation}</td>
                <td>{node.hopDistance}</td>
                <td>{node.exposureTier}</td>
                <td>{node.impactSeverity}</td>
                <td>{node.failurePropagationSummary ?? (node as any).propagationRisk}</td>
              </tr>
            ))}
          </tbody>
        </table>
      )}
      {activeTab === 'topology' && fleetGraph && (
        <div>
          <p>Fleet Configuration Items: {fleetGraph.totalCis ?? (fleetGraph as any).totalConfigurationItems ?? (fleetGraph as any).totalNodes}</p>
          <p>Drifted Services: {fleetGraph.driftedServices ?? (fleetGraph as any).driftedServicesCount}</p>
          <p>Shadow Resources Detected: {fleetGraph.shadowResourcesDetected}</p>
          <p>Directed Dependency Edges:</p>
          <ul>
            {(fleetGraph.directedDependencyEdges ?? (fleetGraph as any).directedEdges ?? []).map((edge: any, idx: number) => (
              <li key={idx}>{typeof edge === 'string' ? edge : `${edge.from} -> ${edge.to} (${edge.protocol})`}</li>
            ))}
          </ul>
        </div>
      )}
      {activeTab === 'taxonomy' && (
        <div>
          <div style={{ marginBottom: 12 }}>
            <button
              style={{ marginRight: 8, fontWeight: taxonomyDomainFilter === 'ALL' ? 'bold' : 'normal' }}
              onClick={() => setTaxonomyDomainFilter('ALL')}
            >
              All Domains
            </button>
            <button
              style={{ marginRight: 8, fontWeight: taxonomyDomainFilter === 'INFRASTRUCTURE' ? 'bold' : 'normal' }}
              onClick={() => setTaxonomyDomainFilter('INFRASTRUCTURE')}
            >
              I. Infrastructure (7 Layers)
            </button>
            <button
              style={{ fontWeight: taxonomyDomainFilter === 'SOFTWARE' ? 'bold' : 'normal' }}
              onClick={() => setTaxonomyDomainFilter('SOFTWARE')}
            >
              II. Software (13 Categories)
            </button>
          </div>
          {snapshot.componentInventory && snapshot.componentInventory.length > 0 && (
            <div style={{ marginBottom: 16 }}>
              <h4>Active Component Inventory</h4>
              <table style={{ width: '100%', borderCollapse: 'collapse' }}>
                <thead>
                  <tr>
                    <th>Domain</th>
                    <th>Category</th>
                    <th>Team Owner</th>
                    <th>Component Name</th>
                    <th>Version/Identifier</th>
                    <th>External EOL &amp; CVE Crosswalk</th>
                    <th>Status</th>
                    <th>Notes</th>
                  </tr>
                </thead>
                <tbody>
                  {snapshot.componentInventory
                    .filter((node) => taxonomyDomainFilter === 'ALL' || node.domain === taxonomyDomainFilter)
                    .map((node, idx) => (
                      <tr key={idx}>
                        <td>
                          <span style={{ fontWeight: 'bold' }}>
                            {node.domain === 'INFRASTRUCTURE' ? 'I. Infrastructure' : 'II. Software'}
                          </span>
                          {node.layerLabel && (
                            <span style={{ marginLeft: 8, fontSize: '0.85em', color: '#555' }}>{node.layerLabel}</span>
                          )}
                        </td>
                        <td>
                          <span style={{ marginRight: 4 }}>{node.icon}</span>
                          {node.categoryLabel}
                        </td>
                        <td><strong>{(node as any).ownerTeamName ?? ((node as any).ownerTeamId === 'app-team' ? 'App Team' : 'SRE Team')}</strong></td>
                        <td>{node.name}</td>
                        <td>{node.versionOrIdentifier}</td>
                        <td style={{ fontSize: '0.82em' }}>
                          {(node as any).normalizedVersion ? (
                            <div>
                              <div><code>{(node as any).normalizedVersion.purl}</code></div>
                              <div><code>{(node as any).normalizedVersion.cpe23Uri}</code></div>
                              <div>
                                EOL: <strong>{(node as any).normalizedVersion.eolProductSlug}@{(node as any).normalizedVersion.eolCycleKey}</strong> ({(node as any).normalizedVersion.eolCycleStrategy}) | OSV: <strong>{(node as any).normalizedVersion.osvEcosystem}/{(node as any).normalizedVersion.osvPackageName}</strong>
                              </div>
                              <div>
                                Sort Tuple: <code>[{(node as any).normalizedVersion.semverSortTuple.join(', ')}]</code>
                              </div>
                            </div>
                          ) : '—'}
                        </td>
                        <td>
                          <span
                            style={{
                              color:
                                node.status === 'HEALTHY'
                                  ? '#2e7d32'
                                  : node.status === 'DRIFTED'
                                  ? '#d32f2f'
                                  : node.status === 'WARNING'
                                  ? '#f9a825'
                                  : '#d32f2f',
                              fontWeight: 'bold',
                            }}
                          >
                            {node.status}
                          </span>
                        </td>
                        <td>{node.notes ?? '—'}</td>
                      </tr>
                    ))}
                </tbody>
              </table>
            </div>
          )}
          {fleetGraph?.taxonomyCatalog && fleetGraph.taxonomyCatalog.length > 0 && (
            <div>
              <h4>Taxonomy Reference Matrix</h4>
              {taxonomyDomainFilter !== 'SOFTWARE' && (
                <div style={{ marginBottom: 16 }}>
                  <h5>Section I: Infrastructure (7 Layers)</h5>
                  {fleetGraph.taxonomyCatalog
                    .filter((cat) => cat.domain === 'INFRASTRUCTURE')
                    .sort((a, b) => (a.layerOrder ?? 0) - (b.layerOrder ?? 0))
                    .map((cat) => (
                      <div key={cat.id} style={{ marginBottom: 8, padding: 8, border: '1px solid #e0e0e0', borderRadius: 4 }}>
                        <div style={{ fontWeight: 'bold', marginBottom: 4 }}>
                          <span style={{ marginRight: 8 }}>{cat.icon}</span>
                          {cat.layerLabel && <span style={{ marginRight: 8, color: '#555' }}>{cat.layerLabel}</span>}
                          {cat.label}
                        </div>
                        <div style={{ fontSize: '0.9em', marginBottom: 4 }}>{cat.definition}</div>
                        <div style={{ fontSize: '0.85em', color: '#555' }}>
                          Examples: {cat.examples.join(', ')}
                        </div>
                      </div>
                    ))}
                </div>
              )}
              {taxonomyDomainFilter !== 'INFRASTRUCTURE' && (
                <div>
                  <h5>Section II: Software (13 Categories)</h5>
                  {fleetGraph.taxonomyCatalog
                    .filter((cat) => cat.domain === 'SOFTWARE')
                    .map((cat) => (
                      <div key={cat.id} style={{ marginBottom: 8, padding: 8, border: '1px solid #e0e0e0', borderRadius: 4 }}>
                        <div style={{ fontWeight: 'bold', marginBottom: 4 }}>
                          <span style={{ marginRight: 8 }}>{cat.icon}</span>
                          {cat.label}
                        </div>
                        <div style={{ fontSize: '0.9em', marginBottom: 4 }}>{cat.definition}</div>
                        <div style={{ fontSize: '0.85em', color: '#555' }}>
                          Examples: {cat.examples.join(', ')}
                        </div>
                      </div>
                    ))}
                </div>
              )}
            </div>
          )}
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

import { useEffect, useMemo, useState } from 'react';
import { Content, Header, InfoCard, Link, Page } from '@backstage/core-components';
import {
  FALLBACK_COMPONENTS,
  FALLBACK_DRIFTS,
  UnifiedComponentItem,
  UnifiedDriftRecord,
  fetchUnifiedInventoryData,
} from './inventoryData';

export function InfrastructureInventoryView() {
  const [infrastructure, setInfrastructure] = useState<UnifiedComponentItem[]>(() =>
    FALLBACK_COMPONENTS.filter(c => c.domain === 'INFRASTRUCTURE'),
  );
  const [drifts, setDrifts] = useState<UnifiedDriftRecord[]>(FALLBACK_DRIFTS);
  const [search, setSearch] = useState('');
  const [layerFilter, setLayerFilter] = useState('ALL');
  const [statusFilter, setStatusFilter] = useState('ALL');

  const layers = useMemo(
    () => Array.from(new Set(infrastructure.map(i => i.layerLabel || i.categoryLabel))),
    [infrastructure],
  );

  useEffect(() => {
    fetchUnifiedInventoryData()
      .then(d => {
        if (d.infrastructure.length > 0) setInfrastructure(d.infrastructure);
        if (d.drifts.length > 0) setDrifts(d.drifts);
      })
      .catch(() => {});
  }, []);

  const filteredInfra = useMemo(
    () =>
      infrastructure.filter(item => {
        const searchStr = `${item.name} ${item.serviceName} ${item.versionOrIdentifier} ${item.categoryLabel} ${item.notes || ''}`.toLowerCase();
        const matchesSearch = !search || searchStr.includes(search.toLowerCase());
        const matchesLayer = layerFilter === 'ALL' || (item.layerLabel || item.categoryLabel) === layerFilter;
        const matchesStatus = statusFilter === 'ALL' || item.status === statusFilter;
        return matchesSearch && matchesLayer && matchesStatus;
      }),
    [infrastructure, search, layerFilter, statusFilter],
  );

  return (
    <Page themeId="tool">
      <Header
        title="Unified Inventory — Infrastructure"
        subtitle="7-Layer Infrastructure Topology, GitOps Drift Detection & Shadow Resource Telemetry"
      />
      <Content>
        <InfoCard title="Infrastructure Component Inventory">
          <div style={{ display: 'flex', gap: '1rem', marginBottom: '1rem' }}>
            <div><strong>Total Infrastructure CIs:</strong> {infrastructure.length}</div>
            <div><strong>Healthy:</strong> {infrastructure.filter(i => i.status === 'HEALTHY').length}</div>
            <div><strong>Drifted CIs:</strong> {infrastructure.filter(i => i.status === 'DRIFTED').length}</div>
            <div><strong>Active GitOps Drifts:</strong> {drifts.length}</div>
          </div>
          <div style={{ display: 'flex', gap: '0.5rem', marginBottom: '1rem' }}>
            <input
              aria-label="Search infrastructure"
              placeholder="Search resource, identifier, service, notes..."
              value={search}
              onChange={e => setSearch(e.target.value)}
            />
            <select
              aria-label="Layer filter"
              value={layerFilter}
              onChange={e => setLayerFilter(e.target.value)}
            >
              <option value="ALL">All Architectural Layers</option>
              {layers.map(l => (
                <option key={l} value={l}>{l}</option>
              ))}
            </select>
            <select
              aria-label="Status filter"
              value={statusFilter}
              onChange={e => setStatusFilter(e.target.value)}
            >
              <option value="ALL">All Statuses</option>
              <option value="HEALTHY">HEALTHY</option>
              <option value="DRIFTED">DRIFTED</option>
              <option value="WARNING">WARNING</option>
              <option value="CRITICAL">CRITICAL</option>
            </select>
          </div>
          <table style={{ width: '100%', borderCollapse: 'collapse' }}>
            <thead>
              <tr>
                <th>Infrastructure Component</th>
                <th>Architectural Layer</th>
                <th>Category</th>
                <th>Identifier / Config</th>
                <th>Service</th>
                <th>Owner Team</th>
                <th>Status</th>
                <th>Notes</th>
              </tr>
            </thead>
            <tbody>
              {filteredInfra.map(item => (
                <tr key={item.componentId}>
                  <td>{item.icon} {item.name}</td>
                  <td>{item.layerLabel || item.categoryLabel}</td>
                  <td>{item.categoryLabel}</td>
                  <td>{item.versionOrIdentifier}</td>
                  <td>
                    <Link to={`/catalog/default/component/${item.serviceName}`}>
                      {item.serviceName}
                    </Link>
                  </td>
                  <td>{item.ownerTeamName}</td>
                  <td>{item.status}</td>
                  <td>{item.notes}</td>
                </tr>
              ))}
            </tbody>
          </table>
          <h4>GitOps Drift &amp; Shadow Resource Detection ({drifts.length})</h4>
          <table style={{ width: '100%', borderCollapse: 'collapse' }}>
            <thead>
              <tr>
                <th>Service</th>
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
              {drifts.map((d, idx) => (
                <tr key={idx}>
                  <td>{d.serviceName}</td>
                  <td>{d.category}</td>
                  <td>{d.severity}</td>
                  <td>{d.fieldPath}</td>
                  <td>{d.gitDeclaredValue}</td>
                  <td>{d.liveObservedValue}</td>
                  <td>{d.detectedSource}</td>
                  <td>{d.status}</td>
                </tr>
              ))}
            </tbody>
          </table>
        </InfoCard>
      </Content>
    </Page>
  );
}

import { useEffect, useMemo, useState } from 'react';
import { Content, Header, InfoCard, Link, Page } from '@backstage/core-components';
import { FALLBACK_COMPONENTS, UnifiedComponentItem, fetchUnifiedInventoryData } from './inventoryData';

export function SoftwareInventoryView() {
  const [software, setSoftware] = useState<UnifiedComponentItem[]>(() =>
    FALLBACK_COMPONENTS.filter(c => c.domain === 'SOFTWARE'),
  );
  const [search, setSearch] = useState('');
  const [categoryFilter, setCategoryFilter] = useState('ALL');
  const [statusFilter, setStatusFilter] = useState('ALL');
  const [teamFilter, setTeamFilter] = useState('ALL');

  useEffect(() => {
    fetchUnifiedInventoryData()
      .then(d => {
        if (d.software.length > 0) setSoftware(d.software);
      })
      .catch(() => {});
  }, []);

  const categories = useMemo(
    () => Array.from(new Set(software.map(s => s.categoryLabel))),
    [software],
  );

  const filteredSoftware = useMemo(
    () =>
      software.filter(s => {
        const q = search.toLowerCase();
        const matchesSearch =
          !q ||
          s.name.toLowerCase().includes(q) ||
          (s.versionOrIdentifier || '').toLowerCase().includes(q) ||
          (s.serviceName || '').toLowerCase().includes(q) ||
          (s.categoryLabel || '').toLowerCase().includes(q) ||
          (s.purl || '').toLowerCase().includes(q) ||
          (s.cpe23Uri || '').toLowerCase().includes(q);
        const matchesCategory = categoryFilter === 'ALL' || s.categoryLabel === categoryFilter;
        const matchesStatus = statusFilter === 'ALL' || s.status === statusFilter;
        const matchesTeam = teamFilter === 'ALL' || s.ownerTeamName === teamFilter;
        return matchesSearch && matchesCategory && matchesStatus && matchesTeam;
      }),
    [software, search, categoryFilter, statusFilter, teamFilter],
  );

  return (
    <Page themeId="tool">
      <Header
        title="Unified Inventory — Software"
        subtitle="13-Category Software Taxonomy, SBOM PURL / CPE 2.3 Crosswalk, End-of-Life & CVE Posture"
      />
      <Content>
        <InfoCard title="Software Component Inventory">
          <div style={{ display: 'flex', gap: 24, marginBottom: 16 }}>
            <div><strong>Total Software:</strong> {software.length}</div>
            <div><strong>Healthy:</strong> {software.filter(s => s.status === 'HEALTHY').length}</div>
            <div><strong>Critical / EOL:</strong> {software.filter(s => s.status === 'CRITICAL').length}</div>
            <div><strong>Total CVEs:</strong> {software.reduce((acc, s) => acc + (s.cveCount || 0), 0)}</div>
          </div>
          <div style={{ display: 'flex', gap: 8, marginBottom: 16, flexWrap: 'wrap' }}>
            <input
              aria-label="Search software"
              placeholder="Search software, version, PURL, service..."
              value={search}
              onChange={e => setSearch(e.target.value)}
            />
            <select aria-label="Category filter" value={categoryFilter} onChange={e => setCategoryFilter(e.target.value)}>
              <option value="ALL">All Categories</option>
              {categories.map(c => (
                <option key={c} value={c}>{c}</option>
              ))}
            </select>
            <select aria-label="Status filter" value={statusFilter} onChange={e => setStatusFilter(e.target.value)}>
              <option value="ALL">All Statuses</option>
              <option value="HEALTHY">HEALTHY</option>
              <option value="WARNING">WARNING</option>
              <option value="CRITICAL">CRITICAL</option>
            </select>
            <select aria-label="Team filter" value={teamFilter} onChange={e => setTeamFilter(e.target.value)}>
              <option value="ALL">All Teams</option>
              <option value="App Team">App Team</option>
              <option value="SRE Team">SRE Team</option>
            </select>
          </div>
          <table style={{ width: '100%', borderCollapse: 'collapse' }}>
            <thead>
              <tr>
                <th>Component</th>
                <th>Category</th>
                <th>Version</th>
                <th>Service</th>
                <th>SBOM Crosswalk</th>
                <th>CVEs</th>
                <th>Status</th>
                <th>Owner Team</th>
                <th>Notes</th>
              </tr>
            </thead>
            <tbody>
              {filteredSoftware.map((s, i) => (
                <tr key={i}>
                  <td><span>{s.icon}</span> <span>{s.name}</span></td>
                  <td>{s.categoryLabel}</td>
                  <td>{s.versionOrIdentifier}</td>
                  <td><Link to={`/catalog/default/component/${s.serviceName}`}>{s.serviceName}</Link></td>
                  <td>
                    {s.purl && <div>PURL: {s.purl}</div>}
                    {s.cpe23Uri && <div>CPE: {s.cpe23Uri}</div>}
                    {s.eolSlug && <div>EOL Cycle: {s.eolSlug} ({s.eolStatus || s.status})</div>}
                  </td>
                  <td>{s.cveCount || 0}</td>
                  <td>{s.status}</td>
                  <td>{s.ownerTeamName}</td>
                  <td>{s.notes}</td>
                </tr>
              ))}
            </tbody>
          </table>
        </InfoCard>
      </Content>
    </Page>
  );
}

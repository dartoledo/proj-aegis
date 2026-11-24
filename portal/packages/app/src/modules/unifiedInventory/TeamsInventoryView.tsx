import { useEffect, useMemo, useState } from 'react';
import { Content, Header, InfoCard, Link, Page } from '@backstage/core-components';
import { FALLBACK_TEAMS, UnifiedTeamRecord, fetchUnifiedInventoryData } from './inventoryData';
import { buildFallbackAttackGraphReport } from '../infrahubAttackGraph/infrahubFallbackData';

export function TeamsInventoryView() {
  const [teams, setTeams] = useState<UnifiedTeamRecord[]>(FALLBACK_TEAMS);
  const [search, setSearch] = useState('');
  const [typeFilter, setTypeFilter] = useState('ALL');

  useEffect(() => {
    fetchUnifiedInventoryData()
      .then(d => {
        if (d.teams.length > 0) setTeams(d.teams);
      })
      .catch(() => {});
  }, []);

  const filteredTeams = useMemo(() => {
    return teams.filter(t => {
      const haystack = `${t.teamName} ${t.email} ${t.slackChannel} ${t.responsibilityScope} ${t.ownedServices.join(' ')}`.toLowerCase();
      const matchesSearch = search === '' || haystack.includes(search.toLowerCase());
      const matchesType = typeFilter === 'ALL' || t.teamType === typeFilter;
      return matchesSearch && matchesType;
    });
  }, [teams, search, typeFilter]);

  return (
    <Page themeId="tool">
      <Header
        title="Unified Inventory — Teams & Ownership"
        subtitle="App Team vs SRE Team Governance Split, Service Delivery Squads & Owned Asset Rollup"
      />
      <Content>
        <InfoCard title="Teams & Asset Ownership Inventory">
          <div style={{ display: 'flex', gap: '1rem', marginBottom: '1rem' }}>
            <div><strong>Total Teams:</strong> {teams.length}</div>
            <div><strong>Owned Services:</strong> {Array.from(new Set(teams.flatMap(t => t.ownedServices))).length}</div>
            <div><strong>Software Assets:</strong> {teams.reduce((a, t) => a + t.softwareCount, 0)}</div>
            <div><strong>Infrastructure Assets:</strong> {teams.reduce((a, t) => a + t.infrastructureCount, 0)}</div>
          </div>
          <div style={{ display: 'flex', gap: '0.5rem', marginBottom: '1rem' }}>
            <input
              aria-label="Search teams"
              placeholder="Search team, email, Slack, scope, or service..."
              value={search}
              onChange={e => setSearch(e.target.value)}
            />
            <select
              aria-label="Team type filter"
              value={typeFilter}
              onChange={e => setTypeFilter(e.target.value)}
            >
              <option value="ALL">All Team Types</option>
              <option value="SERVICE_SQUAD">SERVICE_SQUAD</option>
              <option value="GOVERNANCE_DOMAIN">GOVERNANCE_DOMAIN</option>
            </select>
          </div>
          <table>
            <thead>
              <tr>
                <th>Team Name</th>
                <th>Type</th>
                <th>Contact (Email / Slack)</th>
                <th>Responsibility Scope</th>
                <th>Owned Services</th>
                <th>Software / Infra / Endpoints</th>
                <th>Drifted / Critical</th>
                <th>Attack-Path Risk Rollup</th>
              </tr>
            </thead>
            <tbody>
              {filteredTeams.map(t => (
                <tr key={t.teamId}>
                  <td>{t.teamName}</td>
                  <td>{t.teamType}</td>
                  <td>{t.email} / {t.slackChannel}</td>
                  <td>{t.responsibilityScope}</td>
                  <td>
                    {t.ownedServices.map(s => (
                      <span key={s} style={{ marginRight: 8 }}><Link to={`/catalog/default/component/${s}`}>{s}</Link></span>
                    ))}
                  </td>
                  <td>{t.softwareCount} / {t.infrastructureCount} / {t.endpointCount}</td>
                  <td>{t.driftedOrCriticalCount}</td>
                  <td>
                    {(() => {
                      const serviceReports = t.ownedServices.map(s => buildFallbackAttackGraphReport(s));
                      const maxRisk = serviceReports.reduce((m, r) => Math.max(m, r.facts.attack_path_risk_score), 0);
                      const totalKev = serviceReports.reduce((m, r) => m + r.facts.reachable_kev_cve_count, 0);
                      return `Max Risk: ${maxRisk}/100 | KEV CVEs: ${totalKev}`;
                    })()}
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </InfoCard>
      </Content>
    </Page>
  );
}

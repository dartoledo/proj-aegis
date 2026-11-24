import { useEffect, useMemo, useState } from 'react';
import { Content, Header, InfoCard, Link, Page } from '@backstage/core-components';
import { FALLBACK_ENDPOINTS, UnifiedEndpointItem, fetchUnifiedInventoryData } from './inventoryData';
import { buildFallbackAttackGraphReport } from '../infrahubAttackGraph/infrahubFallbackData';

export function DomainsEndpointsView() {
  const [endpoints, setEndpoints] = useState<UnifiedEndpointItem[]>(FALLBACK_ENDPOINTS);
  const [search, setSearch] = useState('');
  const [envFilter, setEnvFilter] = useState<string>('ALL');
  const [exposureFilter, setExposureFilter] = useState<string>('ALL');
  const [statusFilter, setStatusFilter] = useState<string>('ALL');

  useEffect(() => {
    fetchUnifiedInventoryData()
      .then(data => {
        if (data.endpoints.length > 0) {
          setEndpoints(data.endpoints);
        }
      })
      .catch(() => {});
  }, []);

  const filteredEndpoints = useMemo(() => {
    return endpoints.filter(ep => {
      const haystack = `${ep.serviceName} ${ep.endpointUrl} ${ep.sniHostname} ${ep.issuerCn} ${ep.serialNumberHex}`.toLowerCase();
      if (search && !haystack.includes(search.toLowerCase())) return false;

      if (envFilter !== 'ALL' && ep.environment !== envFilter) return false;

      if (exposureFilter !== 'ALL' && ep.exposureScope !== exposureFilter) return false;

      if (statusFilter !== 'ALL' && ep.complianceStatus !== statusFilter) return false;

      return true;
    });
  }, [endpoints, search, envFilter, exposureFilter, statusFilter]);

  return (
    <Page themeId="tool">
      <Header
        title="Unified Inventory — Domains & Endpoints"
        subtitle="Multi-Environment Ingress FQDNs, 3-Tier Exposure Scope, Split-Horizon DNS & X.509 Certificate Compliance"
      />
      <Content>
        <InfoCard title="Domains & Endpoints Inventory">
          <div style={{ display: 'flex', gap: '1rem', marginBottom: '1rem' }}>
            <div><strong>Total Endpoints:</strong> {endpoints.length}</div>
            <div><strong>Unrestricted Public:</strong> {endpoints.filter(e => e.exposureScope === 'unrestricted-public').length}</div>
            <div><strong>Restricted Public:</strong> {endpoints.filter(e => e.exposureScope === 'restricted-public').length}</div>
            <div><strong>Strictly Private:</strong> {endpoints.filter(e => e.exposureScope === 'strictly-private').length}</div>
            <div><strong>Compliant X.509:</strong> {endpoints.filter(e => e.complianceStatus === 'COMPLIANT').length}</div>
          </div>
          <div style={{ display: 'flex', gap: '0.5rem', marginBottom: '1rem' }}>
            <input
              aria-label="Search endpoints"
              placeholder="Search domain, URL, service, issuer..."
              value={search}
              onChange={e => setSearch(e.target.value)}
            />
            <select
              aria-label="Environment filter"
              value={envFilter}
              onChange={e => setEnvFilter(e.target.value)}
            >
              <option value="ALL">All Envs</option>
              <option value="prod">prod</option>
              <option value="preprod">preprod</option>
              <option value="stg">stg</option>
              <option value="stress-test">stress-test</option>
              <option value="dev">dev</option>
            </select>
            <select
              aria-label="Exposure filter"
              value={exposureFilter}
              onChange={e => setExposureFilter(e.target.value)}
            >
              <option value="ALL">All Exposure Tiers</option>
              <option value="unrestricted-public">Unrestricted Public</option>
              <option value="restricted-public">Restricted Public</option>
              <option value="strictly-private">Strictly Private</option>
            </select>
            <select
              aria-label="Compliance filter"
              value={statusFilter}
              onChange={e => setStatusFilter(e.target.value)}
            >
              <option value="ALL">All Statuses</option>
              <option value="COMPLIANT">COMPLIANT</option>
              <option value="WARNING">WARNING</option>
              <option value="NON_COMPLIANT">NON_COMPLIANT</option>
            </select>
          </div>
          <table style={{ width: '100%', borderCollapse: 'collapse' }}>
            <thead>
              <tr>
                <th>Endpoint / SNI</th>
                <th>Service</th>
                <th>Env</th>
                <th>Exposure &amp; DNS</th>
                <th>Provider</th>
                <th>Certificate &amp; Expiry</th>
                <th>Status</th>
                <th>Owner</th>
                <th>Attack-Path Risk</th>
              </tr>
            </thead>
            <tbody>
              {filteredEndpoints.map(ep => (
                <tr key={ep.endpointId}>
                  <td><div><strong>{ep.endpointUrl}</strong><div style={{ fontSize: 12, color: '#666' }}>SNI: {ep.sniHostname}</div></div></td>
                  <td><Link to={`/catalog/default/component/${ep.serviceName}`}>{ep.serviceName}</Link></td>
                  <td>{ep.environment}</td>
                  <td>{ep.exposureScope} / {ep.dnsScope}</td>
                  <td>{ep.providerType}</td>
                  <td><div>{ep.issuerCn} ({ep.algorithm}) — {ep.daysRemaining}d remaining<div style={{ fontSize: 11, color: '#666' }}>Serial: {ep.serialNumberHex}</div></div></td>
                  <td>{ep.complianceStatus}</td>
                  <td>{ep.ownerTeam}</td>
                  <td>{(() => { const attackReport = buildFallbackAttackGraphReport(ep.serviceName); return `${attackReport.facts.attack_path_risk_score}/100 (${attackReport.scorecardStatus})`; })()}</td>
                </tr>
              ))}
            </tbody>
          </table>
        </InfoCard>
      </Content>
    </Page>
  );
}

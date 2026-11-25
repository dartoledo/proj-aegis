import { useEffect, useMemo, useState } from 'react';
import { Content, Header, InfoCard, Link, Page } from '@backstage/core-components';
import { FALLBACK_ENDPOINTS, UnifiedEndpointItem, fetchUnifiedInventoryData } from './inventoryData';
import { buildFallbackAttackGraphReport } from '../infrahubAttackGraph/infrahubFallbackData';

interface ActiveProbeSslDetails {
  subjectCn: string;
  subjectDn: string;
  sanDnsNames: string[];
  issuerCn: string;
  issuerOrg: string;
  serialNumberHex: string;
  notBefore: string;
  notAfter: string;
  daysRemaining: number;
  expiryStatus: string;
  signatureAlgorithm: string;
  signatureHashAlgorithm: string;
  publicKeyAlgorithm: string;
  publicKeyBits: number;
  complianceStatus: string;
}

interface ActiveProbeItemResult {
  targetInput: string;
  endpointId: string;
  endpointUrl: string;
  hostname: string;
  port: number;
  reachable: boolean;
  error?: string;
  sourceIp: string;
  isZscalerSourceIp: boolean;
  probeNetworkOrigin: 'PRIVATE_NETWORK_ZSCALER' | 'PUBLIC_INTERNET';
  accessibleFromPublicInternet: boolean;
  exposureScope: string;
  wafProvider: 'Akamai' | 'Fastly' | 'Cloud Armor' | 'None';
  wafDetected: boolean;
  wafEvidence: string[];
  httpStatusCode: number | null;
  sslDetails: ActiveProbeSslDetails | null;
  probedAt: string;
}

interface ActiveProbeBatchReport {
  networkContext: {
    sourceIp: string;
    isZscalerSourceIp: boolean;
    networkOrigin: 'PRIVATE_NETWORK_ZSCALER' | 'PUBLIC_INTERNET';
    detectionReason: string;
  };
  totalProbed: number;
  reachableCount: number;
  publicAccessibleCount: number;
  wafProtectedCount: number;
  results: ActiveProbeItemResult[];
}

interface CsvImportValidationError {
  rowNumber: number;
  message: string;
}

interface CsvImportBatchReport {
  totalDataRows: number;
  importedCount: number;
  probedCount: number;
  probedReachableCount: number;
  publicAccessibleCount: number;
  wafProtectedCount: number;
  errors: CsvImportValidationError[];
}

const DEFAULT_CSV_TEMPLATE = [
  'endpoint,service_name,environment,endpoint_key,provider_type,exposure_scope,owner_team_id,notes',
  'https://127.0.0.1:8443,hello-world-app,prod,edge-haproxy,haproxy-edge,restricted-public,sre-team,HAProxy local TLS sandbox',
].join('\n');

export function DomainsEndpointsView() {
  const [endpoints, setEndpoints] = useState<UnifiedEndpointItem[]>(FALLBACK_ENDPOINTS);
  const [search, setSearch] = useState('');
  const [envFilter, setEnvFilter] = useState<string>('ALL');
  const [exposureFilter, setExposureFilter] = useState<string>('ALL');
  const [statusFilter, setStatusFilter] = useState<string>('ALL');

  const [probeInputText, setProbeInputText] = useState('https://127.0.0.1:8443');
  const [sourceIpOverride, setSourceIpOverride] = useState('');
  const [probing, setProbing] = useState(false);
  const [probeReport, setProbeReport] = useState<ActiveProbeBatchReport | null>(null);
  const [probeError, setProbeError] = useState<string | null>(null);

  const [csvContent, setCsvContent] = useState(DEFAULT_CSV_TEMPLATE);
  const [probeOnCsvImport, setProbeOnCsvImport] = useState(true);
  const [importingCsv, setImportingCsv] = useState(false);
  const [csvImportReport, setCsvImportReport] = useState<CsvImportBatchReport | null>(null);
  const [csvImportError, setCsvImportError] = useState<string | null>(null);

  const loadInventory = () => {
    fetchUnifiedInventoryData()
      .then(data => {
        if (data.endpoints.length > 0) {
          setEndpoints(data.endpoints);
        }
      })
      .catch(() => {});
  };

  useEffect(() => {
    loadInventory();
  }, []);

  const handleRunActiveProbe = async () => {
    const rawTargets = probeInputText
      .split(/[\n,]+/)
      .map(s => s.trim())
      .filter(Boolean);
    if (rawTargets.length === 0) return;

    setProbing(true);
    setProbeError(null);
    try {
      const res = await fetch('http://localhost:7007/api/ssl-tracker/probe-active', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          endpoints: rawTargets,
          ...(sourceIpOverride.trim() ? { sourceIpOverride: sourceIpOverride.trim() } : {}),
          persistToCmdb: true,
        }),
      });
      if (!res.ok) {
        throw new Error(`Probe request failed with status ${res.status}`);
      }
      const data: ActiveProbeBatchReport = await res.json();
      setProbeReport(data);
      loadInventory();
    } catch (err) {
      setProbeError(err instanceof Error ? err.message : 'Active probe failed');
    } finally {
      setProbing(false);
    }
  };

  const handleCsvFileSelect = (file: File | null | undefined) => {
    if (!file) return;
    const reader = new FileReader();
    reader.onload = () => {
      if (typeof reader.result === 'string') {
        setCsvContent(reader.result);
      }
    };
    reader.readAsText(file);
  };

  const handleImportCsv = async () => {
    if (!csvContent.trim()) return;
    setImportingCsv(true);
    setCsvImportError(null);
    try {
      const res = await fetch('http://localhost:7007/api/ssl-tracker/import-csv', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          csvContent,
          probeOnImport: probeOnCsvImport,
          ...(sourceIpOverride.trim() ? { sourceIpOverride: sourceIpOverride.trim() } : {}),
        }),
      });
      if (!res.ok) {
        throw new Error(`CSV import failed with status ${res.status}`);
      }
      const report: CsvImportBatchReport = await res.json();
      setCsvImportReport(report);
      loadInventory();
    } catch (err) {
      setCsvImportError(err instanceof Error ? err.message : 'CSV import failed');
    } finally {
      setImportingCsv(false);
    }
  };

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
        <div style={{ marginBottom: '1.25rem' }}>
          <InfoCard title="⚡ Active Endpoint Prober — Live SSL, WAF (Akamai / Fastly / Cloud Armor) & Public vs. Zscaler Network Discovery">
            <div style={{ display: 'flex', flexWrap: 'wrap', gap: '1rem', alignItems: 'flex-start', marginBottom: '0.75rem' }}>
              <div style={{ flex: '2 1 360px' }}>
                <label htmlFor="active-probe-endpoints" style={{ display: 'block', fontWeight: 'bold', marginBottom: 4 }}>
                  Endpoints List (URLs or FQDNs, one per line or comma-separated)
                </label>
                <textarea
                  id="active-probe-endpoints"
                  aria-label="Active probe endpoints list"
                  rows={3}
                  style={{ width: '100%', fontFamily: 'monospace', padding: 6 }}
                  value={probeInputText}
                  onChange={e => setProbeInputText(e.target.value)}
                  placeholder="https://127.0.0.1:8443&#10;https://example.com"
                />
              </div>
              <div style={{ flex: '1 1 240px' }}>
                <label htmlFor="active-probe-source-ip" style={{ display: 'block', fontWeight: 'bold', marginBottom: 4 }}>
                  Source IP Override (optional — Zscaler vs. Public IP test)
                </label>
                <input
                  id="active-probe-source-ip"
                  aria-label="Source IP override"
                  type="text"
                  style={{ width: '100%', padding: 6, marginBottom: 8 }}
                  value={sourceIpOverride}
                  onChange={e => setSourceIpOverride(e.target.value)}
                  placeholder="Auto-detect (e.g. 165.225.72.45 = Zscaler)"
                />
                <button
                  type="button"
                  onClick={handleRunActiveProbe}
                  disabled={probing}
                  style={{ padding: '6px 14px', fontWeight: 'bold', cursor: 'pointer' }}
                >
                  {probing ? 'Probing Endpoints...' : 'Probe Endpoints & Persist to CMDB'}
                </button>
              </div>
            </div>

            {probeError && (
              <div style={{ color: '#c62828', marginBottom: 8 }}>
                <strong>Probe Error:</strong> {probeError}
              </div>
            )}

            {probeReport && (
              <div>
                <div
                  style={{
                    padding: '8px 12px',
                    marginBottom: 10,
                    borderRadius: 4,
                    background: probeReport.networkContext.isZscalerSourceIp ? '#fff3e0' : '#e8f5e9',
                    border: `1px solid ${probeReport.networkContext.isZscalerSourceIp ? '#ffb74d' : '#81c784'}`,
                  }}
                >
                  <strong>Prober Source IP:</strong> <code>{probeReport.networkContext.sourceIp}</code> |{' '}
                  <strong>Network Origin:</strong>{' '}
                  <strong>
                    {probeReport.networkContext.isZscalerSourceIp
                      ? 'PRIVATE_NETWORK_ZSCALER (Corporate Zscaler Egress — Private Network Assumed)'
                      : 'PUBLIC_INTERNET (Non-Zscaler Source IP — Public Internet Probe)'}
                  </strong>{' '}
                  | <span style={{ fontSize: 12 }}>{probeReport.networkContext.detectionReason}</span>
                </div>

                <table style={{ width: '100%', borderCollapse: 'collapse' }}>
                  <thead>
                    <tr>
                      <th>Endpoint</th>
                      <th>SSL Expiry &amp; Status</th>
                      <th>Subject CN</th>
                      <th>Issuer</th>
                      <th>Serial Number</th>
                      <th>Signature Alg &amp; Key Size</th>
                      <th>WAF Protection</th>
                      <th>Public Internet Accessible?</th>
                    </tr>
                  </thead>
                  <tbody>
                    {probeReport.results.map(r => (
                      <tr key={r.endpointId}>
                        <td>
                          <strong>{r.endpointUrl}</strong>
                          {!r.reachable && (
                            <div style={{ color: '#c62828', fontSize: 12 }}>Unreachable: {r.error}</div>
                          )}
                        </td>
                        <td>
                          {r.sslDetails
                            ? `${r.sslDetails.notAfter.slice(0, 10)} (${r.sslDetails.daysRemaining}d — ${r.sslDetails.expiryStatus})`
                            : '—'}
                        </td>
                        <td>{r.sslDetails ? r.sslDetails.subjectCn : '—'}</td>
                        <td>{r.sslDetails ? `${r.sslDetails.issuerCn} (${r.sslDetails.issuerOrg})` : '—'}</td>
                        <td>
                          <code>{r.sslDetails ? r.sslDetails.serialNumberHex : '—'}</code>
                        </td>
                        <td>
                          {r.sslDetails
                            ? `${r.sslDetails.signatureAlgorithm} (${r.sslDetails.publicKeyAlgorithm}-${r.sslDetails.publicKeyBits})`
                            : '—'}
                        </td>
                        <td>
                          <strong>{r.wafProvider}</strong>
                          {r.wafEvidence.length > 0 && (
                            <div style={{ fontSize: 11, color: '#555' }}>{r.wafEvidence.join(', ')}</div>
                          )}
                        </td>
                        <td>
                          {r.reachable
                            ? r.accessibleFromPublicInternet
                              ? 'Yes (Public Non-Zscaler IP)'
                              : 'No (Within Private Network — Zscaler IP)'
                            : 'No (Unreachable)'}
                        </td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              </div>
            )}
          </InfoCard>
        </div>

        <div style={{ marginBottom: '1.25rem' }}>
          <InfoCard title="📂 Import Domains List from CSV (Required Columns: endpoint, service_name, environment)">
            <div style={{ display: 'flex', flexWrap: 'wrap', gap: '1rem', alignItems: 'flex-start', marginBottom: '0.75rem' }}>
              <div style={{ flex: '2 1 380px' }}>
                <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: 4 }}>
                  <label htmlFor="domains-csv-content" style={{ fontWeight: 'bold' }}>
                    CSV Content (Required: <code>endpoint,service_name,environment</code>)
                  </label>
                  <a
                    href="http://localhost:7007/api/ssl-tracker/sample-domains.csv"
                    download="aegis-domains-template.csv"
                    style={{ fontSize: 12, fontWeight: 'bold' }}
                  >
                    ⬇ Download Sample CSV Template
                  </a>
                </div>
                <textarea
                  id="domains-csv-content"
                  aria-label="Domains CSV content"
                  rows={4}
                  style={{ width: '100%', fontFamily: 'monospace', padding: 6 }}
                  value={csvContent}
                  onChange={e => setCsvContent(e.target.value)}
                />
              </div>
              <div style={{ flex: '1 1 240px' }}>
                <label htmlFor="domains-csv-file" style={{ display: 'block', fontWeight: 'bold', marginBottom: 4 }}>
                  Load from .CSV File
                </label>
                <input
                  id="domains-csv-file"
                  aria-label="Upload domains CSV file"
                  type="file"
                  accept=".csv,text/csv"
                  style={{ marginBottom: 8, display: 'block' }}
                  onChange={e => handleCsvFileSelect(e.target.files?.[0])}
                />
                <label style={{ display: 'block', marginBottom: 8, fontSize: 13 }}>
                  <input
                    type="checkbox"
                    checked={probeOnCsvImport}
                    onChange={e => setProbeOnCsvImport(e.target.checked)}
                    style={{ marginRight: 6 }}
                  />
                  Probe Live SSL, WAF &amp; Public/Zscaler Accessibility on Import
                </label>
                <button
                  type="button"
                  onClick={handleImportCsv}
                  disabled={importingCsv}
                  style={{ padding: '6px 14px', fontWeight: 'bold', cursor: 'pointer' }}
                >
                  {importingCsv ? 'Importing CSV...' : 'Import CSV to PostgreSQL CMDB'}
                </button>
              </div>
            </div>

            {csvImportError && (
              <div style={{ color: '#c62828', marginBottom: 8 }}>
                <strong>CSV Import Error:</strong> {csvImportError}
              </div>
            )}

            {csvImportReport && (
              <div style={{ padding: '8px 12px', borderRadius: 4, background: '#f5f5f5', border: '1px solid #bdbdbd' }}>
                <div>
                  <strong>CSV Import Summary:</strong> Imported <strong>{csvImportReport.importedCount}</strong> of{' '}
                  <strong>{csvImportReport.totalDataRows}</strong> rows | Reachable Live SSL:{' '}
                  <strong>{csvImportReport.probedReachableCount}</strong> | Public Internet Accessible:{' '}
                  <strong>{csvImportReport.publicAccessibleCount}</strong> | WAF Protected:{' '}
                  <strong>{csvImportReport.wafProtectedCount}</strong>
                </div>
                {csvImportReport.errors.length > 0 && (
                  <ul style={{ color: '#c62828', margin: '6px 0 0 18px', padding: 0 }}>
                    {csvImportReport.errors.map((err, i) => (
                      <li key={i}>{err.message}</li>
                    ))}
                  </ul>
                )}
              </div>
            )}
          </InfoCard>
        </div>

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

import { useEffect, useState } from 'react';
import { createFrontendModule } from '@backstage/frontend-plugin-api';
import { EntityCardBlueprint } from '@backstage/plugin-catalog-react/alpha';
import { useEntity } from '@backstage/plugin-catalog-react';
import { InfoCard } from '@backstage/core-components';

export interface PackageCveRecord {
  cveId: string;
  severity: 'CRITICAL' | 'HIGH' | 'MEDIUM' | 'LOW';
  cvssScore: number;
  affectedPackage: string;
  installedVersion: string;
  fixedVersion: string;
  title: string;
  publishedAt: string;
  exploitMaturity: 'active-exploit' | 'poc' | 'unproven';
  layerOrigin: 'application-sbom' | 'harbor-base-image';
}

export interface EndOfLifeProductRecord {
  product: string;
  displayName: string;
  cycle: string;
  installedVersion: string;
  latestPatchVersion: string;
  latestCycle: string;
  isLts: boolean;
  releaseDate: string;
  activeSupportEndDate: string;
  eolDate: string;
  daysUntilEol: number;
  eolStatus: 'ACTIVE_LTS' | 'MAINTENANCE' | 'APPROACHING_EOL' | 'END_OF_LIFE';
  upgradeRecommendation: string;
  sourceUrl: string;
  cves: PackageCveRecord[];
}

export interface HarborContainerArtifact {
  repositorySlug: string;
  registryHost: string;
  projectName: string;
  repoName: string;
  activeTag: string;
  tags: string[];
  digest: string;
  baseImage: string;
  sizeMB: number;
  pushedAt: string;
  lastScannedAt: string;
  scanStatus: string;
  scanner: string;
  pullCommand: string;
  vulnerabilitySummary: { critical: number; high: number; medium: number; low: number; fixable: number };
}

export interface EntityHarborEolReport {
  entityRef: string;
  serviceName: string;
  harborArtifact: HarborContainerArtifact;
  eolProducts: EndOfLifeProductRecord[];
  cveList: PackageCveRecord[];
  summary: {
    totalPackages: number;
    eolCount: number;
    approachingEolCount: number;
    supportedCount: number;
    criticalCves: number;
    highCves: number;
    mediumCves: number;
    lowCves: number;
    overallRisk: 'CRITICAL' | 'WARNING' | 'HEALTHY';
  };
  scannedAt: string;
}

const HARBOR_EOL_API_BASE = 'http://localhost:7007/api/harbor-eol';

export const EntityHarborEolCard = () => {
  const { entity } = useEntity();
  const entityRef = `${entity.kind.toLowerCase()}:${entity.metadata.namespace || 'default'}/${entity.metadata.name}`;

  const [report, setReport] = useState<EntityHarborEolReport | null>(null);
  const [fleetReports, setFleetReports] = useState<EntityHarborEolReport[]>([]);
  const [activeTab, setActiveTab] = useState<'eol' | 'cves' | 'harbor' | 'fleet'>('eol');
  const [eolFilter, setEolFilter] = useState<'ALL' | 'END_OF_LIFE' | 'APPROACHING_EOL' | 'SUPPORTED'>('ALL');
  const [loading, setLoading] = useState<boolean>(false);
  const [error, setError] = useState<string | null>(null);
  const [cveSeverityFilter, setCveSeverityFilter] = useState<'ALL' | 'CRITICAL' | 'HIGH' | 'MEDIUM'>('ALL');
  const [packageFilter, setPackageFilter] = useState<string | null>(null);
  const [remediating, setRemediating] = useState<boolean>(false);
  const [copiedPullCmd, setCopiedPullCmd] = useState<boolean>(false);

  const fetchData = async () => {
    setLoading(true);
    setError(null);
    try {
      const [entityRes, fleetRes] = await Promise.all([
        fetch(`${HARBOR_EOL_API_BASE}/entity?entityRef=${encodeURIComponent(entityRef)}`),
        fetch(`${HARBOR_EOL_API_BASE}/fleet`),
      ]);
      if (entityRes.ok) setReport(await entityRes.json());
      if (fleetRes.ok) {
        const fleetData = await fleetRes.json();
        setFleetReports(Array.isArray(fleetData) ? fleetData : fleetData.reports || []);
      }
    } catch (e) {
      setError(e instanceof Error ? e.message : 'Unknown error');
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    fetchData();
  }, [entityRef]);

  const handleRescan = async () => {
    try {
      await fetch(`${HARBOR_EOL_API_BASE}/scan`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ entityRef }),
      });
      await fetchData();
    } catch (e) {
      setError(e instanceof Error ? e.message : 'Rescan failed');
    }
  };

  const handleRemediate = async () => {
    setRemediating(true);
    try {
      await fetch(`${HARBOR_EOL_API_BASE}/remediate`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ entityRef }),
      });
      await fetchData();
    } catch (e) {
      setError(e instanceof Error ? e.message : 'Remediation failed');
    } finally {
      setRemediating(false);
    }
  };

  const eolCount = report?.summary.eolCount ?? 0;
  const cveCount = (report?.summary.criticalCves ?? 0) + (report?.summary.highCves ?? 0);
  const fleetCount = fleetReports.length;

  const eolProducts = report?.eolProducts || [];
  const cveList = report?.cveList || [];

  const filteredEolRecords = eolProducts.filter(r => {
    if (eolFilter === 'ALL') return true;
    if (eolFilter === 'SUPPORTED') return r.eolStatus === 'ACTIVE_LTS' || r.eolStatus === 'MAINTENANCE';
    return r.eolStatus === eolFilter;
  });

  return (
    <InfoCard title="🐳 Harbor Container Registry, Package End-of-Life (endoflife.date) & CVE Tracker">
      <div style={{ marginBottom: 12, display: 'flex', gap: 16, fontSize: 14, alignItems: 'center', flexWrap: 'wrap' }}>
        {report?.harborArtifact && (
          <span style={{ background: '#e3f2fd', padding: '2px 8px', borderRadius: 4, fontSize: 12 }}>
            🐳 {report.harborArtifact.repositorySlug}:{report.harborArtifact.activeTag}
          </span>
        )}
        {report?.summary && (
          <span style={{
            background: report.summary.overallRisk === 'CRITICAL' ? '#d32f2f' : report.summary.overallRisk === 'WARNING' ? '#ed6c02' : '#2e7d32',
            color: '#fff', padding: '2px 8px', borderRadius: 4, fontSize: 12, fontWeight: 700,
          }}>
            {report.summary.overallRisk}
          </span>
        )}
        <span>📅 EOL: <strong>{eolCount}</strong></span>
        <span>⚠️ Approaching: <strong>{report?.summary.approachingEolCount ?? 0}</strong></span>
        <span>🛡️ Critical/High CVEs: <strong>{cveCount}</strong></span>
        <span>🌐 Fleet Entities: <strong>{fleetCount}</strong></span>
        <button onClick={handleRescan} style={{ marginLeft: 'auto' }}>🔄 Rescan</button>
        {eolCount > 0 && (
          <button onClick={handleRemediate} disabled={remediating} style={{ background: '#1565c0', color: '#fff', border: 'none', borderRadius: 4, padding: '4px 10px', cursor: remediating ? 'wait' : 'pointer', fontSize: 13 }}>
            {remediating ? '⏳ Remediating…' : '🚀 Remediate EOL Base Image (Upgrade to LTS)'}
          </button>
        )}
      </div>
      <div style={{ display: 'flex', gap: 8, marginBottom: 12 }}>
        <button onClick={() => setActiveTab('eol')} style={{ fontWeight: activeTab === 'eol' ? 700 : 400 }}>📅 End-of-Life View</button>
        <button onClick={() => setActiveTab('cves')} style={{ fontWeight: activeTab === 'cves' ? 700 : 400 }}>🛡️ Critical & High CVEs</button>
        <button onClick={() => setActiveTab('harbor')} style={{ fontWeight: activeTab === 'harbor' ? 700 : 400 }}>🐳 Harbor Container Image</button>
        <button onClick={() => setActiveTab('fleet')} style={{ fontWeight: activeTab === 'fleet' ? 700 : 400 }}>🌐 Fleet EOL Matrix</button>
      </div>
      {activeTab === 'eol' && (
        <div style={{ marginBottom: 8, display: 'flex', gap: 8 }}>
          {(['ALL', 'END_OF_LIFE', 'APPROACHING_EOL', 'SUPPORTED'] as const).map(f => (
            <button key={f} onClick={() => setEolFilter(f)} style={{ fontWeight: eolFilter === f ? 700 : 400, fontSize: 12 }}>
              {f}
            </button>
          ))}
        </div>
      )}
      {loading && <div>Loading…</div>}
      {error && <div style={{ color: 'red' }}>{error}</div>}
      <div id="harbor-eol-tab-body">
        {activeTab === 'eol' && (
          <table style={{ width: '100%', borderCollapse: 'collapse', fontSize: 13 }}>
            <thead>
              <tr>
                <th style={{ textAlign: 'left', padding: '6px 8px', borderBottom: '2px solid #ddd' }}>Package / Cycle</th>
                <th style={{ textAlign: 'left', padding: '6px 8px', borderBottom: '2px solid #ddd' }}>Installed → Latest</th>
                <th style={{ textAlign: 'left', padding: '6px 8px', borderBottom: '2px solid #ddd' }}>Release / Support End</th>
                <th style={{ textAlign: 'left', padding: '6px 8px', borderBottom: '2px solid #ddd' }}>EOL Date &amp; Countdown</th>
                <th style={{ textAlign: 'left', padding: '6px 8px', borderBottom: '2px solid #ddd' }}>EOL Status</th>
                <th style={{ textAlign: 'left', padding: '6px 8px', borderBottom: '2px solid #ddd' }}>CVEs</th>
                <th style={{ textAlign: 'left', padding: '6px 8px', borderBottom: '2px solid #ddd' }}>Upgrade Recommendation</th>
              </tr>
            </thead>
            <tbody>
              {filteredEolRecords.map(r => {
                const progressColor = r.eolStatus === 'END_OF_LIFE' ? '#d32f2f' : r.eolStatus === 'APPROACHING_EOL' ? '#ed6c02' : '#2e7d32';
                const progressWidth = r.eolStatus === 'END_OF_LIFE' ? 100 : r.eolStatus === 'APPROACHING_EOL' ? 75 : r.eolStatus === 'MAINTENANCE' ? 50 : 25;
                const statusColor = r.eolStatus === 'END_OF_LIFE' ? '#d32f2f' : r.eolStatus === 'APPROACHING_EOL' ? '#ed6c02' : '#2e7d32';
                return (
                  <tr key={`${r.product}-${r.cycle}`} style={{ borderBottom: '1px solid #eee' }}>
                    <td style={{ padding: '6px 8px' }}>
                      {r.displayName} {r.cycle}
                      {r.isLts && <span style={{ marginLeft: 6, background: '#1565c0', color: '#fff', fontSize: 10, padding: '1px 5px', borderRadius: 3, fontWeight: 700 }}>LTS</span>}
                    </td>
                    <td style={{ padding: '6px 8px' }}>{r.installedVersion} → {r.latestPatchVersion}</td>
                    <td style={{ padding: '6px 8px' }}>{r.releaseDate} / {r.activeSupportEndDate}</td>
                    <td style={{ padding: '6px 8px' }}>
                      <div>{r.eolDate}</div>
                      <div style={{ fontSize: 11, color: r.daysUntilEol <= 0 ? '#d32f2f' : r.daysUntilEol <= 90 ? '#ed6c02' : '#2e7d32', fontWeight: 600 }}>
                        {r.daysUntilEol <= 0 ? `EXPIRED (${Math.abs(r.daysUntilEol)}d ago)` : `+${r.daysUntilEol}d left`}
                      </div>
                      <div style={{ width: '100%', height: 6, background: '#eee', borderRadius: 3, marginTop: 4 }}>
                        <div style={{ width: `${progressWidth}%`, height: 6, background: progressColor, borderRadius: 3 }} />
                      </div>
                    </td>
                    <td style={{ padding: '6px 8px' }}>
                      <span style={{ background: statusColor, color: '#fff', padding: '2px 8px', borderRadius: 4, fontSize: 11, fontWeight: 700 }}>
                        {r.eolStatus}
                      </span>
                    </td>
                    <td style={{ padding: '6px 8px' }}>
                      {r.cves.length > 0 ? (
                        <button onClick={() => { setPackageFilter(`${r.product}@${r.cycle}`); setActiveTab('cves'); }} style={{ background: '#fff3e0', border: '1px solid #ed6c02', borderRadius: 4, padding: '2px 8px', cursor: 'pointer', fontSize: 12, fontWeight: 600 }}>
                          🔥 {r.cves.length} CVEs
                        </button>
                      ) : (
                        <span style={{ color: '#2e7d32', fontSize: 12 }}>0 (Clean)</span>
                      )}
                    </td>
                    <td style={{ padding: '6px 8px' }}>{r.upgradeRecommendation}</td>
                  </tr>
                );
              })}
            </tbody>
          </table>
        )}
        {activeTab === 'cves' && (
          <div>
            <div style={{ marginBottom: 8, display: 'flex', gap: 8, alignItems: 'center' }}>
              {(['ALL', 'CRITICAL', 'HIGH', 'MEDIUM'] as const).map(f => (
                <button key={f} onClick={() => setCveSeverityFilter(f)} style={{ fontWeight: cveSeverityFilter === f ? 700 : 400, fontSize: 12 }}>
                  {f}
                </button>
              ))}
              {packageFilter && (
                <button onClick={() => setPackageFilter(null)} style={{ fontSize: 12, background: '#e3f2fd', border: '1px solid #1565c0', borderRadius: 4, padding: '2px 8px', cursor: 'pointer' }}>
                  📦 {packageFilter} ✕
                </button>
              )}
            </div>
            <table style={{ width: '100%', borderCollapse: 'collapse', fontSize: 13 }}>
              <thead>
                <tr>
                  <th style={{ textAlign: 'left', padding: '6px 8px', borderBottom: '2px solid #ddd' }}>CVE ID</th>
                  <th style={{ textAlign: 'left', padding: '6px 8px', borderBottom: '2px solid #ddd' }}>Severity</th>
                  <th style={{ textAlign: 'left', padding: '6px 8px', borderBottom: '2px solid #ddd' }}>CVSS</th>
                  <th style={{ textAlign: 'left', padding: '6px 8px', borderBottom: '2px solid #ddd' }}>Package (Installed → Fixed)</th>
                  <th style={{ textAlign: 'left', padding: '6px 8px', borderBottom: '2px solid #ddd' }}>Origin Layer</th>
                  <th style={{ textAlign: 'left', padding: '6px 8px', borderBottom: '2px solid #ddd' }}>Exploit Status</th>
                  <th style={{ textAlign: 'left', padding: '6px 8px', borderBottom: '2px solid #ddd' }}>Title</th>
                </tr>
              </thead>
              <tbody>
                {cveList
                  .filter(c => cveSeverityFilter === 'ALL' || c.severity === cveSeverityFilter)
                  .filter(c => {
                    if (!packageFilter) return true;
                    const matchedPkg = eolProducts.find(
                      p => `${p.product}@${p.cycle}` === packageFilter || p.product === packageFilter,
                    );
                    return matchedPkg
                      ? matchedPkg.cves.some(pc => pc.cveId === c.cveId)
                      : c.affectedPackage === packageFilter;
                  })
                  .map(c => (
                  <tr key={c.cveId} style={{ borderBottom: '1px solid #eee' }}>
                    <td style={{ padding: '6px 8px' }}>{c.cveId}</td>
                    <td style={{ padding: '6px 8px' }}>
                      <span style={{ background: c.severity === 'CRITICAL' ? '#d32f2f' : c.severity === 'HIGH' ? '#ed6c02' : c.severity === 'MEDIUM' ? '#f9a825' : '#2e7d32', color: '#fff', padding: '1px 6px', borderRadius: 3, fontSize: 11, fontWeight: 700 }}>
                        {c.severity}
                      </span>
                    </td>
                    <td style={{ padding: '6px 8px' }}>{c.cvssScore}</td>
                    <td style={{ padding: '6px 8px' }}>{c.affectedPackage} ({c.installedVersion} → {c.fixedVersion})</td>
                    <td style={{ padding: '6px 8px' }}>{c.layerOrigin}</td>
                    <td style={{ padding: '6px 8px' }}>{c.exploitMaturity}</td>
                    <td style={{ padding: '6px 8px' }}>{c.title}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        )}
        {activeTab === 'harbor' && (
          <div>
            <p><strong>Repository:</strong> {report?.harborArtifact.repositorySlug}</p>
            <p><strong>Active Tag:</strong> {report?.harborArtifact.activeTag}</p>
            <p><strong>Tags:</strong> {report?.harborArtifact.tags.join(', ')}</p>
            <p><strong>Base Image:</strong> {report?.harborArtifact.baseImage}</p>
            <p><strong>Digest:</strong> {report?.harborArtifact.digest}</p>
            <p><strong>Size:</strong> {report?.harborArtifact.sizeMB} MB</p>
            <p><strong>Scanner:</strong> {report?.harborArtifact.scanner}</p>
            <p>
              <strong>Vulnerability Summary:</strong>{' '}
              {report?.harborArtifact.vulnerabilitySummary.critical} critical,{' '}
              {report?.harborArtifact.vulnerabilitySummary.high} high,{' '}
              {report?.harborArtifact.vulnerabilitySummary.medium} medium,{' '}
              {report?.harborArtifact.vulnerabilitySummary.low} low,{' '}
              {report?.harborArtifact.vulnerabilitySummary.fixable} fixable
            </p>
            <p><strong>Pull Command:</strong></p>
            <div style={{ display: 'flex', gap: 8, alignItems: 'center' }}>
              <code>{report?.harborArtifact.pullCommand}</code>
              <button
                onClick={() => {
                  navigator.clipboard.writeText(report?.harborArtifact.pullCommand || '');
                  setCopiedPullCmd(true);
                  setTimeout(() => setCopiedPullCmd(false), 2000);
                }}
                style={{ fontSize: 12, padding: '2px 8px', borderRadius: 4, border: '1px solid #ccc', cursor: 'pointer' }}
              >
                {copiedPullCmd ? '✅ Copied!' : '📋 Copy'}
              </button>
            </div>
          </div>
        )}
        {activeTab === 'fleet' && (
          <table>
            <thead>
              <tr>
                <th>Service</th>
                <th>Harbor Artifact</th>
                <th>Base Image</th>
                <th>EOL</th>
                <th>Approaching EOL</th>
                <th>Critical CVEs</th>
                <th>High CVEs</th>
                <th>Overall Risk</th>
              </tr>
            </thead>
            <tbody>
              {fleetReports.map(r => (
                <tr key={r.entityRef}>
                  <td>{r.serviceName}</td>
                  <td>{r.harborArtifact.repositorySlug}:{r.harborArtifact.activeTag}</td>
                  <td>{r.harborArtifact.baseImage}</td>
                  <td>{r.summary.eolCount}</td>
                  <td>{r.summary.approachingEolCount}</td>
                  <td>{r.summary.criticalCves}</td>
                  <td>{r.summary.highCves}</td>
                  <td>{r.summary.overallRisk}</td>
                </tr>
              ))}
            </tbody>
          </table>
        )}
      </div>
    </InfoCard>
  );
};

const harborEolEntityCard = EntityCardBlueprint.make({
  name: 'harbor-eol-card',
  params: {
    filter: 'kind:component,resource',
    loader: async () => <EntityHarborEolCard />,
  },
});

export const harborEolModule = createFrontendModule({
  pluginId: 'catalog',
  extensions: [harborEolEntityCard],
});

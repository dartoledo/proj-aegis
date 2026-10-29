import { useEffect, useState } from 'react';
import { createFrontendModule } from '@backstage/frontend-plugin-api';
import { EntityCardBlueprint } from '@backstage/plugin-catalog-react/alpha';
import { useEntity } from '@backstage/plugin-catalog-react';
import { InfoCard } from '@backstage/core-components';

interface ContextualCveRecord {
  cveId: string;
  package: string;
  installedVersion: string;
  fixedVersion: string;
  acrsScore: number;
  priorityTier: 'P0_IMMEDIATE_24H' | 'P1_HIGH_7D' | 'P2_SCHEDULED_30D' | 'DEFERRED_VEX';
  sla: string;
  cvssScore: number;
  epssScore: number;
  epssPercentile: number;
  isCisaKev: boolean;
  reachability: string;
  callGraphSymbol: string;
  vexStatus: string;
  attackPathSteps: string[];
  ransomwareCampaign: boolean;
}

interface EntityCveIntelligenceReport {
  serviceName: string;
  entityRef: string;
  maxAcrsScore: number;
  cisaKevCount: number;
  p0ImmediateCount: number;
  rawCriticalHighCount: number;
  noiseReductionPercent: number;
  cves: ContextualCveRecord[];
}

interface FleetCvePrioritizationSummary {
  totalRawCves: number;
  totalActionableP0: number;
  fleetNoiseReductionPercent: number;
  services: Array<{
    serviceName: string;
    rawCves: number;
    actionableP0: number;
    noiseReductionPercent: number;
  }>;
}

export const EntityCveIntelligenceCard = () => {
  const { entity } = useEntity();
  const entityRef = `${entity.kind.toLowerCase()}:${entity.metadata.namespace || 'default'}/${entity.metadata.name}`;

  const [report, setReport] = useState<EntityCveIntelligenceReport | null>(null);
  const [fleet, setFleet] = useState<FleetCvePrioritizationSummary | null>(null);
  const [activeTab, setActiveTab] = useState<'priorities' | 'attack-paths' | 'fleet'>('priorities');
  const [loading, setLoading] = useState(true);

  const fetchData = async () => {
    setLoading(true);
    try {
      const [entityRes, fleetRes] = await Promise.all([
        fetch(`http://127.0.0.1:7007/api/cve-intel/entity?entityRef=${encodeURIComponent(entityRef)}`),
        fetch(`http://127.0.0.1:7007/api/cve-intel/fleet-priorities`),
      ]);
      const entityData = await entityRes.json();
      const fleetData = await fleetRes.json();
      setReport(entityData);
      setFleet(fleetData);
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    fetchData();
  }, [entityRef]);

  const handleVexAttest = async (cveId: string, justification: string) => {
    await fetch(`http://127.0.0.1:7007/api/cve-intel/vex-attest`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ entityRef, cveId, justification }),
    });
    fetchData();
  };

  if (loading || !report) {
    return <InfoCard title="🎯 Contextual CVE Intelligence">Loading…</InfoCard>;
  }

  return (
    <InfoCard title={`🎯 Contextual CVE Intelligence (EPSS + CISA KEV + Reachability) — ${report.serviceName}`}>
      <div style={{ marginBottom: 16, display: 'flex', gap: 16, flexWrap: 'wrap' }}>
        <div>
          <strong>Max ACRS Score</strong>
          <div>{(report.maxAcrsScore / 100).toFixed(2)}</div>
        </div>
        <div>
          <strong>Active CISA KEV Count</strong>
          <div>{report.cisaKevCount}</div>
        </div>
        <div>
          <strong>Actionable P0 Count</strong>
          <div>{report.p0ImmediateCount} vs Raw Critical/High {report.rawCriticalHighCount}</div>
        </div>
        <div>
          <strong>Alert Noise Reduction</strong>
          <div>{`${report.noiseReductionPercent}%`}</div>
        </div>
      </div>

      <div style={{ marginBottom: 8 }}>
        <button
          onClick={() => setActiveTab('priorities')}
          style={{ marginRight: 8, fontWeight: activeTab === 'priorities' ? 'bold' : 'normal' }}
        >
          Priorities
        </button>
        <button
          onClick={() => setActiveTab('attack-paths')}
          style={{ marginRight: 8, fontWeight: activeTab === 'attack-paths' ? 'bold' : 'normal' }}
        >
          Attack Paths
        </button>
        <button
          onClick={() => setActiveTab('fleet')}
          style={{ fontWeight: activeTab === 'fleet' ? 'bold' : 'normal' }}
        >
          Fleet
        </button>
      </div>

      {activeTab === 'priorities' && (
        <table style={{ width: '100%', borderCollapse: 'collapse', fontSize: 13 }}>
          <thead>
            <tr>
              <th>CVE ID</th>
              <th>Package</th>
              <th>ACRS Score</th>
              <th>Priority Tier &amp; SLA</th>
              <th>CVSS vs EPSS</th>
              <th>Runtime Reachability</th>
              <th>VEX Status</th>
              <th>Actions</th>
            </tr>
          </thead>
          <tbody>
            {report.cves.map((cve) => (
              <tr key={cve.cveId}>
                <td>
                  {cve.cveId}
                  {cve.isCisaKev && (
                    <span style={{ marginLeft: 4 }}>🔥 CISA KEV</span>
                  )}
                </td>
                <td>
                  {cve.package} ({cve.installedVersion} → {cve.fixedVersion})
                </td>
                <td>{cve.acrsScore}</td>
                <td>
                  {cve.priorityTier}
                  <br />
                  {cve.sla}
                </td>
                <td>
                  CVSS {cve.cvssScore} / EPSS {cve.epssScore} ({cve.epssPercentile}%)
                </td>
                <td>
                  {cve.reachability}
                  <br />
                  {cve.callGraphSymbol}
                </td>
                <td>{cve.vexStatus}</td>
                <td>
                  <button
                    onClick={() => handleVexAttest(cve.cveId, 'Not affected')}
                    style={{ marginRight: 4 }}
                  >
                    Attest VEX Not Affected
                  </button>
                  <button onClick={() => handleVexAttest(cve.cveId, 'Reset')}>Reset VEX</button>
                </td>
              </tr>
            ))}
          </tbody>
        </table>
      )}

      {activeTab === 'attack-paths' && (
        <div>
          {report.cves.map((cve) => (
            <div key={cve.cveId} style={{ marginBottom: 12 }}>
              <strong>{cve.cveId}</strong>
              {cve.ransomwareCampaign && <span style={{ marginLeft: 8 }}>🦠 Ransomware Campaign</span>}
              <div style={{ marginTop: 4 }}>
                {cve.attackPathSteps.map((step, idx) => (
                  <span key={idx}>
                    {idx > 0 && ' → '}
                    <span>Step {idx + 1}: {step}</span>
                  </span>
                ))}
              </div>
              <div style={{ fontSize: 12, color: '#666' }}>Call-graph symbol: {cve.callGraphSymbol}</div>
            </div>
          ))}
        </div>
      )}

      {activeTab === 'fleet' && fleet && (
        <div>
          <div style={{ marginBottom: 12 }}>
            <strong>Fleet-wide Noise Reduction:</strong> {fleet.totalRawCves} raw CVEs reduced to{' '}
            {fleet.totalActionableP0} P0 items = {fleet.fleetNoiseReductionPercent}% reduction
          </div>
          <table style={{ width: '100%', borderCollapse: 'collapse', fontSize: 13 }}>
            <thead>
              <tr>
                <th>Service</th>
                <th>Raw CVEs</th>
                <th>Actionable P0</th>
                <th>Noise Reduction</th>
              </tr>
            </thead>
            <tbody>
              {fleet.services.map((svc) => (
                <tr key={svc.serviceName}>
                  <td>{svc.serviceName}</td>
                  <td>{svc.rawCves}</td>
                  <td>{svc.actionableP0}</td>
                  <td>{svc.noiseReductionPercent}%</td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      )}
    </InfoCard>
  );
};

const cveIntelEntityCard = EntityCardBlueprint.make({
  name: 'cve-intelligence-card',
  params: {
    filter: 'kind:component,resource',
    loader: async () => <EntityCveIntelligenceCard />,
  },
});

export const cveIntelModule = createFrontendModule({
  pluginId: 'catalog',
  extensions: [cveIntelEntityCard],
});

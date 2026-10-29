import { useEffect, useState } from 'react';
import { createFrontendModule } from '@backstage/frontend-plugin-api';
import { EntityCardBlueprint } from '@backstage/plugin-catalog-react/alpha';
import { useEntity } from '@backstage/plugin-catalog-react';
import { InfoCard } from '@backstage/core-components';

interface QualityGateCheck {
  gateId: string;
  domain: string;
  policyInvariant: string;
  observedState: string;
  verdict: 'PASS' | 'WARN_APPROVAL' | 'HARD_BLOCK';
  remediationDiffHint?: string;
  remediationHint?: string;
}

interface EntityQualityGateReport {
  entityRef: string;
  serviceName: string;
  scenarioTitle: string;
  evaluationMode: 'LIVE_POSTURE' | 'PRE_FLIGHT_SIMULATION';
  overallVerdict: 'AUTO_APPROVED' | 'REQUIRES_VP_ATTESTATION' | 'BLOCKED_BY_POLICY';
  readinessScore: number;
  passedGates: number;
  totalGates: number;
  sonarCodeMetrics: {
    status: string;
    coveragePercent: number;
    bugs: number;
    codeSmells: number;
  };
  gates: QualityGateCheck[];
}

interface PresetInfraScenario {
  scenarioId: string;
  title: string;
}

export const InfraQualityGateCard = () => {
  const { entity } = useEntity();
  const entityRef = `${entity.kind.toLowerCase()}:${entity.metadata.namespace || 'default'}/${entity.metadata.name}`;

  const [report, setReport] = useState<EntityQualityGateReport | null>(null);
  const [scenarios, setScenarios] = useState<PresetInfraScenario[]>([]);

  useEffect(() => {
    const fetchReport = async () => {
      const res = await fetch(`http://127.0.0.1:7007/api/infra-quality-gates/entity?entityRef=${encodeURIComponent(entityRef)}`);
      const data = await res.json();
      setReport(data);
    };
    const fetchScenarios = async () => {
      const res = await fetch('http://127.0.0.1:7007/api/infra-quality-gates/scenarios');
      const data = await res.json();
      setScenarios(Array.isArray(data) ? data : data.scenarios || []);
    };
    fetchReport();
    fetchScenarios();
  }, [entityRef]);

  const handleSimulateScenario = async (scenarioId: string) => {
    const res = await fetch('http://127.0.0.1:7007/api/infra-quality-gates/simulate', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ entityRef, scenarioId }),
    });
    const data = await res.json();
    setReport(data);
  };

  const handleResetLivePosture = async () => {
    const res = await fetch(`http://127.0.0.1:7007/api/infra-quality-gates/entity?entityRef=${encodeURIComponent(entityRef)}`);
    const data = await res.json();
    setReport(data);
  };

  if (!report) {
    return (
      <InfoCard title="Loading Quality Gates...">
        <div>Loading...</div>
      </InfoCard>
    );
  }

  const verdictColor =
    report.overallVerdict === 'AUTO_APPROVED' ? '#2e7d32'
    : report.overallVerdict === 'REQUIRES_VP_ATTESTATION' ? '#ed6c02'
    : '#d32f2f';

  return (
    <InfoCard title={`🛡️ Automated Infra Change Quality Gates & Pre-Flight Policy Gatekeeper — ${report.serviceName}`}>
      <div style={{ display: 'flex', flexDirection: 'column', gap: '12px' }}>
        <div style={{ background: '#f5f5f5', padding: '12px', borderRadius: '6px' }}>
          <div>
            <strong>Evaluation Mode:</strong>{' '}
            {report.evaluationMode === 'LIVE_POSTURE' ? 'LIVE_POSTURE' : `PRE_FLIGHT_SIMULATION: ${report.scenarioTitle}`}
          </div>
          <div>
            <strong>Overall Gate Verdict:</strong>{' '}
            <span style={{ color: verdictColor, fontWeight: 'bold', padding: '2px 8px', borderRadius: '4px', background: `${verdictColor}22` }}>
              {report.overallVerdict}
            </span>
          </div>
          <div>
            <strong>Readiness Score:</strong> {report.readinessScore}% — {report.passedGates}/{report.totalGates} Gates Passed
          </div>
          <div>
            <strong>SonarQube Code Quality:</strong> Status: {report.sonarCodeMetrics.status} | Coverage: {report.sonarCodeMetrics.coveragePercent}% | Bugs: {report.sonarCodeMetrics.bugs} | Code Smells: {report.sonarCodeMetrics.codeSmells}
          </div>
        </div>

        <div>
          <strong>Pre-Flight "What-If" Infra Change Simulator</strong>
          <div style={{ display: 'flex', gap: '8px', marginTop: '8px', flexWrap: 'wrap' }}>
            {scenarios.map((s) => (
              <button key={s.scenarioId} onClick={() => handleSimulateScenario(s.scenarioId)} style={{ padding: '6px 12px', cursor: 'pointer' }}>
                {s.title}
              </button>
            ))}
            <button onClick={handleResetLivePosture} style={{ padding: '6px 12px', cursor: 'pointer' }}>
              🔄 Reset to Live Posture
            </button>
          </div>
        </div>

        <table style={{ width: '100%', borderCollapse: 'collapse', fontSize: '13px' }}>
          <thead>
            <tr>
              <th style={{ border: '1px solid #ddd', padding: '6px' }}>Gate ID</th>
              <th style={{ border: '1px solid #ddd', padding: '6px' }}>Domain</th>
              <th style={{ border: '1px solid #ddd', padding: '6px' }}>Policy Invariant</th>
              <th style={{ border: '1px solid #ddd', padding: '6px' }}>Observed / Simulated State</th>
              <th style={{ border: '1px solid #ddd', padding: '6px' }}>Verdict</th>
              <th style={{ border: '1px solid #ddd', padding: '6px' }}>Remediation / GitOps Diff Hint</th>
            </tr>
          </thead>
          <tbody>
            {report.gates.map((gate) => (
              <tr key={gate.gateId}>
                <td style={{ border: '1px solid #ddd', padding: '6px' }}>{gate.gateId}</td>
                <td style={{ border: '1px solid #ddd', padding: '6px' }}>{gate.domain}</td>
                <td style={{ border: '1px solid #ddd', padding: '6px' }}>{gate.policyInvariant}</td>
                <td style={{ border: '1px solid #ddd', padding: '6px' }}>{gate.observedState}</td>
                <td style={{ border: '1px solid #ddd', padding: '6px', color: gate.verdict === 'PASS' ? '#2e7d32' : gate.verdict === 'WARN_APPROVAL' ? '#ed6c02' : '#d32f2f', fontWeight: 'bold' }}>
                  {gate.verdict}
                </td>
                <td style={{ border: '1px solid #ddd', padding: '6px' }}>{gate.remediationDiffHint || gate.remediationHint}</td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>
    </InfoCard>
  );
};

const qualityGateCard = EntityCardBlueprint.make({
  name: 'mock-sonarqube-card',
  params: {
    filter: 'kind:component,resource',
    loader: async () => <InfraQualityGateCard />,
  },
});

export const qualityModule = createFrontendModule({
  pluginId: 'catalog',
  extensions: [qualityGateCard],
});

import { useState } from 'react';
import { Content, Header, InfoCard, Link, Page } from '@backstage/core-components';
import { EntityAttackGraphScorecardReport } from '../infrahubAttackGraph/infrahubAttackGraphModule';
import { buildFallbackAttackGraphReport, simulateFallbackAttackGraph } from '../infrahubAttackGraph/infrahubFallbackData';

const SERVICES = ['aegis-backend', 'aegis-auth', 'aegis-ui', 'aegis-db', 'hello-world-app'] as const;

export function AttackPathGraphView() {
  const [reportsByService, setReportsByService] = useState<Record<string, EntityAttackGraphScorecardReport>>(() =>
    Object.fromEntries(SERVICES.map(s => [s, buildFallbackAttackGraphReport(s)])),
  );
  const [selectedService, setSelectedService] = useState<string>('aegis-backend');

  const activeReport = reportsByService[selectedService] || buildFallbackAttackGraphReport(selectedService);

  const handleSimulate = (action: string) => {
    setReportsByService(prev => ({
      ...prev,
      [selectedService]: simulateFallbackAttackGraph(activeReport, action),
    }));
  };

  const handleReset = () => {
    setReportsByService(prev => ({
      ...prev,
      [selectedService]: buildFallbackAttackGraphReport(selectedService),
    }));
  };

  const failingCount = Object.values(reportsByService).filter(r => r.scorecardStatus === 'FAIL').length;
  const totalKevCves = Object.values(reportsByService).reduce((a, r) => a + r.facts.reachable_kev_cve_count, 0);

  return (
    <Page themeId="tool">
      <Header
        title="Unified Inventory — Infrahub Attack-Path Graph"
        subtitle="N-Hop Exploitability Chains, Tech-Insights Scorecards & What-If Remediation Simulator"
      />
      <Content>
        <InfoCard title="Fleet Attack-Path Graph & What-If Simulator">
          <p>
            Total Services: <strong>{SERVICES.length}</strong> | Failing Scorecards: <strong>{failingCount}</strong> | Total Reachable KEV CVEs: <strong>{totalKevCves}</strong>
          </p>

          <div style={{ marginBottom: 16 }}>
            <select
              aria-label="Select service"
              value={selectedService}
              onChange={e => setSelectedService(e.target.value)}
            >
              {SERVICES.map(s => (
                <option key={s} value={s}>{s}</option>
              ))}
            </select>
            <button onClick={() => handleSimulate('rotate-ssl')}>Rotate SSL</button>
            <button onClick={() => handleSimulate('upgrade-eol-runtime')}>Upgrade EOL Runtime</button>
            <button onClick={() => handleSimulate('patch-kev-cve')}>Patch KEV CVE</button>
            <button onClick={() => handleSimulate('isolate-lateral-path')}>Isolate Lateral Path</button>
            <button onClick={handleReset}>Reset</button>
          </div>

          <p>
            <Link to={`/catalog/default/component/${selectedService}`}>{selectedService}</Link>
            {' '}— Scorecard Status: <strong>{activeReport.scorecardStatus}</strong> | Risk Score: <strong>{activeReport.facts.attack_path_risk_score}/100</strong> | Checks: <strong>{activeReport.passedChecksCount}/{activeReport.totalChecksCount}</strong>
          </p>

          <h3>N-Hop Attack Paths</h3>
          <ul>
            {activeReport.attackPaths.map((path, i) => (
              <li key={i}>{JSON.stringify(path)}</li>
            ))}
          </ul>

          <h3>Scorecard Checks</h3>
          <table>
            <thead>
              <tr><td>Check</td></tr>
            </thead>
            <tbody>
              {activeReport.scorecardChecks.map((check, i) => (
                <tr key={i}><td>{JSON.stringify(check)}</td></tr>
              ))}
            </tbody>
          </table>
        </InfoCard>
      </Content>
    </Page>
  );
}

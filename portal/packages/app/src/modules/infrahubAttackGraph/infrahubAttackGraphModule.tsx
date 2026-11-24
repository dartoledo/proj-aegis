import { useEffect, useState } from 'react';
import { createFrontendModule } from '@backstage/frontend-plugin-api';
import { EntityCardBlueprint } from '@backstage/plugin-catalog-react/alpha';
import { useEntity } from '@backstage/plugin-catalog-react';
import { InfoCard } from '@backstage/core-components';
import { buildFallbackAttackGraphReport, simulateFallbackAttackGraph } from './infrahubFallbackData';

// --- Interfaces ---

export interface InfrahubTechInsightsFacts {
  exposed_domain_count: number;
  non_compliant_ssl_count: number;
  eol_package_count: number;
  reachable_kev_cve_count: number;
  reachable_lateral_data_paths_count: number;
  attack_path_risk_score: number;
}

export interface TechInsightsScorecardCheck {
  check: string;
  fact: string;
  threshold: string;
  actual: string;
  result: 'PASS' | 'FAIL';
  remediationGuidance: string;
}

export interface AttackGraphNode {
  nodeId: string;
  nodeType: string;
  label: string;
}

export interface AttackGraphEdge {
  fromNodeId: string;
  edgeType: string;
  toNodeId: string;
  protocolOrMechanism: string;
  isExploitableReachable: boolean;
}

export interface NHopAttackPathChain {
  title: string;
  hopCount: number;
  entryDomain: string;
  tlsPosture: string;
  eolRuntimeInChain: string;
  exploitableCveId: string;
  targetDataOrServiceAsset: string;
  chainRiskScore: number;
  aiMcpRemediationPrompt: string;
}

export interface EntityAttackGraphScorecardReport {
  entityRef: string;
  scorecardStatus: 'PASS' | 'WARN' | 'FAIL';
  passedChecksCount: number;
  totalChecksCount: number;
  facts: InfrahubTechInsightsFacts;
  scorecardChecks: TechInsightsScorecardCheck[];
  attackPaths: NHopAttackPathChain[];
  graphNodes: AttackGraphNode[];
  edges: AttackGraphEdge[];
  infrahubDeepLinkUrl: string;
  infrahubMcpAgentUri: string;
  infrahubGraphQlQuery: string;
  infrahubMcpPrompt: string;
}

// --- Card Component ---

export function EntityInfrahubAttackGraphCard() {
  const { entity } = useEntity();
  const entityRef = `${(entity.kind || 'component').toLowerCase()}:${entity.metadata?.namespace || 'default'}/${entity.metadata?.name || 'aegis-backend'}`;
  const [report, setReport] = useState<EntityAttackGraphScorecardReport>(() => buildFallbackAttackGraphReport(entityRef));
  const [error] = useState<string | null>(null);
  const [activeTab, setActiveTab] = useState<'scorecard' | 'attack-graph' | 'graphql-mcp'>('scorecard');
  const [simulating, setSimulating] = useState<string | null>(null);

  useEffect(() => {
    setReport(buildFallbackAttackGraphReport(entityRef));
    const fetchReport = async () => {
      try {
        const url = `http://127.0.0.1:7007/api/infrahub-attack-graph/entity?entityId=${encodeURIComponent(entityRef)}&entityRef=${encodeURIComponent(entityRef)}`;
        const res = await fetch(url);
        if (res.ok) {
          const data: EntityAttackGraphScorecardReport = await res.json();
          setReport({ ...data, graphNodes: data.graphNodes ?? (data as any).nodes ?? [] });
        }
      } catch (e) {
        // keep the fallback report
      }
    };
    fetchReport();
  }, [entityRef]);

  const handleSimulate = async (action: string) => {
    setSimulating(action);
    try {
      const res = await fetch('http://127.0.0.1:7007/api/infrahub-attack-graph/simulate', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ entityId: entityRef, entityRef, action }),
      });
      if (res.ok) {
        const data: EntityAttackGraphScorecardReport = await res.json();
        setReport({ ...data, graphNodes: data.graphNodes ?? (data as any).nodes ?? [] });
      } else {
        setReport(prev => simulateFallbackAttackGraph(prev, action));
      }
    } catch (e) {
      setReport(prev => simulateFallbackAttackGraph(prev, action));
    } finally {
      setSimulating(null);
    }
  };

  const handleReset = async () => {
    setSimulating('reset');
    try {
      const res = await fetch('http://127.0.0.1:7007/api/infrahub-attack-graph/reset', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ entityId: entityRef, entityRef }),
      });
      if (res.ok) {
        const data: EntityAttackGraphScorecardReport = await res.json();
        setReport({ ...data, graphNodes: data.graphNodes ?? (data as any).nodes ?? [] });
      } else {
        setReport(buildFallbackAttackGraphReport(entityRef));
      }
    } catch (e) {
      setReport(buildFallbackAttackGraphReport(entityRef));
    } finally {
      setSimulating(null);
    }
  };

  if (error) {
    return (
      <InfoCard title="Infrahub Attack Graph">
        <p>{error}</p>
      </InfoCard>
    );
  }

  if (!report) {
    return (
      <InfoCard title="Infrahub Attack Graph">
        <p>Loading attack graph report…</p>
      </InfoCard>
    );
  }

  return (
    <InfoCard title="Infrahub Attack Graph">
      {/* Summary Banner */}
      <div style={{ marginBottom: 16 }}>
        <strong>Status:</strong> {report.scorecardStatus} |{' '}
        <strong>Checks:</strong> {report.passedChecksCount}/{report.totalChecksCount} passed |{' '}
        <strong>Risk Score:</strong> {report.facts.attack_path_risk_score}
        <br />
        <a href={report.infrahubDeepLinkUrl} target="_blank" rel="noopener noreferrer">
          🔗 Inspect Full Attack-Path &amp; SBOM Graph in Infrahub
        </a>
        {' | '}
        <a href={report.infrahubMcpAgentUri} target="_blank" rel="noopener noreferrer">
          🤖 Ask infrahub-mcp AI Assistant
        </a>
      </div>

      {/* What-if Remediation Buttons */}
      <div style={{ marginBottom: 16, display: 'flex', gap: 8, flexWrap: 'wrap' }}>
        <button onClick={() => handleSimulate('rotate-ssl')} disabled={simulating !== null}>
          Rotate SSL
        </button>
        <button onClick={() => handleSimulate('upgrade-eol-runtime')} disabled={simulating !== null}>
          Upgrade EOL Runtime
        </button>
        <button onClick={() => handleSimulate('patch-kev-cve')} disabled={simulating !== null}>
          Patch KEV CVE
        </button>
        <button onClick={() => handleSimulate('isolate-lateral-path')} disabled={simulating !== null}>
          Isolate Lateral Path
        </button>
        <button onClick={handleReset} disabled={simulating !== null}>
          Reset
        </button>
      </div>

      {/* Tabs */}
      <div style={{ marginBottom: 8 }}>
        <button
          style={{ marginRight: 8, fontWeight: activeTab === 'scorecard' ? 'bold' : 'normal' }}
          onClick={() => setActiveTab('scorecard')}
        >
          Tech-Insights Scorecard
        </button>
        <button
          style={{ marginRight: 8, fontWeight: activeTab === 'attack-graph' ? 'bold' : 'normal' }}
          onClick={() => setActiveTab('attack-graph')}
        >
          N-Hop Attack-Path Graph
        </button>
        <button
          style={{ fontWeight: activeTab === 'graphql-mcp' ? 'bold' : 'normal' }}
          onClick={() => setActiveTab('graphql-mcp')}
        >
          Infrahub GraphQL &amp; infrahub-mcp AI Bridge
        </button>
      </div>

      {/* Tab: Scorecard */}
      {activeTab === 'scorecard' && (
        <div>
          <h4>Infrahub Facts</h4>
          <div style={{ display: 'flex', gap: 12, flexWrap: 'wrap', marginBottom: 16 }}>
            <span>exposed_domain_count: {report.facts.exposed_domain_count}</span>
            <span>non_compliant_ssl_count: {report.facts.non_compliant_ssl_count}</span>
            <span>eol_package_count: {report.facts.eol_package_count}</span>
            <span>reachable_kev_cve_count: {report.facts.reachable_kev_cve_count}</span>
            <span>reachable_lateral_data_paths_count: {report.facts.reachable_lateral_data_paths_count}</span>
            <span>attack_path_risk_score: {report.facts.attack_path_risk_score}</span>
          </div>
          <h4>Scorecard Checks</h4>
          <table style={{ width: '100%', borderCollapse: 'collapse' }}>
            <thead>
              <tr>
                <th>Check</th>
                <th>Fact</th>
                <th>Threshold</th>
                <th>Actual</th>
                <th>Result</th>
                <th>Remediation Guidance</th>
              </tr>
            </thead>
            <tbody>
              {report.scorecardChecks.map((check, i) => (
                <tr key={i}>
                  <td>{(check as any).checkName ?? check.check}</td>
                  <td>{(check as any).factName ?? check.fact}</td>
                  <td>{(check as any).thresholdValue ?? check.threshold}</td>
                  <td>{(check as any).actualValue ?? check.actual}</td>
                  <td>{check.result}</td>
                  <td>{check.remediationGuidance}</td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      )}

      {/* Tab: Attack Graph */}
      {activeTab === 'attack-graph' && (
        <div>
          <h4>Attack Paths</h4>
          {report.attackPaths.map((path, i) => (
            <div key={i} style={{ marginBottom: 12, padding: 8, border: '1px solid #ccc' }}>
              <strong>{path.title}</strong> (hops: {path.hopCount}, risk: {path.chainRiskScore})
              <br />
              {path.entryDomain} → {path.tlsPosture} → {path.eolRuntimeInChain} → {path.exploitableCveId} → {path.targetDataOrServiceAsset}
              <br />
              <em>AI MCP Remediation:</em> {path.aiMcpRemediationPrompt}
            </div>
          ))}
          <h4>Graph Nodes ({(report.graphNodes ?? []).length})</h4>
          <div style={{ display: 'flex', gap: 8, flexWrap: 'wrap', marginBottom: 16 }}>
            {(report.graphNodes ?? []).map((node, i) => (
              <span key={i} style={{ padding: '4px 8px', border: '1px solid #ccc', borderRadius: 4 }}>
                <strong>{node.nodeType}</strong>: {node.label}
              </span>
            ))}
          </div>
          <h4>Graph Edges</h4>
          <table style={{ width: '100%', borderCollapse: 'collapse' }}>
            <thead>
              <tr>
                <th>From Node</th>
                <th>Edge Type</th>
                <th>To Node</th>
                <th>Protocol/Mechanism</th>
                <th>Exploitable</th>
              </tr>
            </thead>
            <tbody>
              {report.edges.map((edge, i) => (
                <tr key={i}>
                  <td>{edge.fromNodeId}</td>
                  <td>{edge.edgeType}</td>
                  <td>{edge.toNodeId}</td>
                  <td>{edge.protocolOrMechanism}</td>
                  <td>{edge.isExploitableReachable ? 'Yes' : 'No'}</td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      )}

      {/* Tab: GraphQL & MCP */}
      {activeTab === 'graphql-mcp' && (
        <div>
          <h4>Infrahub GraphQL Query</h4>
          <pre style={{ background: '#f5f5f5', padding: 8, overflowX: 'auto' }}>
            {report.infrahubGraphQlQuery}
          </pre>
          <h4>infrahub-mcp AI Prompt</h4>
          <pre style={{ background: '#f5f5f5', padding: 8, overflowX: 'auto' }}>
            {report.infrahubMcpPrompt}
          </pre>
        </div>
      )}
    </InfoCard>
  );
}

// --- Module Export ---

export const infrahubAttackGraphCard = EntityCardBlueprint.make({
  name: 'infrahub-attack-graph-card',
  params: {
    filter: 'kind:component,resource',
    loader: async () => <EntityInfrahubAttackGraphCard />,
  },
});

export const infrahubAttackGraphModule = createFrontendModule({
  pluginId: 'catalog',
  extensions: [infrahubAttackGraphCard],
});

import { EntityAttackGraphScorecardReport, InfrahubTechInsightsFacts, TechInsightsScorecardCheck } from './infrahubAttackGraphModule';

type ServiceSeed = { facts: InfrahubTechInsightsFacts; entryDomain: string; tls: string; runtime: string; cve: string; target: string; hops: number };

const FACTS_BY_SERVICE: Record<string, ServiceSeed> = {
  'aegis-backend': { facts: { non_compliant_ssl_count: 1, eol_package_count: 2, reachable_kev_cve_count: 2, reachable_lateral_data_paths_count: 2, exposed_domain_count: 2, attack_path_risk_score: 92 }, entryDomain: 'stg.backend.api.aegis.cloud.goog', tls: 'TLS-1.2 Expiring', runtime: 'Node.js 18.20.8 EOL', cve: 'CVE-2026-111497', target: 'aegis-db', hops: 7 },
  'aegis-auth': { facts: { non_compliant_ssl_count: 0, eol_package_count: 0, reachable_kev_cve_count: 1, reachable_lateral_data_paths_count: 1, exposed_domain_count: 1, attack_path_risk_score: 68 }, entryDomain: 'auth.aegis.cloud.goog', tls: '', runtime: 'Node.js 20.11.0', cve: 'CVE-2026-111497', target: 'gce-auth-redis-ephemeral-02', hops: 4 },
  'aegis-ui': { facts: { non_compliant_ssl_count: 1, eol_package_count: 0, reachable_kev_cve_count: 0, reachable_lateral_data_paths_count: 1, exposed_domain_count: 3, attack_path_risk_score: 48 }, entryDomain: 'stg.ui.aegis.cloud.goog', tls: 'TLS-1.3 Valid', runtime: 'React 18.2.0', cve: '', target: 'aegis-cdn', hops: 5 },
  'aegis-db': { facts: { non_compliant_ssl_count: 0, eol_package_count: 0, reachable_kev_cve_count: 0, reachable_lateral_data_paths_count: 0, exposed_domain_count: 0, attack_path_risk_score: 12 }, entryDomain: '', tls: '', runtime: '', cve: '', target: '', hops: 1 },
  'hello-world-app': { facts: { non_compliant_ssl_count: 0, eol_package_count: 0, reachable_kev_cve_count: 0, reachable_lateral_data_paths_count: 0, exposed_domain_count: 1, attack_path_risk_score: 15 }, entryDomain: 'hello.aegis.cloud.goog', tls: 'HAProxy 3.0 TLS 1.3', runtime: 'Node.js 22.15.0', cve: '', target: '', hops: 3 },
};

export function resolveServiceKey(entityOrRef: string): string {
  const raw = (entityOrRef || '').split('/').pop()?.split(':').pop() || 'aegis-backend';
  if (raw === 'haproxy-hello-world-tls') return 'hello-world-app';
  return FACTS_BY_SERVICE[raw] ? raw : 'aegis-backend';
}

export function evaluateChecks(facts: InfrahubTechInsightsFacts): TechInsightsScorecardCheck[] {
  return [
    { check: 'SSL/TLS Compliance', fact: 'non_compliant_ssl_count', threshold: '0', actual: String(facts.non_compliant_ssl_count), result: facts.non_compliant_ssl_count === 0 ? 'PASS' : 'FAIL', remediationGuidance: 'Rotate or renew non-compliant SSL/TLS certificates.' },
    { check: 'EOL Runtime Hygiene', fact: 'eol_package_count', threshold: '0', actual: String(facts.eol_package_count), result: facts.eol_package_count === 0 ? 'PASS' : 'FAIL', remediationGuidance: 'Upgrade EOL runtimes and packages to supported versions.' },
    { check: 'Zero Reachable KEV CVEs', fact: 'reachable_kev_cve_count', threshold: '0', actual: String(facts.reachable_kev_cve_count), result: facts.reachable_kev_cve_count === 0 ? 'PASS' : 'FAIL', remediationGuidance: 'Patch all reachable KEV-listed CVEs.' },
    { check: 'Lateral Data Path Isolation', fact: 'reachable_lateral_data_paths_count', threshold: '<= 1', actual: String(facts.reachable_lateral_data_paths_count), result: facts.reachable_lateral_data_paths_count <= 1 ? 'PASS' : 'FAIL', remediationGuidance: 'Isolate or remove excess lateral data paths.' },
    { check: 'Exposed Domain Surface', fact: 'exposed_domain_count', threshold: '<= 3', actual: String(facts.exposed_domain_count), result: facts.exposed_domain_count <= 3 ? 'PASS' : 'FAIL', remediationGuidance: 'Reduce exposed domain surface.' },
    { check: 'Attack Path Risk Ceiling', fact: 'attack_path_risk_score', threshold: '<= 45', actual: String(facts.attack_path_risk_score), result: facts.attack_path_risk_score <= 45 ? 'PASS' : 'FAIL', remediationGuidance: 'Reduce attack path risk by remediating contributing factors.' },
  ];
}

export function buildFallbackAttackGraphReport(entityOrRef: string, customFacts?: InfrahubTechInsightsFacts): EntityAttackGraphScorecardReport {
  const key = resolveServiceKey(entityOrRef);
  const seed = FACTS_BY_SERVICE[key];
  const facts = customFacts ?? seed.facts;
  const chain = [seed.entryDomain, seed.tls, seed.runtime, seed.cve, seed.target].filter(Boolean);
  const types = ['domain', 'protocol', 'runtime', 'cve', 'datastore'];
  const graphNodes = chain.map((item, i) => ({ nodeId: `${key}-node-${i}`, nodeType: types[i] || 'ASSET', label: item }));
  const edges = graphNodes.slice(0, -1).map((n, i) => ({ fromNodeId: n.nodeId, edgeType: 'REACHABLE_HOT_PATH_TO', toNodeId: graphNodes[i + 1].nodeId, protocolOrMechanism: 'HTTPS / Runtime Hop', isExploitableReachable: facts.attack_path_risk_score > 45 }));
  const attackPaths = seed.entryDomain
    ? [{ title: `${seed.hops}-hop attack path: ${seed.entryDomain} -> ${seed.target || seed.runtime}`, hopCount: seed.hops, entryDomain: seed.entryDomain, tlsPosture: seed.tls || 'TLS-1.3 Valid', eolRuntimeInChain: seed.runtime || 'none', exploitableCveId: seed.cve || 'none', targetDataOrServiceAsset: seed.target || seed.runtime || key, chainRiskScore: facts.attack_path_risk_score, aiMcpRemediationPrompt: `Remediate attack path for ${key} by addressing ${seed.runtime || 'TLS'} and ${seed.cve || 'lateral exposure'}.` }]
    : [];
  const checks = evaluateChecks(facts);
  const passedChecksCount = checks.filter((c) => c.result === 'PASS').length;
  const totalChecksCount = checks.length;
  const scorecardStatus = passedChecksCount === totalChecksCount ? 'PASS' : (facts.reachable_kev_cve_count > 0 || facts.attack_path_risk_score > 65 ? 'FAIL' : 'WARN');
  return { entityRef: entityOrRef, scorecardStatus, passedChecksCount, totalChecksCount, facts, scorecardChecks: checks, attackPaths, graphNodes, edges, infrahubDeepLinkUrl: `https://infrahub.example.com/services/${key}`, infrahubMcpAgentUri: `mcp://infrahub/agents/${key}`, infrahubGraphQlQuery: `query TechInsightsFacts { service(key: "${key}") { attackPathRiskScore } }`, infrahubMcpPrompt: `Analyze attack graph for ${key} and recommend remediation.` };
}

export function simulateFallbackAttackGraph(current: EntityAttackGraphScorecardReport, action: string): EntityAttackGraphScorecardReport {
  const f = { ...current.facts };
  if (action === 'rotate-ssl') f.non_compliant_ssl_count = 0;
  if (action === 'upgrade-eol-runtime') f.eol_package_count = 0;
  if (action === 'patch-kev-cve') f.reachable_kev_cve_count = 0;
  if (action === 'isolate-lateral-path') f.reachable_lateral_data_paths_count = 0;
  f.attack_path_risk_score = Math.max(0, f.attack_path_risk_score - (f.non_compliant_ssl_count === 0 ? 20 : 0) - (f.eol_package_count === 0 ? 25 : 0) - (f.reachable_kev_cve_count === 0 ? 30 : 0) - (f.reachable_lateral_data_paths_count === 0 ? 15 : 0));
  return buildFallbackAttackGraphReport(current.entityRef, f);
}

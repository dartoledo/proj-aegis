import {
  getEntityAttackGraphScorecard,
  getFleetAttackGraphSummary,
  resetInfrahubSimulationState,
  retrieveInfrahubTechInsightsFacts,
  simulateInfrahubWhatIfRemediation,
} from './infrahubAttackGraphService';

describe('infrahubAttackGraphService', () => {
  beforeEach(() => {
    resetInfrahubSimulationState();
  });

  describe('retrieveInfrahubTechInsightsFacts', () => {
    it('returns correct facts for aegis-backend', async () => {
      const facts = await retrieveInfrahubTechInsightsFacts('component:default/aegis-backend');
      expect(facts.exposed_domain_count).toBe(2);
      expect(facts.non_compliant_ssl_count).toBe(1);
      expect(facts.eol_package_count).toBe(2);
      expect(facts.reachable_kev_cve_count).toBe(2);
      expect(facts.reachable_lateral_data_paths_count).toBe(2);
      expect(facts.attack_path_risk_score).toBe(92);
    });
  });

  describe('getEntityAttackGraphScorecard', () => {
    it('returns FAIL scorecard for aegis-backend', async () => {
      const scorecard = await getEntityAttackGraphScorecard('component:default/aegis-backend');
      expect(scorecard.scorecardStatus).toBe('FAIL');
      expect(scorecard.scorecardChecks).toHaveLength(6);
      expect(scorecard.nodes).toBeDefined();
      expect(scorecard.edges).toBeDefined();
      expect(scorecard.attackPaths).toBeDefined();
      expect(scorecard.infrahubDeepLinkUrl).toBeDefined();
      expect(scorecard.infrahubMcpAgentUri).toBeDefined();
    });

    it('returns PASS scorecard for aegis-db', async () => {
      const scorecard = await getEntityAttackGraphScorecard('component:default/aegis-db');
      expect(scorecard.scorecardStatus).toBe('PASS');
    });
  });

  describe('simulateInfrahubWhatIfRemediation', () => {
    it('zeroes reachable_kev_cve_count and lowers attack_path_risk_score', async () => {
      const before = await retrieveInfrahubTechInsightsFacts('component:default/aegis-backend');
      const after = await simulateInfrahubWhatIfRemediation('component:default/aegis-backend', 'patch-kev-cve');
      expect(after.facts.reachable_kev_cve_count).toBe(0);
      expect(after.facts.attack_path_risk_score).toBeLessThan(before.attack_path_risk_score);
    });
  });

  describe('getFleetAttackGraphSummary', () => {
    it('evaluates all 5 services and reports highestRiskService', async () => {
      const summary = await getFleetAttackGraphSummary();
      expect(summary.reports).toHaveLength(5);
      expect(summary.totalServicesEvaluated).toBe(5);
      expect(summary.highestRiskService).toBe('aegis-backend');
    });
  });
});

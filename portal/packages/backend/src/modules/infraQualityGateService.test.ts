import {
  evaluateEntityQualityGates,
  getPresetInfraScenarios,
  simulateInfraChangePreFlight,
} from './infraQualityGateService';

describe('infraQualityGateService', () => {
  describe('evaluateEntityQualityGates', () => {
    it('should return 6 gates with overallVerdict BLOCKED_BY_POLICY for aegis-backend', async () => {
      const result = await evaluateEntityQualityGates(
        'component:default/aegis-backend',
      );
      expect(result.gates.length).toBe(6);
      expect(result.overallVerdict).toBe('BLOCKED_BY_POLICY');
    });
  });

  describe('simulateInfraChangePreFlight', () => {
    it('should return PRE_FLIGHT_SIMULATION mode with HARD_BLOCK on GATE-01 for expose-public-no-iap', async () => {
      const result = await simulateInfraChangePreFlight({
        entityRef: 'component:default/aegis-backend',
        scenarioId: 'expose-public-no-iap',
      });
      expect(result.evaluationMode).toBe('PRE_FLIGHT_SIMULATION');
      expect(result.gates.find((g) => g.gateId === 'GATE-01')?.verdict).toBe(
        'HARD_BLOCK',
      );
      expect(result.overallVerdict).toBe('BLOCKED_BY_POLICY');
    });

    it('should return AUTO_APPROVED with readinessScore 100 and passedGates 6 for golden-path-node22-upgrade', async () => {
      const result = await simulateInfraChangePreFlight({
        entityRef: 'component:default/aegis-backend',
        scenarioId: 'golden-path-node22-upgrade',
      });
      expect(result.overallVerdict).toBe('AUTO_APPROVED');
      expect(result.readinessScore).toBe(100);
      expect(result.passedGates).toBe(6);
    });
  });

  describe('getPresetInfraScenarios', () => {
    it('should return 3 preset scenarios', () => {
      const scenarios = getPresetInfraScenarios();
      expect(scenarios.length).toBe(3);
    });
  });
});

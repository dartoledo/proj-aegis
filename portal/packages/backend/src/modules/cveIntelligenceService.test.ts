import {
  computeAcrsScore,
  getEntityCveIntelligenceReport,
  getFleetCvePriorities,
  issueVexAttestation,
  resetCveVexAttestations,
} from './cveIntelligenceService';

describe('cveIntelligenceService', () => {
  beforeEach(() => {
    resetCveVexAttestations();
  });

  describe('computeAcrsScore', () => {
    it('returns a high ACRS score for a critical reachable CVE', () => {
      const score = computeAcrsScore({
        cvssScore: 9.8,
        epssScore: 0.964,
        isCisaKev: true,
        exposureTier: 'strictly-private',
        reachability: 'REACHABLE_HOT_PATH',
        vexStatus: 'AFFECTED',
      });
      expect(score).toBeGreaterThanOrEqual(70);
    });

    it('returns 0 when vexStatus is NOT_AFFECTED_VEX', () => {
      const score = computeAcrsScore({
        cvssScore: 9.8,
        epssScore: 0.964,
        isCisaKev: true,
        exposureTier: 'strictly-private',
        reachability: 'REACHABLE_HOT_PATH',
        vexStatus: 'NOT_AFFECTED_VEX',
      });
      expect(score).toBe(0);
    });
  });

  describe('getEntityCveIntelligenceReport', () => {
    it('returns correct cisaKevCount and top priority CVE', async () => {
      const report = await getEntityCveIntelligenceReport('component:default/aegis-backend');
      expect(report.cisaKevCount).toBe(2);
      expect(report.cves[0].cveId).toBe('CVE-2026-111497');
      expect(report.cves[0].priorityTier).toBe('P0_IMMEDIATE_24H');
    });

    it('assigns low ACRS score and P2 tier to unreachable dead code CVE', async () => {
      const report = await getEntityCveIntelligenceReport('component:default/aegis-backend');
      const cve = report.cves.find((c) => c.cveId === 'CVE-2024-0727');
      expect(cve).toBeDefined();
      expect(cve!.acrsScore).toBeLessThan(20);
      expect(cve!.priorityTier).toBe('P2_SCHEDULED_30D');
    });
  });

  describe('issueVexAttestation', () => {
    it('reduces cisaKevCount after attesting a CISA KEV CVE', async () => {
      const before = await getEntityCveIntelligenceReport('component:default/aegis-backend');
      expect(before.cisaKevCount).toBe(2);

      await issueVexAttestation('component:default/aegis-backend', 'CVE-2026-41092', 'inline_mitigations_already_exist');

      const after = await getEntityCveIntelligenceReport('component:default/aegis-backend');
      expect(after.cisaKevCount).toBe(1);
    });
  });

  describe('getFleetCvePriorities', () => {
    it('returns correct fleet-level statistics', async () => {
      const result = await getFleetCvePriorities();
      expect(result.totalServices).toBe(5);
      expect(result.totalRawCves).toBe(8);
      expect(result.fleetNoiseReductionPercent).toBeGreaterThan(40);
    });
  });
});

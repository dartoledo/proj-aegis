import {
  executeGcpOsConfigPatchJob,
  generateEntitySpdxSbomDocument,
  getEntityGcpCloudPostureReport,
  getFleetGcpCloudPostureSummary,
  resetGcpPostureRemediationState,
  resolveServiceKey,
} from './gcpCloudPostureService';

describe('gcpCloudPostureService', () => {
  beforeEach(async () => {
    await resetGcpPostureRemediationState();
  });

  describe('getEntityGcpCloudPostureReport', () => {
    it('returns correct report for aegis-backend', async () => {
      const report = await getEntityGcpCloudPostureReport('component:default/aegis-backend');

      expect(report.serviceName).toBe('aegis-backend');
      expect(report.domainExposureTier).toBe('strictly-private');
      expect(report.vmInventory.gcpProject).toBe('aegis-prod-cloud');
      expect(report.osPackages.some((p) => p.cveIds.includes('CVE-2026-111497'))).toBe(true);
      expect(report.patchSummary.overallPatchRisk).toBe('CRITICAL');
      expect(report.patchSummary.pendingRebootCount).toBe(1);
      expect(report.patchSummary.unpatchedEolCount).toBe(2);
    });

    it('returns correct report for aegis-ui', async () => {
      const report = await getEntityGcpCloudPostureReport('component:default/aegis-ui');

      expect(report.domainExposureTier).toBe('unrestricted-public');
      expect(report.patchSummary.mitigatedVexCount).toBe(1);
    });
  });

  describe('resolveServiceKey', () => {
    it('resolves haproxy-hello-world-tls to hello-world-app', () => {
      expect(resolveServiceKey('resource:default/haproxy-hello-world-tls')).toBe('hello-world-app');
    });
  });

  describe('getFleetGcpCloudPostureSummary', () => {
    it('returns 5 reports covering all exposure tiers', async () => {
      const summary = await getFleetGcpCloudPostureSummary();

      expect(summary.length).toBe(5);

      const tiers = summary.map((r) => r.domainExposureTier);
      expect(tiers).toContain('unrestricted-public');
      expect(tiers).toContain('restricted-public');
      expect(tiers).toContain('strictly-private');
    });
  });

  describe('executeGcpOsConfigPatchJob', () => {
    it('remediates aegis-backend to COMPLIANT state', async () => {
      const remediated = await executeGcpOsConfigPatchJob('component:default/aegis-backend');

      expect(remediated.vmInventory.patchComplianceState).toBe('COMPLIANT');
      expect(remediated.vmInventory.rebootRequired).toBe(false);
      expect(remediated.patchSummary.overallPatchRisk).toBe('COMPLIANT');
      expect(remediated.patchSummary.unpatchedEolCount).toBe(0);
      expect(remediated.patchSummary.patchAvailableCount).toBe(0);
    });

    it('preserves MITIGATED_VEX packages for aegis-ui', async () => {
      const remediated = await executeGcpOsConfigPatchJob('component:default/aegis-ui');

      expect(remediated.patchSummary.mitigatedVexCount).toBe(1);
    });
  });

  describe('generateEntitySpdxSbomDocument', () => {
    it('generates SPDX 2.3 document for aegis-ui with 4 packages', async () => {
      const sbom = await generateEntitySpdxSbomDocument('component:default/aegis-ui');

      expect(sbom.spdxVersion).toBe('SPDX-2.3');
      expect((sbom.packages as unknown[]).length).toBe(4);
    });
  });
});

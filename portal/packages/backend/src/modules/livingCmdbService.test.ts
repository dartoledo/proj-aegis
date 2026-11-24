import {
  AEGIS_TEAM_OWNERS_TABLE,
  getEntityCmdbSnapshot,
  getFleetCmdbTopology,
  reconcileCmdbDrift,
  resetCmdbReconciliationState,
  getComponentTaxonomyCatalog,
} from './livingCmdbService';

describe('livingCmdbService', () => {
  beforeEach(() => {
    resetCmdbReconciliationState();
  });

  describe('getEntityCmdbSnapshot', () => {
    it('returns snapshot for aegis-backend', async () => {
      const snapshot = await getEntityCmdbSnapshot('component:default/aegis-backend');
      expect(snapshot.ciId).toBe('CI-AEGIS-1002');
      expect(snapshot.driftStatus).toBe('DRIFT_DETECTED');
      expect(snapshot.activeDriftCount).toBe(3);
      expect(snapshot.blastRadius.length).toBe(3);
      expect(snapshot.componentInventory?.length).toBeGreaterThan(0);
      const domains = snapshot.componentInventory!.map((c: any) => c.domain);
      expect(domains).toContain('INFRASTRUCTURE');
      expect(domains).toContain('SOFTWARE');
    });
  });

  describe('getFleetCmdbTopology', () => {
    it('returns fleet topology', async () => {
      const topology = await getFleetCmdbTopology();
      expect(topology.totalConfigurationItems).toBe(5);
      expect(topology.driftedServicesCount).toBe(3);
      expect(topology.totalActiveDrifts).toBe(5);
      expect(topology.shadowResourcesDetected).toBe(1);
      expect(topology.directedEdges.length).toBe(5);
      expect(topology.taxonomyCatalog?.length).toBe(33);
    });
  });

  describe('reconcileCmdbDrift', () => {
    it('enforces git state', async () => {
      const result = await reconcileCmdbDrift('component:default/aegis-backend', 'enforce-git-state');
      expect(result.driftStatus).toBe('IN_SYNC');
      expect(result.activeDriftCount).toBe(0);
      expect(result.observedReplicas).toBe(3);
    });

    it('syncs to git with specific drift', async () => {
      const result = await reconcileCmdbDrift('component:default/aegis-backend', 'sync-to-git', 'drift-backend-replicas');
      expect(result.activeDriftCount).toBe(2);
    });
  });

  describe('getComponentTaxonomyCatalog', () => {
    it('returns 20 INFRASTRUCTURE items across 7 distinct layers', () => {
      const catalog = getComponentTaxonomyCatalog();
      const infra = catalog.filter((c: any) => c.domain === 'INFRASTRUCTURE');
      expect(infra.length).toBe(20);
      const layerIds = new Set(infra.map((c: any) => c.layerId));
      expect(layerIds.size).toBe(7);
      const orders = [...new Set(infra.map((c: any) => c.layerOrder))].sort((a: any, b: any) => a - b);
      expect(orders).toEqual([1, 2, 3, 4, 5, 6, 7]);
    });

    it('returns 13 SOFTWARE items', () => {
      const catalog = getComponentTaxonomyCatalog();
      const software = catalog.filter((c: any) => c.domain === 'SOFTWARE');
      expect(software.length).toBe(13);
      const scm = software.find((c: any) => c.id === 'DEVELOPMENT_TOOLS_SCM');
      expect(scm).toBeDefined();
      expect(scm!.label).toBe('Development Tools & Source Control (SCM)');
    });

    it('assigns ownerTeamId from AEGIS_TEAM_OWNERS_TABLE to every component', async () => {
      const teamIds = AEGIS_TEAM_OWNERS_TABLE.map((t: any) => t.teamId);
      expect(teamIds).toEqual(['app-team', 'sre-team']);
      const snapshot = await getEntityCmdbSnapshot('component:default/aegis-backend');
      const validTeamIds = ['app-team', 'sre-team'];
      for (const node of snapshot.componentInventory!) {
        expect(validTeamIds).toContain((node as any).ownerTeamId);
      }
    });
  });
});

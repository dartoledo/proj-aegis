import {
  getEntityCmdbSnapshot,
  getFleetCmdbTopology,
  reconcileCmdbDrift,
  resetCmdbReconciliationState,
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
});

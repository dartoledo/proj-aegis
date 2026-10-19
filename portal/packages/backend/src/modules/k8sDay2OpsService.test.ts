import {
  evaluateK8sDay2Policy,
  executeK8sDay2Operation,
  inspectK8sDeployment,
  readGitOpsManifestReplicas,
  renderK8sPrometheusMetrics,
  verifyK8sWorkloadAndBuildDiff,
} from './k8sDay2OpsService';

jest.setTimeout(90000);

describe('k8sDay2OpsService', () => {
  describe('OPA Policy Guardrails (evaluateK8sDay2Policy)', () => {
    it('allows valid Count and Percentage scaling on stateless microservices', async () => {
      const countRes = await evaluateK8sDay2Policy({
        entityRef: 'component:default/aegis-backend',
        operationType: 'scale',
        selectionMode: 'Count',
        replicaValue: 3,
        reason: 'Load test scale out',
      });
      expect(countRes.allowed).toBe(true);
      expect(countRes.deploymentName).toBe('backend');
      expect(countRes.targetReplicas).toBe(3);

      const pctRes = await evaluateK8sDay2Policy({
        entityRef: 'component:default/aegis-auth',
        operationType: 'scale',
        selectionMode: 'Percentage',
        replicaValue: 200,
        reason: '200% capacity boost',
      });
      expect(pctRes.allowed).toBe(true);
      expect(pctRes.deploymentName).toBe('auth');
      expect(pctRes.targetReplicas).toBe(2);
    });

    it('rejects scaling above maxReplicas (10) with OPA Policy Violation AEGIS-K8S-002', async () => {
      await expect(
        evaluateK8sDay2Policy({
          entityRef: 'component:default/aegis-backend',
          operationType: 'scale',
          selectionMode: 'Count',
          replicaValue: 15,
          reason: 'Excessive scale attempt',
        }),
      ).rejects.toThrow(/OPA Policy Violation \[AEGIS-K8S-002\]/);
    });

    it('rejects scaling stateful database workload aegis-db with AEGIS-K8S-001 while permitting rolling-restart', async () => {
      await expect(
        evaluateK8sDay2Policy({
          entityRef: 'resource:default/aegis-db',
          operationType: 'scale',
          selectionMode: 'Count',
          replicaValue: 2,
          reason: 'Attempt to scale stateful single-primary Postgres',
        }),
      ).rejects.toThrow(/OPA Policy Violation \[AEGIS-K8S-001\]/);

      const restartDb = await evaluateK8sDay2Policy({
        entityRef: 'resource:default/aegis-db',
        operationType: 'rolling-restart',
        reason: 'Connection pool flush',
      });
      expect(restartDb.allowed).toBe(true);
      expect(restartDb.deploymentName).toBe('db');
      expect(restartDb.targetReplicas).toBe(1);
    });
  });

  describe('Live K3s Day-2 Scale, Rolling Restart, State Diff, and Prometheus Metrics', () => {
    afterAll(async () => {
      // Ensure backend is restored to 1 replica after tests
      try {
        await executeK8sDay2Operation({
          entityRef: 'component:default/aegis-backend',
          deploymentName: 'backend',
          operationType: 'scale',
          targetReplicas: 1,
          syncGitOpsManifest: true,
          reason: 'Restore baseline 1 replica after test suite',
        });
      } catch {
        // Ignore cleanup errors
      }
    });

    it('scales deployment/backend from 1 to 2 replicas on live K3s, syncs GitOps manifest, verifies HTTP health, and generates Before vs After diff', async () => {
      // Ensure starting state is 1 replica
      await executeK8sDay2Operation({
        entityRef: 'component:default/aegis-backend',
        deploymentName: 'backend',
        operationType: 'scale',
        targetReplicas: 1,
        syncGitOpsManifest: true,
        reason: 'Initialize baseline 1 replica',
      });

      const beforeSnap = await inspectK8sDeployment('backend');
      expect(beforeSnap.desiredReplicas).toBe(1);
      expect(beforeSnap.readyReplicas).toBe(1);

      // Scale up to 2 replicas
      const scaleUp = await executeK8sDay2Operation({
        entityRef: 'component:default/aegis-backend',
        deploymentName: 'backend',
        operationType: 'scale',
        targetReplicas: 2,
        syncGitOpsManifest: true,
        reason: 'Day-2 test scale up to 2 replicas',
      });

      expect(scaleUp.targetReplicas).toBe(2);
      expect(scaleUp.gitOpsSynced).toBe(true);
      expect(readGitOpsManifestReplicas('backend')).toBe(2);

      const verifiedDiff = await verifyK8sWorkloadAndBuildDiff({
        deploymentName: 'backend',
        operationType: 'scale',
        expectedReplicas: 2,
        previousSnapshot: scaleUp.previous,
        gitOpsSynced: scaleUp.gitOpsSynced,
        reason: 'Day-2 test scale up to 2 replicas',
      });

      expect(verifiedDiff.steadyStateVerified).toBe(true);
      expect(verifiedDiff.serviceHealthVerified).toBe(true);
      expect(verifiedDiff.current.readyReplicas).toBe(2);
      expect(verifiedDiff.current.pods.length).toBe(2);
      expect(verifiedDiff.unifiedDiff).toContain(
        '-  Desired Replicas    : 1',
      );
      expect(verifiedDiff.unifiedDiff).toContain(
        '+  Desired Replicas    : 2',
      );
      expect(verifiedDiff.unifiedDiff).toContain(
        '-  Ready Replicas      : 1 / 1 Ready',
      );
      expect(verifiedDiff.unifiedDiff).toContain(
        '+  Ready Replicas      : 2 / 2 Ready',
      );
      expect(verifiedDiff.markdownDiff).toContain(
        '| K8s Workload Attribute | Pre-Operation State (Before) | Post-Operation State (After) |',
      );

      // Scale back down to 1 replica
      const scaleDown = await executeK8sDay2Operation({
        entityRef: 'component:default/aegis-backend',
        deploymentName: 'backend',
        operationType: 'scale',
        targetReplicas: 1,
        syncGitOpsManifest: true,
        reason: 'Scale back down to baseline 1 replica',
      });
      expect(scaleDown.current.desiredReplicas).toBe(1);
      expect(readGitOpsManifestReplicas('backend')).toBe(1);
    });

    it('executes a zero-downtime rolling-restart on deployment/auth, verifies new restartedAt timestamp and Prometheus metrics', async () => {
      const beforeAuth = await inspectK8sDeployment('auth');

      const restartRes = await executeK8sDay2Operation({
        entityRef: 'component:default/aegis-auth',
        deploymentName: 'auth',
        operationType: 'rolling-restart',
        reason: 'Zero-downtime rolling restart verification',
      });

      expect(restartRes.restartedAt).not.toBe('initial');
      expect(restartRes.restartedAt).not.toBe(beforeAuth.restartedAt);
      expect(restartRes.current.readyReplicas).toBe(1);
      expect(restartRes.operationDiff.steadyStateVerified).toBe(true);
      expect(restartRes.operationDiff.unifiedDiff).toContain(
        'Rollout RestartedAt',
      );

      const metrics = await renderK8sPrometheusMetrics();
      expect(metrics).toContain(
        'idp_k8s_deployment_desired_replicas{deployment="backend",namespace="default",entity="component:default/aegis-backend"} 1',
      );
      expect(metrics).toContain(
        'idp_k8s_deployment_ready_replicas{deployment="auth",namespace="default",entity="component:default/aegis-auth"} 1',
      );
      expect(metrics).toContain(
        'idp_k8s_day2_operations_total{deployment="auth",operation="rolling-restart"}',
      );
    });
  });
});

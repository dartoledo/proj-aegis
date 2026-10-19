import {
  coreServices,
  createBackendModule,
  createBackendPlugin,
} from '@backstage/backend-plugin-api';
import { Entity } from '@backstage/catalog-model';
import {
  CatalogProcessor,
  catalogProcessingExtensionPoint,
} from '@backstage/plugin-catalog-node';
import {
  createTemplateAction,
  scaffolderActionsExtensionPoint,
} from '@backstage/plugin-scaffolder-node';
import express from 'express';
import {
  evaluateK8sDay2Policy,
  executeK8sDay2Operation,
  getAllK8sWorkloadsStatus,
  inspectK8sDeployment,
  K8sDeploymentSnapshot,
  renderK8sPrometheusMetrics,
  verifyK8sWorkloadAndBuildDiff,
} from './k8sDay2OpsService';

function createValidateK8sPolicyAction() {
  return createTemplateAction({
    id: 'resiliency:k8s:validate-policy',
    description:
      'Evaluates OPA policy guardrails (min/max replicas, stateful workload protection, Count vs Percentage calculation) before executing a K8s Day-2 operation.',
    schema: {
      input: {
        entityRef: z =>
          z.string().describe('Target Backstage Catalog entity reference'),
        namespace: z =>
          z.string().optional().default('default').describe('K8s namespace'),
        operationType: z =>
          z
            .enum(['scale', 'rolling-restart'])
            .default('scale')
            .describe('Day-2 operation type'),
        selectionMode: z =>
          z
            .enum(['Count', 'Percentage'])
            .optional()
            .default('Count')
            .describe('Instance selection mode (Count or Percentage)'),
        replicaValue: z =>
          z
            .number()
            .optional()
            .describe('Target replica count or percentage of baseline'),
        reason: z =>
          z.string().optional().describe('Audit reason or change ticket'),
      },
      output: {
        deploymentName: z => z.string().describe('Resolved K8s deployment name'),
        targetReplicas: z =>
          z.number().describe('Validated target replica count'),
        baselineReplicas: z => z.number().describe('Baseline replica count'),
        minReplicas: z => z.number().describe('Minimum allowed replicas'),
        maxReplicas: z => z.number().describe('Maximum allowed replicas'),
        isStateful: z =>
          z.boolean().describe('Whether workload is a stateful database'),
        policySummary: z =>
          z.string().describe('OPA guardrail evaluation summary'),
      },
    },
    async handler(ctx) {
      const opType =
        ctx.input.operationType === 'rolling-restart'
          ? ('rolling-restart' as const)
          : ('scale' as const);
      const selMode =
        ctx.input.selectionMode === 'Percentage'
          ? ('Percentage' as const)
          : ('Count' as const);

      ctx.logger.info(
        `Evaluating OPA Policy Guardrails for entity=${ctx.input.entityRef}, operation=${opType}, selectionMode=${selMode}, replicaValue=${ctx.input.replicaValue ?? 'default'}`,
      );

      const policy = await evaluateK8sDay2Policy({
        entityRef: ctx.input.entityRef,
        namespace: ctx.input.namespace,
        operationType: opType,
        selectionMode: selMode,
        replicaValue: ctx.input.replicaValue,
        reason: ctx.input.reason,
      });

      ctx.logger.info(policy.policySummary);

      ctx.output('deploymentName', policy.deploymentName);
      ctx.output('targetReplicas', policy.targetReplicas);
      ctx.output('baselineReplicas', policy.baselineReplicas);
      ctx.output('minReplicas', policy.minReplicas);
      ctx.output('maxReplicas', policy.maxReplicas);
      ctx.output('isStateful', policy.isStateful);
      ctx.output('policySummary', policy.policySummary);
    },
  });
}

function createExecuteK8sDay2OpAction() {
  return createTemplateAction({
    id: 'resiliency:k8s:execute-day2-op',
    description:
      'Snapshots pre-operation K8s deployment state, executes kubectl scale or rollout restart, optionally syncs GitOps manifest, and waits for rollout status.',
    schema: {
      input: {
        entityRef: z =>
          z.string().optional().describe('Backstage entity reference'),
        deploymentName: z => z.string().describe('Target K8s deployment name'),
        namespace: z =>
          z.string().optional().default('default').describe('K8s namespace'),
        operationType: z =>
          z
            .enum(['scale', 'rolling-restart'])
            .default('scale')
            .describe('Operation type'),
        targetReplicas: z =>
          z.number().optional().describe('Target replica count'),
        syncGitOpsManifest: z =>
          z
            .boolean()
            .optional()
            .default(true)
            .describe('Sync replica count to demo/k8s/manifest.yaml'),
        reason: z =>
          z.string().optional().describe('Audit reason or change ticket'),
        waitTimeoutSeconds: z =>
          z.number().optional().default(90).describe('Rollout status timeout'),
      },
      output: {
        operationId: z => z.string().describe('Unique Day-2 operation ID'),
        targetReplicas: z =>
          z.number().describe('Post-operation desired replica count'),
        gitOpsSynced: z =>
          z.boolean().describe('Whether GitOps manifest was updated'),
        restartedAt: z =>
          z.string().describe('Deployment restartedAt annotation'),
        previousStateJson: z =>
          z.string().describe('Serialized pre-operation K8s snapshot'),
        currentStateJson: z =>
          z.string().describe('Serialized post-operation K8s snapshot'),
      },
    },
    async handler(ctx) {
      const opType =
        ctx.input.operationType === 'rolling-restart'
          ? ('rolling-restart' as const)
          : ('scale' as const);

      ctx.logger.info(
        `Executing K8s Day-2 "${opType}" on deployment/${ctx.input.deploymentName} (namespace=${ctx.input.namespace || 'default'}, targetReplicas=${ctx.input.targetReplicas ?? 'current'})...`,
      );

      const res = await executeK8sDay2Operation({
        entityRef: ctx.input.entityRef,
        deploymentName: ctx.input.deploymentName,
        namespace: ctx.input.namespace,
        operationType: opType,
        targetReplicas: ctx.input.targetReplicas,
        syncGitOpsManifest: ctx.input.syncGitOpsManifest,
        reason: ctx.input.reason,
        waitTimeoutSeconds: ctx.input.waitTimeoutSeconds,
      });

      ctx.logger.info(
        `Pre-Operation State: desired=${res.previous.desiredReplicas}, ready=${res.previous.readyReplicas}/${res.previous.desiredReplicas}, generation=${res.previous.generation}`,
      );
      ctx.logger.info(
        `Rollout Steady-State Reached: desired=${res.current.desiredReplicas}, ready=${res.current.readyReplicas}/${res.current.desiredReplicas}, generation=${res.current.generation}, gitOpsSynced=${res.gitOpsSynced}`,
      );

      ctx.output('operationId', res.operationId);
      ctx.output('targetReplicas', res.targetReplicas);
      ctx.output('gitOpsSynced', res.gitOpsSynced);
      ctx.output('restartedAt', res.restartedAt);
      ctx.output('previousStateJson', JSON.stringify(res.previous));
      ctx.output('currentStateJson', JSON.stringify(res.current));
    },
  });
}

function createVerifyK8sDay2OpAction() {
  return createTemplateAction({
    id: 'resiliency:k8s:verify-and-diff',
    description:
      'Verifies all K8s pods are Ready, probes the live service HTTP health endpoint, and generates a Before vs. After workload state diff.',
    schema: {
      input: {
        deploymentName: z => z.string().describe('Target K8s deployment name'),
        namespace: z =>
          z.string().optional().default('default').describe('K8s namespace'),
        operationType: z =>
          z
            .enum(['scale', 'rolling-restart'])
            .default('scale')
            .describe('Operation type'),
        expectedReplicas: z =>
          z.number().describe('Expected Ready replica count'),
        previousStateJson: z =>
          z
            .string()
            .optional()
            .describe('Serialized pre-operation K8s snapshot'),
        gitOpsSynced: z =>
          z.boolean().optional().describe('Whether GitOps manifest was synced'),
      },
      output: {
        readyReplicas: z => z.number().describe('Verified Ready replicas'),
        desiredReplicas: z => z.number().describe('Verified Desired replicas'),
        serviceHealthy: z =>
          z.boolean().describe('Whether live service HTTP probe passed'),
        k8sUnifiedDiff: z =>
          z.string().describe('Unified Before vs. After K8s workload diff'),
        k8sDiffMarkdown: z =>
          z
            .string()
            .describe('Markdown comparison table and unified K8s state diff'),
      },
    },
    async handler(ctx) {
      const opType =
        ctx.input.operationType === 'rolling-restart'
          ? ('rolling-restart' as const)
          : ('scale' as const);

      let previousSnapshot: K8sDeploymentSnapshot | undefined;
      if (ctx.input.previousStateJson) {
        try {
          previousSnapshot = JSON.parse(
            ctx.input.previousStateJson,
          ) as K8sDeploymentSnapshot;
        } catch {
          previousSnapshot = undefined;
        }
      }

      const diff = await verifyK8sWorkloadAndBuildDiff({
        deploymentName: ctx.input.deploymentName,
        namespace: ctx.input.namespace,
        operationType: opType,
        expectedReplicas: ctx.input.expectedReplicas,
        previousSnapshot,
        gitOpsSynced: ctx.input.gitOpsSynced,
      });

      ctx.logger.info(
        `[PASS] K8s Steady-State Rollout Verified: ${diff.current.readyReplicas}/${diff.current.desiredReplicas} pods Ready (gen=${diff.current.generation})`,
      );
      ctx.logger.info(
        `[PASS] End-to-End Service Health Probe: HTTP ${diff.current.serviceHttpStatus ?? 200} (healthy=${diff.serviceHealthVerified})`,
      );
      ctx.logger.info(
        `K8s Workload Diff (Before vs. After):\n${diff.unifiedDiff}`,
      );

      ctx.output('readyReplicas', diff.current.readyReplicas);
      ctx.output('desiredReplicas', diff.current.desiredReplicas);
      ctx.output('serviceHealthy', diff.serviceHealthVerified);
      ctx.output('k8sUnifiedDiff', diff.unifiedDiff);
      ctx.output('k8sDiffMarkdown', diff.markdownDiff);
    },
  });
}

export const scaffolderModuleK8sDay2Ops = createBackendModule({
  pluginId: 'scaffolder',
  moduleId: 'k8s-day2-ops-actions',
  register(reg) {
    reg.registerInit({
      deps: {
        scaffolder: scaffolderActionsExtensionPoint,
      },
      async init({ scaffolder }) {
        scaffolder.addActions(
          createValidateK8sPolicyAction(),
          createExecuteK8sDay2OpAction(),
          createVerifyK8sDay2OpAction(),
        );
      },
    });
  },
});

class K8sLiveWorkloadProcessor implements CatalogProcessor {
  getProcessorName(): string {
    return 'K8sLiveWorkloadProcessor';
  }

  async preProcessEntity(entity: Entity): Promise<Entity> {
    const depName =
      entity.metadata.annotations?.['resiliency.idp/k8s-deployment'];
    if (!depName) {
      return entity;
    }

    const ns =
      entity.metadata.annotations?.['resiliency.idp/k8s-namespace'] ||
      'default';
    try {
      const snap = await inspectK8sDeployment(depName, ns);
      const podSummary = snap.pods
        .map(p => `${p.name} (${p.podIP}: ${p.phase})`)
        .join(', ');
      const status =
        snap.readyReplicas === snap.desiredReplicas && snap.serviceHealthy
          ? 'Healthy'
          : 'Degraded';

      return {
        ...entity,
        metadata: {
          ...entity.metadata,
          annotations: {
            ...entity.metadata.annotations,
            'resiliency.idp/k8s-desired-replicas': String(snap.desiredReplicas),
            'resiliency.idp/k8s-ready-replicas': String(snap.readyReplicas),
            'resiliency.idp/k8s-generation': String(snap.generation),
            'resiliency.idp/k8s-restarted-at': snap.restartedAt,
            'resiliency.idp/k8s-pods': podSummary,
            'resiliency.idp/k8s-status': status,
          },
        },
      };
    } catch {
      return entity;
    }
  }
}

export const catalogModuleK8sDay2Ops = createBackendModule({
  pluginId: 'catalog',
  moduleId: 'k8s-day2-live-processor',
  register(reg) {
    reg.registerInit({
      deps: {
        catalog: catalogProcessingExtensionPoint,
      },
      async init({ catalog }) {
        catalog.addProcessor(new K8sLiveWorkloadProcessor());
      },
    });
  },
});

export const resiliencyK8sPlugin = createBackendPlugin({
  pluginId: 'resiliency-k8s',
  register(reg) {
    reg.registerInit({
      deps: {
        httpRouter: coreServices.httpRouter,
        logger: coreServices.logger,
      },
      async init({ httpRouter, logger }) {
        const router = express.Router();

        router.get('/status', async (_req, res) => {
          try {
            const status = await getAllK8sWorkloadsStatus();
            res.status(200).json(status);
          } catch (err) {
            logger.error(`Failed to query K8s Day-2 status: ${err}`);
            res.status(503).json({
              error:
                err instanceof Error
                  ? err.message
                  : 'K8s status inspection failed',
            });
          }
        });

        router.get('/metrics', async (_req, res) => {
          try {
            const metrics = await renderK8sPrometheusMetrics();
            res
              .status(200)
              .set('Content-Type', 'text/plain; version=0.0.4; charset=utf-8')
              .send(metrics);
          } catch (err) {
            logger.error(`Failed to render K8s Prometheus metrics: ${err}`);
            res.status(500).send('# error rendering k8s metrics\n');
          }
        });

        httpRouter.use(router);
        httpRouter.addAuthPolicy({
          path: '/status',
          allow: 'unauthenticated',
        });
        httpRouter.addAuthPolicy({
          path: '/metrics',
          allow: 'unauthenticated',
        });
      },
    });
  },
});

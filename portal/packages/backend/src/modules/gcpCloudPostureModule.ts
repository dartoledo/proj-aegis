import { coreServices, createBackendPlugin } from '@backstage/backend-plugin-api';
import express from 'express';
import {
  executeGcpOsConfigPatchJob,
  generateEntitySpdxSbomDocument,
  getEntityGcpCloudPostureReport,
  getFleetGcpCloudPostureSummary,
} from './gcpCloudPostureService';

export const gcpCloudPosturePlugin = createBackendPlugin({
  pluginId: 'gcp-posture',
  register(reg) {
    reg.registerInit({
      deps: {
        httpRouter: coreServices.httpRouter,
        logger: coreServices.logger,
      },
      async init({ httpRouter, logger }) {
        const router = express.Router();
        router.use(express.json());
    router.use((_req, res, next) => {
      res.header('Access-Control-Allow-Origin', '*');
      res.header('Access-Control-Allow-Methods', 'GET, POST, OPTIONS');
      res.header('Access-Control-Allow-Headers', 'Content-Type, Authorization');
      next();
    });

    router.get('/entity', async (req, res) => {
      const entityRef = String(req.query.entityRef || 'component:default/aegis-backend');
      const report = await getEntityGcpCloudPostureReport(entityRef);
      res.json(report);
    });

    router.get('/fleet', async (_req, res) => {
      const reports = await getFleetGcpCloudPostureSummary();
      res.json({
        totalServices: reports.length,
        compliantVms: reports.filter(r => r.vmInventory.patchComplianceState === 'COMPLIANT').length,
        pendingRebootVms: reports.filter(r => r.vmInventory.rebootRequired).length,
        totalUnpatchedPackages: reports.reduce((s, r) => s + r.patchSummary.patchAvailableCount + r.patchSummary.pendingRebootCount + r.patchSummary.unpatchedEolCount, 0),
        reports,
      });
    });

    router.post('/patch-job', async (req, res) => {
      const entityRef = String(req.body?.entityRef || req.query.entityRef || 'component:default/aegis-backend');
      const result = await executeGcpOsConfigPatchJob(entityRef);
      res.json(result);
    });

    router.get('/sbom', async (req, res) => {
      const entityRef = String(req.query.entityRef || 'component:default/aegis-backend');
      const sbom = await generateEntitySpdxSbomDocument(entityRef);
      res.json(sbom);
    });

    httpRouter.use(router as any);

    for (const p of ['/entity', '/fleet', '/patch-job', '/sbom']) {
      httpRouter.addAuthPolicy({ path: p, allow: 'unauthenticated' });
    }

        logger.info('gcp-posture plugin registered');
      },
    });
  },
});

import { coreServices, createBackendPlugin } from '@backstage/backend-plugin-api';
import express from 'express';
import { getEntityHarborEolReport, getFleetHarborEolSummary, remediateEntityEolPackages, renderHarborEolPrometheusMetrics } from './harborEolService';

export const harborEolPlugin = createBackendPlugin({
  pluginId: 'harbor-eol',
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
          res.setHeader('Access-Control-Allow-Origin', '*');
          res.setHeader('Access-Control-Allow-Methods', 'GET, POST, OPTIONS');
          res.setHeader('Access-Control-Allow-Headers', 'Content-Type, Authorization');
          next();
        });

        router.get('/entity', async (req, res) => {
          const entityRef = String(req.query.entityRef || 'component:default/aegis-backend');
          const report = await getEntityHarborEolReport(entityRef);
          res.json(report);
        });

        router.get('/fleet', async (_req, res) => {
          const reports = await getFleetHarborEolSummary();
          const totalEolPackages = reports.reduce((sum, r) => sum + r.summary.eolCount, 0);
          const totalApproachingEolPackages = reports.reduce((sum, r) => sum + r.summary.approachingEolCount, 0);
          const totalCriticalCves = reports.reduce((sum, r) => sum + r.summary.criticalCves, 0);
          const totalHighCves = reports.reduce((sum, r) => sum + r.summary.highCves, 0);
          res.json({
            totalServices: reports.length,
            totalEolPackages,
            totalApproachingEolPackages,
            totalCriticalCves,
            totalHighCves,
            reports,
          });
        });

        router.post('/scan', async (req, res) => {
          const entityRef = String(req.body?.entityRef || req.query.entityRef || 'component:default/aegis-backend');
          const report = await getEntityHarborEolReport(entityRef, { triggerScan: true });
          res.json(report);
        });

        router.post('/remediate', async (req, res) => {
          const entityRef = String(req.body?.entityRef || req.query.entityRef || 'component:default/aegis-backend');
          const report = await remediateEntityEolPackages(entityRef);
          res.json(report);
        });

        router.get('/metrics', async (_req, res) => {
          const reports = await getFleetHarborEolSummary();
          res.setHeader('Content-Type', 'text/plain; version=0.0.4; charset=utf-8');
          res.send(renderHarborEolPrometheusMetrics(reports));
        });

        httpRouter.use(router as any);

        const paths = ['/entity', '/fleet', '/scan', '/remediate', '/metrics'];
        for (const p of paths) {
          httpRouter.addAuthPolicy({ path: p, allow: 'unauthenticated' });
        }

        logger.info('harbor-eol plugin registered');
      },
    });
  },
});

import { coreServices, createBackendPlugin } from '@backstage/backend-plugin-api';
import express from 'express';
import {
  getEntityCveIntelligenceReport,
  getFleetCvePriorities,
  issueVexAttestation,
  VexJustification,
} from './cveIntelligenceService';

export const cveIntelligencePlugin = createBackendPlugin({
  pluginId: 'cve-intel',
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
          const report = await getEntityCveIntelligenceReport(entityRef);
          res.json(report);
        });

        router.get('/fleet-priorities', async (_req, res) => {
          const priorities = await getFleetCvePriorities();
          res.json(priorities);
        });

        router.post('/vex-attest', async (req, res) => {
          const entityRef = String(req.body?.entityRef || 'component:default/aegis-backend');
          const cveId = String(req.body?.cveId || 'CVE-2024-0727');
          const justification = (req.body?.justification || 'vulnerable_code_not_in_execute_path') as VexJustification;
          const result = await issueVexAttestation(entityRef, cveId, justification);
          res.json(result);
        });

        httpRouter.use(router as any);

        for (const p of ['/entity', '/fleet-priorities', '/vex-attest']) {
          httpRouter.addAuthPolicy({ path: p, allow: 'unauthenticated' });
        }

        logger.info('cve-intel plugin registered');
      },
    });
  },
});

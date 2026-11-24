import { coreServices, createBackendPlugin } from '@backstage/backend-plugin-api';
import express from 'express';
import {
  getEntityAttackGraphScorecard,
  getFleetAttackGraphSummary,
  resetInfrahubSimulationState,
  retrieveInfrahubTechInsightsFacts,
  simulateInfrahubWhatIfRemediation,
} from './infrahubAttackGraphService';

export const infrahubAttackGraphPlugin = createBackendPlugin({
  pluginId: 'infrahub-attack-graph',
  register(reg) {
    reg.registerInit({
      deps: {
        httpRouter: coreServices.httpRouter,
        logger: coreServices.logger,
      },
      async init({ httpRouter, logger }) {
        const router = express.Router();
        router.use(express.json());

        router.use((req, res, next) => {
          res.setHeader('Access-Control-Allow-Origin', '*');
          res.setHeader('Access-Control-Allow-Methods', 'GET, POST, OPTIONS');
          res.setHeader('Access-Control-Allow-Headers', 'Content-Type, Authorization');
          if (req.method === 'OPTIONS') {
            res.sendStatus(204);
            return;
          }
          next();
        });

        router.get('/entity', async (req, res) => {
          try {
            const entityId = String(req.query.entityId || req.query.entityRef || 'aegis-backend');
            const result = await getEntityAttackGraphScorecard(entityId);
            res.json(result);
          } catch (error) {
            logger.error('Error in /entity', error as Error);
            res.status(500).json({ error: 'Internal Server Error' });
          }
        });

        router.get('/facts', async (req, res) => {
          try {
            const entityId = String(req.query.entityId || req.query.entityRef || 'aegis-backend');
            const result = await retrieveInfrahubTechInsightsFacts(entityId);
            res.json(result);
          } catch (error) {
            logger.error('Error in /facts', error as Error);
            res.status(500).json({ error: 'Internal Server Error' });
          }
        });

        router.get('/fleet', async (_req, res) => {
          try {
            const result = await getFleetAttackGraphSummary();
            res.json(result);
          } catch (error) {
            logger.error('Error in /fleet', error as Error);
            res.status(500).json({ error: 'Internal Server Error' });
          }
        });

        router.post('/simulate', async (req, res) => {
          try {
            const entityOrRef = String(req.body?.entityId || req.body?.entityRef || req.body?.entityOrRef || 'aegis-backend');
            const action = (req.body?.action) as
              | 'rotate-ssl'
              | 'upgrade-eol-runtime'
              | 'patch-kev-cve'
              | 'isolate-lateral-path';
            const result = await simulateInfrahubWhatIfRemediation(entityOrRef, action);
            res.json(result);
          } catch (error) {
            logger.error('Error in /simulate', error as Error);
            res.status(500).json({ error: 'Internal Server Error' });
          }
        });

        router.post('/reset', async (req, res) => {
          try {
            resetInfrahubSimulationState();
            const entityOrRef = String(req.body?.entityId || req.body?.entityRef || req.body?.entityOrRef || 'aegis-backend');
            const report = await getEntityAttackGraphScorecard(entityOrRef);
            res.json(report);
          } catch (error) {
            logger.error('Error in /reset', error as Error);
            res.status(500).json({ error: 'Internal Server Error' });
          }
        });

        httpRouter.use(router as any);

        for (const p of ['/entity', '/facts', '/fleet', '/simulate', '/reset']) {
          httpRouter.addAuthPolicy({ path: p, allow: 'unauthenticated' });
        }
      },
    });
  },
});

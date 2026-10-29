import { coreServices, createBackendPlugin } from '@backstage/backend-plugin-api';
import express from 'express';
import { getEntityCmdbSnapshot, getFleetCmdbTopology, reconcileCmdbDrift } from './livingCmdbService';

export const livingCmdbPlugin = createBackendPlugin({
  pluginId: 'living-cmdb',
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
          res.json(await getEntityCmdbSnapshot(entityRef));
        });

        router.get('/fleet-graph', async (_req, res) => {
          res.json(await getFleetCmdbTopology());
        });

        router.post('/reconcile', async (req, res) => {
          const entityRef = String(req.body?.entityRef || 'component:default/aegis-backend');
          const action = req.body?.action === 'sync-to-git' ? 'sync-to-git' : 'enforce-git-state';
          const driftId = req.body?.driftId ? String(req.body.driftId) : undefined;
          res.json(await reconcileCmdbDrift(entityRef, action, driftId));
        });

        httpRouter.use(router as any);

        for (const p of ['/entity', '/fleet-graph', '/reconcile']) {
          httpRouter.addAuthPolicy({ path: p, allow: 'unauthenticated' });
        }

        logger.info('living-cmdb plugin registered');
      },
    });
  },
});

import { coreServices, createBackendPlugin } from '@backstage/backend-plugin-api';
import express from 'express';
import {
  evaluateEntityQualityGates,
  getPresetInfraScenarios,
  simulateInfraChangePreFlight,
} from './infraQualityGateService';

export const infraQualityGatePlugin = createBackendPlugin({
  pluginId: 'infra-quality-gates',
  register(reg) {
    reg.registerInit({
      deps: {
        httpRouter: coreServices.httpRouter,
        logger: coreServices.logger,
      },
      async init({ httpRouter, logger }) {
        const router = express.Router();
        router.use(express.json());

        router.use((_req, _res, next) => {
          _res.header('Access-Control-Allow-Origin', '*');
          _res.header('Access-Control-Allow-Methods', 'GET, POST, OPTIONS');
          _res.header('Access-Control-Allow-Headers', 'Content-Type, Authorization');
          next();
        });

        router.get('/entity', async (req, res) => {
          const entityRef = String(
            req.query.entityRef || 'component:default/aegis-backend',
          );
          const result = await evaluateEntityQualityGates(entityRef);
          res.json(result);
        });

        router.get('/scenarios', (_req, res) => {
          res.json({ scenarios: getPresetInfraScenarios() });
        });

        router.post('/simulate', async (req, res) => {
          const entityRef = String(
            req.body?.entityRef || 'component:default/aegis-backend',
          );
          const result = await simulateInfraChangePreFlight({
            ...req.body,
            entityRef,
          });
          res.json(result);
        });

        httpRouter.use(router as any);

        for (const p of ['/entity', '/scenarios', '/simulate']) {
          httpRouter.addAuthPolicy({ path: p, allow: 'unauthenticated' });
        }

        logger.info('infra-quality-gates plugin initialized');
      },
    });
  },
});

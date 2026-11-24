import { coreServices, createBackendPlugin } from '@backstage/backend-plugin-api';
import express from 'express';
import { getEntityCmdbSnapshot, getFleetCmdbTopology, reconcileCmdbDrift, getComponentTaxonomyCatalog, AEGIS_TEAM_OWNERS_TABLE } from './livingCmdbService';
import { crossCheckSoftwareVersion, SoftwareEcosystem } from './softwareVersionNormalizerService';
import { initializeAegisPostgresSchema } from './aegisPostgresStore';

export const livingCmdbPlugin = createBackendPlugin({
  pluginId: 'living-cmdb',
  register(reg) {
    reg.registerInit({
      deps: {
        httpRouter: coreServices.httpRouter,
        logger: coreServices.logger,
        database: coreServices.database,
      },
      async init({ httpRouter, logger, database }) {
        const router = express.Router();
        router.use(express.json());

        try {
          const knex = await database.getClient();
          await initializeAegisPostgresSchema(knex);
          logger.info('Initialized Aegis PostgreSQL schema & seeds');
        } catch (err) {
          logger.warn(`PostgreSQL schema init deferred: ${err}`);
        }

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

        router.get('/taxonomy', async (_req, res) => {
          res.json(getComponentTaxonomyCatalog());
        });

        router.get('/teams', async (_req, res) => {
          res.json(AEGIS_TEAM_OWNERS_TABLE);
        });

        router.get('/normalize-version', async (req, res) => {
          const productName = String(req.query.productName || 'Node.js');
          const rawVersion = String(req.query.rawVersion || '18.20.8');
          const ecosystem = req.query.ecosystem ? (String(req.query.ecosystem) as SoftwareEcosystem) : undefined;
          const distroQualifier = req.query.distroQualifier ? String(req.query.distroQualifier) : null;
          res.json(
            crossCheckSoftwareVersion({
              productName,
              rawVersion,
              ecosystem,
              distroQualifier,
            }),
          );
        });

        router.post('/reconcile', async (req, res) => {
          const entityRef = String(req.body?.entityRef || 'component:default/aegis-backend');
          const action = req.body?.action === 'sync-to-git' ? 'sync-to-git' : 'enforce-git-state';
          const driftId = req.body?.driftId ? String(req.body.driftId) : undefined;
          res.json(await reconcileCmdbDrift(entityRef, action, driftId));
        });

        router.get('/db-status', async (_req, res) => {
          res.json({ engine: 'postgresql', tables: ['team_owners', 'cmdb_services', 'cmdb_component_nodes', 'software_version_crosswalk', 'public_eol_cycles', 'public_cve_ranges'] });
        });

        httpRouter.use(router as any);

        for (const p of ['/entity', '/fleet-graph', '/taxonomy', '/teams', '/normalize-version', '/reconcile', '/db-status']) {
          httpRouter.addAuthPolicy({ path: p, allow: 'unauthenticated' });
        }

        logger.info('living-cmdb plugin registered');
      },
    });
  },
});

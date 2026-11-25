import { coreServices, createBackendPlugin } from '@backstage/backend-plugin-api';
import express from 'express';
import { getEntityCmdbSnapshot, getFleetCmdbTopology, getComponentTaxonomyCatalog, AEGIS_TEAM_OWNERS_TABLE } from './livingCmdbService';
import { crossCheckSoftwareVersion, SoftwareEcosystem } from './softwareVersionNormalizerService';
import { getAegisPostgresTableCounts, initializeAegisPostgresSchema } from './aegisPostgresStore';

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

        let knexClient: any = null;
        try {
          knexClient = await database.getClient();
          await initializeAegisPostgresSchema(knexClient);
          logger.info('Initialized Aegis PostgreSQL schema & seeds');
        } catch (err) {
          logger.warn(`PostgreSQL schema init deferred: ${err}`);
        }

        router.use((_req, res, next) => {
          res.header('Access-Control-Allow-Origin', '*');
          res.header('Access-Control-Allow-Methods', 'GET, OPTIONS');
          res.header('Access-Control-Allow-Headers', 'Content-Type, Authorization');
          next();
        });

        router.get('/entity', async (req, res) => {
          const entityRef = String(req.query.entityRef || 'component:default/aegis-backend');
          res.json(await getEntityCmdbSnapshot(entityRef, knexClient));
        });

        router.get('/fleet-graph', async (_req, res) => {
          res.json(await getFleetCmdbTopology(knexClient));
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

        router.get('/db-status', async (_req, res) => {
          const counts = await getAegisPostgresTableCounts(knexClient);
          res.json({
            engine: 'postgresql',
            tables: [
              'items',
              'team_owners',
              'tracked_endpoints',
              'certificate_inventory',
              'cmdb_services',
              'cmdb_component_nodes',
              'software_version_crosswalk',
              'public_eol_cycles',
              'public_cve_ranges',
            ],
            rowCounts: counts,
          });
        });

        httpRouter.use(router as any);

        for (const p of ['/entity', '/fleet-graph', '/taxonomy', '/teams', '/normalize-version', '/db-status']) {
          httpRouter.addAuthPolicy({ path: p, allow: 'unauthenticated' });
        }

        logger.info('living-cmdb plugin registered');
      },
    });
  },
});

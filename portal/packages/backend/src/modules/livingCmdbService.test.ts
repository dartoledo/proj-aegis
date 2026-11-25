import {
  AEGIS_TEAM_OWNERS_TABLE,
  getEntityCmdbSnapshot,
  getFleetCmdbTopology,
  getComponentTaxonomyCatalog,
} from './livingCmdbService';
import { getAegisPostgresTableCounts, initializeAegisPostgresSchema, setAegisKnexClient, syncSslEndpointsWithPostgres } from './aegisPostgresStore';
import { getFleetSslInventory, removeTrackedEndpointFromMemory } from './sslEndpointTrackerService';

describe('livingCmdbService', () => {
  describe('getEntityCmdbSnapshot', () => {
    it('returns snapshot for aegis-backend', async () => {
      const snapshot = await getEntityCmdbSnapshot('component:default/aegis-backend');
      expect(snapshot.ciId).toBe('CI-AEGIS-1002');
      expect(snapshot.driftStatus).toBe('DRIFT_DETECTED');
      expect(snapshot.activeDriftCount).toBe(3);
      expect(snapshot.blastRadius.length).toBe(3);
      expect(snapshot.componentInventory?.length).toBeGreaterThan(0);
      const domains = snapshot.componentInventory!.map((c: any) => c.domain);
      expect(domains).toContain('INFRASTRUCTURE');
      expect(domains).toContain('SOFTWARE');
    });
  });

  describe('getFleetCmdbTopology', () => {
    it('returns fleet topology', async () => {
      const topology = await getFleetCmdbTopology();
      expect(topology.totalConfigurationItems).toBe(5);
      expect(topology.driftedServicesCount).toBe(3);
      expect(topology.totalActiveDrifts).toBe(5);
      expect(topology.shadowResourcesDetected).toBe(1);
      expect(topology.directedEdges.length).toBe(5);
      expect(topology.taxonomyCatalog?.length).toBe(33);
    });
  });

  describe('drift detection only', () => {
    it('aegis-backend has driftItems with ACTIVE_DRIFT status and non-empty values', async () => {
      const snapshot = await getEntityCmdbSnapshot('component:default/aegis-backend');
      expect(snapshot.driftItems!.length).toBeGreaterThan(0);
      for (const item of snapshot.driftItems!) {
        expect(item.status).toBe('ACTIVE_DRIFT');
        expect(item.gitDeclaredValue).toBeTruthy();
        expect(item.liveObservedValue).toBeTruthy();
      }
    });

    it('aegis-db is IN_SYNC with zero active drifts', async () => {
      const snapshot = await getEntityCmdbSnapshot('component:default/aegis-db');
      expect(snapshot.driftStatus).toBe('IN_SYNC');
      expect(snapshot.activeDriftCount).toBe(0);
    });
  });

  describe('getComponentTaxonomyCatalog', () => {
    it('returns 20 INFRASTRUCTURE items across 7 distinct layers', () => {
      const catalog = getComponentTaxonomyCatalog();
      const infra = catalog.filter((c: any) => c.domain === 'INFRASTRUCTURE');
      expect(infra.length).toBe(20);
      const layerIds = new Set(infra.map((c: any) => c.layerId));
      expect(layerIds.size).toBe(7);
      const orders = [...new Set(infra.map((c: any) => c.layerOrder))].sort((a: any, b: any) => a - b);
      expect(orders).toEqual([1, 2, 3, 4, 5, 6, 7]);
    });

    it('returns 13 SOFTWARE items', () => {
      const catalog = getComponentTaxonomyCatalog();
      const software = catalog.filter((c: any) => c.domain === 'SOFTWARE');
      expect(software.length).toBe(13);
      const scm = software.find((c: any) => c.id === 'DEVELOPMENT_TOOLS_SCM');
      expect(scm).toBeDefined();
      expect(scm!.label).toBe('Development Tools & Source Control (SCM)');
    });

    it('assigns ownerTeamId from AEGIS_TEAM_OWNERS_TABLE to every component', async () => {
      const teamIds = AEGIS_TEAM_OWNERS_TABLE.map((t: any) => t.teamId);
      expect(teamIds).toEqual(['app-team', 'sre-team']);
      const snapshot = await getEntityCmdbSnapshot('component:default/aegis-backend');
      const validTeamIds = ['app-team', 'sre-team'];
      for (const node of snapshot.componentInventory!) {
        expect(validTeamIds).toContain((node as any).ownerTeamId);
      }
    });
  });

  describe('aegisPostgresStore 9-table persistence & read paths', () => {
    let mockKnex: any;
    let tables: Map<string, any[]>;

    beforeEach(async () => {
      const createMockKnex = () => {
        const tables = new Map<string, any[]>();

        const schema = {
          hasTable: async (t: string) => tables.has(t),
          hasColumn: async () => true,
          dropTableIfExists: async (t: string) => { tables.delete(t); },
          createTable: async (t: string, cb: (tbl: any) => void) => {
            tables.set(t, []);
            const col: any = {
              primary: () => col,
              notNullable: () => col,
              unique: () => col,
              references: () => col,
              inTable: () => col,
              onDelete: () => col,
              defaultTo: () => col,
            };
            cb({
              increments: () => col,
              string: () => col,
              integer: () => col,
              text: () => col,
              timestamp: () => col,
              boolean: () => col,
              jsonb: () => col,
              specificType: () => col,
              date: () => col,
              decimal: () => col,
              unique: () => col,
              primary: () => col,
            });
          },
        };

        const mockKnex: any = (tableName: string) => {
          const rows = tables.get(tableName) || [];
          const qb: any = {
            _insertData: undefined as any,
            _whereList: [] as Array<Record<string, any>>,
            _orWhereList: [] as Array<Record<string, any>>,
            _orderBy: null as any,
            _select: null as any,
            _update: null as any,
            _onConflict: null as any,
            _merge: false,
            _count: false,
            _first: false,
            insert(data: any) {
              qb._insertData = data;
              return qb;
            },
            onConflict(keyCols: any) {
              qb._onConflict = keyCols;
              return qb;
            },
            merge() {
              qb._merge = true;
              return qb;
            },
            count(_arg: string) {
              qb._count = true;
              return qb;
            },
            where(a: any, b?: any) {
              qb._whereList.push(typeof a === 'string' ? { [a]: b } : a);
              return qb;
            },
            orWhere(a: any, b?: any) {
              qb._orWhereList.push(typeof a === 'string' ? { [a]: b } : a);
              return qb;
            },
            orderBy(col: string) {
              qb._orderBy = col;
              return qb;
            },
            select(_cols: string) {
              qb._select = _cols;
              return qb;
            },
            first() {
              qb._first = true;
              return qb;
            },
            update(patch: any) {
              qb._update = patch;
              return qb;
            },
            then(resolve: any, _reject: any) {
              return new Promise((_res, rej) => {
                try {
                  if (qb._insertData !== undefined) {
                    const items = Array.isArray(qb._insertData) ? qb._insertData : [qb._insertData];
                    if (qb._merge && qb._onConflict) {
                      const keyCols = Array.isArray(qb._onConflict) ? qb._onConflict : [qb._onConflict];
                      for (const item of items) {
                        const idx = rows.findIndex((r: any) => keyCols.every((k: string) => r[k] === item[k]));
                        if (idx >= 0) {
                          rows[idx] = { ...rows[idx], ...item };
                        } else {
                          rows.push({ ...item });
                        }
                      }
                    } else {
                      for (const item of items) {
                        const row = { ...item };
                        if (row.id === undefined) {
                          row.id = rows.length + 1;
                        }
                        rows.push(row);
                      }
                    }
                    resolve(items);
                  } else if (qb._update) {
                    const matched = rows.filter((r: any) => {
                      if (qb._whereList.length > 0 || qb._orWhereList.length > 0) {
                        const whereMatch = qb._whereList.every((cond: Record<string, any>) => Object.entries(cond).every(([k, v]) => r[k] === v));
                        const orMatch = qb._orWhereList.some((cond: Record<string, any>) => Object.entries(cond).every(([k, v]) => r[k] === v));
                        return whereMatch || orMatch;
                      }
                      return true;
                    });
                    matched.forEach((r: any) => Object.assign(r, qb._update));
                    resolve(matched.length);
                  } else if (qb._count) {
                    resolve({ cnt: rows.length });
                  } else {
                    let result = [...rows];
                    if (qb._whereList.length > 0 || qb._orWhereList.length > 0) {
                      result = result.filter((r: any) => {
                        const whereMatch = qb._whereList.every((cond: Record<string, any>) => Object.entries(cond).every(([k, v]) => r[k] === v));
                        const orMatch = qb._orWhereList.some((cond: Record<string, any>) => Object.entries(cond).every(([k, v]) => r[k] === v));
                        return whereMatch || orMatch;
                      });
                    }
                    if (qb._orderBy) {
                      result.sort((a: any, b: any) => (a[qb._orderBy] > b[qb._orderBy] ? 1 : -1));
                    }
                    if (qb._first) {
                      resolve(result[0] || null);
                    } else {
                      resolve(result);
                    }
                  }
                } catch (e) {
                  rej(e);
                }
              });
            },
          };
          return qb;
        };

        mockKnex.schema = schema;
        mockKnex.tables = tables;
        return mockKnex;
      };

      mockKnex = createMockKnex();
      tables = mockKnex.tables;
      await initializeAegisPostgresSchema(mockKnex);
      setAegisKnexClient(mockKnex);
    });

    afterEach(() => {
      setAegisKnexClient(null);
    });

    it('creates all 9 canonical tables and populates seed data', async () => {
      const counts = await getAegisPostgresTableCounts(mockKnex);
      expect(counts.items).toBe(1);
      expect(counts.team_owners).toBe(2);
      expect(counts.tracked_endpoints).toBeGreaterThanOrEqual(0);
      expect(counts.certificate_inventory).toBeGreaterThanOrEqual(0);
      expect(counts.cmdb_services).toBe(5);
      expect(counts.cmdb_component_nodes).toBe(51);
      expect(counts.software_version_crosswalk).toBe(25);
      expect(counts.public_eol_cycles).toBe(11);
      expect(counts.public_cve_ranges).toBe(5);
    });

    it('getEntityCmdbSnapshot and getFleetCmdbTopology read from Knex-backed tables', async () => {
      const beforeSnap = await getEntityCmdbSnapshot('component:default/aegis-backend', mockKnex);
      const beforeCount = beforeSnap.componentInventory!.length;
      await mockKnex('cmdb_component_nodes').insert({
        component_id: 'be-extra-nodejs',
        ci_id: 'CI-AEGIS-1002',
        name: 'Node.js 20.11.0',
        version_or_identifier: '20.11.0',
        domain: 'SOFTWARE',
        category_type: 'PLATFORM_RUNTIME_ENVIRONMENT',
        status: 'HEALTHY',
        owner_team_id: 'app-team',
      });

      const snapshot = await getEntityCmdbSnapshot('component:default/aegis-backend', mockKnex);
      expect(snapshot.componentInventory!.length).toBe(beforeCount + 1);
      const nodejsComponent = snapshot.componentInventory!.find((c: any) => c.componentId === 'be-extra-nodejs');
      expect(nodejsComponent).toBeDefined();
      expect(nodejsComponent?.normalizedVersion?.purl).toContain('pkg:generic/nodejs@20.11.0');

      const topology = await getFleetCmdbTopology(mockKnex);
      expect(topology.totalConfigurationItems).toBeGreaterThanOrEqual(5);
    });

    it('syncSslEndpointsWithPostgres imports tracked_endpoints into SSL inventory', async () => {
      await mockKnex('tracked_endpoints').insert({
        id: 999,
        endpoint_name: 'imported.aegis.cloud.goog',
        protocol: 'HTTPS',
        port: 443,
        owner_team_id: 'sre-team',
        environment: 'prod',
      });

      await syncSslEndpointsWithPostgres(mockKnex);

      const inventory = getFleetSslInventory();
      const imported = inventory.endpoints.find((e: any) => e.sniHostname === 'imported.aegis.cloud.goog');
      expect(imported).toBeDefined();

      const certRows = tables.get('certificate_inventory') || [];
      expect(certRows.length).toBeGreaterThan(0);

      if (imported) removeTrackedEndpointFromMemory(imported.endpointId);
      setAegisKnexClient(null);
    });
  });
});

import {
  AEGIS_TEAM_OWNERS_TABLE,
  CMDB_SERVICE_SEEDS,
  getEntityCmdbSnapshot,
} from './livingCmdbService';
import {
  PUBLIC_CVE_RANGE_REFERENCE_DB,
  PUBLIC_EOL_CYCLE_REFERENCE_DB,
} from './softwareVersionNormalizerService';

export async function initializeAegisPostgresSchema(knex: any): Promise<void> {
  // Create tables if they do not exist
  const hasTeamOwners = await knex.schema.hasTable('team_owners');
  if (!hasTeamOwners) {
    await knex.schema.createTable('team_owners', (table: any) => {
      table.string('team_name').primary();
      table.string('owner_email');
      table.string('owner_name');
    });
  }

  const hasCmdbServices = await knex.schema.hasTable('cmdb_services');
  if (!hasCmdbServices) {
    await knex.schema.createTable('cmdb_services', (table: any) => {
      table.string('entity_ref').primary();
      table.string('service_name');
      table.text('description');
      table.jsonb('component_inventory');
      table.string('normalized_version');
    });
  }

  const hasCmdbComponentNodes = await knex.schema.hasTable('cmdb_component_nodes');
  if (!hasCmdbComponentNodes) {
    await knex.schema.createTable('cmdb_component_nodes', (table: any) => {
      table.increments('id').primary();
      table.string('service_ref');
      table.string('component_name');
      table.string('version');
    });
  }

  const hasSoftwareVersionCrosswalk = await knex.schema.hasTable('software_version_crosswalk');
  if (!hasSoftwareVersionCrosswalk) {
    await knex.schema.createTable('software_version_crosswalk', (table: any) => {
      table.increments('id').primary();
      table.string('component_name');
      table.string('raw_version');
      table.string('normalized_version');
    });
  }

  const hasPublicEolCycles = await knex.schema.hasTable('public_eol_cycles');
  if (!hasPublicEolCycles) {
    await knex.schema.createTable('public_eol_cycles', (table: any) => {
      table.increments('id').primary();
      table.string('product_name');
      table.string('version');
      table.date('eol_date');
    });
  }

  const hasPublicCveRanges = await knex.schema.hasTable('public_cve_ranges');
  if (!hasPublicCveRanges) {
    await knex.schema.createTable('public_cve_ranges', (table: any) => {
      table.increments('id').primary();
      table.string('product_name');
      table.string('version_range');
      table.string('cve_id');
    });
  }

  // Seed team_owners
  if (AEGIS_TEAM_OWNERS_TABLE.length > 0) {
    await knex('team_owners').insert(AEGIS_TEAM_OWNERS_TABLE);
  }

  // Seed public_eol_cycles
  if (PUBLIC_EOL_CYCLE_REFERENCE_DB.length > 0) {
    await knex('public_eol_cycles').insert(PUBLIC_EOL_CYCLE_REFERENCE_DB);
  }

  // Seed public_cve_ranges
  if (PUBLIC_CVE_RANGE_REFERENCE_DB.length > 0) {
    await knex('public_cve_ranges').insert(PUBLIC_CVE_RANGE_REFERENCE_DB);
  }

  // Seed CMDB service snapshots
  for (const [entityRef, seed] of Object.entries(CMDB_SERVICE_SEEDS)) {
    const snapshot = await getEntityCmdbSnapshot(entityRef);

    await knex('cmdb_services').insert({
      entity_ref: entityRef,
      service_name: seed.serviceName,
      description: (seed as any).description ?? null,
      component_inventory: snapshot.componentInventory,
      normalized_version: (snapshot as any).normalizedVersion ?? null,
    });

    if (snapshot.componentInventory && snapshot.componentInventory.length > 0) {
      const componentRows = snapshot.componentInventory.map((component: any) => ({
        service_ref: entityRef,
        component_name: component.name,
        version: component.version,
      }));
      await knex('cmdb_component_nodes').insert(componentRows);

      const crosswalkRows = snapshot.componentInventory.map((component: any) => ({
        component_name: component.name,
        raw_version: component.version,
        normalized_version: (snapshot as any).normalizedVersion ?? null,
      }));
      await knex('software_version_crosswalk').insert(crosswalkRows);
    }
  }
}

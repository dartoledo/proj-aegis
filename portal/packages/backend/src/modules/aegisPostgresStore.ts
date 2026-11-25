import {
  AEGIS_COMPONENT_TAXONOMY_CATALOG,
  AEGIS_TEAM_OWNERS_TABLE,
  CMDB_SERVICE_SEEDS,
  CmdbComponentNode,
  CmdbDriftItem,
  EntityCmdbSnapshot,
  FleetCmdbTopologyReport,
  getComponentTaxonomyCatalog,
  resolveCmdbServiceKey,
  resolveComponentOwnerTeam,
} from './livingCmdbService';
import {
  crossCheckSoftwareVersion,
  PUBLIC_CVE_RANGE_REFERENCE_DB,
  PUBLIC_EOL_CYCLE_REFERENCE_DB,
} from './softwareVersionNormalizerService';
import {
  TrackedSslEndpointRecord,
  getFleetSslInventory,
  hydrateTrackedEndpointRecordFromDbRow,
  removeTrackedEndpointFromMemory,
  SslEnvironmentTier,
  SslProviderType,
  SslRenewalMode,
} from './sslEndpointTrackerService';

let activeKnexClient: any = null;

export function setAegisKnexClient(knex: any): void {
  activeKnexClient = knex;
}

export function getAegisKnexClient(): any {
  return activeKnexClient;
}

export async function initializeAegisPostgresSchema(knex: any): Promise<void> {
  setAegisKnexClient(knex);

  // Check if legacy incompatible schema exists
  const hasTeamOwners = await knex.schema.hasTable('team_owners');
  const hasTeamIdCol = hasTeamOwners ? await knex.schema.hasColumn('team_owners', 'team_id') : true;
  const hasCmdbServices = await knex.schema.hasTable('cmdb_services');
  const hasCiIdCol = hasCmdbServices ? await knex.schema.hasColumn('cmdb_services', 'ci_id') : true;
  if (!hasTeamIdCol || !hasCiIdCol) {
    for (const tbl of [
      'software_version_crosswalk',
      'cmdb_component_nodes',
      'cmdb_services',
      'certificate_inventory',
      'tracked_endpoints',
      'public_cve_ranges',
      'public_eol_cycles',
      'team_owners',
    ]) {
      await knex.schema.dropTableIfExists(tbl);
    }
  }

  // Create 9 canonical tables if they do not exist

  const hasItems = await knex.schema.hasTable('items');
  if (!hasItems) {
    await knex.schema.createTable('items', (table: any) => {
      table.increments('id').primary();
      table.string('name', 100);
      table.string('status', 50);
    });
  }

  const hasTeamOwners2 = await knex.schema.hasTable('team_owners');
  if (!hasTeamOwners2) {
    await knex.schema.createTable('team_owners', (table: any) => {
      table.string('team_id', 32).primary();
      table.string('team_name', 128).notNullable();
      table.string('responsibility_scope', 255).notNullable();
      table.string('email', 128).notNullable();
      table.string('slack_channel', 64).notNullable();
    });
  }

  const hasTrackedEndpoints = await knex.schema.hasTable('tracked_endpoints');
  if (!hasTrackedEndpoints) {
    await knex.schema.createTable('tracked_endpoints', (table: any) => {
      table.increments('id').primary();
      table.string('endpoint_uid', 255).unique();
      table.string('endpoint_name', 255).notNullable();
      table.string('protocol', 32).notNullable();
      table.integer('port').notNullable();
      table.string('owner_team_id', 32).notNullable().references('team_id').inTable('team_owners');
      table.string('environment', 64);
      table.text('notes');
      table.string('entity_ref', 255);
      table.string('service_name', 255);
      table.string('endpoint_key', 128);
      table.string('endpoint_url', 512);
      table.string('sni_hostname', 255);
      table.string('provider_type', 64);
      table.string('renewal_mode', 64);
      table.string('exposure_scope', 64);
      table.string('dns_scope', 64);
      table.string('ingress_type', 128);
      table.integer('auto_renew_threshold_days');
      table.string('gcp_project', 128);
      table.string('gcp_target_proxy', 128);
      table.timestamp('last_probed_at');
    });
  }

  const hasCertificateInventory = await knex.schema.hasTable('certificate_inventory');
  if (!hasCertificateInventory) {
    await knex.schema.createTable('certificate_inventory', (table: any) => {
      table.increments('id').primary();
      table.integer('endpoint_id').notNullable().references('id').inTable('tracked_endpoints').onDelete('CASCADE');
      table.string('cert_issuer', 255);
      table.string('cert_subject', 255);
      table.string('serial_number', 128);
      table.timestamp('not_before');
      table.timestamp('not_after');
      table.string('key_algorithm', 64);
      table.integer('key_size');
      table.boolean('auto_renew').defaultTo(false);
      table.text('notes');
      table.string('compliance_status', 32);
      table.integer('days_remaining');
      table.boolean('is_active').defaultTo(true);
      table.jsonb('cert_details_json');
      table.unique(['endpoint_id', 'serial_number']);
    });
  }

  const hasCmdbServices2 = await knex.schema.hasTable('cmdb_services');
  if (!hasCmdbServices2) {
    await knex.schema.createTable('cmdb_services', (table: any) => {
      table.string('ci_id', 64).primary();
      table.string('entity_ref', 255).notNullable();
      table.string('service_name', 255).notNullable();
      table.string('owner_team', 128);
      table.string('declared_exposure_tier', 32);
      table.string('observed_exposure_tier', 32);
      table.integer('declared_replicas');
      table.integer('observed_replicas');
      table.string('declared_image_digest', 255);
      table.string('observed_image_digest', 255);
      table.string('drift_status', 32);
      table.jsonb('drift_items');
      table.jsonb('blast_radius');
      table.timestamp('last_reconciled_at');
    });
  }

  const hasCmdbComponentNodes = await knex.schema.hasTable('cmdb_component_nodes');
  if (!hasCmdbComponentNodes) {
    await knex.schema.createTable('cmdb_component_nodes', (table: any) => {
      table.string('component_id', 64).primary();
      table.string('ci_id', 64).notNullable().references('ci_id').inTable('cmdb_services').onDelete('CASCADE');
      table.string('domain', 128);
      table.string('layer_id', 64);
      table.string('layer_label', 128);
      table.string('category_type', 64);
      table.string('category_label', 128);
      table.string('icon', 32);
      table.string('owner_team_id', 32).references('team_id').inTable('team_owners');
      table.string('name', 255);
      table.string('version_or_identifier', 128);
      table.string('status', 32);
      table.text('notes');
    });
  }

  const hasSoftwareVersionCrosswalk = await knex.schema.hasTable('software_version_crosswalk');
  if (!hasSoftwareVersionCrosswalk) {
    await knex.schema.createTable('software_version_crosswalk', (table: any) => {
      table.string('component_id', 64).primary().references('component_id').inTable('cmdb_component_nodes').onDelete('CASCADE');
      table.string('purl', 512);
      table.string('cpe23_uri', 255);
      table.string('eol_product_slug', 128);
      table.string('eol_cycle_key', 128);
      table.string('eol_cycle_strategy', 64);
      table.string('eol_api_url', 512);
      table.string('vendor_lifecycle_stream', 128);
      table.string('osv_ecosystem', 64);
      table.string('osv_package_name', 255);
      table.string('nvd_cpe_match_string', 255);
      table.string('ghsa_ecosystem', 64);
      table.string('distro_advisory_namespace', 128);
      table.specificType('semver_sort_tuple', 'INT[]');
    });
  }

  const hasPublicEolCycles = await knex.schema.hasTable('public_eol_cycles');
  if (!hasPublicEolCycles) {
    await knex.schema.createTable('public_eol_cycles', (table: any) => {
      table.string('eol_product_slug', 128).notNullable();
      table.string('cycle', 64).notNullable();
      table.boolean('is_lts').defaultTo(false);
      table.date('release_date');
      table.date('active_support_end_date');
      table.date('eol_date');
      table.string('latest_patch_version', 64);
      table.primary(['eol_product_slug', 'cycle']);
    });
  }

  const hasPublicCveRanges = await knex.schema.hasTable('public_cve_ranges');
  if (!hasPublicCveRanges) {
    await knex.schema.createTable('public_cve_ranges', (table: any) => {
      table.string('cve_id', 32).primary();
      table.string('eol_product_slug', 128);
      table.string('distro_advisory_namespace', 128);
      table.string('introduced_version', 64);
      table.string('fixed_version', 64);
      table.decimal('cvss_v3_score', 3, 1);
      table.decimal('epss_score', 5, 4);
      table.boolean('is_cisa_kev').defaultTo(false);
      table.string('advisory_source', 128);
    });
  }

  // Seed items if empty
  const existingItems = await knex('items').count('* as cnt').first();
  if (!Number(existingItems?.cnt)) {
    await knex('items').insert({ name: 'Auth', status: 'Online' });
  }

  // Seed team_owners idempotently
  for (const t of AEGIS_TEAM_OWNERS_TABLE) {
    await knex('team_owners').insert({
      team_id: t.teamId,
      team_name: t.teamName,
      responsibility_scope: t.responsibilityScope,
      email: t.email,
      slack_channel: t.slackChannel,
    }).onConflict('team_id').merge();
  }

  // Seed public_eol_cycles idempotently
  for (const c of PUBLIC_EOL_CYCLE_REFERENCE_DB) {
    await knex('public_eol_cycles').insert({
      eol_product_slug: c.eolProductSlug,
      cycle: c.cycle,
      is_lts: c.isLts,
      release_date: c.releaseDate,
      active_support_end_date: c.activeSupportEndDate,
      eol_date: c.eolDate,
      latest_patch_version: c.latestPatchVersion,
    }).onConflict(['eol_product_slug', 'cycle']).merge();
  }

  // Seed public_cve_ranges idempotently
  for (const e of PUBLIC_CVE_RANGE_REFERENCE_DB) {
    await knex('public_cve_ranges').insert({
      cve_id: e.cveId,
      eol_product_slug: e.eolProductSlug,
      distro_advisory_namespace: e.distroAdvisoryNamespace,
      introduced_version: e.introducedVersion,
      fixed_version: e.fixedVersion,
      cvss_v3_score: e.cvssV3Score,
      epss_score: e.epssScore,
      is_cisa_kev: e.isCisaKev,
      advisory_source: e.advisorySource,
    }).onConflict('cve_id').merge();
  }

  // Seed cmdb_services, cmdb_component_nodes, and software_version_crosswalk idempotently
  for (const [, seed] of Object.entries(CMDB_SERVICE_SEEDS)) {
    const activeDrifts = (seed.driftItems || []).filter(d => d.status === 'ACTIVE_DRIFT').length;

    await knex('cmdb_services').insert({
      ci_id: seed.ciId,
      entity_ref: seed.entityRef,
      service_name: seed.serviceName,
      owner_team: seed.ownerTeam,
      declared_exposure_tier: seed.declaredExposureTier,
      observed_exposure_tier: seed.observedExposureTier,
      declared_replicas: seed.declaredReplicas,
      observed_replicas: seed.observedReplicas,
      declared_image_digest: seed.declaredImageDigest,
      observed_image_digest: seed.observedImageDigest,
      drift_status: activeDrifts > 0 ? 'DRIFT_DETECTED' : 'IN_SYNC',
      drift_items: JSON.stringify(seed.driftItems || []),
      blast_radius: JSON.stringify(seed.blastRadius || []),
      last_reconciled_at: new Date(),
    }).onConflict('ci_id').merge();

    for (const node of seed.componentInventory || []) {
      const owner = resolveComponentOwnerTeam(node.domain, node.categoryType);

      await knex('cmdb_component_nodes').insert({
        component_id: node.componentId,
        ci_id: seed.ciId,
        domain: node.domain,
        layer_id: node.layerId ?? null,
        layer_label: node.layerLabel ?? null,
        category_type: node.categoryType,
        category_label: node.categoryLabel,
        icon: node.icon,
        owner_team_id: owner.teamId,
        name: node.name,
        version_or_identifier: node.versionOrIdentifier,
        status: node.status,
        notes: node.notes ?? null,
      }).onConflict('component_id').merge();

      if (node.domain === 'SOFTWARE') {
        const cc = crossCheckSoftwareVersion({ productName: node.name, rawVersion: node.versionOrIdentifier });
        await knex('software_version_crosswalk').insert({
          component_id: node.componentId,
          purl: cc.normalized.purl,
          cpe23_uri: cc.normalized.cpe23Uri,
          eol_product_slug: cc.normalized.eolProductSlug,
          eol_cycle_key: cc.normalized.eolCycleKey,
          eol_cycle_strategy: cc.normalized.eolCycleStrategy,
          eol_api_url: cc.normalized.eolApiUrl,
          vendor_lifecycle_stream: cc.normalized.vendorLifecycleStream,
          osv_ecosystem: cc.normalized.osvEcosystem,
          osv_package_name: cc.normalized.osvPackageName,
          nvd_cpe_match_string: cc.normalized.nvdCpeMatchString,
          ghsa_ecosystem: cc.normalized.ghsaEcosystem,
          distro_advisory_namespace: cc.normalized.distroAdvisoryNamespace,
          semver_sort_tuple: cc.normalized.semverSortTuple,
        }).onConflict('component_id').merge();
      }
    }
  }

  // Sync SSL endpoints
  await syncSslEndpointsWithPostgres(knex);
}

export async function syncSslEndpointsWithPostgres(knex?: any): Promise<TrackedSslEndpointRecord[]> {
  const client = knex ?? getAegisKnexClient();
  if (!client) return getFleetSslInventory().endpoints;

  for (const rec of getFleetSslInventory().endpoints) {
    if (rec.endpointKey && rec.endpointKey.startsWith('imported-')) continue;
    let protocol = 'HTTPS';
    let port = 443;
    if (rec.endpointUrl) {
      try {
        const parsed = new URL(rec.endpointUrl);
        protocol = parsed.protocol.replace(':', '').toUpperCase();
        if (parsed.port) port = parseInt(parsed.port, 10);
      } catch { /* use defaults */ }
    }

    await client('tracked_endpoints').insert({
      endpoint_uid: rec.endpointId,
      endpoint_name: rec.sniHostname,
      protocol,
      port,
      owner_team_id: 'sre-team',
      environment: rec.environment,
      notes: `${rec.ingressType} (${rec.providerType})`,
      entity_ref: rec.entityRef,
      service_name: rec.serviceName,
      endpoint_key: rec.endpointKey,
      endpoint_url: rec.endpointUrl,
      sni_hostname: rec.sniHostname,
      provider_type: rec.providerType,
      renewal_mode: rec.renewalMode,
      exposure_scope: rec.exposureScope,
      dns_scope: rec.dnsScope,
      ingress_type: rec.ingressType,
      auto_renew_threshold_days: rec.autoRenewThresholdDays,
      gcp_project: rec.gcpProject ?? null,
      gcp_target_proxy: rec.gcpTargetProxy ?? null,
      last_probed_at: new Date(rec.lastProbedAt || Date.now()),
    }).onConflict('endpoint_uid').merge();

    const epRow = await client('tracked_endpoints').where('endpoint_uid', rec.endpointId).first();

    if (epRow?.id) {
      await client('certificate_inventory').insert({
        endpoint_id: epRow.id,
        cert_issuer: rec.certificate.issuerCn,
        cert_subject: rec.certificate.subjectCn,
        serial_number: rec.certificate.serialNumberHex,
        not_before: new Date(rec.certificate.notBefore),
        not_after: new Date(rec.certificate.notAfter),
        key_algorithm: rec.certificate.publicKeyAlgorithm,
        key_size: rec.certificate.publicKeyBits,
        auto_renew: rec.renewalMode !== 'manual-or-template',
        notes: (rec.certificate.complianceFindings || []).join('; ') || null,
        compliance_status: rec.certificate.complianceStatus,
        days_remaining: rec.certificate.daysRemaining,
        is_active: true,
        cert_details_json: JSON.stringify(rec.certificate),
      }).onConflict(['endpoint_id', 'serial_number']).merge();
    }
  }

  const dbEndpoints = await client('tracked_endpoints').select('*');
  const activeDbUids = new Set<string>();
  for (const row of dbEndpoints) {
    const env = (['dev', 'stg', 'stress-test', 'preprod', 'prod'].includes(row.environment) ? row.environment : 'prod') as SslEnvironmentTier;
    const svcName = row.service_name || 'aegis-ui';
    const entityRef = row.entity_ref || `component:default/${svcName}`;
    const epKey = row.endpoint_key || `imported-${row.id}`;
    const endpointId = row.endpoint_uid || `${entityRef}:${env}:${epKey}`;
    activeDbUids.add(endpointId);

    if (!row.endpoint_uid) {
      await client('tracked_endpoints').where('id', row.id).update({
        endpoint_uid: endpointId,
        entity_ref: entityRef,
        service_name: svcName,
        endpoint_key: epKey,
      });
    }

    const certRow = await client('certificate_inventory').where({ endpoint_id: row.id }).orderBy('is_active', 'desc').first();

    const certDetails = certRow?.cert_details_json ? (typeof certRow.cert_details_json === 'string' ? JSON.parse(certRow.cert_details_json) : certRow.cert_details_json) : null;

    const hydrated = await hydrateTrackedEndpointRecordFromDbRow({
      endpointId,
      entityRef,
      serviceName: svcName,
      environment: env,
      endpointKey: epKey,
      endpointUrl: row.endpoint_url || `${(row.protocol || 'https').toLowerCase()}://${row.endpoint_name}:${row.port || 443}`,
      sniHostname: row.sni_hostname || row.endpoint_name,
      providerType: (row.provider_type || 'gcp-cloud-lb') as SslProviderType,
      renewalMode: (row.renewal_mode || 'workflow-auto-renew') as SslRenewalMode,
      autoRenewThresholdDays: Number(row.auto_renew_threshold_days ?? 30),
      gcpProject: row.gcp_project ?? null,
      gcpTargetProxy: row.gcp_target_proxy ?? null,
      exposureScope: (row.exposure_scope || 'unrestricted-public') as any,
      dnsScope: (row.dns_scope || 'public-authoritative') as any,
      ingressType: row.ingress_type || 'Google Cloud Global External Application LB (GCLB)',
      lastProbedAt: row.last_probed_at ? new Date(row.last_probed_at).toISOString() : new Date().toISOString(),
      certificateDetails: certDetails,
    });

    if (!certRow) {
      await client('certificate_inventory').insert({
        endpoint_id: row.id,
        cert_issuer: hydrated.certificate.issuerCn,
        cert_subject: hydrated.certificate.subjectCn,
        serial_number: hydrated.certificate.serialNumberHex,
        not_before: new Date(hydrated.certificate.notBefore),
        not_after: new Date(hydrated.certificate.notAfter),
        key_algorithm: hydrated.certificate.publicKeyAlgorithm,
        key_size: hydrated.certificate.publicKeyBits,
        auto_renew: hydrated.renewalMode !== 'manual-or-template',
        notes: (hydrated.certificate.complianceFindings || []).join('; ') || null,
        compliance_status: hydrated.certificate.complianceStatus,
        days_remaining: hydrated.certificate.daysRemaining,
        is_active: true,
        cert_details_json: JSON.stringify(hydrated.certificate),
      }).onConflict(['endpoint_id', 'serial_number']).merge();
    }
  }

  for (const rec of getFleetSslInventory().endpoints) {
    if (rec.endpointKey?.startsWith('imported-') && !activeDbUids.has(rec.endpointId)) {
      removeTrackedEndpointFromMemory(rec.endpointId);
    }
  }

  return getFleetSslInventory().endpoints;
}

function mapServiceAndNodesToSnapshot(serviceRow: any, nodeRows: any[]): EntityCmdbSnapshot {
  let driftItems: CmdbDriftItem[];
  if (typeof serviceRow.drift_items === 'string') {
    try { driftItems = JSON.parse(serviceRow.drift_items); } catch { driftItems = []; }
  } else {
    driftItems = serviceRow.drift_items || [];
  }

  let blastRadius: any[];
  if (typeof serviceRow.blast_radius === 'string') {
    try { blastRadius = JSON.parse(serviceRow.blast_radius); } catch { blastRadius = []; }
  } else {
    blastRadius = serviceRow.blast_radius || [];
  }

  const componentInventory: CmdbComponentNode[] = nodeRows.map((r: any) => {
    const taxMeta = AEGIS_COMPONENT_TAXONOMY_CATALOG.find(c => c.id === r.category_type);
    const domain = (r.domain || taxMeta?.domain || 'SOFTWARE') as any;
    const categoryType = (r.category_type || taxMeta?.id || 'APPLICATION_CORE') as any;
    const owner = resolveComponentOwnerTeam(domain, categoryType);
    const ownerTeamId = (r.owner_team_id === 'app-team' || r.owner_team_id === 'sre-team') ? r.owner_team_id : owner.teamId;
    const ownerTeamName = ownerTeamId === 'app-team' ? 'App Team' : 'SRE Team';

    const node: any = {
      componentId: r.component_id,
      domain,
      layerId: r.layer_id || null,
      layerLabel: r.layer_label || null,
      categoryType,
      categoryLabel: r.category_label || null,
      icon: r.icon || null,
      ownerTeamId,
      ownerTeamName,
      name: r.name,
      versionOrIdentifier: r.version_or_identifier || null,
      status: r.status || null,
      notes: r.notes || null,
    };

    if (domain === 'SOFTWARE') {
      const cc = crossCheckSoftwareVersion({ productName: r.name, rawVersion: r.version_or_identifier });
      node.normalizedVersion = cc.normalized;
      node.versionCrossCheck = cc;
    }

    return node;
  });

  const activeDriftCount = driftItems.filter(d => d.status === 'ACTIVE_DRIFT').length;

  return {
    ciId: serviceRow.ci_id,
    entityRef: serviceRow.entity_ref,
    serviceName: serviceRow.service_name,
    ownerTeam: serviceRow.owner_team || null,
    declaredExposureTier: serviceRow.declared_exposure_tier || null,
    observedExposureTier: serviceRow.observed_exposure_tier || null,
    declaredReplicas: serviceRow.declared_replicas ?? null,
    observedReplicas: serviceRow.observed_replicas ?? null,
    declaredImageDigest: serviceRow.declared_image_digest || null,
    observedImageDigest: serviceRow.observed_image_digest || null,
    driftStatus: serviceRow.drift_status || null,
    driftItems,
    blastRadius,
    activeDriftCount,
    lastReconciledAt: serviceRow.last_reconciled_at ? new Date(serviceRow.last_reconciled_at).toISOString() : '',
    componentInventory,
  };
}

export async function queryEntityCmdbSnapshotFromPostgres(entityRef: string, knex?: any): Promise<EntityCmdbSnapshot | null> {
  const client = knex ?? getAegisKnexClient();
  if (!client) return null;

  const raw = entityRef.split('/').pop()?.split(':').pop() || 'aegis-ui';
  const key = resolveCmdbServiceKey(entityRef);

  let serviceRow = await client('cmdb_services')
    .where('entity_ref', raw)
    .orWhere('service_name', raw)
    .orWhere('ci_id', entityRef)
    .first();

  if (!serviceRow) {
    serviceRow = await client('cmdb_services').where('entity_ref', key).first();
  }

  if (!serviceRow) return null;

  const nodeRows = await client('cmdb_component_nodes').where('ci_id', serviceRow.ci_id);

  return mapServiceAndNodesToSnapshot(serviceRow, nodeRows);
}

export async function queryFleetCmdbTopologyFromPostgres(knex?: any): Promise<FleetCmdbTopologyReport | null> {
  const client = knex ?? getAegisKnexClient();
  if (!client) return null;

  const serviceRows = await client('cmdb_services').orderBy('ci_id');
  if (!serviceRows || serviceRows.length === 0) return null;
  const allNodeRows = await client('cmdb_component_nodes');

  const snapshots: EntityCmdbSnapshot[] = serviceRows.map((serviceRow: any) => {
    const nodeRows = allNodeRows.filter((n: any) => n.ci_id === serviceRow.ci_id);
    return mapServiceAndNodesToSnapshot(serviceRow, nodeRows);
  });

  const driftedServicesCount = snapshots.filter(s => s.activeDriftCount > 0).length;
  const totalActiveDrifts = snapshots.reduce((sum, s) => sum + s.activeDriftCount, 0);
  const shadowResourcesDetected = snapshots.reduce((sum, s) => sum + s.driftItems.filter(d => d.status === 'ACTIVE_DRIFT' && d.category === 'SHADOW_RESOURCE').length, 0);
  const totalConfigurationItems = snapshots.length;

  const directedEdges = [
    { from: 'hello-world-app', to: 'aegis-ui', protocol: 'HTTPS/TLS-1.3' },
    { from: 'aegis-ui', to: 'aegis-backend', protocol: 'REST/JSON-mTLS' },
    { from: 'aegis-ui', to: 'aegis-auth', protocol: 'OIDC/JWT' },
    { from: 'aegis-backend', to: 'aegis-auth', protocol: 'gRPC/Introspect' },
    { from: 'aegis-backend', to: 'aegis-db', protocol: 'PostgreSQL/TLS' },
  ];

  return {
    snapshots,
    driftedServicesCount,
    totalActiveDrifts,
    shadowResourcesDetected,
    totalConfigurationItems,
    directedEdges,
    taxonomyCatalog: getComponentTaxonomyCatalog(),
    teamOwnersTable: AEGIS_TEAM_OWNERS_TABLE,
  };
}

export async function getAegisPostgresTableCounts(knex?: any): Promise<Record<string, number>> {
  const client = knex ?? getAegisKnexClient();
  if (!client) return {};

  const tables = [
    'items',
    'team_owners',
    'tracked_endpoints',
    'certificate_inventory',
    'cmdb_services',
    'cmdb_component_nodes',
    'software_version_crosswalk',
    'public_eol_cycles',
    'public_cve_ranges',
  ];

  const counts: Record<string, number> = {};
  for (const tbl of tables) {
    const row = await client(tbl).count('* as cnt').first();
    counts[tbl] = Number(row?.cnt ?? 0);
  }
  return counts;
}

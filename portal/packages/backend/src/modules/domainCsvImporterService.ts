import {
  ActiveEndpointProbeResult,
  normalizeTargetEndpointInput,
  probeEndpointListLive,
  SourceIpNetworkContext,
} from './activeEndpointProberService';
import {
  getAegisKnexClient,
  syncSslEndpointsWithPostgres,
} from './aegisPostgresStore';
import { CMDB_SERVICE_SEEDS } from './livingCmdbService';
import {
  hydrateTrackedEndpointRecordFromDbRow,
  IngressExposureScope,
  normalizeExposureScope,
  SslEnvironmentTier,
  SslProviderType,
  SslRenewalMode,
  TrackedSslEndpointRecord,
} from './sslEndpointTrackerService';

export interface ParsedDomainCsvRow {
  rowNumber: number;
  endpointInput: string;
  endpointUrl: string;
  hostname: string;
  port: number;
  serviceName: string;
  entityRef: string;
  environment: SslEnvironmentTier;
  endpointKey: string;
  providerType: SslProviderType;
  renewalMode: SslRenewalMode;
  exposureScope?: IngressExposureScope;
  ownerTeamId: 'sre-team' | 'app-team';
  notes?: string;
}

export interface DomainCsvRowValidationError {
  rowNumber: number;
  message: string;
  rawRow: Record<string, string>;
}

export interface DomainCsvParseResult {
  validRows: ParsedDomainCsvRow[];
  errors: DomainCsvRowValidationError[];
  totalDataRows: number;
}

export interface DomainCsvImportReport {
  totalDataRows: number;
  importedCount: number;
  probedCount: number;
  probedReachableCount: number;
  publicAccessibleCount: number;
  wafProtectedCount: number;
  errors: DomainCsvRowValidationError[];
  networkContext?: SourceIpNetworkContext;
  importedEndpoints: TrackedSslEndpointRecord[];
  probeResults: ActiveEndpointProbeResult[];
}

export const SAMPLE_DOMAINS_CSV_TEMPLATE = [
  'endpoint,service_name,environment,endpoint_key,provider_type,exposure_scope,owner_team_id,notes',
  'https://127.0.0.1:8443,hello-world-app,prod,edge-haproxy,haproxy-edge,restricted-public,sre-team,HAProxy local TLS sandbox',
  'auth.prod.aegisplatform.io,aegis-auth,prod,primary-sso,gcp-cloud-lb,unrestricted-public,sre-team,Customer CIAM OIDC login',
  'stg-api.backend.aegisplatform.io,aegis-backend,stg,canary-api,private-cloud-lb,strictly-private,sre-team,Internal staging API gateway',
].join('\n');

const ENDPOINT_HEADER_ALIASES = new Set([
  'endpoint',
  'domain',
  'fqdn',
  'url',
  'endpoint_url',
  'endpointurl',
  'hostname',
  'host',
]);

const SERVICE_HEADER_ALIASES = new Set([
  'service_name',
  'servicename',
  'service',
  'app',
  'application',
  'component',
]);

const ENVIRONMENT_HEADER_ALIASES = new Set([
  'environment',
  'env',
  'tier',
  'env_tier',
]);

const ENDPOINT_KEY_ALIASES = new Set([
  'endpoint_key',
  'endpointkey',
  'key',
  'sub_endpoint',
  'role',
]);

const PROVIDER_HEADER_ALIASES = new Set([
  'provider_type',
  'providertype',
  'provider',
  'lb_type',
  'lb',
]);

const EXPOSURE_HEADER_ALIASES = new Set([
  'exposure_scope',
  'exposurescope',
  'exposure',
  'visibility',
]);

const OWNER_HEADER_ALIASES = new Set([
  'owner_team_id',
  'ownerteamid',
  'owner_team',
  'owner',
  'team',
]);

const NOTES_HEADER_ALIASES = new Set([
  'notes',
  'note',
  'description',
  'comment',
  'comments',
]);

function parseCsvLine(line: string): string[] {
  const fields: string[] = [];
  let current = '';
  let inQuotes = false;
  for (let i = 0; i < line.length; i += 1) {
    const ch = line[i];
    if (ch === '"') {
      if (inQuotes && line[i + 1] === '"') {
        current += '"';
        i += 1;
      } else {
        inQuotes = !inQuotes;
      }
    } else if (ch === ',' && !inQuotes) {
      fields.push(current.trim());
      current = '';
    } else {
      current += ch;
    }
  }
  fields.push(current.trim());
  return fields;
}

export function normalizeEnvironmentTier(
  rawEnv: string,
): SslEnvironmentTier | null {
  const cleaned = rawEnv.trim().toLowerCase();
  if (!cleaned) return null;
  if (cleaned === 'dev' || cleaned === 'development') return 'dev';
  if (cleaned === 'stg' || cleaned === 'stage' || cleaned === 'staging')
    return 'stg';
  if (
    cleaned === 'stress-test' ||
    cleaned === 'stresstest' ||
    cleaned === 'stress_test' ||
    cleaned === 'stress'
  ) {
    return 'stress-test';
  }
  if (
    cleaned === 'preprod' ||
    cleaned === 'pre-prod' ||
    cleaned === 'pre_prod' ||
    cleaned === 'uat'
  ) {
    return 'preprod';
  }
  if (cleaned === 'prod' || cleaned === 'production' || cleaned === 'prd')
    return 'prod';
  return null;
}

function normalizeProviderType(rawProvider?: string): SslProviderType {
  const cleaned = (rawProvider || '').trim().toLowerCase();
  if (cleaned === 'haproxy-edge' || cleaned === 'haproxy') {
    return 'haproxy-edge';
  }
  if (
    cleaned === 'private-cloud-lb' ||
    cleaned === 'private-lb' ||
    cleaned === 'private' ||
    cleaned === 'vault'
  ) {
    return 'private-cloud-lb';
  }
  return 'gcp-cloud-lb';
}

function defaultRenewalModeForProvider(
  provider: SslProviderType,
): SslRenewalMode {
  if (provider === 'haproxy-edge') return 'manual-or-template';
  if (provider === 'private-cloud-lb') return 'self-renewing-monitored';
  return 'workflow-auto-renew';
}

/**
 * Parses and validates a CSV string of domains.
 * Enforces that `endpoint`, `service_name`, and `environment` are present and valid.
 */
export function parseDomainsCsv(csvText: string): DomainCsvParseResult {
  const cleanedText = (csvText || '').replace(/^\uFEFF/, '').trim();
  if (!cleanedText) {
    return {
      validRows: [],
      errors: [
        {
          rowNumber: 1,
          message: 'CSV content is empty.',
          rawRow: {},
        },
      ],
      totalDataRows: 0,
    };
  }

  const rawLines = cleanedText
    .split(/\r?\n/)
    .map(l => l.trim())
    .filter(l => l.length > 0 && !l.startsWith('#'));

  if (rawLines.length === 0) {
    return {
      validRows: [],
      errors: [
        {
          rowNumber: 1,
          message: 'CSV contains no header or data lines.',
          rawRow: {},
        },
      ],
      totalDataRows: 0,
    };
  }

  const rawHeaders = parseCsvLine(rawLines[0]);
  const normalizedHeaders = rawHeaders.map(h =>
    h.trim().toLowerCase().replace(/[\s-]+/g, '_'),
  );

  const hasEndpointCol = normalizedHeaders.some(h =>
    ENDPOINT_HEADER_ALIASES.has(h),
  );
  const hasServiceCol = normalizedHeaders.some(h =>
    SERVICE_HEADER_ALIASES.has(h),
  );
  const hasEnvCol = normalizedHeaders.some(h =>
    ENVIRONMENT_HEADER_ALIASES.has(h),
  );

  const missingRequiredCols: string[] = [];
  if (!hasEndpointCol) missingRequiredCols.push('endpoint');
  if (!hasServiceCol) missingRequiredCols.push('service_name');
  if (!hasEnvCol) missingRequiredCols.push('environment');

  if (missingRequiredCols.length > 0) {
    return {
      validRows: [],
      errors: [
        {
          rowNumber: 1,
          message: `Missing required CSV header column(s): ${missingRequiredCols.join(', ')}. Required headers are: endpoint, service_name, environment.`,
          rawRow: {},
        },
      ],
      totalDataRows: Math.max(0, rawLines.length - 1),
    };
  }

  const validRows: ParsedDomainCsvRow[] = [];
  const errors: DomainCsvRowValidationError[] = [];

  for (let idx = 1; idx < rawLines.length; idx += 1) {
    const rowNumber = idx + 1;
    const values = parseCsvLine(rawLines[idx]);
    const rawRow: Record<string, string> = {};
    for (let c = 0; c < normalizedHeaders.length; c += 1) {
      rawRow[normalizedHeaders[c]] = values[c] ?? '';
    }

    const findCol = (aliases: Set<string>): string => {
      for (const [k, v] of Object.entries(rawRow)) {
        if (aliases.has(k)) return v.trim();
      }
      return '';
    };

    const rawEndpoint = findCol(ENDPOINT_HEADER_ALIASES);
    const rawService = findCol(SERVICE_HEADER_ALIASES);
    const rawEnvironment = findCol(ENVIRONMENT_HEADER_ALIASES);

    if (!rawEndpoint) {
      errors.push({
        rowNumber,
        message: `Row ${rowNumber}: Missing required 'endpoint' value.`,
        rawRow,
      });
      continue;
    }

    if (!rawService) {
      errors.push({
        rowNumber,
        message: `Row ${rowNumber}: Missing required 'service_name' value for endpoint '${rawEndpoint}'.`,
        rawRow,
      });
      continue;
    }

    if (!rawEnvironment) {
      errors.push({
        rowNumber,
        message: `Row ${rowNumber}: Missing required 'environment' value for endpoint '${rawEndpoint}'.`,
        rawRow,
      });
      continue;
    }

    const environment = normalizeEnvironmentTier(rawEnvironment);
    if (!environment) {
      errors.push({
        rowNumber,
        message: `Row ${rowNumber}: Invalid 'environment' value '${rawEnvironment}'. Must be one of: dev, stg, stress-test, preprod, prod.`,
        rawRow,
      });
      continue;
    }

    let normalizedTarget: { endpointUrl: string; hostname: string; port: number };
    try {
      normalizedTarget = normalizeTargetEndpointInput(rawEndpoint);
      if (!normalizedTarget.hostname) {
        throw new Error('Empty hostname');
      }
    } catch {
      errors.push({
        rowNumber,
        message: `Row ${rowNumber}: Invalid endpoint URL or hostname '${rawEndpoint}'.`,
        rawRow,
      });
      continue;
    }

    const serviceName = rawService
      .trim()
      .toLowerCase()
      .replace(/[^a-z0-9-_]/g, '-');
    const entityRef = rawService.includes(':')
      ? rawService
      : `component:default/${serviceName}`;

    const rawKey = findCol(ENDPOINT_KEY_ALIASES);
    const endpointKey =
      rawKey
        .trim()
        .toLowerCase()
        .replace(/[^a-z0-9-_]/g, '-') ||
      normalizedTarget.hostname.replace(/[^a-zA-Z0-9-]/g, '-').toLowerCase();

    const providerType = normalizeProviderType(
      findCol(PROVIDER_HEADER_ALIASES),
    );
    const renewalMode = defaultRenewalModeForProvider(providerType);
    const rawExposure = findCol(EXPOSURE_HEADER_ALIASES);
    const exposureScope = rawExposure
      ? normalizeExposureScope(rawExposure, 'unrestricted-public')
      : undefined;

    const rawOwner = findCol(OWNER_HEADER_ALIASES).toLowerCase();
    const ownerTeamId: 'sre-team' | 'app-team' =
      rawOwner === 'app-team' || rawOwner === 'app' ? 'app-team' : 'sre-team';
    const notes = findCol(NOTES_HEADER_ALIASES) || undefined;

    validRows.push({
      rowNumber,
      endpointInput: rawEndpoint,
      endpointUrl: normalizedTarget.endpointUrl,
      hostname: normalizedTarget.hostname,
      port: normalizedTarget.port,
      serviceName,
      entityRef,
      environment,
      endpointKey,
      providerType,
      renewalMode,
      exposureScope,
      ownerTeamId,
      notes,
    });
  }

  return {
    validRows,
    errors,
    totalDataRows: Math.max(0, rawLines.length - 1),
  };
}

async function upsertDomainToCmdbTables(
  row: ParsedDomainCsvRow,
  probeResult: ActiveEndpointProbeResult | undefined,
  knexClient: any,
): Promise<void> {
  if (!knexClient) return;

  const existingService = await knexClient('cmdb_services')
    .where('service_name', row.serviceName)
    .orWhere('entity_ref', row.serviceName)
    .orWhere('entity_ref', row.entityRef)
    .first();

  let ciId = existingService?.ci_id;
  if (!ciId) {
    const seedMatch = CMDB_SERVICE_SEEDS[row.serviceName];
    ciId =
      seedMatch?.ciId ||
      `CI-AEGIS-${row.serviceName.toUpperCase().replace(/[^A-Z0-9]/g, '').slice(0, 12) || 'CUSTOM'}`;

    await knexClient('cmdb_services')
      .insert({
        ci_id: ciId,
        entity_ref: row.serviceName,
        service_name: row.serviceName,
        owner_team: seedMatch?.ownerTeam || 'edge-platform',
        declared_exposure_tier: row.exposureScope || 'unrestricted-public',
        observed_exposure_tier:
          probeResult?.exposureScope ||
          row.exposureScope ||
          'unrestricted-public',
        declared_replicas: 2,
        observed_replicas: 2,
        declared_image_digest: 'sha256:csv-imported',
        observed_image_digest: 'sha256:csv-imported',
        drift_status: 'IN_SYNC',
        drift_items: JSON.stringify([]),
        blast_radius: JSON.stringify([]),
        last_reconciled_at: new Date(),
      })
      .onConflict('ci_id')
      .merge();
  }

  const componentId =
    `dom-${row.serviceName}-${row.environment}-${row.endpointKey}`
      .toLowerCase()
      .replace(/[^a-z0-9-_]/g, '-')
      .slice(0, 64);

  const noteParts: string[] = [];
  if (row.notes) noteParts.push(row.notes);
  if (probeResult?.wafDetected) {
    noteParts.push(`WAF: ${probeResult.wafProvider}`);
  }
  if (probeResult) {
    noteParts.push(
      probeResult.accessibleFromPublicInternet
        ? `Public Internet Accessible (Source IP ${probeResult.sourceIp})`
        : `Private/Zscaler Network (${probeResult.sourceIp})`,
    );
  }

  await knexClient('cmdb_component_nodes')
    .insert({
      component_id: componentId,
      ci_id: ciId,
      domain: 'INFRASTRUCTURE',
      layer_id: 'EDGE_EXTERNAL_SECURITY',
      layer_label: 'Edge & External Security',
      category_type: 'DOMAIN_ENDPOINT',
      category_label: 'Domain Endpoint',
      icon: '🌐',
      owner_team_id: row.ownerTeamId,
      name: row.hostname,
      version_or_identifier: `${row.environment.toUpperCase()} (${row.endpointUrl})`,
      status:
        probeResult?.sslDetails?.complianceStatus === 'NON_COMPLIANT'
          ? 'CRITICAL'
          : probeResult?.sslDetails?.complianceStatus === 'WARNING'
          ? 'WARNING'
          : 'HEALTHY',
      notes: noteParts.join(' | ') || 'Imported via Domains CSV Loader',
    })
    .onConflict('component_id')
    .merge();
}

/**
 * Imports a CSV of domains into the SSL Tracker and PostgreSQL CMDB tables
 * (`tracked_endpoints`, `certificate_inventory`, `cmdb_services`, `cmdb_component_nodes`).
 */
export async function importDomainsCsvToCmdb(params: {
  csvText: string;
  probeOnImport?: boolean;
  sourceIpOverride?: string;
  orgNameOverride?: string;
  timeoutMs?: number;
  knex?: any;
}): Promise<DomainCsvImportReport> {
  const parsed = parseDomainsCsv(params.csvText);
  const probeOnImport = params.probeOnImport !== false;
  const timeoutMs = params.timeoutMs ?? 3500;
  const knexClient = params.knex ?? getAegisKnexClient();

  if (parsed.validRows.length === 0) {
    return {
      totalDataRows: parsed.totalDataRows,
      importedCount: 0,
      probedCount: 0,
      probedReachableCount: 0,
      publicAccessibleCount: 0,
      wafProtectedCount: 0,
      errors: parsed.errors,
      importedEndpoints: [],
      probeResults: [],
    };
  }

  let probeResults: ActiveEndpointProbeResult[] = [];
  let networkContext: SourceIpNetworkContext | undefined;

  if (probeOnImport) {
    const batchReport = await probeEndpointListLive(
      parsed.validRows.map(r => ({
        target: r.endpointUrl,
        serviceName: r.serviceName,
        entityRef: r.entityRef,
        environment: r.environment,
        endpointKey: r.endpointKey,
        ownerTeamId: r.ownerTeamId,
      })),
      {
        sourceIpOverride: params.sourceIpOverride,
        orgNameOverride: params.orgNameOverride,
        timeoutMs,
        persistToStore: true,
      },
    );
    probeResults = batchReport.results;
    networkContext = batchReport.networkContext;
  }

  const importedEndpoints: TrackedSslEndpointRecord[] = [];

  for (let i = 0; i < parsed.validRows.length; i += 1) {
    const row = parsed.validRows[i];
    const probeRes = probeResults[i];
    const endpointId = `${row.entityRef}:${row.environment}:${row.endpointKey}`;

    const resolvedExposure =
      row.exposureScope ||
      probeRes?.exposureScope ||
      'unrestricted-public';

    const ingressLabelParts: string[] = [];
    if (probeRes?.wafDetected) {
      ingressLabelParts.push(`${probeRes.wafProvider} WAF`);
    }
    if (row.notes) {
      ingressLabelParts.push(row.notes);
    }

    const record = await hydrateTrackedEndpointRecordFromDbRow({
      endpointId,
      entityRef: row.entityRef,
      serviceName: row.serviceName,
      environment: row.environment,
      endpointKey: row.endpointKey,
      endpointUrl: row.endpointUrl,
      sniHostname: row.hostname,
      providerType: row.providerType,
      renewalMode: row.renewalMode,
      exposureScope: resolvedExposure,
      dnsScope:
        resolvedExposure === 'strictly-private'
          ? 'private-split-horizon'
          : 'public-authoritative',
      ingressType:
        ingressLabelParts.join(' — ') ||
        'CSV Imported Endpoint',
      lastProbedAt: new Date().toISOString(),
      certificateDetails: probeRes?.sslDetails
        ? {
            serialNumberHex: probeRes.sslDetails.serialNumberHex,
            serialNumberDecimal: probeRes.sslDetails.serialNumberDecimal,
            rotatedFromSerial: null,
            historyCount: 1,
            notBefore: probeRes.sslDetails.notBefore,
            notAfter: probeRes.sslDetails.notAfter,
            daysRemaining: probeRes.sslDetails.daysRemaining,
            expiryStatus: probeRes.sslDetails.expiryStatus,
            subjectCn: probeRes.sslDetails.subjectCn,
            subjectDn: probeRes.sslDetails.subjectDn,
            sanDnsNames: probeRes.sslDetails.sanDnsNames,
            hostnameMatchesSan: probeRes.sslDetails.hostnameMatchesSan,
            issuerCn: probeRes.sslDetails.issuerCn,
            issuerOrg: probeRes.sslDetails.issuerOrg,
            issuerDn: probeRes.sslDetails.issuerDn,
            isSelfSigned: probeRes.sslDetails.isSelfSigned,
            signatureAlgorithm: probeRes.sslDetails.signatureAlgorithm,
            signatureHashAlgorithm: probeRes.sslDetails.signatureHashAlgorithm,
            publicKeyAlgorithm: probeRes.sslDetails.publicKeyAlgorithm,
            publicKeyBits: probeRes.sslDetails.publicKeyBits,
            fingerprintSha256: probeRes.sslDetails.fingerprintSha256,
            complianceStatus: probeRes.sslDetails.complianceStatus,
            complianceFindings: probeRes.sslDetails.complianceFindings,
            isActive: true,
          }
        : null,
    });

    importedEndpoints.push(record);
    await upsertDomainToCmdbTables(row, probeRes, knexClient);
  }

  if (knexClient) {
    await syncSslEndpointsWithPostgres(knexClient);
  }

  return {
    totalDataRows: parsed.totalDataRows,
    importedCount: importedEndpoints.length,
    probedCount: probeResults.length,
    probedReachableCount: probeResults.filter(r => r.reachable).length,
    publicAccessibleCount: probeResults.filter(
      r => r.accessibleFromPublicInternet,
    ).length,
    wafProtectedCount: probeResults.filter(r => r.wafDetected).length,
    errors: parsed.errors,
    networkContext,
    importedEndpoints,
    probeResults,
  };
}

import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { Entity } from '@backstage/catalog-model';
import {
  clearSslTrackerStoreForTests,
  createQualityGateApprovalRequest,
  decideQualityGateApproval,
  evaluateCryptoCompliance,
  evaluateExpiryAndRenewalSla,
  extractHostPortFromUrl,
  getEndpointCertificateHistory,
  getEntitySslRollupFromStore,
  getQualityGateStatus,
  loadSslTrackerStateFromDisk,
  matchHostnameSan,
  parseEntityEnvironmentEndpoints,
  parseEntitySoftwareStack,
  previewMockGcpAutoRenewalDiff,
  remediatePrivateCloudEndpointCrypto,
  saveSslTrackerStateToDisk,
  scanEntityEndpoints,
  triggerMockGcpAutoRenewal,
} from './sslEndpointTrackerService';

describe('sslEndpointTrackerService', () => {
  beforeEach(() => {
    clearSslTrackerStoreForTests();
  });

  it('parses 1:N environment endpoints (including 3+ stg endpoints) and comma-separated lists', () => {
    const entity: Entity = {
      apiVersion: 'backstage.io/v1alpha1',
      kind: 'Component',
      metadata: {
        name: 'aegis-auth',
        annotations: {
          'resiliency.idp/ssl-provider': 'private-cloud-lb',
          'resiliency.idp/ssl-renewal-mode': 'self-renewing-monitored',
          'resiliency.idp/endpoints.dev': 'https://dev.auth.internal:8443/healthz',
          'resiliency.idp/endpoints.stg.primary':
            'https://stg.auth.internal:8443/healthz',
          'resiliency.idp/endpoints.stg.eu-central':
            'https://stg-eu.auth.internal:8443/healthz',
          'resiliency.idp/endpoints.stg.partner-sso':
            'https://stg-sso.auth.internal:8443/healthz',
          'resiliency.idp/endpoints.stress-test':
            'https://stress-1.auth.internal:8443/healthz, https://stress-2.auth.internal:8443/healthz',
          'resiliency.idp/endpoints.preprod':
            'https://preprod.auth.internal:8443/healthz',
          'resiliency.idp/endpoints.prod':
            'https://prod.auth.internal:8443/healthz',
        },
      },
    };

    const parsed = parseEntityEnvironmentEndpoints(entity);
    expect(parsed).toHaveLength(8);
    const stgEndpoints = parsed.filter(e => e.environment === 'stg');
    expect(stgEndpoints).toHaveLength(3);
    expect(stgEndpoints.map(e => e.endpointKey)).toEqual([
      'primary',
      'eu-central',
      'partner-sso',
    ]);
  });

  it('evaluates all 5 X.509 compliance pillars and flags SHA-1 / 1024-bit weak keys', async () => {
    expect(
      evaluateCryptoCompliance(
        'sha256WithRSAEncryption',
        'SHA256',
        'RSA',
        2048,
      ).compliant,
    ).toBe(true);

    const weak = evaluateCryptoCompliance(
      'sha1WithRSAEncryption',
      'SHA1',
      'RSA',
      1024,
    );
    expect(weak.compliant).toBe(false);
    expect(weak.findings.join(' ')).toContain('INSECURE_SIGNATURE_HASH');
    expect(weak.findings.join(' ')).toContain('WEAK_KEY_SIZE');

    expect(
      matchHostnameSan('stg-eu.auth.internal', 'auth.internal', [
        '*.auth.internal',
      ]),
    ).toBe(true);
    expect(
      matchHostnameSan('deep.sub.auth.internal', 'auth.internal', [
        '*.auth.internal',
      ]),
    ).toBe(false);
  });

  it('detects stalled self-renewal on private-cloud-lb when daysRemaining <= threshold', () => {
    const stalled = evaluateExpiryAndRenewalSla(
      12,
      'self-renewing-monitored',
      15,
    );
    expect(stalled.findings.join(' ')).toContain('SELF_RENEWAL_STALLED');
  });

  it('performs mocked GCP Public Cloud LB auto-renewal and rotates serialNumberHex', async () => {
    const uiEntity: Entity = {
      apiVersion: 'backstage.io/v1alpha1',
      kind: 'Component',
      metadata: {
        name: 'aegis-ui',
        annotations: {
          'resiliency.idp/ssl-provider': 'gcp-cloud-lb',
          'resiliency.idp/ssl-renewal-mode': 'workflow-auto-renew',
          'resiliency.idp/gcp-project': 'aegis-prod-cloud',
          'resiliency.idp/gcp-target-https-proxy': 'aegis-ui-https-proxy',
          'resiliency.idp/endpoints.stg.web':
            'https://stg-web.ui.aegis.cloud.goog/healthz',
          'resiliency.idp/endpoints.stg.cdn':
            'https://stg-cdn.ui.aegis.cloud.goog/healthz',
          'resiliency.idp/endpoints.prod':
            'https://prod.ui.aegis.cloud.goog/healthz',
        },
      },
    };

    const initialRollup = await scanEntityEndpoints(uiEntity);
    expect(initialRollup).not.toBeNull();
    expect(initialRollup!.totalEndpoints).toBe(3);
    expect(initialRollup!.environmentCounts.stg).toBe(2);

    const oldProdSerial = initialRollup!.endpoints.find(
      e => e.environment === 'prod',
    )!.certificate.serialNumberHex;

    const renewal = await triggerMockGcpAutoRenewal({
      entityRef: 'component:default/aegis-ui',
      environment: 'prod',
      keyAlgorithm: 'ECDSA-P256',
      validityDays: 90,
    });

    expect(renewal.status).toBe('RENEWED');
    expect(renewal.renewedCount).toBe(1);
    expect(renewal.renewals[0].previousSerial).toBe(oldProdSerial);
    expect(renewal.renewals[0].newSerial).not.toBe(oldProdSerial);
    expect(
      renewal.renewals[0].endpoint.certificate.rotatedFromSerial,
    ).toBe(oldProdSerial);
    expect(renewal.renewals[0].endpoint.certificate.historyCount).toBe(2);
    expect(renewal.targetEndpointUrls).toEqual([
      'https://prod.ui.aegis.cloud.goog/healthz',
    ]);
    expect(renewal.verifiedDomains).toEqual(['prod.ui.aegis.cloud.goog']);
    expect(renewal.renewals[0].domain).toBe('prod.ui.aegis.cloud.goog');
    expect(renewal.perEnvDiffMarkdown).toContain('--- Current');
    expect(renewal.perEnvDiffMarkdown).toContain('+++ Proposed');
  });

  it('generates per-environment certificate diff, manages Quality Gate approval, and filters target endpoints', async () => {
    const uiEntity: Entity = {
      apiVersion: 'backstage.io/v1alpha1',
      kind: 'Component',
      metadata: {
        name: 'aegis-ui',
        annotations: {
          'resiliency.idp/ssl-provider': 'gcp-cloud-lb',
          'resiliency.idp/ssl-renewal-mode': 'workflow-auto-renew',
          'resiliency.idp/gcp-project': 'aegis-prod-cloud',
          'resiliency.idp/gcp-target-https-proxy': 'aegis-ui-https-proxy',
          'resiliency.idp/endpoints.stg.web':
            'https://stg-web.ui.aegis.cloud.goog/healthz',
          'resiliency.idp/endpoints.stg.cdn':
            'https://stg-cdn.ui.aegis.cloud.goog/healthz',
          'resiliency.idp/endpoints.prod':
            'https://prod.ui.aegis.cloud.goog/healthz',
        },
      },
    };

    await scanEntityEndpoints(uiEntity);

    const diffPlan = await previewMockGcpAutoRenewalDiff({
      entityRef: 'component:default/aegis-ui',
      environment: 'all',
      targetEndpointsFilter: [
        'https://stg-web.ui.aegis.cloud.goog/healthz',
        'https://prod.ui.aegis.cloud.goog/healthz',
      ],
      keyAlgorithm: 'ECDSA-P256',
      validityDays: 90,
    });

    expect(diffPlan.proposedChanges).toHaveLength(2);
    expect(diffPlan.targetEndpointUrls).toEqual([
      'https://stg-web.ui.aegis.cloud.goog/healthz',
      'https://prod.ui.aegis.cloud.goog/healthz',
    ]);
    expect(diffPlan.targetDomains).toEqual([
      'stg-web.ui.aegis.cloud.goog',
      'prod.ui.aegis.cloud.goog',
    ]);
    expect(diffPlan.diffMarkdownByEnv).toContain('Environment: `STG`');
    expect(diffPlan.diffMarkdownByEnv).toContain('Environment: `PROD`');

    const gate = createQualityGateApprovalRequest(diffPlan);
    expect(gate.status).toBe('PENDING_APPROVAL');
    expect(
      getQualityGateStatus({ entityRef: 'component:default/aegis-ui' })?.gateId,
    ).toBe(gate.gateId);

    const decided = decideQualityGateApproval({
      entityRef: 'component:default/aegis-ui',
      decision: 'APPROVED',
      decidedBy: 'user:default/platform-sre',
      comments: 'Diff reviewed across stg and prod',
    });
    expect(decided?.status).toBe('APPROVED');
    expect(decided?.decidedBy).toBe('user:default/platform-sre');
  });

  it('extracts host:port from endpoint URLs and clears Quality Gate stores on reset', () => {
    expect(
      extractHostPortFromUrl('https://stg-east.hello.internal:8443/healthz'),
    ).toBe('stg-east.hello.internal:8443');
    expect(
      extractHostPortFromUrl('https://prod.ui.aegis.cloud.goog/healthz'),
    ).toBe('prod.ui.aegis.cloud.goog:8443');

    const gate = createQualityGateApprovalRequest({
      entityRef: 'component:default/aegis-ui',
      environment: 'prod',
      proposedChanges: [],
      targetEndpointUrls: [],
      targetDomains: [],
      diffMarkdownByEnv: '',
    } as any);
    expect(gate.status).toBe('PENDING_APPROVAL');

    clearSslTrackerStoreForTests();
    expect(
      getQualityGateStatus({ entityRef: 'component:default/aegis-ui' }),
    ).toBeNull();
  });

  it('tracks certificate rotation lineage via getEndpointCertificateHistory and falls back dynamically when template filter URLs belong to another entity', async () => {
    const uiEntity: Entity = {
      apiVersion: 'backstage.io/v1alpha1',
      kind: 'Component',
      metadata: {
        name: 'aegis-ui',
        annotations: {
          'resiliency.idp/ssl-provider': 'gcp-cloud-lb',
          'resiliency.idp/ssl-renewal-mode': 'workflow-auto-renew',
          'resiliency.idp/gcp-project': 'aegis-prod-cloud',
          'resiliency.idp/gcp-target-https-proxy': 'aegis-ui-https-proxy',
          'resiliency.idp/endpoints.prod':
            'https://prod.ui.aegis.cloud.goog/healthz',
        },
      },
    };

    await scanEntityEndpoints(uiEntity);

    const renewal = await triggerMockGcpAutoRenewal({
      entityRef: 'component:default/aegis-ui',
      environment: 'prod',
      targetEndpointsFilter: ['https://unrelated.other.service/healthz'],
    });
    expect(renewal.renewedCount).toBe(1);

    const history = getEndpointCertificateHistory({
      entityRef: 'component:default/aegis-ui',
      environment: 'prod',
    });
    expect(history).toHaveLength(1);
    expect(history[0].certificates).toHaveLength(2);
    expect(history[0].certificates[0].isActive).toBe(true);
    expect(history[0].certificates[1].isActive).toBe(false);
  });

  it('remediates simulated weak crypto (SHA-1 / RSA-1024) on private-cloud-lb endpoints and persists across rescans', async () => {
    const backendEntity: Entity = {
      apiVersion: 'backstage.io/v1alpha1',
      kind: 'Component',
      metadata: {
        name: 'aegis-backend',
        annotations: {
          'resiliency.idp/ssl-provider': 'private-cloud-lb',
          'resiliency.idp/endpoints.stress-test.legacy-audit':
            'https://stress-legacy.backend.internal:8443/items',
          'resiliency.idp/ssl-simulate-weak-crypto.stress-test.legacy-audit':
            'true',
        },
      },
    };

    const initial = await scanEntityEndpoints(backendEntity);
    expect(initial!.overallStatus).toBe('NON_COMPLIANT');
    expect(initial!.endpoints[0].certificate.complianceStatus).toBe(
      'NON_COMPLIANT',
    );

    const rem = await remediatePrivateCloudEndpointCrypto({
      entityRef: 'component:default/aegis-backend',
      environment: 'stress-test',
      endpointKey: 'legacy-audit',
    });
    expect(rem.renewedCount).toBe(1);
    expect(rem.renewals[0].endpoint.certificate.complianceStatus).toBe(
      'COMPLIANT',
    );

    const rescanned = await scanEntityEndpoints(backendEntity, {
      forceRescan: true,
    });
    expect(rescanned!.overallStatus).toBe('COMPLIANT');
  });

  it('persists and reloads SSL tracker inventory, history, and quality gates from disk', async () => {
    const uiEntity: Entity = {
      apiVersion: 'backstage.io/v1alpha1',
      kind: 'Component',
      metadata: {
        name: 'aegis-ui',
        annotations: {
          'resiliency.idp/ssl-provider': 'gcp-cloud-lb',
          'resiliency.idp/ssl-renewal-mode': 'workflow-auto-renew',
          'resiliency.idp/gcp-project': 'aegis-prod-cloud',
          'resiliency.idp/gcp-target-https-proxy': 'aegis-ui-https-proxy',
          'resiliency.idp/endpoints.prod':
            'https://prod.ui.aegis.cloud.goog/healthz',
        },
      },
    };

    await scanEntityEndpoints(uiEntity);

    const diffPlan = await previewMockGcpAutoRenewalDiff({
      entityRef: 'component:default/aegis-ui',
      environment: 'prod',
      keyAlgorithm: 'ECDSA-P256',
      validityDays: 90,
    });
    createQualityGateApprovalRequest(diffPlan);

    const tmpFile = path.join(
      os.tmpdir(),
      `ssl-tracker-test-${Date.now()}.json`,
    );

    try {
      saveSslTrackerStateToDisk(tmpFile);

      clearSslTrackerStoreForTests();
      expect(
        getEntitySslRollupFromStore('component:default/aegis-ui'),
      ).toBeNull();

      expect(loadSslTrackerStateFromDisk(tmpFile)).toBe(true);

      expect(
        getEntitySslRollupFromStore('component:default/aegis-ui'),
      ).not.toBeNull();
      expect(
        getQualityGateStatus({ entityRef: 'component:default/aegis-ui' }),
      ).not.toBeNull();
    } finally {
      fs.unlinkSync(tmpFile);
    }
  });

  it('synthesizes default multi-tier endpoints for catalogue elements without explicit endpoints.* annotations', () => {
    const haproxyEntity = {
      apiVersion: 'backstage.io/v1alpha1',
      kind: 'Component',
      metadata: {
        name: 'edge-svc',
        annotations: {
          'resiliency.idp/haproxy-host': '127.0.0.1:8443',
        },
      },
    };

    const haproxyParsed = parseEntityEnvironmentEndpoints(haproxyEntity as any);
    expect(haproxyParsed).toHaveLength(5);
    for (const e of haproxyParsed) {
      expect(e.endpointUrl).toBe('https://hello.internal:8443/healthz');
    }

    const k8sEntity = {
      apiVersion: 'backstage.io/v1alpha1',
      kind: 'Component',
      metadata: {
        name: 'backend-svc',
        annotations: {
          'resiliency.idp/k8s-health-url': 'http://127.0.0.1:30002/items',
        },
      },
    };

    const k8sParsed = parseEntityEnvironmentEndpoints(k8sEntity as any);
    expect(k8sParsed).toHaveLength(5);
    for (const e of k8sParsed) {
      expect(e.endpointUrl).toContain('https://');
    }

    const certEntity = {
      apiVersion: 'backstage.io/v1alpha1',
      kind: 'Component',
      metadata: {
        name: 'cert-svc',
        annotations: {
          'resiliency.idp/cert-expiry': '2027-01-01T00:00:00Z',
        },
      },
    };

    const certParsed = parseEntityEnvironmentEndpoints(certEntity as any);
    expect(certParsed).toHaveLength(5);
    for (const e of certParsed) {
      expect(e.providerType).toBe('haproxy-edge');
      expect(e.renewalMode).toBe('manual-or-template');
      expect(e.endpointUrl).toBe('https://localhost:8443/healthz');
    }
  });

  it('classifies domain ingress exposure scope and parses application software stack (SBOM)', async () => {
    const publicEntity = {
      apiVersion: 'backstage.io/v1alpha1',
      kind: 'Component',
      metadata: {
        name: 'aegis-ui',
        annotations: {
          'resiliency.idp/ssl-provider': 'gcp-cloud-lb',
          'resiliency.idp/exposure-scope': 'internet-facing',
          'resiliency.idp/endpoints.prod':
            'https://prod.ui.aegis.cloud.goog/healthz',
        },
      },
    };

    const publicParsed = parseEntityEnvironmentEndpoints(publicEntity as any);
    expect(publicParsed[0].exposureScope).toBe('internet-facing');
    expect(publicParsed[0].dnsScope).toBe('public-authoritative');

    const rollup = await scanEntityEndpoints(publicEntity as any);
    expect(rollup?.exposureCounts?.internetFacing).toBe(1);
    expect(Array.isArray(rollup?.softwareStack)).toBe(true);
    expect(rollup!.softwareStack!.length).toBeGreaterThanOrEqual(1);
    const sbomItem = rollup!.softwareStack![0];
    expect(sbomItem.name).toBeDefined();
    expect(sbomItem.version).toBeDefined();
    expect(sbomItem.category).toBeDefined();

    const privateEntity = {
      apiVersion: 'backstage.io/v1alpha1',
      kind: 'Component',
      metadata: {
        name: 'aegis-backend',
        annotations: {
          'resiliency.idp/exposure-scope': 'internal-only',
          'resiliency.idp/endpoints.dev':
            'https://dev.backend.internal:8443/items',
        },
      },
    };

    const privateParsed = parseEntityEnvironmentEndpoints(privateEntity as any);
    expect(privateParsed[0].exposureScope).toBe('internal-only');
    expect(privateParsed[0].dnsScope).toBe('private-split-horizon');

    const softwareStack = parseEntitySoftwareStack(privateEntity as any);
    expect(Array.isArray(softwareStack)).toBe(true);

    const uiRollup = await scanEntityEndpoints(publicEntity as any);
    expect(uiRollup?.softwareStack?.length).toBeGreaterThan(0);

    const fromStore = getEntitySslRollupFromStore('component:default/aegis-ui');
    expect(fromStore?.softwareStack).toBeDefined();
    expect(fromStore?.softwareStack?.length).toBeGreaterThan(0);
  });
});

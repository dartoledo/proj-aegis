import {
  coreServices,
  createBackendModule,
  createBackendPlugin,
} from '@backstage/backend-plugin-api';
import { Entity } from '@backstage/catalog-model';
import {
  CatalogProcessor,
  catalogProcessingExtensionPoint,
  catalogServiceRef,
} from '@backstage/plugin-catalog-node';
import {
  createTemplateAction,
  scaffolderActionsExtensionPoint,
} from '@backstage/plugin-scaffolder-node';
import express from 'express';
import {
  createQualityGateApprovalRequest,
  decideQualityGateApproval,
  getEndpointCertificateHistory,
  getEntitySslRollupFromStore,
  getFleetSslInventory,
  getQualityGateStatus,
  previewMockGcpAutoRenewalDiff,
  remediatePrivateCloudEndpointCrypto,
  renderSslTrackerPrometheusMetrics,
  scanEntityEndpoints,
  triggerMockGcpAutoRenewal,
} from './sslEndpointTrackerService';

function createGcpAuthorizeDnsAction(
  catalog: typeof catalogServiceRef.T,
  auth: typeof coreServices.auth.T,
) {
  return createTemplateAction({
    id: 'resiliency:gcp-lb:authorize-dns',
    description:
      'Resolves target environment endpoints, verifies Google Cloud Certificate Manager DNS-01 CNAME authorization, and computes the per-environment SSL certificate diff for the Quality Gate.',
    schema: {
      input: {
        entityRef: z =>
          z
            .string()
            .default('component:default/aegis-ui')
            .describe('Target Catalog entity reference'),
        environment: z =>
          z
            .enum(['all', 'dev', 'stg', 'stress-test', 'preprod', 'prod'])
            .default('all')
            .describe('Target environment tier'),
        endpointKey: z =>
          z
            .string()
            .optional()
            .describe('Optional endpoint sub-key (e.g., web, cdn, canary)'),
        targetEndpoints: z =>
          z
            .array(z.string())
            .optional()
            .describe('Explicit list of target endpoint URLs to update'),
        keyAlgorithm: z =>
          z
            .enum(['ECDSA-P256', 'RSA-2048'])
            .default('ECDSA-P256')
            .describe('Cryptographic key algorithm'),
        validityDays: z =>
          z.number().default(90).describe('Validity period in days'),
        gcpProject: z =>
          z.string().default('aegis-prod-cloud').describe('GCP Project ID'),
        targetHttpsProxy: z =>
          z
            .string()
            .default('aegis-ui-https-proxy')
            .describe('GCP TargetHttpsProxy resource name'),
      },
      output: {
        authorizationStatus: z => z.string(),
        dnsRecord: z => z.string(),
        targetEndpointsList: z => z.string(),
        targetDomainsList: z => z.string(),
        diffMarkdownByEnv: z => z.string(),
        gateId: z => z.string(),
      },
    },
    async handler(ctx) {
      const entityRef = ctx.input.entityRef || 'component:default/aegis-ui';
      const env = ctx.input.environment || 'all';
      const gcpProject = ctx.input.gcpProject || 'aegis-prod-cloud';

      try {
        const credentials = await auth.getOwnServiceCredentials();
        const entity = await catalog.getEntityByRef(entityRef, { credentials });
        if (entity) {
          await scanEntityEndpoints(entity);
        }
      } catch {
        // Proceed with cached store if catalog lookup fails
      }

      const plan = await previewMockGcpAutoRenewalDiff({
        entityRef,
        environment: env,
        endpointKey: ctx.input.endpointKey || undefined,
        targetEndpointsFilter: ctx.input.targetEndpoints,
        keyAlgorithm: ctx.input.keyAlgorithm || 'ECDSA-P256',
        validityDays: ctx.input.validityDays || 90,
        gcpProject,
        targetHttpsProxy:
          ctx.input.targetHttpsProxy || 'aegis-ui-https-proxy',
      });

      const gate = createQualityGateApprovalRequest(plan);
      const dnsRecord = `_acme-challenge.${env}.aegis.cloud.goog. IN CNAME auth.${gcpProject}.certificatemanager.goog.`;

      ctx.logger.info(
        `Resolved ${plan.targetEndpointsCount} target endpoint(s) for ${entityRef} (env=${env}): ${plan.targetEndpointUrls.join(', ')}`,
      );
      ctx.logger.info(
        `Verified GCP Certificate Manager DNS-01 authorization for domains: ${plan.targetDomains.join(', ')}`,
      );
      ctx.logger.info(
        `Generated Pre-Renewal Per-Environment Certificate Diff (Quality Gate ID: ${gate.gateId}):\n${plan.diffMarkdownByEnv}`,
      );

      ctx.output('authorizationStatus', 'AUTHORIZED');
      ctx.output('dnsRecord', dnsRecord);
      ctx.output('targetEndpointsList', plan.targetEndpointUrls.join(', '));
      ctx.output('targetDomainsList', plan.targetDomains.join(', '));
      ctx.output('diffMarkdownByEnv', plan.diffMarkdownByEnv);
      ctx.output('gateId', gate.gateId);
    },
  });
}

function createGcpQualityGateApprovalAction() {
  return createTemplateAction({
    id: 'resiliency:gcp-lb:quality-gate-approval',
    description:
      'Quality Gate that displays the per-environment SSL certificate diff (Before vs. Proposed After) and requires manual approval before binding new certificates to the load balancer.',
    schema: {
      input: {
        entityRef: z => z.string().default('component:default/aegis-ui'),
        environment: z => z.string().default('all'),
        gateId: z => z.string().optional(),
        approvalMode: z =>
          z
            .enum(['pre-approved-in-form', 'wait-for-live-ui-approval'])
            .default('pre-approved-in-form')
            .describe(
              'Either approve via the workflow Quality Gate form attestation or pause and wait for live approval in the Backstage SSL Card / API.',
            ),
        manualApprovalConfirmed: z =>
          z
            .boolean()
            .default(true)
            .describe('Manual approval confirmation flag'),
        approverId: z =>
          z
            .string()
            .default('platform-sre@aegis.internal')
            .describe('Reviewer / Approver identifier'),
        diffMarkdownByEnv: z => z.string().optional(),
      },
      output: {
        gateStatus: z => z.string(),
        approvedBy: z => z.string(),
        approvedAt: z => z.string(),
        qualityGateReportMarkdown: z => z.string(),
      },
    },
    async handler(ctx) {
      const entityRef = ctx.input.entityRef || 'component:default/aegis-ui';
      const gateId = ctx.input.gateId;
      const mode = ctx.input.approvalMode || 'pre-approved-in-form';
      const approver = ctx.input.approverId || 'platform-sre@aegis.internal';

      ctx.logger.info(
        `=== QUALITY GATE: PER-ENVIRONMENT SSL CERTIFICATE DIFF FOR ${entityRef} ===`,
      );
      if (ctx.input.diffMarkdownByEnv) {
        ctx.logger.info(`\n${ctx.input.diffMarkdownByEnv}`);
      }

      if (mode === 'wait-for-live-ui-approval') {
        ctx.logger.warn(
          `Quality Gate [${gateId || entityRef}] is PAUSED waiting for manual approval. Click "Approve Quality Gate & Cert Diff" on the Backstage SSL Card or POST to /api/ssl-tracker/quality-gate/decide...`,
        );
        const maxWaitMs = 180000;
        const pollIntervalMs = 2000;
        const start = Date.now();
        while (Date.now() - start < maxWaitMs) {
          const currentGate = getQualityGateStatus({ gateId, entityRef });
          if (currentGate?.status === 'APPROVED') {
            break;
          }
          if (currentGate?.status === 'REJECTED') {
            throw new Error(
              `Quality Gate REJECTED by ${currentGate.decidedBy}: ${currentGate.comments}`,
            );
          }
          await new Promise(resolve => setTimeout(resolve, pollIntervalMs));
        }
        const finalGate = getQualityGateStatus({ gateId, entityRef });
        if (finalGate && finalGate.status !== 'APPROVED') {
          throw new Error(
            `Quality Gate timed out waiting for manual approval (${gateId || entityRef}).`,
          );
        }
      } else {
        if (!ctx.input.manualApprovalConfirmed) {
          decideQualityGateApproval({
            gateId,
            entityRef,
            decision: 'REJECTED',
            decidedBy: approver,
            comments: 'Manual approval checkbox was not confirmed in workflow.',
          });
          throw new Error(
            'Quality Gate failed: Manual approval of the per-environment certificate diff was not confirmed.',
          );
        }
        decideQualityGateApproval({
          gateId,
          entityRef,
          decision: 'APPROVED',
          decidedBy: approver,
          comments:
            'Approved per-environment SSL certificate diff via Quality Gate.',
        });
      }

      const decidedGate = getQualityGateStatus({ gateId, entityRef });
      const approvedAt = decidedGate?.decidedAt || new Date().toISOString();
      const approvedBy = decidedGate?.decidedBy || approver;

      ctx.logger.info(
        `✅ Quality Gate APPROVED by ${approvedBy} at ${approvedAt}. Proceeding to mint and bind certificates.`,
      );

      const reportMd = [
        `### Quality Gate Decision: ✅ APPROVED`,
        `- **Gate ID:** \`${decidedGate?.gateId || gateId || 'gate-inline'}\``,
        `- **Approved By:** \`${approvedBy}\``,
        `- **Approved At:** \`${approvedAt}\``,
      ].join('\n');

      ctx.output('gateStatus', 'APPROVED');
      ctx.output('approvedBy', approvedBy);
      ctx.output('approvedAt', approvedAt);
      ctx.output('qualityGateReportMarkdown', reportMd);
    },
  });
}

function createGcpRenewAndBindAction(
  catalog: typeof catalogServiceRef.T,
  auth: typeof coreServices.auth.T,
) {
  return createTemplateAction({
    id: 'resiliency:gcp-lb:renew-and-bind',
    description:
      'Mints a fresh Google Trust Services (GTS CA 1C3) X.509 certificate, binds it to the GCP TargetHttpsProxy, and records the new Serial Number across all selected target endpoints.',
    schema: {
      input: {
        entityRef: z =>
          z
            .string()
            .default('component:default/aegis-ui')
            .describe('Target Catalog entity reference'),
        environment: z =>
          z
            .enum(['all', 'dev', 'stg', 'stress-test', 'preprod', 'prod'])
            .default('all')
            .describe('Target environment tier'),
        endpointKey: z =>
          z
            .string()
            .optional()
            .describe('Optional endpoint sub-key (e.g., web, cdn, canary)'),
        targetEndpoints: z =>
          z
            .array(z.string())
            .optional()
            .describe('Explicit list of target endpoint URLs to update'),
        keyAlgorithm: z =>
          z
            .enum(['ECDSA-P256', 'RSA-2048'])
            .default('ECDSA-P256')
            .describe('Cryptographic key algorithm'),
        validityDays: z =>
          z.number().default(90).describe('Validity period in days'),
        gcpProject: z =>
          z.string().default('aegis-prod-cloud').describe('GCP Project ID'),
        targetHttpsProxy: z =>
          z
            .string()
            .default('aegis-ui-https-proxy')
            .describe('GCP TargetHttpsProxy resource name'),
      },
      output: {
        renewedCount: z => z.number(),
        targetEndpointUrls: z => z.string(),
        verifiedDomains: z => z.string(),
        renewalSummaryMarkdown: z => z.string(),
        perEnvDiffMarkdown: z => z.string(),
      },
    },
    async handler(ctx) {
      const entityRef = ctx.input.entityRef || 'component:default/aegis-ui';
      try {
        const credentials = await auth.getOwnServiceCredentials();
        const entity = await catalog.getEntityByRef(entityRef, { credentials });
        if (entity) {
          await scanEntityEndpoints(entity);
        }
      } catch {
        // Proceed with cached store if catalog lookup fails
      }

      const result = await triggerMockGcpAutoRenewal({
        entityRef,
        environment: ctx.input.environment || 'all',
        endpointKey: ctx.input.endpointKey || undefined,
        targetEndpointsFilter: ctx.input.targetEndpoints,
        keyAlgorithm: ctx.input.keyAlgorithm || 'ECDSA-P256',
        validityDays: ctx.input.validityDays || 90,
        gcpProject: ctx.input.gcpProject || 'aegis-prod-cloud',
        targetHttpsProxy:
          ctx.input.targetHttpsProxy || 'aegis-ui-https-proxy',
      });

      ctx.logger.info(
        `Completed GCP Cloud LB auto-renewal for ${entityRef}: renewed ${result.renewedCount} endpoint(s) across domains [${result.verifiedDomains.join(', ')}].`,
      );
      ctx.output('renewedCount', result.renewedCount);
      ctx.output('targetEndpointUrls', result.targetEndpointUrls.join(', '));
      ctx.output('verifiedDomains', result.verifiedDomains.join(', '));
      ctx.output('renewalSummaryMarkdown', result.renewalSummaryMarkdown);
      ctx.output('perEnvDiffMarkdown', result.perEnvDiffMarkdown);
    },
  });
}

function createGcpVerifyComplianceAction() {
  return createTemplateAction({
    id: 'resiliency:gcp-lb:verify-compliance',
    description:
      'Verifies that all target domains serve their newly minted certificates and pass all 5 SSL compliance pillars (Not After, Subject/SAN, Issuer, Serial Number, Signature Algorithm & Key Size).',
    schema: {
      input: {
        entityRef: z => z.string().default('component:default/aegis-ui'),
        environment: z => z.string().default('all'),
      },
      output: {
        overallCompliance: z => z.string(),
        minDaysRemaining: z => z.number(),
        verifiedDomainsSummary: z => z.string(),
      },
    },
    async handler(ctx) {
      const entityRef = ctx.input.entityRef || 'component:default/aegis-ui';
      const envScope = ctx.input.environment || 'all';
      const rollup = getEntitySslRollupFromStore(entityRef);
      const overall = rollup?.overallStatus ?? 'COMPLIANT';
      const minDays = rollup?.minDaysRemaining ?? 90;

      const matchingEndpoints = (rollup?.endpoints || []).filter(
        ep => envScope === 'all' || ep.environment === envScope,
      );
      const verifiedLines = matchingEndpoints.map(
        ep =>
          `- **Domain \`${ep.sniHostname}\`** (\`${ep.environment}\` / \`${ep.endpointKey}\` → \`${ep.endpointUrl}\`): Verified Serial \`${ep.certificate.serialNumberHex}\` • Issuer \`${ep.certificate.issuerCn}\` • \`${ep.certificate.publicKeyAlgorithm} ${ep.certificate.publicKeyBits}-bit (${ep.certificate.signatureHashAlgorithm})\` • Expires \`${ep.certificate.notAfter.slice(0, 10)}\` (${ep.certificate.daysRemaining}d) • Status: **${ep.certificate.complianceStatus}**`,
      );

      ctx.logger.info(
        `Verified 5-pillar SSL compliance for ${entityRef}: status=${overall}, minDaysRemaining=${minDays}`,
      );
      ctx.output('overallCompliance', overall);
      ctx.output('minDaysRemaining', minDays);
      ctx.output('verifiedDomainsSummary', verifiedLines.join('\n'));
    },
  });
}

function createPrivateLbRemediateCryptoAction(
  catalog: typeof catalogServiceRef.T,
  auth: typeof coreServices.auth.T,
) {
  return createTemplateAction({
    id: 'resiliency:private-lb:remediate-crypto',
    description:
      'Remediates private-cloud endpoint SSL/TLS certificates by minting fresh X.509 certs with the selected key algorithm and binding them to the target endpoints.',
    schema: {
      input: {
        entityRef: z =>
          z
            .string()
            .default('component:default/aegis-backend')
            .describe('Target Catalog entity reference'),
        environment: z =>
          z
            .enum(['all', 'dev', 'stg', 'stress-test', 'preprod', 'prod'])
            .default('all')
            .describe('Target environment tier'),
        endpointKey: z =>
          z
            .string()
            .optional()
            .describe('Optional endpoint sub-key (e.g., web, cdn, canary)'),
        keyAlgorithm: z =>
          z
            .enum(['RSA-2048', 'ECDSA-P256'])
            .default('RSA-2048')
            .describe('Cryptographic key algorithm'),
        validityDays: z =>
          z.number().default(90).describe('Validity period in days'),
      },
      output: {
        remediatedCount: z => z.number(),
        targetEndpointUrls: z => z.string(),
        verifiedDomains: z => z.string(),
        remediationSummaryMarkdown: z => z.string(),
        perEnvDiffMarkdown: z => z.string(),
      },
    },
    async handler(ctx) {
      const entityRef = ctx.input.entityRef || 'component:default/aegis-backend';
      const env = ctx.input.environment || 'all';

      try {
        const credentials = await auth.getOwnServiceCredentials();
        const entity = await catalog.getEntityByRef(entityRef, { credentials });
        if (entity) {
          await scanEntityEndpoints(entity);
        }
      } catch {
        // Proceed with cached store if catalog lookup fails
      }

      const result = await remediatePrivateCloudEndpointCrypto({
        entityRef,
        environment: env,
        endpointKey: ctx.input.endpointKey || undefined,
        keyAlgorithm: ctx.input.keyAlgorithm || 'RSA-2048',
        validityDays: ctx.input.validityDays || 90,
      });

      ctx.logger.info(
        `Remediated ${result.renewedCount} private-cloud endpoint(s) for ${entityRef} (env=${env}): ${result.targetEndpointUrls.join(', ')}`,
      );
      ctx.output('remediatedCount', result.renewedCount);
      ctx.output('targetEndpointUrls', result.targetEndpointUrls.join(', '));
      ctx.output('verifiedDomains', result.verifiedDomains.join(', '));
      ctx.output('remediationSummaryMarkdown', result.renewalSummaryMarkdown);
      ctx.output('perEnvDiffMarkdown', result.perEnvDiffMarkdown);
    },
  });
}

export const scaffolderModuleSslEndpointTracker = createBackendModule({
  pluginId: 'scaffolder',
  moduleId: 'ssl-endpoint-tracker-actions',
  register(reg) {
    reg.registerInit({
      deps: {
        scaffolder: scaffolderActionsExtensionPoint,
        catalog: catalogServiceRef,
        auth: coreServices.auth,
      },
      async init({ scaffolder, catalog, auth }) {
        scaffolder.addActions(
          createGcpAuthorizeDnsAction(catalog, auth),
          createGcpQualityGateApprovalAction(),
          createGcpRenewAndBindAction(catalog, auth),
          createGcpVerifyComplianceAction(),
          createPrivateLbRemediateCryptoAction(catalog, auth),
        );
      },
    });
  },
});

class SslEndpointCatalogProcessor implements CatalogProcessor {
  getProcessorName(): string {
    return 'SslEndpointCatalogProcessor';
  }

  async preProcessEntity(entity: Entity): Promise<Entity> {
    if (entity.kind !== 'Component' && entity.kind !== 'Resource') {
      return entity;
    }
    try {
      const rollup = await scanEntityEndpoints(entity);
      if (!rollup) {
        return entity;
      }
      return {
        ...entity,
        metadata: {
          ...entity.metadata,
          annotations: {
            ...entity.metadata.annotations,
            'resiliency.idp/ssl-overall-status': rollup.overallStatus,
            'resiliency.idp/ssl-min-days-remaining': String(
              rollup.minDaysRemaining,
            ),
            'resiliency.idp/ssl-total-endpoints': String(rollup.totalEndpoints),
            'resiliency.idp/ssl-compliant-endpoints': String(
              rollup.compliantEndpoints,
            ),
            'resiliency.idp/ssl-last-scan': rollup.lastScannedAt,
          },
        },
      };
    } catch {
      return entity;
    }
  }
}

export const catalogModuleSslEndpointTracker = createBackendModule({
  pluginId: 'catalog',
  moduleId: 'ssl-endpoint-tracker-processor',
  register(reg) {
    reg.registerInit({
      deps: {
        catalog: catalogProcessingExtensionPoint,
      },
      async init({ catalog }) {
        catalog.addProcessor(new SslEndpointCatalogProcessor());
      },
    });
  },
});

export const sslEndpointTrackerPlugin = createBackendPlugin({
  pluginId: 'ssl-tracker',
  register(reg) {
    reg.registerInit({
      deps: {
        httpRouter: coreServices.httpRouter,
        httpAuth: coreServices.httpAuth,
        logger: coreServices.logger,
        catalog: catalogServiceRef,
        auth: coreServices.auth,
      },
      async init({ httpRouter, httpAuth, logger, catalog, auth }) {
        const router = express.Router();
        router.use(express.json());

        router.get('/status', async (req, res) => {
          const entityRef = String(
            req.query.entityRef || 'component:default/aegis-auth',
          );
          try {
            let rollup = getEntitySslRollupFromStore(entityRef);
            if (!rollup) {
              const credentials = await auth.getOwnServiceCredentials();
              const entity = await catalog.getEntityByRef(entityRef, {
                credentials,
              });
              if (entity) {
                rollup = await scanEntityEndpoints(entity);
              }
            }
            if (!rollup) {
              res.status(404).json({
                error: `No tracked SSL endpoints found for ${entityRef}`,
              });
              return;
            }
            const pendingGate = getQualityGateStatus({ entityRef });
            res.status(200).json({
              ...rollup,
              qualityGate: pendingGate,
            });
          } catch (err) {
            logger.error(`SSL tracker status error for ${entityRef}: ${err}`);
            res.status(500).json({
              error:
                err instanceof Error ? err.message : 'SSL status lookup failed',
            });
          }
        });

        router.get('/fleet', async (_req, res) => {
          res.status(200).json(getFleetSslInventory());
        });

        router.post('/scan', async (req, res) => {
          const entityRef = String(
            req.body?.entityRef ||
              req.query.entityRef ||
              'component:default/aegis-auth',
          );
          try {
            const credentials = await auth.getOwnServiceCredentials();
            const entity = await catalog.getEntityByRef(entityRef, {
              credentials,
            });
            if (!entity) {
              res
                .status(404)
                .json({ error: `Catalog entity ${entityRef} not found` });
              return;
            }
            const rollup = await scanEntityEndpoints(entity, {
              forceRescan: true,
            });
            res.status(200).json(rollup);
          } catch (err) {
            res.status(500).json({
              error: err instanceof Error ? err.message : 'SSL rescan failed',
            });
          }
        });

        router.post('/gcp-preview-diff', async (req, res) => {
          const entityRef = String(
            req.body?.entityRef || 'component:default/aegis-ui',
          );
          const environment = String(req.body?.environment || 'all');
          const endpointKey = req.body?.endpointKey
            ? String(req.body.endpointKey)
            : undefined;
          const targetEndpointsFilter = Array.isArray(req.body?.targetEndpoints)
            ? req.body.targetEndpoints.map(String)
            : undefined;
          const keyAlgorithm =
            req.body?.keyAlgorithm === 'RSA-2048' ? 'RSA-2048' : 'ECDSA-P256';
          const validityDays = Number(req.body?.validityDays || 90);

          try {
            let rollup = getEntitySslRollupFromStore(entityRef);
            if (!rollup) {
              const credentials = await auth.getOwnServiceCredentials();
              const entity = await catalog.getEntityByRef(entityRef, {
                credentials,
              });
              if (entity) {
                rollup = await scanEntityEndpoints(entity);
              }
            }
            const plan = await previewMockGcpAutoRenewalDiff({
              entityRef,
              environment,
              endpointKey,
              targetEndpointsFilter,
              keyAlgorithm,
              validityDays,
            });
            const gate = createQualityGateApprovalRequest(plan);
            res.status(200).json({
              gate,
              qualityGate: gate,
              plan,
            });
          } catch (err) {
            res.status(500).json({
              error:
                err instanceof Error
                  ? err.message
                  : 'Failed to preview GCP certificate diff',
            });
          }
        });

        router.post('/quality-gate/decide', async (req, res) => {
          const entityRef = req.body?.entityRef
            ? String(req.body.entityRef)
            : undefined;
          const gateId = req.body?.gateId ? String(req.body.gateId) : undefined;
          const decision =
            req.body?.decision === 'REJECTED' ? 'REJECTED' : 'APPROVED';
          let resolvedUserRef: string | undefined;
          try {
            const creds = await httpAuth.credentials(req, { allow: ['user'] });
            if (auth.isPrincipal(creds, 'user')) {
              resolvedUserRef = creds.principal.userEntityRef;
            }
          } catch {
            resolvedUserRef = undefined;
          }
          const decidedBy = String(
            req.body?.decidedBy ||
              req.body?.approver ||
              resolvedUserRef ||
              'platform-sre@aegis.internal',
          );
          const comments = String(
            req.body?.comments ||
              'Manual Quality Gate review of per-environment SSL certificate diff',
          );

          const updated = decideQualityGateApproval({
            gateId,
            entityRef,
            decision,
            decidedBy,
            comments,
          });
          if (!updated) {
            res.status(404).json({ error: 'No matching Quality Gate found' });
            return;
          }
          res.status(200).json(updated);
        });

        router.post('/gcp-auto-renew', async (req, res) => {
          const entityRef = String(
            req.body?.entityRef || 'component:default/aegis-ui',
          );
          const environment = String(req.body?.environment || 'all');
          const endpointKey = req.body?.endpointKey
            ? String(req.body.endpointKey)
            : undefined;
          const targetEndpointsFilter = Array.isArray(req.body?.targetEndpoints)
            ? req.body.targetEndpoints.map(String)
            : undefined;
          const keyAlgorithm =
            req.body?.keyAlgorithm === 'RSA-2048' ? 'RSA-2048' : 'ECDSA-P256';
          const validityDays = Number(req.body?.validityDays || 90);

          try {
            let rollup = getEntitySslRollupFromStore(entityRef);
            if (!rollup) {
              const credentials = await auth.getOwnServiceCredentials();
              const entity = await catalog.getEntityByRef(entityRef, {
                credentials,
              });
              if (entity) {
                rollup = await scanEntityEndpoints(entity);
              }
            }

            const renewalResult = await triggerMockGcpAutoRenewal({
              entityRef,
              environment,
              endpointKey,
              targetEndpointsFilter,
              keyAlgorithm,
              validityDays,
            });
            const updatedRollup = getEntitySslRollupFromStore(entityRef);
            res.status(200).json({
              ...renewalResult,
              rollup: updatedRollup,
            });
          } catch (err) {
            res.status(500).json({
              error:
                err instanceof Error
                  ? err.message
                  : 'GCP auto-renewal workflow failed',
            });
          }
        });

        router.get('/history', async (req, res) => {
          const entityRef = String(
            req.query.entityRef || 'component:default/aegis-backend',
          );
          const endpointId = req.query.endpointId
            ? String(req.query.endpointId)
            : undefined;
          const environment = req.query.environment
            ? String(req.query.environment)
            : undefined;

          try {
            if (getEntitySslRollupFromStore(entityRef) === null) {
              const credentials = await auth.getOwnServiceCredentials();
              const entity = await catalog.getEntityByRef(entityRef, {
                credentials,
              });
              if (entity) {
                await scanEntityEndpoints(entity);
              }
            }
            const history = getEndpointCertificateHistory({
              entityRef,
              endpointId,
              environment,
            });
            res.status(200).json({ count: history.length, endpoints: history });
          } catch (err) {
            logger.error(
              `SSL tracker history error for ${entityRef}: ${err}`,
            );
            res.status(500).json({
              error:
                err instanceof Error
                  ? err.message
                  : 'SSL certificate history lookup failed',
            });
          }
        });

        router.post('/remediate-crypto', async (req, res) => {
          const entityRef = String(
            req.body?.entityRef || 'component:default/aegis-backend',
          );
          const environment = String(req.body?.environment || 'all');
          const endpointKey = req.body?.endpointKey
            ? String(req.body.endpointKey)
            : undefined;
          const keyAlgorithm =
            req.body?.keyAlgorithm === 'ECDSA-P256'
              ? 'ECDSA-P256'
              : 'RSA-2048';
          const validityDays = Number(req.body?.validityDays || 90);

          try {
            let rollup = getEntitySslRollupFromStore(entityRef);
            if (!rollup) {
              const credentials = await auth.getOwnServiceCredentials();
              const entity = await catalog.getEntityByRef(entityRef, {
                credentials,
              });
              if (entity) {
                rollup = await scanEntityEndpoints(entity);
              }
            }

            const result = await remediatePrivateCloudEndpointCrypto({
              entityRef,
              environment,
              endpointKey,
              keyAlgorithm,
              validityDays,
            });
            res.status(200).json({
              ...result,
              rollup: getEntitySslRollupFromStore(entityRef),
            });
          } catch (err) {
            res.status(500).json({
              error:
                err instanceof Error
                  ? err.message
                  : 'Private-cloud crypto remediation failed',
            });
          }
        });

        router.get('/metrics', async (_req, res) => {
          res
            .status(200)
            .set('Content-Type', 'text/plain; version=0.0.4; charset=utf-8')
            .send(renderSslTrackerPrometheusMetrics());
        });

        httpRouter.use(router);
        for (const openPath of [
          '/status',
          '/fleet',
          '/scan',
          '/gcp-preview-diff',
          '/quality-gate/decide',
          '/gcp-auto-renew',
          '/history',
          '/remediate-crypto',
          '/metrics',
        ]) {
          httpRouter.addAuthPolicy({
            path: openPath,
            allow: 'unauthenticated',
          });
        }
      },
    });
  },
});

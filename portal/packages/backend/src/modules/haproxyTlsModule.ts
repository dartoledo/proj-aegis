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
  buildAndValidateHaproxyPem,
  deployCertToHaproxy,
  getLatestRotationDiff,
  probeLiveTlsCertificate,
  renderPrometheusMetrics,
  updateCatalogYamlAnnotations,
  verifyLiveTlsSerial,
} from './haproxyTlsService';

function createBuildPemTemplateAction(actionId: string) {
  return createTemplateAction({
    id: actionId,
    description:
      'Validates X.509 certificate and private key match (or auto-generates a self-signed pair) and bundles into an HAProxy PEM file.',
    schema: {
      input: {
        mode: z =>
          z
            .enum(['upload', 'auto-generate'])
            .default('auto-generate')
            .describe('Upload custom PEM artifacts or auto-generate via OpenSSL'),
        cert: z =>
          z.string().optional().describe('Public X.509 certificate PEM'),
        key: z =>
          z
            .string()
            .optional()
            .describe('Private key PEM (redacted from logs)'),
        commonName: z =>
          z
            .string()
            .optional()
            .default('hello.internal')
            .describe('Common Name (CN) for auto-generated certificate'),
        validDays: z =>
          z
            .number()
            .optional()
            .default(90)
            .describe('Validity period in days for auto-generated certificate'),
      },
      output: {
        pemBundle: z => z.string().describe('Combined HAProxy PEM bundle'),
        serialNumber: z =>
          z.string().describe('Colon-delimited uppercase hex serial number'),
        expiryDate: z => z.string().describe('ISO-8601 expiration timestamp'),
        daysRemaining: z =>
          z.number().describe('Days remaining until certificate expiration'),
      },
    },
    async handler(ctx) {
      const mode =
        ctx.input.mode === 'upload' ? 'upload' : ('auto-generate' as const);
      ctx.logger.info(
        `Executing ${actionId} in mode="${mode}" (private key material redacted)`,
      );

      const result = await buildAndValidateHaproxyPem({
        mode,
        cert: ctx.input.cert,
        key: ctx.input.key,
        commonName: ctx.input.commonName,
        validDays: ctx.input.validDays,
      });

      ctx.logger.info(
        `Validated X.509 certificate serial=${result.serialNumber}, expires=${result.expiryDate} (${result.daysRemaining} days remaining)`,
      );

      ctx.output('pemBundle', result.pemBundle);
      ctx.output('serialNumber', result.serialNumber);
      ctx.output('expiryDate', result.expiryDate);
      ctx.output('daysRemaining', result.daysRemaining);
    },
  });
}

function createDeployCertTemplateAction() {
  return createTemplateAction({
    id: 'resiliency:haproxy:deploy-cert',
    description:
      'Captures pre-rotation SSL state, writes the validated PEM bundle, and hot-reloads HAProxy TLS without dropping connections.',
    schema: {
      input: {
        entityRef: z =>
          z
            .string()
            .optional()
            .describe('Target Backstage catalog entity reference'),
        pemBundle: z =>
          z
            .string()
            .describe('Validated HAProxy PEM bundle (cert + private key)'),
      },
      output: {
        reloadedVia: z =>
          z.string().describe('Mechanism used to hot-reload HAProxy'),
        serialNumber: z => z.string().describe('Deployed certificate serial'),
        expiryDate: z => z.string().describe('Deployed certificate expiry'),
        previousSerial: z =>
          z.string().describe('Pre-rotation certificate serial number'),
        previousExpiry: z =>
          z.string().describe('Pre-rotation certificate expiration date'),
        previousFingerprint: z =>
          z.string().describe('Pre-rotation SHA-256 fingerprint'),
        previousDaysRemaining: z =>
          z.number().describe('Pre-rotation days remaining'),
        previousStatus: z =>
          z.string().describe('Pre-rotation certificate health status'),
      },
    },
    async handler(ctx) {
      ctx.logger.info(
        `Deploying PEM bundle to HAProxy for entity="${
          ctx.input.entityRef || 'resource:default/haproxy-hello-world-tls'
        }" (bundle content redacted)`,
      );

      const deployed = await deployCertToHaproxy({
        entityRef: ctx.input.entityRef,
        pemBundle: ctx.input.pemBundle,
      });

      if (deployed.previousProbe) {
        ctx.logger.info(
          `Captured Old SSL Certificate before rotation: serial=${deployed.previousProbe.serialNumber}, fingerprint=${deployed.previousProbe.fingerprint256}, expiry=${deployed.previousProbe.expiryDate} (${deployed.previousProbe.daysRemaining}d, ${deployed.previousProbe.status})`,
        );
      }

      ctx.logger.info(
        `HAProxy TLS certificate hot-reloaded via ${deployed.reloadedVia} (new serial=${deployed.serialNumber}, expiry=${deployed.expiryDate})`,
      );

      ctx.output('reloadedVia', deployed.reloadedVia);
      ctx.output('serialNumber', deployed.serialNumber);
      ctx.output('expiryDate', deployed.expiryDate);
      ctx.output(
        'previousSerial',
        deployed.previousProbe?.serialNumber || 'NONE',
      );
      ctx.output(
        'previousExpiry',
        deployed.previousProbe?.expiryDate || 'N/A',
      );
      ctx.output(
        'previousFingerprint',
        deployed.previousProbe?.fingerprint256 || 'N/A',
      );
      ctx.output(
        'previousDaysRemaining',
        deployed.previousProbe?.daysRemaining ?? 0,
      );
      ctx.output(
        'previousStatus',
        deployed.previousProbe?.status || 'Warning',
      );
    },
  });
}

function createVerifyTlsTemplateAction() {
  return createTemplateAction({
    id: 'resiliency:haproxy:verify-tls',
    description:
      'Performs a live TLS handshake + HTTPS /healthz verification against HAProxy, confirms the active certificate serial matches expectedSerial, and outputs a diff between the Old and New SSL certificate responses.',
    schema: {
      input: {
        expectedSerial: z =>
          z.string().describe('Expected X.509 certificate serial number'),
        hostPort: z =>
          z
            .string()
            .optional()
            .describe('Optional HAProxy host:port override'),
      },
      output: {
        verifiedSerial: z =>
          z.string().describe('Live serial number observed from handshake'),
        expiryDate: z =>
          z.string().describe('Live expiration timestamp observed'),
        daysRemaining: z =>
          z.number().describe('Live days remaining until expiration'),
        fingerprint256: z =>
          z.string().describe('Live SHA-256 certificate fingerprint'),
        tlsProtocol: z => z.string().describe('Negotiated TLS protocol'),
        cipherName: z => z.string().describe('Negotiated TLS cipher suite'),
        httpStatus: z =>
          z.number().describe('HTTP status from HTTPS /healthz probe'),
        sslUnifiedDiff: z =>
          z
            .string()
            .describe('Unified diff comparing Old vs New SSL certificate'),
        sslDiffMarkdown: z =>
          z
            .string()
            .describe(
              'Markdown summary table and unified diff of Old vs New SSL certificate',
            ),
      },
    },
    async handler(ctx) {
      ctx.logger.info(
        `Probing live HAProxy TLS endpoint to verify serial=${ctx.input.expectedSerial}...`,
      );
      const verified = await verifyLiveTlsSerial(
        ctx.input.expectedSerial,
        ctx.input.hostPort,
      );

      ctx.logger.info(
        `[PASS] X.509 Serial Match: ${verified.serialNumber} (expected ${ctx.input.expectedSerial})`,
      );
      ctx.logger.info(
        `[PASS] SHA-256 Fingerprint: ${verified.fingerprint256}`,
      );
      ctx.logger.info(
        `[PASS] TLS Handshake Protocol & Cipher: ${verified.tlsProtocol} / ${verified.cipherName}`,
      );
      ctx.logger.info(
        `[PASS] HTTPS Backend Health Probe (/healthz): HTTP ${verified.httpStatus} (OK=${verified.httpHealthPassed})`,
      );
      ctx.logger.info(
        `SSL Certificate Diff (Old vs. New):\n${verified.rotationDiff.unifiedDiff}`,
      );

      ctx.output('verifiedSerial', verified.serialNumber);
      ctx.output('expiryDate', verified.expiryDate);
      ctx.output('daysRemaining', verified.daysRemaining);
      ctx.output('fingerprint256', verified.fingerprint256);
      ctx.output('tlsProtocol', verified.tlsProtocol);
      ctx.output('cipherName', verified.cipherName);
      ctx.output('httpStatus', verified.httpStatus);
      ctx.output('sslUnifiedDiff', verified.rotationDiff.unifiedDiff);
      ctx.output('sslDiffMarkdown', verified.rotationDiff.markdownDiff);
    },
  });
}

function createCatalogRefreshTemplateAction(
  catalog: typeof catalogServiceRef.T,
  auth: typeof coreServices.auth.T,
) {
  return createTemplateAction({
    id: 'catalog:refresh',
    description:
      'Refreshes a Backstage Catalog entity and syncs its live TLS certificate annotations.',
    schema: {
      input: {
        entityRef: z =>
          z
            .string()
            .describe('Entity reference to refresh in the Backstage Catalog'),
      },
    },
    async handler(ctx) {
      ctx.logger.info(
        `Refreshing catalog entity=${ctx.input.entityRef} with latest live TLS metadata...`,
      );
      try {
        const probe = await probeLiveTlsCertificate();
        updateCatalogYamlAnnotations(probe);
      } catch {
        // Ignore if live probe fails during refresh
      }

      try {
        const credentials = await ctx.getInitiatorCredentials();
        await catalog.refreshEntity(ctx.input.entityRef, { credentials });
      } catch {
        const serviceCreds = await auth.getOwnServiceCredentials();
        await catalog.refreshEntity(ctx.input.entityRef, {
          credentials: serviceCreds,
        });
      }

      ctx.logger.info(
        `Successfully triggered catalog refresh for ${ctx.input.entityRef}`,
      );
    },
  });
}

export const scaffolderModuleHaproxyTls = createBackendModule({
  pluginId: 'scaffolder',
  moduleId: 'haproxy-tls-actions',
  register(reg) {
    reg.registerInit({
      deps: {
        scaffolder: scaffolderActionsExtensionPoint,
        catalog: catalogServiceRef,
        auth: coreServices.auth,
      },
      async init({ scaffolder, catalog, auth }) {
        scaffolder.addActions(
          createBuildPemTemplateAction('resiliency:haproxy:build-pem'),
          createBuildPemTemplateAction('resiliency:cert:bundle-haproxy-pem'),
          createDeployCertTemplateAction(),
          createVerifyTlsTemplateAction(),
          createCatalogRefreshTemplateAction(catalog, auth),
        );
      },
    });
  },
});

class HaproxyTlsLiveProbeProcessor implements CatalogProcessor {
  getProcessorName(): string {
    return 'HaproxyTlsLiveProbeProcessor';
  }

  async preProcessEntity(entity: Entity): Promise<Entity> {
    if (
      entity.kind === 'Resource' &&
      entity.spec?.type === 'tls-certificate'
    ) {
      const hostAnnotation =
        entity.metadata.annotations?.['resiliency.idp/haproxy-host'];
      try {
        const probe = await probeLiveTlsCertificate(hostAnnotation);
        return {
          ...entity,
          metadata: {
            ...entity.metadata,
            annotations: {
              ...entity.metadata.annotations,
              'resiliency.idp/cert-provider': 'Self-Signed (OpenSSL)',
              'resiliency.idp/cert-version': `v1 (Serial: ${probe.serialNumber})`,
              'resiliency.idp/cert-expiry': probe.expiryDate,
              'resiliency.idp/days-remaining': String(probe.daysRemaining),
              'resiliency.idp/cert-status': probe.status,
            },
          },
        };
      } catch {
        return entity;
      }
    }
    return entity;
  }
}

export const catalogModuleHaproxyTls = createBackendModule({
  pluginId: 'catalog',
  moduleId: 'haproxy-tls-live-probe',
  register(reg) {
    reg.registerInit({
      deps: {
        catalog: catalogProcessingExtensionPoint,
      },
      async init({ catalog }) {
        catalog.addProcessor(new HaproxyTlsLiveProbeProcessor());
      },
    });
  },
});

export const resiliencyTlsPlugin = createBackendPlugin({
  pluginId: 'resiliency-tls',
  register(reg) {
    reg.registerInit({
      deps: {
        httpRouter: coreServices.httpRouter,
        logger: coreServices.logger,
      },
      async init({ httpRouter, logger }) {
        const router = express.Router();

        router.get('/metrics', async (_req, res) => {
          try {
            const metrics = await renderPrometheusMetrics();
            res
              .status(200)
              .set('Content-Type', 'text/plain; version=0.0.4; charset=utf-8')
              .send(metrics);
          } catch (err) {
            logger.error(`Failed to render TLS Prometheus metrics: ${err}`);
            res.status(500).send('# error rendering metrics\n');
          }
        });

        router.get('/status', async (_req, res) => {
          try {
            const probe = await probeLiveTlsCertificate();
            res.status(200).json({
              ...probe,
              rotationDiff: getLatestRotationDiff(),
            });
          } catch (err) {
            res.status(503).json({
              error:
                err instanceof Error ? err.message : 'Live TLS probe failed',
            });
          }
        });

        httpRouter.use(router);
        httpRouter.addAuthPolicy({
          path: '/metrics',
          allow: 'unauthenticated',
        });
        httpRouter.addAuthPolicy({
          path: '/status',
          allow: 'unauthenticated',
        });
      },
    });
  },
});

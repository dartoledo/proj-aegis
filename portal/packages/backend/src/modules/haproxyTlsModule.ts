import {
  coreServices,
  createBackendModule,
  createBackendPlugin,
} from '@backstage/backend-plugin-api';
import { Entity } from '@backstage/catalog-model';
import {
  CatalogProcessor,
  catalogProcessingExtensionPoint,
} from '@backstage/plugin-catalog-node';
import {
  createTemplateAction,
  scaffolderActionsExtensionPoint,
} from '@backstage/plugin-scaffolder-node';
import express from 'express';
import {
  buildAndValidateHaproxyPem,
  deployCertToHaproxy,
  probeLiveTlsCertificate,
  renderPrometheusMetrics,
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
      'Writes the validated PEM bundle and hot-reloads HAProxy TLS without dropping connections.',
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

      ctx.logger.info(
        `HAProxy TLS certificate hot-reloaded via ${deployed.reloadedVia} (serial=${deployed.serialNumber}, expiry=${deployed.expiryDate})`,
      );

      ctx.output('reloadedVia', deployed.reloadedVia);
      ctx.output('serialNumber', deployed.serialNumber);
      ctx.output('expiryDate', deployed.expiryDate);
    },
  });
}

function createVerifyTlsTemplateAction() {
  return createTemplateAction({
    id: 'resiliency:haproxy:verify-tls',
    description:
      'Performs a live TLS handshake against HAProxy and verifies the active certificate serial number matches expectedSerial.',
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
      },
    },
    async handler(ctx) {
      ctx.logger.info(
        `Probing live HAProxy TLS endpoint to verify serial=${ctx.input.expectedSerial}...`,
      );
      const probe = await verifyLiveTlsSerial(
        ctx.input.expectedSerial,
        ctx.input.hostPort,
      );
      ctx.logger.info(
        `Live TLS handshake verified! Active serial=${probe.serialNumber}, status=${probe.status}, daysRemaining=${probe.daysRemaining}`,
      );

      ctx.output('verifiedSerial', probe.serialNumber);
      ctx.output('expiryDate', probe.expiryDate);
      ctx.output('daysRemaining', probe.daysRemaining);
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
      },
      async init({ scaffolder }) {
        scaffolder.addActions(
          createBuildPemTemplateAction('resiliency:haproxy:build-pem'),
          createBuildPemTemplateAction('resiliency:cert:bundle-haproxy-pem'),
          createDeployCertTemplateAction(),
          createVerifyTlsTemplateAction(),
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
        // Keep existing catalog annotations if live sandbox is unreachable
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
            res.status(200).json(probe);
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

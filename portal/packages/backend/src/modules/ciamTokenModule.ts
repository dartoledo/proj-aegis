import {
  coreServices,
  createBackendModule,
  createBackendPlugin,
} from '@backstage/backend-plugin-api';
import {
  createTemplateAction,
  scaffolderActionsExtensionPoint,
} from '@backstage/plugin-scaffolder-node';
import express from 'express';
import {
  DEFAULT_AEGIS_SECRET,
  inspectCiamToken,
  KNOWN_CIAM_POLICIES,
  mintCiamToken,
  renderCiamPrometheusMetrics,
  simulateCiamPolicy,
} from './ciamTokenService';

export function createMintTestTokenScaffolderAction() {
  return createTemplateAction({
    id: 'ciam:token:mint-test-token',
    description:
      'Mints a cryptographically signed test CIAM JWT token with configurable roles and claims for automated sandbox testing.',
    schema: {
      input: {
        subject: z =>
          z
            .string()
            .default('scaffolder-service-test')
            .describe('Token subject claim (sub)'),
        roles: z =>
          z
            .array(z.string())
            .optional()
            .default(['ciam:user'])
            .describe('Assigned CIAM roles (e.g. admin, ciam:user, service-account)'),
        scope: z =>
          z
            .string()
            .optional()
            .default('ciam:read')
            .describe('OAuth 2.0 scope string'),
        ttlMinutes: z =>
          z
            .number()
            .optional()
            .default(60)
            .describe('Validity duration in minutes'),
        secret: z =>
          z
            .string()
            .optional()
            .describe('Custom HMAC signing secret (falls back to Aegis default)'),
        algorithm: z =>
          z
            .enum(['HS256', 'HS384', 'HS512', 'none'])
            .optional()
            .default('HS256')
            .describe('Signing algorithm'),
      },
      output: {
        token: z => z.string().describe('Minted JWT token string'),
        expiresAt: z => z.string().describe('Expiration timestamp'),
      },
    },
    async handler(ctx) {
      ctx.logger.info(`Minting test CIAM token for subject="${ctx.input.subject}"`);
      const token = mintCiamToken({
        subject: ctx.input.subject,
        roles: ctx.input.roles,
        scope: ctx.input.scope,
        ttlMinutes: ctx.input.ttlMinutes,
        secret: ctx.input.secret,
        algorithm: ctx.input.algorithm as any,
      });

      const inspection = inspectCiamToken(token, ctx.input.secret || DEFAULT_AEGIS_SECRET);
      ctx.output('token', token);
      ctx.output('expiresAt', inspection.expiresAt || '');
      ctx.logger.info(
        `Successfully minted token (algorithm=${inspection.signatureAlgorithm}, compliance=${inspection.complianceStatus})`,
      );
    },
  });
}

export function createVerifyPolicyAccessScaffolderAction() {
  return createTemplateAction({
    id: 'ciam:policy:verify-access',
    description:
      'Evaluates whether a CIAM token or claims payload satisfies microservice route authorization policies.',
    schema: {
      input: {
        targetService: z =>
          z
            .string()
            .describe('Target CIAM microservice entity name (e.g. aegis-backend)'),
        endpoint: z =>
          z
            .string()
            .describe('Target endpoint path (e.g. /api/data)'),
        method: z =>
          z
            .enum(['GET', 'POST', 'PUT', 'DELETE'])
            .default('GET')
            .describe('HTTP method'),
        token: z =>
          z
            .string()
            .optional()
            .describe('CIAM JWT token string to evaluate'),
        secret: z =>
          z
            .string()
            .optional()
            .describe('Signing secret used to verify token signature'),
      },
      output: {
        allowed: z => z.boolean().describe('Whether access is permitted'),
        reasons: z => z.array(z.string()).describe('Decision rationale'),
      },
    },
    async handler(ctx) {
      ctx.logger.info(
        `Evaluating policy access: ${ctx.input.method} ${ctx.input.targetService}${ctx.input.endpoint}`,
      );

      const result = simulateCiamPolicy({
        targetService: ctx.input.targetService,
        endpoint: ctx.input.endpoint,
        method: ctx.input.method,
        token: ctx.input.token,
        secret: ctx.input.secret,
      });

      ctx.output('allowed', result.allowed);
      ctx.output('reasons', result.reasons);

      if (!result.allowed) {
        ctx.logger.warn(`Policy Access Denied: ${result.reasons.join('; ')}`);
      } else {
        ctx.logger.info(`Policy Access Granted: ${result.reasons.join('; ')}`);
      }
    },
  });
}

export const scaffolderModuleCiamToken = createBackendModule({
  pluginId: 'scaffolder',
  moduleId: 'ciam-token-actions',
  register(reg) {
    reg.registerInit({
      deps: {
        scaffolder: scaffolderActionsExtensionPoint,
      },
      async init({ scaffolder }) {
        scaffolder.addActions(createMintTestTokenScaffolderAction());
        scaffolder.addActions(createVerifyPolicyAccessScaffolderAction());
      },
    });
  },
});

export const ciamTokenPlugin = createBackendPlugin({
  pluginId: 'ciam-token',
  register(reg) {
    reg.registerInit({
      deps: {
        httpRouter: coreServices.httpRouter,
        logger: coreServices.logger,
      },
      async init({ httpRouter, logger }) {
        const router = express.Router();
        router.use(express.json());

        router.get('/metrics', async (_req, res) => {
          try {
            const metrics = renderCiamPrometheusMetrics();
            res
              .status(200)
              .set('Content-Type', 'text/plain; version=0.0.4; charset=utf-8')
              .send(metrics);
          } catch (err) {
            logger.error(`Failed to render CIAM Prometheus metrics: ${err}`);
            res.status(500).send('# error rendering metrics\n');
          }
        });

        router.get('/policies', (_req, res) => {
          res.status(200).json(KNOWN_CIAM_POLICIES);
        });

        router.post('/inspect', (req, res) => {
          try {
            const { token, secret } = req.body || {};
            if (!token) {
              res.status(400).json({ error: 'Missing token in request body' });
              return;
            }
            const inspection = inspectCiamToken(token, secret);
            res.status(200).json(inspection);
          } catch (err) {
            res.status(500).json({
              error: err instanceof Error ? err.message : 'Inspection failed',
            });
          }
        });

        router.post('/simulate', (req, res) => {
          try {
            const { targetService, endpoint, method, token, claims, secret } =
              req.body || {};
            if (!targetService || !endpoint || !method) {
              res.status(400).json({
                error: 'Missing targetService, endpoint, or method',
              });
              return;
            }
            const result = simulateCiamPolicy({
              targetService,
              endpoint,
              method,
              token,
              claims,
              secret,
            });
            res.status(200).json(result);
          } catch (err) {
            res.status(500).json({
              error: err instanceof Error ? err.message : 'Simulation failed',
            });
          }
        });

        router.post('/mint', (req, res) => {
          try {
            const { subject, roles, scope, issuer, audience, ttlMinutes, secret, algorithm, customClaims } =
              req.body || {};
            if (!subject) {
              res.status(400).json({ error: 'Missing subject' });
              return;
            }
            const token = mintCiamToken({
              subject,
              roles,
              scope,
              issuer,
              audience,
              ttlMinutes,
              secret,
              algorithm,
              customClaims,
            });
            const inspection = inspectCiamToken(token, secret);
            res.status(200).json({
              token,
              inspection,
            });
          } catch (err) {
            res.status(500).json({
              error: err instanceof Error ? err.message : 'Minting failed',
            });
          }
        });

        httpRouter.use(router);
        httpRouter.addAuthPolicy({
          path: '/metrics',
          allow: 'unauthenticated',
        });
        httpRouter.addAuthPolicy({
          path: '/policies',
          allow: 'unauthenticated',
        });
        httpRouter.addAuthPolicy({
          path: '/inspect',
          allow: 'unauthenticated',
        });
        httpRouter.addAuthPolicy({
          path: '/simulate',
          allow: 'unauthenticated',
        });
        httpRouter.addAuthPolicy({
          path: '/mint',
          allow: 'unauthenticated',
        });
      },
    });
  },
});

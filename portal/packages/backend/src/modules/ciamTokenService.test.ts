import {
  CiamTokenInspectionResult,
  DEFAULT_AEGIS_AUDIENCE,
  DEFAULT_AEGIS_ISSUER,
  DEFAULT_AEGIS_SECRET,
  inspectCiamToken,
  mintCiamToken,
  renderCiamPrometheusMetrics,
  simulateCiamPolicy,
} from './ciamTokenService';

describe('ciamTokenService', () => {
  describe('mintCiamToken', () => {
    it('mints a valid HS256 JWT with default issuer, audience, and requested roles', () => {
      const token = mintCiamToken({
        subject: 'user-123',
        roles: ['admin'],
        scope: 'ciam:read ciam:write',
        ttlMinutes: 60,
      });

      expect(typeof token).toBe('string');
      const parts = token.split('.');
      expect(parts.length).toBe(3);

      const header = JSON.parse(Buffer.from(parts[0], 'base64url').toString('utf8'));
      const payload = JSON.parse(Buffer.from(parts[1], 'base64url').toString('utf8'));

      expect(header.alg).toBe('HS256');
      expect(payload.sub).toBe('user-123');
      expect(payload.roles).toContain('admin');
      expect(payload.iss).toBe(DEFAULT_AEGIS_ISSUER);
      expect(payload.aud).toBe(DEFAULT_AEGIS_AUDIENCE);
      expect(payload.exp).toBeGreaterThan(payload.iat);
    });

    it('can mint insecure alg:none token for test & vulnerability analysis', () => {
      const token = mintCiamToken({
        subject: 'attacker-1',
        algorithm: 'none',
      });
      const parts = token.split('.');
      expect(parts.length).toBe(3);
      expect(parts[2]).toBe('');
    });
  });

  describe('inspectCiamToken', () => {
    it('successfully validates a compliant token with valid signature', () => {
      const token = mintCiamToken({
        subject: 'developer-alice',
        roles: ['ciam:user'],
        ttlMinutes: 30,
      });

      const inspection: CiamTokenInspectionResult = inspectCiamToken(token, DEFAULT_AEGIS_SECRET);

      expect(inspection.validSignature).toBe(true);
      expect(inspection.signatureAlgorithm).toBe('HS256');
      expect(inspection.payload.sub).toBe('developer-alice');
      expect(inspection.isExpired).toBe(false);
      expect(inspection.complianceStatus).toBe('COMPLIANT');
      expect(inspection.securityFlaws).toHaveLength(0);
    });

    it('flags alg:none tokens as CRITICAL security flaw', () => {
      const token = mintCiamToken({
        subject: 'attacker',
        algorithm: 'none',
      });

      const inspection = inspectCiamToken(token);
      expect(inspection.complianceStatus).toBe('CRITICAL');
      const flaw = inspection.securityFlaws.find(f => f.code === 'ALG_NONE');
      expect(flaw).toBeDefined();
      expect(flaw?.severity).toBe('CRITICAL');
    });

    it('flags weak HMAC secrets (< 32 characters / 256 bits)', () => {
      const weakSecret = 'short';
      const token = mintCiamToken({
        subject: 'service-bob',
        secret: weakSecret,
      });

      const inspection = inspectCiamToken(token, weakSecret);
      expect(inspection.validSignature).toBe(true);
      const weakFlaw = inspection.securityFlaws.find(f => f.code === 'WEAK_HMAC_SECRET');
      expect(weakFlaw).toBeDefined();
      expect(weakFlaw?.severity).toBe('WARNING');
    });

    it('flags excessive TTL (> 24 hours)', () => {
      const token = mintCiamToken({
        subject: 'service-carol',
        ttlMinutes: 60 * 48, // 48 hours
      });

      const inspection = inspectCiamToken(token, DEFAULT_AEGIS_SECRET);
      const ttlFlaw = inspection.securityFlaws.find(f => f.code === 'EXCESSIVE_TTL');
      expect(ttlFlaw).toBeDefined();
    });

    it('flags exposed PII or credential fields in payload', () => {
      const token = mintCiamToken({
        subject: 'user-dan',
        customClaims: {
          password: 'plain-password-123',
          apiKey: 'secret-api-key',
        },
      });

      const inspection = inspectCiamToken(token, DEFAULT_AEGIS_SECRET);
      const piiFlaw = inspection.securityFlaws.find(f => f.code === 'EXPOSED_PII_OR_SECRET');
      expect(piiFlaw).toBeDefined();
      expect(piiFlaw?.severity).toBe('CRITICAL');
    });

    it('detects invalid signatures when secret differs', () => {
      const token = mintCiamToken({
        subject: 'user-eva',
        secret: 'mock-signing-key-for-test-32bytes-001',
      });

      const inspection = inspectCiamToken(
        token,
        'mock-signing-key-for-test-32bytes-002',
      );
      expect(inspection.validSignature).toBe(false);
      expect(inspection.complianceStatus).toBe('INVALID');
    });
  });

  describe('simulateCiamPolicy', () => {
    it('allows anonymous access to /login and /jwks.json on aegis-auth', () => {
      const res = simulateCiamPolicy({
        targetService: 'aegis-auth',
        endpoint: '/login',
        method: 'POST',
      });
      expect(res.allowed).toBe(true);
      expect(res.reasons).toContain('Endpoint allows anonymous access');
    });

    it('denies unauthenticated requests to protected endpoints', () => {
      const res = simulateCiamPolicy({
        targetService: 'aegis-backend',
        endpoint: '/api/data',
        method: 'GET',
      });
      expect(res.allowed).toBe(false);
      expect(res.reasons.some(r => r.includes('No token or valid claims provided'))).toBe(true);
    });

    it('allows GET /api/data for ciam:user role', () => {
      const token = mintCiamToken({
        subject: 'test-user',
        roles: ['ciam:user'],
      });

      const res = simulateCiamPolicy({
        token,
        targetService: 'aegis-backend',
        endpoint: '/api/data',
        method: 'GET',
        secret: DEFAULT_AEGIS_SECRET,
      });

      expect(res.allowed).toBe(true);
    });

    it('denies POST /api/data when token lacks required role and scope', () => {
      const token = mintCiamToken({
        subject: 'test-viewer',
        roles: ['viewer'],
      });

      const res = simulateCiamPolicy({
        token,
        targetService: 'aegis-backend',
        endpoint: '/api/data',
        method: 'POST',
        secret: DEFAULT_AEGIS_SECRET,
      });

      expect(res.allowed).toBe(false);
      expect(res.reasons.some(r => r.includes('Missing required role') || r.includes('scope'))).toBe(true);
    });

    it('allows POST /api/data when token has admin role and ciam:write scope', () => {
      const token = mintCiamToken({
        subject: 'admin-user',
        roles: ['admin'],
        scope: 'ciam:write',
      });

      const res = simulateCiamPolicy({
        token,
        targetService: 'aegis-backend',
        endpoint: '/api/data',
        method: 'POST',
        secret: DEFAULT_AEGIS_SECRET,
      });

      expect(res.allowed).toBe(true);
    });
  });

  describe('renderCiamPrometheusMetrics', () => {
    it('outputs Prometheus formatted metrics including inspection and flaw gauges', () => {
      const metrics = renderCiamPrometheusMetrics();
      expect(metrics).toContain('aegis_ciam_token_inspections_total');
      expect(metrics).toContain('aegis_ciam_policy_simulations_total');
    });
  });
});

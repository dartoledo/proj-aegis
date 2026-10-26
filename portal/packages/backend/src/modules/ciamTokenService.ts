import crypto from 'crypto';

export interface CiamTokenHeader {
  alg: string;
  typ?: string;
  kid?: string;
  [key: string]: any;
}

export interface CiamTokenPayload {
  sub?: string;
  iss?: string;
  aud?: string | string[];
  exp?: number;
  nbf?: number;
  iat?: number;
  roles?: string[];
  role?: string;
  scope?: string;
  permissions?: string[];
  user?: string;
  email?: string;
  [key: string]: any;
}

export interface SecurityFlaw {
  code:
    | 'ALG_NONE'
    | 'WEAK_HMAC_SECRET'
    | 'EXCESSIVE_TTL'
    | 'MISSING_AUDIENCE'
    | 'MISSING_ISSUER'
    | 'EXPOSED_PII_OR_SECRET'
    | 'EXPIRED_TOKEN'
    | 'TOKEN_NOT_YET_VALID';
  severity: 'CRITICAL' | 'WARNING' | 'INFO';
  message: string;
  remediation: string;
}

export interface CiamTokenInspectionResult {
  validSignature: boolean;
  signatureAlgorithm: string;
  header: CiamTokenHeader;
  payload: CiamTokenPayload;
  isExpired: boolean;
  notBeforeValid: boolean;
  issuedAt: string | null;
  expiresAt: string | null;
  ttlSecondsRemaining: number;
  clockSkewSeconds: number;
  securityFlaws: SecurityFlaw[];
  complianceStatus: 'COMPLIANT' | 'WARNING' | 'CRITICAL' | 'INVALID';
}

export interface CiamRoutePolicy {
  endpoint: string;
  method: string;
  allowAnonymous?: boolean;
  requiredRoles?: string[];
  requiredScopes?: string[];
  description: string;
}

export interface CiamPolicySimulationRequest {
  token?: string;
  claims?: Partial<CiamTokenPayload>;
  targetService: string;
  endpoint: string;
  method: string;
  secret?: string;
}

export interface CiamPolicySimulationResult {
  allowed: boolean;
  targetService: string;
  endpoint: string;
  method: string;
  matchedPolicy?: CiamRoutePolicy;
  reasons: string[];
}

export interface CiamTokenMintOptions {
  subject: string;
  roles?: string[];
  scope?: string;
  issuer?: string;
  audience?: string;
  ttlMinutes?: number;
  customClaims?: Record<string, any>;
  secret?: string;
  algorithm?: 'HS256' | 'HS384' | 'HS512' | 'none';
}

export const DEFAULT_AEGIS_SECRET =
  'aegis-ciam-default-secure-secret-key-32-bytes!';
export const DEFAULT_AEGIS_ISSUER = 'https://auth.aegis.internal';
export const DEFAULT_AEGIS_AUDIENCE = 'aegis-ciam-services';

export const KNOWN_CIAM_POLICIES: Record<string, CiamRoutePolicy[]> = {
  'aegis-backend': [
    {
      endpoint: '/api/data',
      method: 'GET',
      requiredRoles: ['admin', 'ciam:user', 'service-account', 'viewer'],
      description: 'Fetch general CIAM backend telemetry data',
    },
    {
      endpoint: '/api/data',
      method: 'POST',
      requiredRoles: ['admin', 'service-account'],
      requiredScopes: ['ciam:write'],
      description: 'Create or mutate CIAM dataset',
    },
    {
      endpoint: '/api/admin/users',
      method: 'GET',
      requiredRoles: ['admin'],
      description: 'Read all provisioned CIAM user identities',
    },
    {
      endpoint: '/api/keys',
      method: 'POST',
      requiredRoles: ['admin', 'security-officer'],
      description: 'Rotate cryptographic API signing keys',
    },
  ],
  'aegis-auth': [
    {
      endpoint: '/login',
      method: 'POST',
      allowAnonymous: true,
      description: 'Public identity authentication endpoint',
    },
    {
      endpoint: '/jwks.json',
      method: 'GET',
      allowAnonymous: true,
      description: 'Public cryptographic keyset',
    },
    {
      endpoint: '/oauth/token',
      method: 'POST',
      allowAnonymous: true,
      description: 'Public OAuth token exchange endpoint',
    },
    {
      endpoint: '/api/admin/sessions',
      method: 'GET',
      requiredRoles: ['admin'],
      description: 'Manage active customer identity sessions',
    },
  ],
};

function base64UrlEncode(strOrBuffer: string | Buffer): string {
  const buf = typeof strOrBuffer === 'string' ? Buffer.from(strOrBuffer, 'utf8') : strOrBuffer;
  return buf.toString('base64url');
}

function base64UrlDecode(str: string): string {
  return Buffer.from(str, 'base64url').toString('utf8');
}

const metricsState = {
  inspectionsTotal: 0,
  flawsTotal: {} as Record<string, number>,
  simulationsTotal: { allowed: 0, denied: 0 },
  mintedTotal: 0,
};

export function mintCiamToken(options: CiamTokenMintOptions): string {
  const now = Math.floor(Date.now() / 1000);
  const alg = options.algorithm || 'HS256';
  const header: CiamTokenHeader = { alg, typ: 'JWT' };

  const ttlMinutes = options.ttlMinutes !== undefined ? options.ttlMinutes : 60;
  const payload: CiamTokenPayload = {
    sub: options.subject,
    iss: options.issuer || DEFAULT_AEGIS_ISSUER,
    aud: options.audience || DEFAULT_AEGIS_AUDIENCE,
    iat: now,
    exp: now + ttlMinutes * 60,
    roles: options.roles || [],
    ...(options.scope ? { scope: options.scope } : {}),
    ...(options.customClaims || {}),
  };

  const encodedHeader = base64UrlEncode(JSON.stringify(header));
  const encodedPayload = base64UrlEncode(JSON.stringify(payload));

  let signature = '';
  if (alg !== 'none') {
    const hashAlg = alg === 'HS384' ? 'sha384' : alg === 'HS512' ? 'sha512' : 'sha256';
    const signingKey = options.secret !== undefined ? options.secret : DEFAULT_AEGIS_SECRET;
    signature = base64UrlEncode(
      crypto
        .createHmac(hashAlg, signingKey)
        .update(`${encodedHeader}.${encodedPayload}`)
        .digest(),
    );
  }

  metricsState.mintedTotal++;
  return `${encodedHeader}.${encodedPayload}.${signature}`;
}

export function inspectCiamToken(
  token: string,
  secret?: string,
): CiamTokenInspectionResult {
  metricsState.inspectionsTotal++;
  const signingKey = secret !== undefined && secret !== null ? secret : DEFAULT_AEGIS_SECRET;

  const parts = (token || '').split('.');
  if (parts.length !== 3) {
    return {
      validSignature: false,
      signatureAlgorithm: 'UNKNOWN',
      header: { alg: 'UNKNOWN' },
      payload: {},
      isExpired: true,
      notBeforeValid: false,
      issuedAt: null,
      expiresAt: null,
      ttlSecondsRemaining: 0,
      clockSkewSeconds: 0,
      securityFlaws: [
        {
          code: 'ALG_NONE',
          severity: 'CRITICAL',
          message: 'Malformed JWT token structure',
          remediation: 'Provide a valid 3-part base64url encoded JWT token',
        },
      ],
      complianceStatus: 'INVALID',
    };
  }

  let header: CiamTokenHeader = { alg: 'UNKNOWN' };
  let payload: CiamTokenPayload = {};

  try {
    header = JSON.parse(base64UrlDecode(parts[0]));
  } catch {
    header = { alg: 'INVALID' };
  }

  try {
    payload = JSON.parse(base64UrlDecode(parts[1]));
  } catch {
    payload = {};
  }

  const alg = header.alg || 'UNKNOWN';
  let validSignature = false;

  if (alg === 'none') {
    validSignature = parts[2] === '';
  } else if (['HS256', 'HS384', 'HS512'].includes(alg)) {
    const hashAlg = alg === 'HS384' ? 'sha384' : alg === 'HS512' ? 'sha512' : 'sha256';
    const expectedSig = base64UrlEncode(
      crypto
        .createHmac(hashAlg, signingKey)
        .update(`${parts[0]}.${parts[1]}`)
        .digest(),
    );
    validSignature = parts[2] === expectedSig;
  }

  const now = Math.floor(Date.now() / 1000);
  const securityFlaws: SecurityFlaw[] = [];

  if (alg === 'none') {
    securityFlaws.push({
      code: 'ALG_NONE',
      severity: 'CRITICAL',
      message: 'Token signed with alg: none allows signature forgery',
      remediation: 'Enforce HS256 or RS256 signing algorithms in CIAM services',
    });
  }

  if (signingKey.length < 32 && alg !== 'none') {
    securityFlaws.push({
      code: 'WEAK_HMAC_SECRET',
      severity: 'WARNING',
      message: 'HMAC secret key is shorter than 32 characters (256-bit entropy threshold)',
      remediation: 'Provision a high-entropy secret with at least 32 characters',
    });
  }

  if (payload.exp && payload.iat && payload.exp - payload.iat > 24 * 3600) {
    securityFlaws.push({
      code: 'EXCESSIVE_TTL',
      severity: 'WARNING',
      message: 'Token validity period exceeds 24 hours',
      remediation: 'Configure short-lived access tokens (≤ 1 hour) with refresh rotation',
    });
  }

  const isExpired = Boolean(payload.exp && now > payload.exp);
  if (isExpired) {
    securityFlaws.push({
      code: 'EXPIRED_TOKEN',
      severity: 'WARNING',
      message: 'Token timestamp has expired',
      remediation: 'Re-authenticate to acquire a fresh token',
    });
  }

  const notBeforeValid = !payload.nbf || now >= payload.nbf;
  if (!notBeforeValid) {
    securityFlaws.push({
      code: 'TOKEN_NOT_YET_VALID',
      severity: 'WARNING',
      message: 'Token not-before (nbf) timestamp is in the future',
      remediation: 'Check server clock synchronization (NTP)',
    });
  }

  for (const key of Object.keys(payload)) {
    if (/password|apikey|api_key|secret|private_key/i.test(key)) {
      securityFlaws.push({
        code: 'EXPOSED_PII_OR_SECRET',
        severity: 'CRITICAL',
        message: `Sensitive credential detected in claim "${key}"`,
        remediation: 'Never include plaintext secrets or credentials in JWT payload claims',
      });
      break;
    }
  }

  if (!payload.aud) {
    securityFlaws.push({
      code: 'MISSING_AUDIENCE',
      severity: 'INFO',
      message: 'Token is missing the audience ("aud") claim',
      remediation: 'Define target audience in token minting configurations',
    });
  }

  if (!payload.iss) {
    securityFlaws.push({
      code: 'MISSING_ISSUER',
      severity: 'INFO',
      message: 'Token is missing the issuer ("iss") claim',
      remediation: 'Set authorized issuer URI in token minting configurations',
    });
  }

  for (const flaw of securityFlaws) {
    metricsState.flawsTotal[flaw.code] = (metricsState.flawsTotal[flaw.code] || 0) + 1;
  }

  let complianceStatus: 'COMPLIANT' | 'WARNING' | 'CRITICAL' | 'INVALID' = 'COMPLIANT';
  if (!validSignature) {
    complianceStatus = 'INVALID';
  } else if (securityFlaws.some(f => f.severity === 'CRITICAL')) {
    complianceStatus = 'CRITICAL';
  } else if (securityFlaws.some(f => f.severity === 'WARNING')) {
    complianceStatus = 'WARNING';
  }

  const ttlSecondsRemaining = payload.exp ? Math.max(0, payload.exp - now) : 0;
  const clockSkewSeconds = payload.iat ? Math.abs(now - payload.iat) : 0;

  return {
    validSignature,
    signatureAlgorithm: alg,
    header,
    payload,
    isExpired,
    notBeforeValid,
    issuedAt: payload.iat ? new Date(payload.iat * 1000).toISOString() : null,
    expiresAt: payload.exp ? new Date(payload.exp * 1000).toISOString() : null,
    ttlSecondsRemaining,
    clockSkewSeconds,
    securityFlaws,
    complianceStatus,
  };
}

export function simulateCiamPolicy(
  request: CiamPolicySimulationRequest,
): CiamPolicySimulationResult {
  const servicePolicies = KNOWN_CIAM_POLICIES[request.targetService] || [];
  const matchedPolicy = servicePolicies.find(
    p =>
      p.endpoint === request.endpoint &&
      p.method.toUpperCase() === request.method.toUpperCase(),
  );

  if (!matchedPolicy) {
    metricsState.simulationsTotal.denied++;
    return {
      allowed: false,
      targetService: request.targetService,
      endpoint: request.endpoint,
      method: request.method,
      reasons: ['No route policy defined for this endpoint and method'],
    };
  }

  if (matchedPolicy.allowAnonymous) {
    metricsState.simulationsTotal.allowed++;
    return {
      allowed: true,
      targetService: request.targetService,
      endpoint: request.endpoint,
      method: request.method,
      matchedPolicy,
      reasons: ['Endpoint allows anonymous access'],
    };
  }

  let payload: CiamTokenPayload | undefined = undefined;
  if (request.token) {
    const inspected = inspectCiamToken(request.token, request.secret);
    if (!inspected.validSignature) {
      metricsState.simulationsTotal.denied++;
      return {
        allowed: false,
        targetService: request.targetService,
        endpoint: request.endpoint,
        method: request.method,
        matchedPolicy,
        reasons: ['Invalid token signature'],
      };
    }
    if (inspected.isExpired) {
      metricsState.simulationsTotal.denied++;
      return {
        allowed: false,
        targetService: request.targetService,
        endpoint: request.endpoint,
        method: request.method,
        matchedPolicy,
        reasons: ['Token has expired'],
      };
    }
    payload = inspected.payload;
  } else if (request.claims) {
    payload = request.claims as CiamTokenPayload;
  }

  if (!payload) {
    metricsState.simulationsTotal.denied++;
    return {
      allowed: false,
      targetService: request.targetService,
      endpoint: request.endpoint,
      method: request.method,
      matchedPolicy,
      reasons: ['No token or valid claims provided'],
    };
  }

  const reasons: string[] = [];
  let rolesAllowed = true;
  if (matchedPolicy.requiredRoles && matchedPolicy.requiredRoles.length > 0) {
    const tokenRoles = payload.roles || (payload.role ? [payload.role] : []);
    const hasRole = matchedPolicy.requiredRoles.some(r => tokenRoles.includes(r));
    if (!hasRole) {
      rolesAllowed = false;
      reasons.push(
        `Missing required role. Needed one of: ${matchedPolicy.requiredRoles.join(', ')}`,
      );
    }
  }

  let scopesAllowed = true;
  if (matchedPolicy.requiredScopes && matchedPolicy.requiredScopes.length > 0) {
    const tokenScopes = (payload.scope || '').split(/\s+/).filter(Boolean);
    const missingScopes = matchedPolicy.requiredScopes.filter(
      s => !tokenScopes.includes(s),
    );
    if (missingScopes.length > 0) {
      scopesAllowed = false;
      reasons.push(`Missing required scope(s): ${missingScopes.join(', ')}`);
    }
  }

  const allowed = rolesAllowed && scopesAllowed;
  if (allowed) {
    metricsState.simulationsTotal.allowed++;
    reasons.push('All required roles and scopes satisfied');
  } else {
    metricsState.simulationsTotal.denied++;
  }

  return {
    allowed,
    targetService: request.targetService,
    endpoint: request.endpoint,
    method: request.method,
    matchedPolicy,
    reasons,
  };
}

export function renderCiamPrometheusMetrics(): string {
  const lines: string[] = [
    '# HELP aegis_ciam_token_inspections_total Total number of CIAM token inspections',
    '# TYPE aegis_ciam_token_inspections_total counter',
    `aegis_ciam_token_inspections_total ${metricsState.inspectionsTotal}`,
    '# HELP aegis_ciam_tokens_minted_total Total number of sandbox CIAM tokens minted',
    '# TYPE aegis_ciam_tokens_minted_total counter',
    `aegis_ciam_tokens_minted_total ${metricsState.mintedTotal}`,
    '# HELP aegis_ciam_policy_simulations_total Total CIAM policy simulations by outcome',
    '# TYPE aegis_ciam_policy_simulations_total counter',
    `aegis_ciam_policy_simulations_total{decision="allowed"} ${metricsState.simulationsTotal.allowed}`,
    `aegis_ciam_policy_simulations_total{decision="denied"} ${metricsState.simulationsTotal.denied}`,
  ];

  for (const [code, count] of Object.entries(metricsState.flawsTotal)) {
    lines.push(
      `aegis_ciam_token_security_flaws_total{code="${code}"} ${count}`,
    );
  }

  return `${lines.join('\n')}\n`;
}


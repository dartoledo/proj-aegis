import { useEffect, useState } from 'react';
import { createFrontendModule } from '@backstage/frontend-plugin-api';
import { EntityCardBlueprint } from '@backstage/plugin-catalog-react/alpha';
import { useEntity } from '@backstage/plugin-catalog-react';
import { InfoCard } from '@backstage/core-components';

interface SecurityFlaw {
  code: string;
  severity: 'CRITICAL' | 'WARNING' | 'INFO';
  message: string;
  remediation: string;
}

interface InspectionResult {
  validSignature: boolean;
  signatureAlgorithm: string;
  header: Record<string, any>;
  payload: Record<string, any>;
  isExpired: boolean;
  notBeforeValid: boolean;
  issuedAt: string | null;
  expiresAt: string | null;
  ttlSecondsRemaining: number;
  clockSkewSeconds: number;
  securityFlaws: SecurityFlaw[];
  complianceStatus: 'COMPLIANT' | 'WARNING' | 'CRITICAL' | 'INVALID';
}

interface SimulationResult {
  allowed: boolean;
  targetService: string;
  endpoint: string;
  method: string;
  matchedPolicy?: {
    endpoint: string;
    method: string;
    allowAnonymous?: boolean;
    requiredRoles?: string[];
    requiredScopes?: string[];
    description: string;
  };
  reasons: string[];
}

const CIAM_API_BASE = 'http://localhost:7007/api/ciam-token';

export const EntityCiamTokenDebuggerCard = () => {
  const { entity } = useEntity();
  const serviceName = entity.metadata.name;

  const [activeTab, setActiveTab] = useState<'inspect' | 'simulate' | 'mint'>('inspect');
  const [tokenInput, setTokenInput] = useState<string>('');
  const [secretInput, setSecretInput] = useState<string>('');
  const [inspection, setInspection] = useState<InspectionResult | null>(null);
  const [loading, setLoading] = useState<boolean>(false);
  const [error, setError] = useState<string | null>(null);

  // Simulation state
  const [selectedEndpoint, setSelectedEndpoint] = useState<string>('/api/data');
  const [selectedMethod, setSelectedMethod] = useState<string>('GET');
  const [simResult, setSimResult] = useState<SimulationResult | null>(null);

  // Minting state
  const [mintSubject, setMintSubject] = useState<string>('dev-user-01');
  const [mintRoles, setMintRoles] = useState<string>('ciam:user');
  const [mintScope, setMintScope] = useState<string>('ciam:read');
  const [mintTtl, setMintTtl] = useState<number>(60);
  const [mintAlg, setMintAlg] = useState<string>('HS256');

  // Auto-mint an initial demo token on first mount so the card has live data immediately
  useEffect(() => {
    let mounted = true;
    fetch(`${CIAM_API_BASE}/mint`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        subject: `dev-${serviceName}`,
        roles: ['ciam:user'],
        scope: 'ciam:read',
        ttlMinutes: 60,
      }),
    })
      .then(res => (res.ok ? res.json() : null))
      .then(data => {
        if (mounted && data?.token) {
          setTokenInput(data.token);
          setInspection(data.inspection);
        }
      })
      .catch(() => {
        // Backend might be offline during build/test; ignore gracefully
      });
    return () => {
      mounted = false;
    };
  }, [serviceName]);

  const handleInspect = async (overrideToken?: string) => {
    const t = overrideToken || tokenInput;
    if (!t) return;
    setLoading(true);
    setError(null);
    try {
      const res = await fetch(`${CIAM_API_BASE}/inspect`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          token: t,
          secret: secretInput || undefined,
        }),
      });
      if (!res.ok) {
        throw new Error(`Inspect failed: ${res.statusText}`);
      }
      const data = await res.json();
      setInspection(data);
    } catch (err: any) {
      setError(err.message || 'Inspection error');
    } finally {
      setLoading(false);
    }
  };

  const handleSimulate = async () => {
    setLoading(true);
    setError(null);
    try {
      const res = await fetch(`${CIAM_API_BASE}/simulate`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          targetService: serviceName,
          endpoint: selectedEndpoint,
          method: selectedMethod,
          token: tokenInput || undefined,
          secret: secretInput || undefined,
        }),
      });
      if (!res.ok) {
        throw new Error(`Simulation failed: ${res.statusText}`);
      }
      const data = await res.json();
      setSimResult(data);
    } catch (err: any) {
      setError(err.message || 'Simulation error');
    } finally {
      setLoading(false);
    }
  };

  const handleMint = async (preset?: {
    roles: string[];
    scope?: string;
    alg?: string;
    ttl?: number;
  }) => {
    setLoading(true);
    setError(null);
    try {
      const rolesArray = preset
        ? preset.roles
        : mintRoles.split(',').map(s => s.trim()).filter(Boolean);
      const res = await fetch(`${CIAM_API_BASE}/mint`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          subject: mintSubject,
          roles: rolesArray,
          scope: preset ? preset.scope : mintScope,
          ttlMinutes: preset?.ttl !== undefined ? preset.ttl : mintTtl,
          algorithm: preset ? preset.alg : mintAlg,
          secret: secretInput || undefined,
        }),
      });
      if (!res.ok) {
        throw new Error(`Minting failed: ${res.statusText}`);
      }
      const data = await res.json();
      setTokenInput(data.token);
      setInspection(data.inspection);
      setActiveTab('inspect');
    } catch (err: any) {
      setError(err.message || 'Minting error');
    } finally {
      setLoading(false);
    }
  };

  const getStatusBadge = (status?: string) => {
    let bg = '#e0e0e0';
    let fg = '#212121';
    let label = status || 'UNKNOWN';

    if (status === 'COMPLIANT') {
      bg = '#e8f5e9';
      fg = '#2e7d32';
      label = '✓ COMPLIANT';
    } else if (status === 'WARNING') {
      bg = '#fff3e0';
      fg = '#ef6c00';
      label = '⚠ WARNING';
    } else if (status === 'CRITICAL' || status === 'INVALID') {
      bg = '#ffebee';
      fg = '#c62828';
      label = `✖ ${status}`;
    }

    return (
      <span
        style={{
          display: 'inline-block',
          padding: '4px 10px',
          borderRadius: '16px',
          fontWeight: 600,
          fontSize: '0.8rem',
          backgroundColor: bg,
          color: fg,
        }}
      >
        {label}
      </span>
    );
  };

  return (
    <InfoCard
      title={`🛡️ CIAM Auth Token Debugger & Zero-Trust Simulator: ${serviceName}`}
      subheader="Inspect JWT/OIDC tokens, audit security flaws, simulate RBAC route permissions, and mint test credentials"
    >
      <div style={{ display: 'flex', flexDirection: 'column', gap: '14px' }}>
        {/* Tab Buttons */}
        <div style={{ display: 'flex', gap: '8px', borderBottom: '1px solid #e0e0e0', paddingBottom: '6px' }}>
          <button
            type="button"
            onClick={() => setActiveTab('inspect')}
            style={{
              padding: '6px 14px',
              border: 'none',
              background: activeTab === 'inspect' ? '#1976d2' : '#f5f5f5',
              color: activeTab === 'inspect' ? '#fff' : '#424242',
              borderRadius: '4px',
              cursor: 'pointer',
              fontWeight: 600,
            }}
          >
            🔍 Token Inspector & Linter
          </button>
          <button
            type="button"
            onClick={() => setActiveTab('simulate')}
            style={{
              padding: '6px 14px',
              border: 'none',
              background: activeTab === 'simulate' ? '#1976d2' : '#f5f5f5',
              color: activeTab === 'simulate' ? '#fff' : '#424242',
              borderRadius: '4px',
              cursor: 'pointer',
              fontWeight: 600,
            }}
          >
            🚦 RBAC Route Simulator
          </button>
          <button
            type="button"
            onClick={() => setActiveTab('mint')}
            style={{
              padding: '6px 14px',
              border: 'none',
              background: activeTab === 'mint' ? '#1976d2' : '#f5f5f5',
              color: activeTab === 'mint' ? '#fff' : '#424242',
              borderRadius: '4px',
              cursor: 'pointer',
              fontWeight: 600,
            }}
          >
            ⚡ Sandbox Token Minting
          </button>
        </div>

        {error && (
          <div
            style={{
              padding: '8px 12px',
              backgroundColor: '#ffebee',
              color: '#c62828',
              borderRadius: '4px',
              fontSize: '0.85rem',
            }}
          >
            {error}
          </div>
        )}

        {/* TAB 1: INSPECTION & ZERO-TRUST LINTER */}
        {activeTab === 'inspect' && (
          <div style={{ display: 'flex', flexDirection: 'column', gap: '12px' }}>
            <div style={{ display: 'flex', flexDirection: 'column', gap: '4px' }}>
              <label htmlFor="token-input" style={{ fontSize: '0.85rem', fontWeight: 600 }}>JWT Token String:</label>
              <textarea
                id="token-input"
                rows={3}
                value={tokenInput}
                onChange={e => setTokenInput(e.target.value)}
                placeholder="eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9..."
                style={{
                  fontFamily: 'monospace',
                  fontSize: '0.8rem',
                  padding: '8px',
                  borderRadius: '4px',
                  border: '1px solid #ccc',
                }}
              />
            </div>

            <div style={{ display: 'flex', gap: '12px', alignItems: 'center' }}>
              <input
                type="text"
                placeholder="Optional HMAC secret (default: Aegis secret)"
                value={secretInput}
                onChange={e => setSecretInput(e.target.value)}
                style={{
                  padding: '6px 8px',
                  fontSize: '0.85rem',
                  borderRadius: '4px',
                  border: '1px solid #ccc',
                  flex: 1,
                }}
              />
              <button
                type="button"
                onClick={() => handleInspect()}
                disabled={loading || !tokenInput}
                style={{
                  padding: '7px 16px',
                  backgroundColor: '#1976d2',
                  color: '#fff',
                  border: 'none',
                  borderRadius: '4px',
                  cursor: 'pointer',
                  fontWeight: 600,
                }}
              >
                {loading ? 'Inspecting...' : 'Inspect & Lint'}
              </button>
            </div>

            {inspection && (
              <div
                style={{
                  marginTop: '8px',
                  padding: '12px',
                  backgroundColor: '#fafafa',
                  borderRadius: '6px',
                  border: '1px solid #e0e0e0',
                  display: 'flex',
                  flexDirection: 'column',
                  gap: '12px',
                }}
              >
                <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
                  <div style={{ display: 'flex', gap: '8px', alignItems: 'center' }}>
                    <span style={{ fontWeight: 600, fontSize: '0.9rem' }}>Compliance Gate:</span>
                    {getStatusBadge(inspection.complianceStatus)}
                  </div>
                  <div style={{ fontSize: '0.85rem', color: '#616161' }}>
                    Signature: <strong>{inspection.validSignature ? 'VALID' : 'INVALID'}</strong> ({inspection.signatureAlgorithm})
                  </div>
                </div>

                {/* Security Flaws */}
                {inspection.securityFlaws.length > 0 && (
                  <div style={{ display: 'flex', flexDirection: 'column', gap: '6px' }}>
                    <span style={{ fontSize: '0.85rem', fontWeight: 600, color: '#b71c1c' }}>
                      Security Flaws Detected ({inspection.securityFlaws.length}):
                    </span>
                    {inspection.securityFlaws.map((flaw, idx) => (
                      <div
                        key={idx}
                        style={{
                          padding: '6px 10px',
                          backgroundColor: flaw.severity === 'CRITICAL' ? '#ffebee' : '#fff8e1',
                          borderLeft: `4px solid ${flaw.severity === 'CRITICAL' ? '#c62828' : '#f57f17'}`,
                          borderRadius: '2px',
                          fontSize: '0.8rem',
                        }}
                      >
                        <strong>[{flaw.severity}] {flaw.code}:</strong> {flaw.message}
                        <div style={{ color: '#555', marginTop: '2px' }}>💡 Remediation: {flaw.remediation}</div>
                      </div>
                    ))}
                  </div>
                )}

                {/* Token Claims Details */}
                <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: '10px' }}>
                  <div style={{ backgroundColor: '#fff', padding: '8px', borderRadius: '4px', border: '1px solid #eee' }}>
                    <span style={{ fontSize: '0.8rem', fontWeight: 600, color: '#1565c0' }}>Header:</span>
                    <pre style={{ margin: '4px 0 0', fontSize: '0.75rem' }}>{JSON.stringify(inspection.header, null, 2)}</pre>
                  </div>
                  <div style={{ backgroundColor: '#fff', padding: '8px', borderRadius: '4px', border: '1px solid #eee' }}>
                    <span style={{ fontSize: '0.8rem', fontWeight: 600, color: '#2e7d32' }}>Payload Claims:</span>
                    <pre style={{ margin: '4px 0 0', fontSize: '0.75rem' }}>{JSON.stringify(inspection.payload, null, 2)}</pre>
                  </div>
                </div>

                <div style={{ display: 'flex', gap: '16px', fontSize: '0.8rem', color: '#555' }}>
                  <span>TTL Remaining: <strong>{inspection.ttlSecondsRemaining}s</strong></span>
                  <span>Expires: <strong>{inspection.expiresAt ? new Date(inspection.expiresAt).toLocaleString() : 'N/A'}</strong></span>
                  <span>Clock Skew: <strong>{inspection.clockSkewSeconds}s</strong></span>
                </div>
              </div>
            )}
          </div>
        )}

        {/* TAB 2: RBAC ROUTE SIMULATOR */}
        {activeTab === 'simulate' && (
          <div style={{ display: 'flex', flexDirection: 'column', gap: '12px' }}>
            <div style={{ display: 'flex', gap: '10px' }}>
              <div style={{ flex: 1 }}>
                <label htmlFor="method-select" style={{ fontSize: '0.8rem', fontWeight: 600, display: 'block' }}>Method:</label>
                <select
                  id="method-select"
                  value={selectedMethod}
                  onChange={e => setSelectedMethod(e.target.value)}
                  style={{ width: '100%', padding: '6px', borderRadius: '4px', border: '1px solid #ccc' }}
                >
                  <option value="GET">GET</option>
                  <option value="POST">POST</option>
                  <option value="PUT">PUT</option>
                  <option value="DELETE">DELETE</option>
                </select>
              </div>
              <div style={{ flex: 3 }}>
                <label htmlFor="endpoint-select" style={{ fontSize: '0.8rem', fontWeight: 600, display: 'block' }}>Endpoint:</label>
                <select
                  id="endpoint-select"
                  value={selectedEndpoint}
                  onChange={e => setSelectedEndpoint(e.target.value)}
                  style={{ width: '100%', padding: '6px', borderRadius: '4px', border: '1px solid #ccc' }}
                >
                  <option value="/api/data">/api/data</option>
                  <option value="/api/admin/users">/api/admin/users</option>
                  <option value="/api/keys">/api/keys</option>
                  <option value="/login">/login (Auth Service)</option>
                  <option value="/jwks.json">/jwks.json</option>
                  <option value="/api/admin/sessions">/api/admin/sessions</option>
                </select>
              </div>
              <div style={{ alignSelf: 'flex-end' }}>
                <button
                  type="button"
                  onClick={handleSimulate}
                  disabled={loading}
                  style={{
                    padding: '7px 16px',
                    backgroundColor: '#2e7d32',
                    color: '#fff',
                    border: 'none',
                    borderRadius: '4px',
                    cursor: 'pointer',
                    fontWeight: 600,
                  }}
                >
                  {loading ? 'Evaluating...' : 'Simulate Access'}
                </button>
              </div>
            </div>

            {simResult && (
              <div
                style={{
                  marginTop: '10px',
                  padding: '12px',
                  borderRadius: '6px',
                  backgroundColor: simResult.allowed ? '#e8f5e9' : '#ffebee',
                  border: `1px solid ${simResult.allowed ? '#a5d6a7' : '#ef9a9a'}`,
                }}
              >
                <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
                  <span style={{ fontWeight: 700, fontSize: '0.95rem', color: simResult.allowed ? '#1b5e20' : '#b71c1c' }}>
                    {simResult.allowed ? '✓ ACCESS GRANTED' : '✖ ACCESS DENIED'}
                  </span>
                  <span style={{ fontSize: '0.8rem', color: '#666' }}>
                    {simResult.method} {simResult.targetService}{simResult.endpoint}
                  </span>
                </div>

                {simResult.matchedPolicy && (
                  <div style={{ marginTop: '8px', fontSize: '0.8rem' }}>
                    <strong>Policy Rule:</strong> {simResult.matchedPolicy.description}
                    {simResult.matchedPolicy.requiredRoles && (
                      <div>Required Roles: <code>{simResult.matchedPolicy.requiredRoles.join(', ')}</code></div>
                    )}
                    {simResult.matchedPolicy.requiredScopes && (
                      <div>Required Scopes: <code>{simResult.matchedPolicy.requiredScopes.join(', ')}</code></div>
                    )}
                  </div>
                )}

                <div style={{ marginTop: '8px', fontSize: '0.8rem' }}>
                  <strong>Evaluation Reasons:</strong>
                  <ul style={{ margin: '4px 0 0', paddingLeft: '20px' }}>
                    {simResult.reasons.map((r, i) => (
                      <li key={i}>{r}</li>
                    ))}
                  </ul>
                </div>
              </div>
            )}
          </div>
        )}

        {/* TAB 3: SANDBOX TOKEN MINTING */}
        {activeTab === 'mint' && (
          <div style={{ display: 'flex', flexDirection: 'column', gap: '12px' }}>
            <div style={{ fontSize: '0.85rem', color: '#555' }}>
              Quick Presets for Local Testing:
            </div>
            <div style={{ display: 'flex', gap: '8px', flexWrap: 'wrap' }}>
              <button
                type="button"
                onClick={() => handleMint({ roles: ['admin'], scope: 'ciam:read ciam:write' })}
                style={{ padding: '6px 12px', borderRadius: '4px', border: '1px solid #1976d2', background: '#e3f2fd', cursor: 'pointer', fontSize: '0.8rem' }}
              >
                👑 Mint Admin Token
              </button>
              <button
                type="button"
                onClick={() => handleMint({ roles: ['ciam:user'], scope: 'ciam:read' })}
                style={{ padding: '6px 12px', borderRadius: '4px', border: '1px solid #388e3c', background: '#e8f5e9', cursor: 'pointer', fontSize: '0.8rem' }}
              >
                👤 Mint Standard User Token
              </button>
              <button
                type="button"
                onClick={() => handleMint({ roles: ['admin'], alg: 'none' })}
                style={{ padding: '6px 12px', borderRadius: '4px', border: '1px solid #d32f2f', background: '#ffebee', cursor: 'pointer', fontSize: '0.8rem' }}
              >
                ⚠️ Mint Vulnerable alg:none Token
              </button>
              <button
                type="button"
                onClick={() => handleMint({ roles: ['ciam:user'], ttl: -5 })}
                style={{ padding: '6px 12px', borderRadius: '4px', border: '1px solid #f57c00', background: '#fff3e0', cursor: 'pointer', fontSize: '0.8rem' }}
              >
                ⏱ Mint Expired Token
              </button>
            </div>

            <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: '10px', marginTop: '6px' }}>
              <div>
                <label htmlFor="mint-subject" style={{ fontSize: '0.8rem', fontWeight: 600 }}>Subject (sub):</label>
                <input
                  id="mint-subject"
                  type="text"
                  value={mintSubject}
                  onChange={e => setMintSubject(e.target.value)}
                  style={{ width: '100%', padding: '6px', borderRadius: '4px', border: '1px solid #ccc' }}
                />
              </div>
              <div>
                <label htmlFor="mint-roles" style={{ fontSize: '0.8rem', fontWeight: 600 }}>Roles (comma-separated):</label>
                <input
                  id="mint-roles"
                  type="text"
                  value={mintRoles}
                  onChange={e => setMintRoles(e.target.value)}
                  style={{ width: '100%', padding: '6px', borderRadius: '4px', border: '1px solid #ccc' }}
                />
              </div>
              <div>
                <label htmlFor="mint-scope" style={{ fontSize: '0.8rem', fontWeight: 600 }}>Scope:</label>
                <input
                  id="mint-scope"
                  type="text"
                  value={mintScope}
                  onChange={e => setMintScope(e.target.value)}
                  style={{ width: '100%', padding: '6px', borderRadius: '4px', border: '1px solid #ccc' }}
                />
              </div>
              <div>
                <label htmlFor="mint-ttl" style={{ fontSize: '0.8rem', fontWeight: 600 }}>TTL (Minutes):</label>
                <input
                  id="mint-ttl"
                  type="number"
                  value={mintTtl}
                  onChange={e => setMintTtl(Number(e.target.value))}
                  style={{ width: '100%', padding: '6px', borderRadius: '4px', border: '1px solid #ccc' }}
                />
              </div>
              <div>
                <label htmlFor="mint-alg" style={{ fontSize: '0.8rem', fontWeight: 600 }}>Algorithm:</label>
                <select
                  id="mint-alg"
                  value={mintAlg}
                  onChange={e => setMintAlg(e.target.value)}
                  style={{ width: '100%', padding: '6px', borderRadius: '4px', border: '1px solid #ccc' }}
                >
                  <option value="HS256">HS256 (Default)</option>
                  <option value="HS384">HS384</option>
                  <option value="HS512">HS512</option>
                  <option value="none">none (Insecure)</option>
                </select>
              </div>
            </div>

            <button
              type="button"
              onClick={() => handleMint()}
              disabled={loading}
              style={{
                marginTop: '6px',
                padding: '8px 16px',
                backgroundColor: '#1976d2',
                color: '#fff',
                border: 'none',
                borderRadius: '4px',
                cursor: 'pointer',
                fontWeight: 600,
              }}
            >
              {loading ? 'Minting...' : 'Mint Custom Token & Inspect'}
            </button>
          </div>
        )}
      </div>
    </InfoCard>
  );
};

const ciamTokenCard = EntityCardBlueprint.make({
  name: 'ciam-token-card',
  params: {
    filter: 'kind:component',
    loader: async () => <EntityCiamTokenDebuggerCard />,
  },
});

export const ciamTokenModule = createFrontendModule({
  pluginId: 'catalog',
  extensions: [ciamTokenCard],
});

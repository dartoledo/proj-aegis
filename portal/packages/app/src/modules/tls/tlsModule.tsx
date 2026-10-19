import { useEffect, useState } from 'react';
import { createFrontendModule } from '@backstage/frontend-plugin-api';
import { EntityCardBlueprint } from '@backstage/plugin-catalog-react/alpha';
import { useEntity } from '@backstage/plugin-catalog-react';
import { InfoCard, LinkButton } from '@backstage/core-components';

interface LiveTlsStatus {
  serialNumber: string;
  expiryDate: string;
  daysRemaining: number;
  status: 'Healthy' | 'Warning' | 'Critical';
  hostPort: string;
}

const ROTATE_CERT_URL =
  '/create/templates/default/update-haproxy-tls-cert?formData=%7B%22certEntity%22%3A%22resource%3Adefault%2Fhaproxy-hello-world-tls%22%7D';

function statusBadgeColor(status: string): {
  bg: string;
  fg: string;
  border: string;
} {
  if (status === 'Healthy') {
    return { bg: '#e8f5e9', fg: '#1b5e20', border: '#4caf50' };
  }
  if (status === 'Critical') {
    return { bg: '#ffebee', fg: '#b71c1c', border: '#f44336' };
  }
  return { bg: '#fff3e0', fg: '#e65100', border: '#ff9800' };
}

const HaproxyTlsResiliencyCard = () => {
  const { entity } = useEntity();
  const [liveStatus, setLiveStatus] = useState<LiveTlsStatus | null>(null);

  const annotations = entity.metadata.annotations ?? {};
  const isTlsResource =
    entity.kind === 'Resource' && entity.spec?.type === 'tls-certificate';
  const isHelloWorldComponent =
    entity.metadata.name === 'hello-world-app' ||
    entity.metadata.name === 'haproxy-hello-world-tls';

  useEffect(() => {
    if (!isTlsResource && !isHelloWorldComponent) {
      return;
    }
    let mounted = true;
    fetch('http://localhost:7007/api/resiliency-tls/status')
      .then(res => (res.ok ? res.json() : null))
      .then(data => {
        if (mounted && data && data.serialNumber) {
          setLiveStatus(data);
        }
      })
      .catch(() => {
        // Fallback to catalog annotations when backend endpoint is not reachable in unit tests
      });
    return () => {
      mounted = false;
    };
  }, [isTlsResource, isHelloWorldComponent]);

  if (!isTlsResource && !isHelloWorldComponent) {
    return null;
  }

  const provider =
    annotations['resiliency.idp/cert-provider'] || 'Self-Signed (OpenSSL)';
  const version = liveStatus
    ? `v1 (Serial: ${liveStatus.serialNumber})`
    : annotations['resiliency.idp/cert-version'] || 'v1 (Serial: PENDING)';
  const expiry =
    liveStatus?.expiryDate ||
    annotations['resiliency.idp/cert-expiry'] ||
    '2026-11-04T00:00:00Z';
  const daysRemaining =
    liveStatus?.daysRemaining !== undefined
      ? String(liveStatus.daysRemaining)
      : annotations['resiliency.idp/days-remaining'] || '15';
  const status =
    liveStatus?.status ||
    annotations['resiliency.idp/cert-status'] ||
    'Warning';
  const haproxyHost =
    liveStatus?.hostPort ||
    annotations['resiliency.idp/haproxy-host'] ||
    '127.0.0.1:8443';
  const pemPath =
    annotations['resiliency.idp/haproxy-pem-path'] ||
    '/etc/haproxy/certs/hello-world.pem';

  const colors = statusBadgeColor(status);

  return (
    <InfoCard title="HAProxy Edge TLS Certificate Resiliency">
      <div style={{ display: 'flex', flexDirection: 'column', gap: '10px' }}>
        <div
          style={{
            display: 'flex',
            alignItems: 'center',
            justifyContent: 'space-between',
          }}
        >
          <strong>Health Status:</strong>
          <span
            style={{
              backgroundColor: colors.bg,
              color: colors.fg,
              border: `1px solid ${colors.border}`,
              borderRadius: '12px',
              padding: '2px 10px',
              fontWeight: 700,
              fontSize: '0.85rem',
            }}
          >
            {status} ({daysRemaining} days left)
          </span>
        </div>
        <div>
          <strong>Provider:</strong> {provider}
        </div>
        <div>
          <strong>Version / Serial:</strong> <code>{version}</code>
        </div>
        <div>
          <strong>Expiration Date:</strong> <code>{expiry}</code>
        </div>
        <div>
          <strong>HAProxy Endpoint:</strong> <code>https://{haproxyHost}</code>
        </div>
        <div>
          <strong>PEM Bundle Path:</strong> <code>{pemPath}</code>
        </div>
        <div
          style={{
            display: 'flex',
            gap: '12px',
            marginTop: '8px',
            alignItems: 'center',
          }}
        >
          <LinkButton
            color="primary"
            variant="contained"
            to={ROTATE_CERT_URL}
          >
            Rotate Certificate
          </LinkButton>
          <a
            href="http://localhost:7007/api/resiliency-tls/metrics"
            target="_blank"
            rel="noopener noreferrer"
            style={{ fontSize: '0.85rem', fontWeight: 600 }}
          >
            Prometheus Metrics
          </a>
        </div>
      </div>
    </InfoCard>
  );
};

const haproxyTlsCard = EntityCardBlueprint.make({
  name: 'haproxy-tls-card',
  params: {
    filter: 'kind:resource,component',
    loader: async () => <HaproxyTlsResiliencyCard />,
  },
});

export const tlsModule = createFrontendModule({
  pluginId: 'catalog',
  extensions: [haproxyTlsCard],
});

import React from 'react';
import { fireEvent, render, screen, waitFor } from '@testing-library/react';
import { DomainsEndpointsView } from './DomainsEndpointsView';
import { SoftwareInventoryView } from './SoftwareInventoryView';
import { InfrastructureInventoryView } from './InfrastructureInventoryView';
import { TeamsInventoryView } from './TeamsInventoryView';
import { AttackPathGraphView } from './AttackPathGraphView';
import { FALLBACK_ENDPOINTS, fetchUnifiedInventoryData } from './inventoryData';

jest.mock('@backstage/core-components', () => ({
  Page: ({ children }: { children: React.ReactNode }) => <div data-testid="page">{children}</div>,
  Header: ({ title, children }: { title?: string; children?: React.ReactNode }) => (
    <header>
      {title && <h1>{title}</h1>}
      {children}
    </header>
  ),
  Content: ({ children }: { children: React.ReactNode }) => <div data-testid="content">{children}</div>,
  InfoCard: ({ title, children }: { title?: string; children?: React.ReactNode }) => (
    <div data-testid="infocard">
      {title && <h3>{title}</h3>}
      {children}
    </div>
  ),
  Link: ({ to, children }: { to: string; children: React.ReactNode }) => (
    <a href={to}>{children}</a>
  ),
}));

describe('Unified Inventory', () => {
  let originalFetch: typeof global.fetch;

  beforeEach(() => {
    originalFetch = global.fetch;
    global.fetch = jest.fn().mockRejectedValue(new Error('offline')) as unknown as typeof global.fetch;
  });

  afterEach(() => {
    global.fetch = originalFetch;
  });

  test('fetchUnifiedInventoryData returns fallback data when backend is offline', async () => {
    const result = await fetchUnifiedInventoryData();
    expect(result.isLiveBackend).toBe(false);
    expect(result.endpoints.length).toBe(FALLBACK_ENDPOINTS.length);
  });

  test('fetchUnifiedInventoryData extracts nested certificate fields and handles partial backend failure', async () => {
    global.fetch = jest.fn(async (url: string) => {
      if (url.includes('/api/living-cmdb/fleet-graph')) {
        return { ok: false, status: 500 } as Response;
      }
      if (url.includes('/api/ssl-tracker/fleet')) {
        return {
          ok: true,
          json: async () => ({
            endpoints: [
              {
                endpointId: 'ep-1',
                serviceName: 'aegis-ui',
                entityRef: 'component:default/aegis-ui',
                environment: 'prod',
                endpointUrl: 'https://ui.aegis.io',
                sniHostname: 'ui.aegis.io',
                providerType: 'gcp-cloud-lb',
                certificate: {
                  issuerCn: 'GTS CA 1C3',
                  publicKeyAlgorithm: 'ECDSA',
                  publicKeyBits: 256,
                  serialNumberHex: 'AA:BB',
                  daysRemaining: 88,
                  complianceStatus: 'COMPLIANT',
                },
              },
            ],
          }),
        } as Response;
      }
      return { ok: false, status: 404 } as Response;
    }) as unknown as typeof global.fetch;

    const result = await fetchUnifiedInventoryData();
    expect(result.endpoints[0].issuerCn).toBe('GTS CA 1C3');
    expect(result.endpoints[0].daysRemaining).toBe(88);
    expect(result.software.length).toBeGreaterThan(0);
  });

  test('DomainsEndpointsView renders endpoints and filters by search and environment', async () => {
    render(<DomainsEndpointsView />);

    await waitFor(() => {
      expect(screen.getByText('Unified Inventory — Domains & Endpoints')).toBeInTheDocument();
    });

    await waitFor(() => {
      expect(document.body.textContent).toContain('aegis-ui.prod.aegisplatform.io');
    });

    const searchInput = screen.getByLabelText('Search endpoints') as HTMLInputElement;
    fireEvent.change(searchInput, { target: { value: 'db.aegisplatform.io' } });

    await waitFor(() => {
      expect(document.body.textContent).toContain('db.aegisplatform.io');
    });

    await waitFor(() => {
      expect(document.body.textContent).not.toContain('aegis-ui.prod.aegisplatform.io');
    });
  });

  test('DomainsEndpointsView Active Endpoint Prober probes list and displays SSL, WAF, and Zscaler/Public accessibility', async () => {
    global.fetch = jest.fn(async (url: string) => {
      if (url.includes('/api/ssl-tracker/probe-active')) {
        return {
          ok: true,
          json: async () => ({
            networkContext: {
              sourceIp: '165.225.72.45',
              isZscalerSourceIp: true,
              networkOrigin: 'PRIVATE_NETWORK_ZSCALER',
              detectionReason: 'Source IP 165.225.72.45 matched Zscaler Public Service Edge CIDR 165.225.0.0/16',
            },
            totalProbed: 1,
            reachableCount: 1,
            publicAccessibleCount: 0,
            wafProtectedCount: 1,
            results: [
              {
                targetInput: 'https://login.aegis.cloud.goog',
                endpointId: 'component:default/aegis-ui:prod:login-aegis-cloud-goog',
                endpointUrl: 'https://login.aegis.cloud.goog',
                hostname: 'login.aegis.cloud.goog',
                port: 443,
                reachable: true,
                sourceIp: '165.225.72.45',
                isZscalerSourceIp: true,
                probeNetworkOrigin: 'PRIVATE_NETWORK_ZSCALER',
                accessibleFromPublicInternet: false,
                exposureScope: 'strictly-private',
                wafProvider: 'Akamai',
                wafDetected: true,
                wafEvidence: ['header: server=AkamaiGHost'],
                httpStatusCode: 200,
                sslDetails: {
                  subjectCn: 'login.aegis.cloud.goog',
                  subjectDn: 'CN=login.aegis.cloud.goog',
                  sanDnsNames: ['login.aegis.cloud.goog'],
                  issuerCn: 'GTS CA 1C3',
                  issuerOrg: 'Google Trust Services LLC',
                  serialNumberHex: '0A:1B:2C:3D',
                  notBefore: '2026-11-01T00:00:00Z',
                  notAfter: '2027-02-01T00:00:00Z',
                  daysRemaining: 67,
                  expiryStatus: 'HEALTHY',
                  signatureAlgorithm: 'sha256WithRSAEncryption',
                  signatureHashAlgorithm: 'SHA256',
                  publicKeyAlgorithm: 'RSA',
                  publicKeyBits: 2048,
                  complianceStatus: 'COMPLIANT',
                },
                probedAt: '2026-11-26T00:00:00Z',
              },
            ],
          }),
        } as Response;
      }
      return { ok: false, status: 404 } as Response;
    }) as unknown as typeof global.fetch;

    render(<DomainsEndpointsView />);

    const endpointsArea = screen.getByLabelText('Active probe endpoints list');
    fireEvent.change(endpointsArea, { target: { value: 'https://login.aegis.cloud.goog' } });
    const ipInput = screen.getByLabelText('Source IP override');
    fireEvent.change(ipInput, { target: { value: '165.225.72.45' } });

    const probeBtn = screen.getByText('Probe Endpoints & Persist to CMDB');
    fireEvent.click(probeBtn);

    await waitFor(() => {
      expect(document.body.textContent).toContain('PRIVATE_NETWORK_ZSCALER');
      expect(document.body.textContent).toContain('0A:1B:2C:3D');
      expect(document.body.textContent).toContain('sha256WithRSAEncryption (RSA-2048)');
      expect(document.body.textContent).toContain('Akamai');
      expect(document.body.textContent).toContain('No (Within Private Network — Zscaler IP)');
    });
  });

  test('DomainsEndpointsView CSV Loader submits CSV with required endpoint, service_name, environment and displays summary', async () => {
    global.fetch = jest.fn(async (url: string) => {
      if (url.includes('/api/ssl-tracker/import-csv')) {
        return {
          ok: true,
          json: async () => ({
            totalDataRows: 2,
            importedCount: 1,
            probedCount: 1,
            probedReachableCount: 1,
            publicAccessibleCount: 1,
            wafProtectedCount: 1,
            errors: [
              {
                rowNumber: 3,
                message: "Row 3: Missing required 'environment' value for endpoint 'https://no-env.aegis.io'.",
              },
            ],
          }),
        } as Response;
      }
      return { ok: false, status: 404 } as Response;
    }) as unknown as typeof global.fetch;

    render(<DomainsEndpointsView />);

    const csvTextarea = screen.getByLabelText('Domains CSV content');
    fireEvent.change(csvTextarea, {
      target: {
        value: [
          'endpoint,service_name,environment',
          'https://auth.aegis.io,aegis-auth,prod',
          'https://no-env.aegis.io,aegis-auth,',
        ].join('\n'),
      },
    });

    const importBtn = screen.getByText('Import CSV to PostgreSQL CMDB');
    fireEvent.click(importBtn);

    await waitFor(() => {
      expect(document.body.textContent).toContain('CSV Import Summary:');
      expect(document.body.textContent).toContain("Missing required 'environment' value");
    });
  });

  test('SoftwareInventoryView renders software taxonomy and filters by status', async () => {
    render(<SoftwareInventoryView />);

    await waitFor(() => {
      expect(screen.getByText('Unified Inventory — Software')).toBeInTheDocument();
    });

    await waitFor(() => {
      expect(screen.getByText('Node.js')).toBeInTheDocument();
    });

    const statusFilter = screen.getByLabelText('Status filter') as HTMLSelectElement;
    fireEvent.change(statusFilter, { target: { value: 'CRITICAL' } });

    await waitFor(() => {
      expect(screen.getByText('Node.js')).toBeInTheDocument();
    });

    expect(screen.queryByText('Express')).not.toBeInTheDocument();
  });

  test('InfrastructureInventoryView renders 7-layer infrastructure and drift table', async () => {
    render(<InfrastructureInventoryView />);

    await waitFor(() => {
      expect(screen.getByText('Unified Inventory — Infrastructure')).toBeInTheDocument();
    });

    await waitFor(() => {
      expect(document.body.textContent).toContain('Cloudflare CDN');
    });

    await waitFor(() => {
      expect(document.body.textContent).toContain('gce-auth-redis-ephemeral-02');
    });

    await waitFor(() => {
      expect(document.body.textContent).toContain('cloudflare-api-poll');
    });

    expect(document.body.textContent).toContain('Active GitOps Drifts');
    expect(screen.queryByText('Sync to Git')).not.toBeInTheDocument();
    expect(screen.queryByText('Enforce Git')).not.toBeInTheDocument();

    const statusFilter = screen.getByLabelText('Status filter') as HTMLSelectElement;
    fireEvent.change(statusFilter, { target: { value: 'DRIFTED' } });

    await waitFor(() => {
      expect(document.body.textContent).toContain('Cloudflare CDN');
    });

    await waitFor(() => {
      expect(document.body.textContent).not.toContain('HAProxy');
    });
  });

  test('TeamsInventoryView renders App Team, SRE Team, and service squads with filtering', async () => {
    render(<TeamsInventoryView />);

    await waitFor(() => {
      expect(screen.getByText('Unified Inventory — Teams & Ownership')).toBeInTheDocument();
    });

    expect(screen.getByText('App Team')).toBeInTheDocument();
    expect(screen.getByText('SRE Team')).toBeInTheDocument();

    const teamTypeFilter = screen.getByLabelText('Team type filter') as HTMLSelectElement;
    fireEvent.change(teamTypeFilter, { target: { value: 'SERVICE_SQUAD' } });

    await waitFor(() => {
      expect(screen.getByText('App Team')).toBeInTheDocument();
    });

    expect(screen.queryByText('core-services')).not.toBeInTheDocument();
  });

  test('AttackPathGraphView renders N-Hop attack paths and What-If remediation simulator', async () => {
    render(<AttackPathGraphView />);

    await waitFor(() => {
      expect(document.body.textContent).toContain('Unified Inventory — Infrahub Attack-Path Graph');
    });

    await waitFor(() => {
      expect(document.body.textContent).toContain('92/100');
    });

    const patchButton = screen.getByText('Patch KEV CVE');
    fireEvent.click(patchButton);

    await waitFor(() => {
      expect(document.body.textContent).toContain('62/100');
    });

    const resetButton = screen.getByText('Reset');
    fireEvent.click(resetButton);

    await waitFor(() => {
      expect(document.body.textContent).toContain('92/100');
    });
  });
});

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

    const syncButtons = screen.getAllByText('Sync to Git');
    fireEvent.click(syncButtons[0]);

    await waitFor(() => {
      expect(document.body.textContent).toContain('RECONCILED_TO_GIT');
    });

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

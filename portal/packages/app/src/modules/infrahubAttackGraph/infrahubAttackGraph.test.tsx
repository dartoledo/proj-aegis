import { fireEvent, render, screen, waitFor } from '@testing-library/react';
import { EntityInfrahubAttackGraphCard } from './infrahubAttackGraphModule';

jest.mock('@backstage/core-components', () => ({
  InfoCard: ({ title, children }: any) => (
    <div>
      <h3>{title}</h3>
      {children}
    </div>
  ),
}));

jest.mock('@backstage/plugin-catalog-react', () => ({
  useEntity: () => ({
    entity: {
      kind: 'Component',
      metadata: {
        uid: 'random-uuid-9999',
        namespace: 'default',
        name: 'aegis-auth',
      },
    },
  }),
}));

describe('EntityInfrahubAttackGraphCard', () => {
  let originalFetch: typeof global.fetch;

  beforeEach(() => {
    originalFetch = global.fetch;
    global.fetch = jest.fn().mockRejectedValue(new Error('offline'));
  });

  afterEach(() => {
    global.fetch = originalFetch;
  });

  it('resolves entityRef from kind:namespace/name instead of metadata.uid and renders fallback scorecard when offline', async () => {
    render(<EntityInfrahubAttackGraphCard />);

    await waitFor(() => {
      expect(document.body.textContent).toContain('Risk Score: 68');
    });
    expect(document.body.textContent).toContain('reachable_kev_cve_count: 1');
  });

  it('supports What-If simulation and N-Hop Attack-Path Graph tab with graph nodes', async () => {
    render(<EntityInfrahubAttackGraphCard />);

    await waitFor(() => {
      expect(document.body.textContent).toContain('reachable_kev_cve_count: 1');
    });

    const patchBtn = screen.getByText('Patch KEV CVE');
    fireEvent.click(patchBtn);

    await waitFor(() => {
      expect(document.body.textContent).toContain('reachable_kev_cve_count: 0');
    });

    const resetBtn = screen.getByText('Reset');
    fireEvent.click(resetBtn);

    await waitFor(() => {
      expect(document.body.textContent).toContain('reachable_kev_cve_count: 1');
    });

    const nHopTab = screen.getByText('N-Hop Attack-Path Graph');
    fireEvent.click(nHopTab);

    await waitFor(() => {
      expect(document.body.textContent).toContain('Graph Nodes');
    });
    expect(document.body.textContent).toContain('auth.aegis.cloud.goog');
  });
});

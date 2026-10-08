import { createFrontendModule } from '@backstage/frontend-plugin-api';
import { EntityCardBlueprint } from '@backstage/plugin-catalog-react/alpha';
import { InfoCard } from '@backstage/core-components';

const MockSonarQubeWidget = () => (
  <InfoCard title="SonarQube Code Quality (Mock)">
    <div style={{ display: 'flex', flexDirection: 'column', gap: '8px' }}>
      <div><strong>Status:</strong> <span style={{ color: 'green' }}>Passed</span></div>
      <div><strong>Bugs:</strong> 0</div>
      <div><strong>Vulnerabilities:</strong> 0</div>
      <div><strong>Code Smells:</strong> 2</div>
      <div><strong>Coverage:</strong> 94.5%</div>
      <div><strong>Duplications:</strong> 1.2%</div>
    </div>
  </InfoCard>
);

const sonarqubeCard = EntityCardBlueprint.make({
  name: 'mock-sonarqube-card',
  params: {
    filter: 'kind:component',
    loader: async () => <MockSonarQubeWidget />,
  },
});

export const qualityModule = createFrontendModule({
  pluginId: 'catalog',
  extensions: [sonarqubeCard],
});

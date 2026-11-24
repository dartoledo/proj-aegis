import { createFrontendModule } from '@backstage/frontend-plugin-api';
import { HomePageWidgetBlueprint } from '@backstage/plugin-home-react/alpha';
import { MarkdownContent } from '@backstage/core-components';
import { Actions, Content, ContextProvider, Settings } from './RandomJokeWidget';

const content = `
## Welcome to the Aegis Unified Inventory Portal 👋

Your single place to manage all software, services, and documentation.

### Unified Inventory Views

- **[Domains / Endpoints](/inventory/domains)** — Multi-environment ingress FQDNs, 3-tier exposure scope, split-horizon DNS, and X.509 certificate compliance
- **[Software](/inventory/software)** — 13-category software taxonomy, SBOM PURL / CPE 2.3 crosswalk, endoflife.date lifecycle tracking, and CVE posture
- **[Infrastructure](/inventory/infrastructure)** — 7-layer infrastructure topology, GitOps drift detection, and shadow resource telemetry
- **[Teams](/inventory/teams)** — App Team vs SRE Team governance split, service delivery squads, and owned asset rollup

### Quick Start

- **Explore the catalog** — Browse all your organization's software in
  the [Software Catalog](/catalog)
- **Create something new** — Use a [Software Template](/create) to
  scaffold a new project in minutes
`;

const gettingStartedWidget = HomePageWidgetBlueprint.make({
  name: 'getting-started',
  params: {
    name: 'GettingStarted',
    title: 'Aegis Unified Inventory',
    description: 'Welcome to the Aegis Unified Inventory Portal — explore domains, software, infrastructure, and teams',
    components: async () => ({
      Content: () => <MarkdownContent content={content} />,
    }),
  },
});

const randomJokeWidget = HomePageWidgetBlueprint.make({
  name: 'random-joke',
  params: {
    name: 'HomePageRandomJoke',
    title: 'Random Joke',
    description: 'Shows a random programming joke',
    components: async () => ({
      Content,
      Settings,
      Actions,
      ContextProvider,
    }),
    layout: {
      height: { minRows: 4 },
      width: { minColumns: 3 },
    },
    settings: {
      schema: {
        title: 'Random Joke settings',
        type: 'object',
        properties: {
          defaultCategory: {
            title: 'Category',
            type: 'string',
            enum: ['any', 'programming', 'dad'],
            default: 'any',
          },
        },
      },
    },
  },
});

export const homeModule = createFrontendModule({
  pluginId: 'home',
  extensions: [gettingStartedWidget, randomJokeWidget],
});

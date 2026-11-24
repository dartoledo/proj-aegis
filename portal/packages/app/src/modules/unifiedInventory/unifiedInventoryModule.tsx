import { PageBlueprint, createFrontendPlugin, createRouteRef } from '@backstage/frontend-plugin-api';
import LanguageIcon from '@material-ui/icons/Language';
import CodeIcon from '@material-ui/icons/Code';
import StorageIcon from '@material-ui/icons/Storage';
import PeopleIcon from '@material-ui/icons/People';
import { DomainsEndpointsView } from './DomainsEndpointsView';
import { SoftwareInventoryView } from './SoftwareInventoryView';
import { InfrastructureInventoryView } from './InfrastructureInventoryView';
import { TeamsInventoryView } from './TeamsInventoryView';
import SecurityIcon from '@material-ui/icons/Security';
import { AttackPathGraphView } from './AttackPathGraphView';

export const domainsRouteRef = createRouteRef();
export const softwareRouteRef = createRouteRef();
export const infrastructureRouteRef = createRouteRef();
export const teamsRouteRef = createRouteRef();
export const attackPathsRouteRef = createRouteRef();

const domainsEndpointsPage = PageBlueprint.make({
  name: 'domains',
  params: {
    path: '/inventory/domains',
    routeRef: domainsRouteRef,
    title: 'Domains / Endpoints',
    icon: <LanguageIcon />,
    noHeader: true,
    loader: async () => <DomainsEndpointsView />,
  },
});

const softwareInventoryPage = PageBlueprint.make({
  name: 'software',
  params: {
    path: '/inventory/software',
    routeRef: softwareRouteRef,
    title: 'Software Inventory',
    icon: <CodeIcon />,
    noHeader: true,
    loader: async () => <SoftwareInventoryView />,
  },
});

const infrastructureInventoryPage = PageBlueprint.make({
  name: 'infrastructure',
  params: {
    path: '/inventory/infrastructure',
    routeRef: infrastructureRouteRef,
    title: 'Infrastructure Inventory',
    icon: <StorageIcon />,
    noHeader: true,
    loader: async () => <InfrastructureInventoryView />,
  },
});

const teamsInventoryPage = PageBlueprint.make({
  name: 'teams',
  params: {
    path: '/inventory/teams',
    routeRef: teamsRouteRef,
    title: 'Teams Inventory',
    icon: <PeopleIcon />,
    noHeader: true,
    loader: async () => <TeamsInventoryView />,
  },
});

const attackPathsPage = PageBlueprint.make({
  name: 'attack-paths',
  params: {
    path: '/inventory/attack-paths',
    routeRef: attackPathsRouteRef,
    title: 'Attack-Path Graph',
    icon: <SecurityIcon />,
    noHeader: true,
    loader: async () => <AttackPathGraphView />,
  },
});

export const unifiedInventoryPlugin = createFrontendPlugin({
  pluginId: 'unified-inventory',
  extensions: [domainsEndpointsPage, softwareInventoryPage, infrastructureInventoryPage, teamsInventoryPage, attackPathsPage],
  routes: {
    domains: domainsRouteRef,
    software: softwareRouteRef,
    infrastructure: infrastructureRouteRef,
    teams: teamsRouteRef,
    attackPaths: attackPathsRouteRef,
  },
});

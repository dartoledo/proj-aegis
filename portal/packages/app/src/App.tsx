import { createApp } from '@backstage/frontend-defaults';
import catalogPlugin from '@backstage/plugin-catalog/alpha';
import { navModule } from './modules/nav';
import { homeModule } from './modules/home';
import { qualityModule } from './modules/quality';
import { tlsModule } from './modules/tls';
import { k8sOpsModule } from './modules/k8sOps';
import { sslTrackerModule } from './modules/sslTracker';
import { ciamTokenModule } from './modules/ciamToken';
import { harborEolModule } from './modules/harborEol';
import { gcpPostureModule } from './modules/gcpPosture';
import { livingCmdbModule } from './modules/livingCmdb';
import { cveIntelModule } from './modules/cveIntel';

import notificationsPlugin from '@backstage/plugin-notifications/alpha';

export default createApp({
  features: [
    catalogPlugin,
    navModule,
    homeModule,
    qualityModule,
    tlsModule,
    k8sOpsModule,
    sslTrackerModule,
    ciamTokenModule,
    harborEolModule,
    gcpPostureModule,
    livingCmdbModule,
    cveIntelModule,
    notificationsPlugin,
  ],
});



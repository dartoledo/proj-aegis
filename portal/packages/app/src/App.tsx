import { createApp } from '@backstage/frontend-defaults';
import catalogPlugin from '@backstage/plugin-catalog/alpha';
import { navModule } from './modules/nav';
import { homeModule } from './modules/home';
import { qualityModule } from './modules/quality';

import notificationsPlugin from '@backstage/plugin-notifications/alpha';

export default createApp({
  features: [catalogPlugin, navModule, homeModule, qualityModule, notificationsPlugin],
});

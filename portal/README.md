# Project Aegis Developer Portal ([Backstage](https://backstage.io))

This is the Backstage Internal Developer Portal (IDP) for Project Aegis, including the **HAProxy Edge TLS Certificate Visibility & Zero-Downtime Rotation** workflow.

## Quick Start

1. **Start the HAProxy + Hello-World TLS Sandbox:**
   ```sh
   bash ../demo/haproxy/start-sandbox.sh --reset
   ```

2. **Start the Backstage Portal:**
   ```sh
   yarn install
   yarn start
   ```
   - Frontend UI: `http://localhost:3000`
   - Backend API: `http://localhost:7007`
   - Prometheus TLS Expiry Metrics: `http://localhost:7007/api/resiliency-tls/metrics`
   - Live TLS Handshake Status JSON: `http://localhost:7007/api/resiliency-tls/status`

## HAProxy TLS Certificate Rotation Workflow

- **Catalog Entities:** `component:default/hello-world-app`, `resource:default/haproxy-hello-world-tls`, and `group:default/resiliency-group` (loaded from `../demo/haproxy/catalog-info.yaml`).
- **Scaffolder Template:** `update-haproxy-tls-cert` (`examples/haproxy-tls-template/template.yaml`) supports both custom certificate/key uploads and auto-generated self-signed X.509 certificates.
- **Custom Scaffolder Actions (`packages/backend/src/modules/haproxyTlsModule.ts`):**
  - `resiliency:haproxy:build-pem` / `resiliency:cert:bundle-haproxy-pem`: Validates X.509 key-pair match via OpenSSL and builds a combined `.pem` bundle.
  - `resiliency:haproxy:deploy-cert`: Pushes the `.pem` bundle to HAProxy and performs a zero-downtime in-memory hot-swap over the HAProxy Runtime Socket.
  - `resiliency:haproxy:verify-tls`: Verifies the new certificate serial number on the live TLS endpoint.
- **Frontend Card (`packages/app/src/modules/tls/tlsModule.tsx`):** Displays certificate health badge, days remaining, active serial number, and a **Rotate Certificate** button pre-populated with `resource:default/haproxy-hello-world-tls`.

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

## PostgreSQL 9-Table CMDB & SSL Tracker Schema (`packages/backend/src/modules/aegisPostgresStore.ts`)

All CMDB inventory, software EOL/CVE crosswalks, and multi-environment domain/TLS endpoints are persisted in PostgreSQL across 9 canonical tables (defined in `../demo/db-init/init.sql` and managed via Knex in `aegisPostgresStore.ts`):

- **Owner (`team_owners`):** Primary key `team_id` (`app-team`, `sre-team`). Referenced via foreign key `owner_team_id` by both `cmdb_component_nodes` and `tracked_endpoints`.
- **Service (`cmdb_services`):** Primary key `ci_id` (`CI-AEGIS-1001`..`1005`), storing `entity_ref`, `service_name`, `owner_team` (service squad), read-only `drift_status`, `drift_items` (`JSONB`), and `blast_radius` (`JSONB`).
- **Infrastructure & Software (`cmdb_component_nodes`):** Primary key `component_id`, foreign keys `ci_id -> cmdb_services(ci_id) ON DELETE CASCADE` and `owner_team_id -> team_owners(team_id)`. Distinguishes `domain = 'INFRASTRUCTURE'` (7 architectural layers / 20 types, owned by `sre-team`) and `domain = 'SOFTWARE'` (13 categories, split between `sre-team` for OS/Containerization and `app-team` for application stack).
- **Software Version Crosswalk & Advisories (`software_version_crosswalk`, `public_eol_cycles`, `public_cve_ranges`):** `1:1` extension of software nodes (`component_id -> cmdb_component_nodes(component_id) ON DELETE CASCADE`) storing `purl`, `cpe23_uri`, `eol_product_slug`, `eol_cycle_key`, and `semver_sort_tuple` (`INT[]`), joining against `public_eol_cycles(eol_product_slug, cycle)` and `public_cve_ranges(cve_id)`.
- **Domains & Certificates (`tracked_endpoints`, `certificate_inventory`):** `tracked_endpoints` (`id` PK, `endpoint_uid` unique, `owner_team_id -> team_owners(team_id)`) stores multi-environment FQDNs/URLs and links `1:N` to `certificate_inventory` (`endpoint_id -> tracked_endpoints(id) ON DELETE CASCADE`, unique on `(endpoint_id, serial_number)`), synced bidirectionally with `GET /api/ssl-tracker/fleet`.
- **Live Database Health Endpoint:** `GET http://localhost:7007/api/living-cmdb/db-status` returns all 9 table names and live PostgreSQL row counts.

## Active Endpoint Prober & Domains CSV Loader (`DomainsEndpointsView.tsx`)

- **Active Endpoint Prober (`POST /api/ssl-tracker/probe-active`):**
  - Probes real endpoints via live TLS handshake & HTTPS headers to populate **SSL Expiry (`notAfter`, `daysRemaining`)**, **Subject CN & SANs**, **Issuer**, **Serial Number**, **Signature Algorithm & Key Size**, **WAF Protection** (`Akamai`, `Fastly`, `Cloud Armor`), and **Public Internet Accessibility** (classifying Zscaler source IPs as `PRIVATE_NETWORK_ZSCALER` and non-Zscaler source IPs as `PUBLIC_INTERNET`).
- **Domains CSV Loader (`POST /api/ssl-tracker/import-csv` & `GET /api/ssl-tracker/sample-domains.csv`):**
  - Bulk-loads domain lists from `.csv` files into PostgreSQL (`tracked_endpoints`, `certificate_inventory`, `cmdb_services`, and Layer 1 `DOMAIN_ENDPOINT` nodes in `cmdb_component_nodes`).
  - **Required CSV Columns:** `endpoint`, `service_name`, `environment` (`dev`, `stg`, `stress-test`, `preprod`, `prod`).
  - **Optional CSV Columns:** `endpoint_key`, `provider_type`, `exposure_scope`, `owner_team_id`, `notes`.

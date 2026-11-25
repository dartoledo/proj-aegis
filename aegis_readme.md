# Project Aegis 🛡️ 

**The Internal Developer Platform (IDP) for our Customer Identity & Access Management (CIAM) Ecosystem**

Welcome to Project Aegis! This platform, built on top of [Spotify's Backstage](https://backstage.io/), is designed to reduce cognitive load, standardize security practices, and accelerate the delivery of our CIAM microservices.

## 📖 Overview

The CIAM ecosystem consists of numerous high-security microservices, databases, and third-party integrations. Project Aegis serves as the single pane of glass for our developers, abstracting away infrastructure complexity while enforcing strict SRE and security standards through "Golden Paths."

## 🏗️ Architecture & Philosophy

Project Aegis follows a strict **GitOps-first** philosophy. Backstage is NOT an infrastructure deployment tool; it is a developer portal and a **commit generator**.

1. **Self-Service UI (Backstage):** Developers request a new service or resource.
2. **Scaffold & Commit:** Aegis generates the boilerplate code, **Dagger** CI pipelines (as code), and Kubernetes manifests, committing them directly to our Git repositories.
3. **Continuous Integration (Dagger):** GitLab CI triggers our Dagger pipelines, executing complex testing and build logic safely and deterministically.
4. **Deploy (GitOps):** Our GitOps controllers (e.g., ArgoCD/Flux) detect the changes and reconcile the infrastructure in our Kubernetes clusters.

## ✨ Key Capabilities

*   **Software Catalog:** The single source of truth for all CIAM microservices, APIs, databases (Redis, PostgreSQL), and data pipelines. It tracks ownership, dependencies, and lifecycle states.
*   **Golden Path Scaffolding:** Standardized templates for creating new services (e.g., "Secure Spring Boot CIAM Service"). These templates automatically inject required security headers, OAuth libraries, and code-based CI pipelines using **Dagger** (replacing extensive YAML).
*   **Integrated Quality Gates:** Quality and security are built-in from day one, not treated as an afterthought. Backstage integrates directly with SonarQube, Snyk, and our Dagger CI pipelines to surface test coverage, code smells, and vulnerability scanning results right on the component dashboard—shifting quality checks left. Check the components in Aegis Backstage to see this in action.

*   **TechDocs:** "Docs-like-code" approach. Architecture diagrams, threat models, and runbooks are stored as Markdown alongside the source code and rendered centrally here.
*   **Kubernetes Visibility:** Developers get a service-centric view of their pods, deployments, and cluster health directly in the portal, reducing the need for direct cluster access.
*   **Edge TLS Certificate Visibility & Zero-Downtime Rotation:** Live TLS handshake probing, certificate expiry tracking, Prometheus reliability metrics, and one-click Scaffolder workflows that validate X.509 key-pair modulus matches, bundle `.pem` artifacts, and hot-swap certificates in HAProxy memory via the HAProxy Runtime Socket without dropping active connections.
*   **Multi-Environment & Multi-Provider SSL/TLS Compliance Tracker:** End-to-end 5-pillar X.509 compliance engine across `dev`, `stg` (`1:N` sub-endpoints), `stress-test`, `preprod`, and `prod` for **Google Cloud Load Balancer (`gcp-cloud-lb`)**, **Private Cloud Load Balancer (`private-cloud-lb`)**, and **HAProxy Edge (`haproxy-edge`)**, featuring interactive Quality Gate certificate diffs, rotation lineage history, and one-click weak-crypto remediation.

## 🎯 The Value of Accuracy (Why This Matters)

To get the full value out of Project Aegis, teams must maintain the accuracy of their `catalog-info.yaml` files and TechDocs. 
* **Dependency Mapping:** Accurate `dependsOn` and `owner` definitions prevent orphaned services and allow us to rapidly trace the blast radius of a security vulnerability or outage across the entire CIAM ecosystem.
* **Kubernetes Mapping:** Proper `backstage.io/kubernetes-label-selector` annotations are critical. If they fall out of sync with your actual deployment manifests, you lose live visibility into your pod health and autoscaling metrics.
* **TechDocs (Docs-like-Code):** Keeping documentation alongside the source code in `docs/` and generating it natively ensures that runbooks, APIs, and threat models evolve at the same speed as the code. Outdated docs lead to incident response delays, so treat your `mkdocs.yml` configurations with the same rigor as your application logic.

## 🚀 Getting Started

### Prerequisites
* Node.js (v22+)
* Yarn (v4.13.0+)
* Podman (for daemonless image building)
* K3s (for local Kubernetes deployment)
* Access to our internal GitHub/GitLab organization

### Local Developer Portal (Backstage)

We have successfully provisioned a local instance of the Aegis Developer Portal (Backstage) using Node v22.

1. **Install Node 22 & Yarn:**
   ```bash
   nvm install 22
   nvm use 22
   npm install -g yarn
   ```

2. **Install dependencies and start Backstage:**
   ```bash
   cd portal
   yarn install
   yarn start
   ```
   *The Backstage application will be running at `http://localhost:3000`.*

3. **Explore the Software Catalog:**
   The `catalog-info.yaml` definitions for the demo microservices are automatically loaded into Backstage on startup. Head over to the catalog page to see the dependency graph of `Aegis UI`, `Aegis Auth`, `Aegis Backend`, `Aegis DB`, and `hello-world-app` (`haproxy-hello-world-tls`)!

4. **Kubernetes Integration (K3s):**
   Backstage is configured to securely authenticate with your local K3s cluster. Components are mapped to their respective deployments and pods using the `backstage.io/kubernetes-label-selector` annotation.

5. **TechDocs (Local Generation):**
   TechDocs has been configured to build documentation natively on the host machine (`runIn: local`) using Python and `mkdocs`, completely bypassing the need for a Docker daemon. The `mkdocs.yml` configurations for the demo services are already provisioned.

### Local Kubernetes Deployment (K3s)

For a fully representative local environment without Docker Desktop, you can run the Aegis microservices using K3s (a lightweight Kubernetes distribution) and Podman.

1. **Install K3s and Podman:**
   ```bash
   # Install K3s
   curl -sfL https://get.k3s.io | sh -
   
   # Configure kubectl access for your user
   mkdir -p ~/.kube
   sudo cp /etc/rancher/k3s/k3s.yaml ~/.kube/config
   sudo chown $(whoami):$(whoami) ~/.kube/config
   echo 'export KUBECONFIG=~/.kube/config' >> ~/.bashrc
   source ~/.bashrc
   
   # Install Podman for daemonless image building
   sudo apt update && sudo apt install podman -y
   ```

2. **Build and Import Images:**
   Navigate to the `demo` directory to build the images and import them into K3s's containerd runtime.
   ```bash
   cd demo
   podman build -t localhost/aegis-auth:latest ./auth
   podman build -t localhost/aegis-backend:latest ./backend
   
   podman save -o auth.tar localhost/aegis-auth:latest
   podman save -o backend.tar localhost/aegis-backend:latest
   
   sudo k3s ctr images import auth.tar
   sudo k3s ctr images import backend.tar
   ```

3. **Deploy to Kubernetes:**
   ```bash
   # Create a ConfigMap for the frontend UI
   kubectl create configmap ui-html-config --from-file=ui/index.html
   
   # Apply the application manifest
   kubectl apply -f k8s/manifest.yaml
   ```
   *The demo UI will now be available at `http://localhost:30080`. (Test credentials: **admin** / **admin**)*

### 🔐 HAProxy Edge TLS Certificate Visibility & Zero-Downtime Rotation

Project Aegis includes an end-to-end **Software Catalog + Scaffolder + Zero-Downtime HAProxy Cutover** workflow (`demo/haproxy/`):

1. **Start the HAProxy + Hello-World TLS Sandbox:**
   ```bash
   bash demo/haproxy/start-sandbox.sh --reset
   ```
   This spins up the `haproxy-sandbox` container fronting `hello-world-app` on `https://127.0.0.1:8443` with an initial **15-day** self-signed certificate (`CN=hello.internal`) to immediately demonstrate a `Warning` state in the catalog, with the HAProxy Runtime Admin Socket enabled at `/var/run/haproxy/haproxy.sock`.

2. **Catalog Visibility & Live TLS Handshake Probing:**
   - Catalog entities (`hello-world-app`, `haproxy-hello-world-tls`, and `resiliency-group` in `demo/haproxy/catalog-info.yaml`) track certificate provider, active X.509 serial/version, expiry timestamp, days remaining, and target HAProxy PEM path.
   - `HaproxyTlsLiveProbeProcessor` in `portal/packages/backend/src/modules/haproxyTlsModule.ts` inspects the live peer certificate via Node's native `tls.connect` during catalog processing and refreshes.
   - The **HAProxy Edge TLS Certificate Resiliency** frontend card (`portal/packages/app/src/modules/tls/tlsModule.tsx`) renders a color-coded health badge (`Healthy`, `Warning`, `Critical`), live certificate metadata, and a one-click **Rotate Certificate** button that pre-fills `resource:default/haproxy-hello-world-tls`.

3. **Zero-Downtime Scaffolder Actions (`update-haproxy-tls-cert`):**
   - `resiliency:haproxy:build-pem` (alias `resiliency:cert:bundle-haproxy-pem`): Supports uploading custom PEM cert/key pairs or auto-generating a fresh self-signed X.509 cert/key, verifies modulus/public-key match via OpenSSL, and concatenates `cert + "\n" + key` into HAProxy's unified `.pem` bundle format while redacting private keys from logs.
   - `resiliency:haproxy:deploy-cert`: Writes `/etc/haproxy/certs/hello-world.pem` (`0600`) and streams the new bundle into HAProxy memory via the Runtime Socket (`set ssl cert` / `commit ssl cert`) with graceful master reload fallback (`SIGUSR2`).
   - `resiliency:haproxy:verify-tls`: Performs a post-flight live TLS handshake check to verify the new X.509 serial number is active on the edge before syncing the Backstage Catalog (`catalog:refresh`).

4. **Reliability KPI & Prometheus Metrics:**
   - `GET http://localhost:7007/api/resiliency-tls/metrics`: Exposes Prometheus gauges `idp_certificate_expiry_days{service="hello-world",proxy="haproxy"}` and `idp_certificate_info`.
   - `GET http://localhost:7007/api/resiliency-tls/status`: Returns live JSON probe telemetry from the HAProxy TLS edge.

### 🌐 Multi-Environment & Multi-Provider SSL/TLS Endpoint & Compliance Tracker

Project Aegis extends edge TLS visibility into a full fleet-wide **Multi-Environment (`1:N`) & Multi-Provider SSL/TLS Compliance Tracker** (`portal/packages/backend/src/modules/sslEndpointTracker*`, `portal/packages/app/src/modules/sslTracker/`, and `services/ssl_tracker/`):

1. **5 Mandatory X.509 Security & Reliability Pillars:**
   - **Pillar 1 — Not After (Expiry & SSO Guard):** Categorizes certificates into `HEALTHY`, `WARNING` ($\le 30\text{d}$), `CRITICAL` ($\le 7\text{d}$), and `EXPIRED` ($\le 0\text{d}$), and detects `SELF_RENEWAL_STALLED` SLA breaches on autonomous Private Cloud LBs.
   - **Pillar 2 — Subject (Common Name & SANs):** Enforces RFC 6125 single-label wildcard DNS matching (`*.domain`) with CN fallback to prevent hostname routing mismatches.
   - **Pillar 3 — Issuer (CA & Renewal Path):** Tracks issuing CA lineage (`GTS CA 1C3`, `Aegis Private Cloud Vault Intermediate CA G2`, `Aegis HAProxy Edge Root CA`) and self-signed status.
   - **Pillar 4 — Serial Number (Unique DB Key & Lineage):** Normalizes colon-delimited hex serials, links rotated certificates via `rotatedFromSerial`, and preserves full rotation history (`historyCount` + active/rotated states).
   - **Pillar 5 — Signature Algorithm & Key Size:** Flags deprecated hashes (`SHA-1`, `MD5`) and weak asymmetric keys (`RSA < 2048-bit`, `ECDSA < 256-bit`) as `NON_COMPLIANT`.

2. **1:N Multi-Environment Catalog Annotations & Provider Modes:**
   - Catalog entities (`aegis-ui`, `aegis-auth`, `aegis-backend`, `hello-world-app`, `haproxy-hello-world-tls`) declare endpoints across `dev`, `stg` (supporting `1:N` named sub-endpoints such as `endpoints.stg.web`, `endpoints.stg.cdn`, `endpoints.stg.canary`), `stress-test`, `preprod`, and `prod`.
   - Supports three provider renewal archetypes:
     - `gcp-cloud-lb` (`workflow-auto-renew`): Automated Google Trust Services (`GTS CA 1C3`) DNS-01 authorization, Quality Gate diff review, and `TargetHttpsProxy` binding.
     - `private-cloud-lb` (`self-renewing-monitored`): Autonomous Vault PKI renewal monitoring with one-click cryptographic remediation (`⚡ Remediate Weak Crypto (RSA-2048)`) for legacy/non-compliant endpoints (e.g., `aegis-backend` `stress-test.legacy-audit`).
     - `haproxy-edge` (`manual-or-template`): Per-endpoint `host:port` live TLS socket probing paired with hitless HAProxy Runtime Socket PEM rotation.

3. **Frontend UX & QOL Capabilities (`EntityMultiEnvSslComplianceCard`):**
   - **Environment & Compliance Filtering:** Filter endpoints by environment tier tabs (`ALL`, `DEV`, `STG`, `STRESS-TEST`, `PREPROD`, `PROD`), compliance status chips (`ALL`, `COMPLIANT`, `WARNING`, `NON_COMPLIANT`), and real-time search across hostname, URL, endpoint key, issuer, or serial number.
   - **Interactive Quality Gate & Unified Diff Review:** Preview `--- Current` vs. `+++ Proposed` unified X.509 certificate diffs per environment and approve/reject directly in the card (with approver identity auto-populated via Backstage `identityApiRef` and verified via `coreServices.httpAuth`).
   - **Certificate Rotation History & Serial Lineage Drawer:** Expandable audit table displaying active and historical rotated certificates for every endpoint.
   - **Resilient API Discovery & Persistence:** Uses Backstage `discoveryApiRef` and `fetchApiRef` with graceful offline fallback banners (`Retry Live Sync`) and self-contained disk persistence (`.ssl_tracker_state.json`).

4. **Scaffolder Actions & Backend API Endpoints (`/api/ssl-tracker/*`):**
   - **Scaffolder Template (`renew-gcp-lb-tls-cert`):** 4-step workflow (`resiliency:gcp-lb:authorize-dns`, `resiliency:gcp-lb:quality-gate-approval`, `resiliency:gcp-lb:renew-and-bind`, `resiliency:gcp-lb:verify-compliance`) with dynamic catalog endpoint resolution, plus `resiliency:private-lb:remediate-crypto`.
   - **REST & Observability Routes:** `GET /status`, `GET /fleet`, `GET /history`, `POST /scan`, `POST /probe-active`, `GET /prober-network-context`, `POST /import-csv`, `GET /sample-domains.csv`, `POST /gcp-preview-diff`, `POST /quality-gate/decide`, `POST /gcp-auto-renew`, `POST /remediate-crypto`, and Prometheus `GET /metrics` (`aegis_ssl_endpoint_expiry_days`, `aegis_ssl_endpoint_compliant`, `aegis_ssl_endpoint_key_bits`).

5. **Active Endpoint Prober (`activeEndpointProberService.ts` & `services/ssl_tracker/active_prober.py`):**
   - **Live 5-Pillar X.509 SSL Extraction:** Connects to real endpoints via live TLS handshake to extract **Not After / Expiry Details** (`daysRemaining`, `expiryStatus`), **Subject CN & SANs**, **Issuer CN/Org/DN**, **Serial Number** (colon-delimited hex & decimal), and **Signature Algorithm & Key Size** (`RSA`, `ECDSA`, `Ed25519` bit length).
   - **WAF Edge Protection Fingerprinting (`Akamai` / `Fastly` / `Cloud Armor`):** Inspects live HTTPS response headers, cookies, and DNS CNAME chains to identify **Akamai** (`Server: AkamaiGHost`, `X-Akamai-*`, `Akamai-GRN`, `*.akamaiedge.net`), **Fastly** (`X-Fastly-*`, `X-Served-By: cache-*`, `X-Timer`, `*.fastly.net`), or **Google Cloud Armor** (`Server: Google Frontend` / `ESF`, `Via: 1.1 google`, `X-Cloud-Trace-Context`).
   - **Zscaler vs. Public Internet Accessibility Logic:** Checks the prober's egress source IP against Zscaler Public Service Edge (ZIA/ZPA) CIDR blocks (`165.225.0.0/16`, `147.161.128.0/17`, `136.226.0.0/16`, `170.85.0.0/16`, `104.129.192.0/20`, `185.46.212.0/22`, `199.168.148.0/22`, `167.103.0.0/16`, `137.83.128.0/18`, etc.) and reverse DNS PTR/org names (`*.zscloud.net`, `zscaler`):
     - If the source IP belongs to **Zscaler**, the prober assumes it is operating **within the private network** (`PRIVATE_NETWORK_ZSCALER`, `accessibleFromPublicInternet: false`).
     - If the source IP is a **non-Zscaler IP**, the prober assumes it is probing **from the public internet** (`PUBLIC_INTERNET`, `accessibleFromPublicInternet: true` when reachable).

6. **Domains CSV Loader (`domainCsvImporterService.ts` & Unified Inventory UI):**
   - Allows bulk loading of domain lists via `.csv` file upload or direct CSV paste in **Unified Inventory — Domains & Endpoints** (`POST /api/ssl-tracker/import-csv` and template `GET /api/ssl-tracker/sample-domains.csv`).
   - **Required CSV Columns:** `endpoint`, `service_name`, and `environment` (`dev`, `stg`, `stress-test`, `preprod`, `prod`).
   - **Optional CSV Columns:** `endpoint_key`, `provider_type` (`gcp-cloud-lb`, `private-cloud-lb`, `haproxy-edge`), `exposure_scope`, `owner_team_id` (`sre-team`, `app-team`), and `notes`.
   - Automatically runs the **Active Endpoint Prober** on imported domains (when enabled) and upserts all rows idempotently into PostgreSQL (`tracked_endpoints`, `certificate_inventory`, `cmdb_services`, and Layer 1 `DOMAIN_ENDPOINT` nodes in `cmdb_component_nodes`).

### Canonical 33-Category Component Taxonomy & 2-Team Ownership Split (`SRE Team` vs. `App Team`)

The **Autonomous Living CMDB (`living-cmdb`)** organizes all configuration items into two top-level domains (**I. Infrastructure** across 7 architectural layers & 20 component types, and **II. Software** across 13 categories), automatically assigning stewardship between **SRE Team (`sre-team`)** and **App Team (`app-team`)**:

- **I. Infrastructure (7 Layers / 20 Component Types — Owned by `SRE Team`):**
  1. **Edge & External Security Layer:** 🌐 Domain / Endpoint, 🛡️ WAF / Edge Protection, 🚀 CDN (Content Delivery Network)
  2. **Ingress & Traffic Routing Layer:** 🔀 Load Balancer, 🚪 Ingress Controller, 🕸️ Service Mesh
  3. **Cloud Governance & Logical Boundaries:** ☁️ GCP Project / Cloud Account, 🔒 IAM & Secrets Management, 🛡️ Namespace
  4. **Orchestration & Compute Units:** ☸️ Kubernetes (K8s) Cluster, 📜 Kubernetes (K8s) Deployment, 🌱 Pod, 🐳 Container
  5. **Dedicated Hosts & Traditional Compute:** 🖥️ Virtual Machine (VM) Server, 🧱 Baremetal Server, ⏱️ Batch Server / Event Workers
  6. **Data, Cache & State Layer:** 🗄️ Database (Infra Instance), ⚡ Distributed Cache, 📦 Object Storage
  7. **Observability & Telemetry Platform:** 📊 Metrics & Logging Engines
- **II. Software (13 Categories — Split between `SRE Team` & `App Team`):**
  - **SRE Team (`sre-team`):** 💻 Operating System (OS), 🐳 Containerization
  - **App Team (`app-team`):** 🚀 Platform & Runtime Environment, 📦 Library & Framework, 🛡️ Security & Identity Software, 🔄 Middleware & Integration Software, 🗺️ Data Access & ORM, ⚙️ Configuration & Feature Flag Software, 🛠️ Application Core (Internal Business Logic), 📊 Observability, 🌐 External API, 🧪 Testing, 🛠️ Development Tools & Source Control (SCM)

### Infrahub Attack-Path Graph & Tech-Insights Thin Scorecard Projector (`infrahub-attack-graph`)

Aegis uses **Infrahub** as the Graph & AI Brain and Backstage **Tech-Insights** as a Thin Scorecard Projector:
- **Explicit Reachability & N-Hop Attack-Path Graph:** Connects `EXPOSED_HTTPS_DOMAIN` → `SSL_TLS_CERTIFICATE` → `COMPUTE_HOST_OR_POD` → `EOL_RUNTIME_OR_OS` → `SBOM_PACKAGE` → `CVE_VULNERABILITY` → `LATERAL_SERVICE_OR_DATA_STORE` via explicit directed edges (`EXPOSES_INGRESS`, `TERMINATES_TLS_WITH`, `EXECUTES_ON_RUNTIME`, `AFFECTED_BY_CVE`, `REACHABLE_HOT_PATH_TO`, `LATERAL_MOVEMENT_TO_DATA`).
- **Lightweight Infrahub GraphQL Fact Retriever:** Queries Infrahub's GraphQL API for 6 pre-computed summary metrics per service (`exposed_domain_count`, `non_compliant_ssl_count`, `eol_package_count`, `reachable_kev_cve_count`, `reachable_lateral_data_paths_count`, `attack_path_risk_score`) and evaluates pass/fail Tech-Insights Scorecards with deep-links to Infrahub and `infrahub-mcp`.

### Software Version Normalizer & 100% PostgreSQL Persistence (`softwareVersionNormalizerService` & `aegisPostgresStore`)

- **Multi-Source EOL & CVE Version Crosswalk:** Decomposes raw software versions (SemVer, Debian epochs `1:`, OpenSSL letter patches `1.1.1w-r1`, Alpine/Debian revisions) into `purl`, `cpe23Uri`, `eolProductSlug`, `eolCycleKey` (`MAJOR`, `MAJOR_MINOR`, `MAJOR_MINOR_PATCH`), `eolApiUrl`, `vendorLifecycleStream`, `osvEcosystem`, `osvPackageName`, `nvdCpeMatchString`, `ghsaEcosystem`, `distroAdvisoryNamespace`, and a 7-element lexicographical sort array `semverSortTuple` (`INT[7]`).
- **100% PostgreSQL Database Architecture (9 Canonical Tables):**
  - **Backstage Core & Custom Plugins (`portal/app-config.yaml` & `aegisPostgresStore.ts`):** Configured on PostgreSQL (`client: pg`) with idempotent `ON CONFLICT DO UPDATE` seeding and live Knex read/sync paths across all 9 canonical tables (`items`, `team_owners`, `tracked_endpoints`, `certificate_inventory`, `cmdb_services`, `cmdb_component_nodes`, `software_version_crosswalk`, `public_eol_cycles`, and `public_cve_ranges`).
  - **Python SSL Tracker (`services/ssl_tracker`):** Supports `AEGIS_SSL_TRACKER_DB_URL` (`postgresql://...`) with SQLAlchemy `pool_pre_ping=True`, managing `team_owners`, `tracked_endpoints`, and `certificate_inventory`.
  - **Canonical DDL (`demo/db-init/init.sql`):** Unified PostgreSQL schema and seed script for all 9 tables.

#### PostgreSQL Entity-Relationship Model: Service, Owner, Software, Infrastructure & Domains

```mermaid
erDiagram
    team_owners ||--o{ cmdb_component_nodes : "owns (owner_team_id)"
    team_owners ||--o{ tracked_endpoints : "owns (owner_team_id)"
    cmdb_services ||--o{ cmdb_component_nodes : "contains (ci_id)"
    cmdb_component_nodes ||--o| software_version_crosswalk : "normalizes (component_id)"
    software_version_crosswalk }o--o{ public_eol_cycles : "matches (eol_product_slug, eol_cycle_key)"
    software_version_crosswalk }o--o{ public_cve_ranges : "matches (eol_product_slug)"
    tracked_endpoints ||--o{ certificate_inventory : "terminates TLS (endpoint_id)"
    cmdb_services }o--o{ tracked_endpoints : "exposes (entity_ref / service_name)"

    team_owners {
        varchar team_id PK "app-team | sre-team"
        varchar team_name
        varchar responsibility_scope
        varchar email
        varchar slack_channel
    }
    cmdb_services {
        varchar ci_id PK "CI-AEGIS-1001..1005"
        varchar entity_ref
        varchar service_name
        varchar owner_team "Service squad"
        varchar drift_status "IN_SYNC | DRIFT_DETECTED"
        jsonb drift_items
        jsonb blast_radius
    }
    cmdb_component_nodes {
        varchar component_id PK
        varchar ci_id FK "-> cmdb_services.ci_id"
        varchar domain "INFRASTRUCTURE | SOFTWARE"
        varchar layer_id "7 Infra Layers (nullable for Software)"
        varchar category_type "20 Infra + 13 Software Categories"
        varchar owner_team_id FK "-> team_owners.team_id"
        varchar name
        varchar version_or_identifier
        varchar status "HEALTHY | DRIFTED | WARNING | CRITICAL"
    }
    software_version_crosswalk {
        varchar component_id PK_FK "-> cmdb_component_nodes.component_id"
        varchar purl
        varchar cpe23_uri
        varchar eol_product_slug
        varchar eol_cycle_key
        int_array semver_sort_tuple
    }
    tracked_endpoints {
        serial id PK
        varchar endpoint_uid UK
        varchar endpoint_name "SNI Hostname / FQDN"
        varchar protocol
        int port
        varchar owner_team_id FK "-> team_owners.team_id"
        varchar environment "dev | stg | stress-test | preprod | prod"
        varchar entity_ref
        varchar service_name
        varchar provider_type "gcp-cloud-lb | private-cloud-lb | haproxy-edge"
    }
    certificate_inventory {
        serial id PK
        int endpoint_id FK "-> tracked_endpoints.id"
        varchar serial_number
        varchar cert_issuer
        varchar cert_subject
        timestamp not_after
        varchar compliance_status "COMPLIANT | WARNING | NON_COMPLIANT"
        jsonb cert_details_json
    }
```

| Domain Entity | PostgreSQL Table(s) | Primary Key | Foreign Keys & Join Relationships |
| :--- | :--- | :--- | :--- |
| **1. Owner (`Team`)** | `team_owners` | `team_id` (`app-team`, `sre-team`) | Referenced by `cmdb_component_nodes.owner_team_id` and `tracked_endpoints.owner_team_id`. Service-level squad ownership (`platform-experience`, `core-services`, `secops-iam`, `data-platform`, `edge-platform`) is stored on `cmdb_services.owner_team`. |
| **2. Service (`CI`)** | `cmdb_services` | `ci_id` (e.g., `CI-AEGIS-1002`) | Parent configuration item (`1:N`) for all software and infrastructure nodes in `cmdb_component_nodes` (`ci_id` FK with `ON DELETE CASCADE`) and logically linked (`1:N`) to `tracked_endpoints` via `entity_ref` / `service_name`. |
| **3. Infrastructure (7 Layers / 20 Types)** | `cmdb_component_nodes` (`domain = 'INFRASTRUCTURE'`) | `component_id` | Joins to parent service via `ci_id -> cmdb_services.ci_id` and to owning team via `owner_team_id -> team_owners.team_id` (always `sre-team`). Categorized by `layer_id` (7 architectural layers) and `category_type` (20 infrastructure types, including `DOMAIN_ENDPOINT` in Layer 1). |
| **4. Software (13 Categories + EOL/CVE)** | `cmdb_component_nodes` (`domain = 'SOFTWARE'`) + `software_version_crosswalk` + `public_eol_cycles` + `public_cve_ranges` | `component_id` | Joins to parent service via `ci_id -> cmdb_services.ci_id` and to `team_owners.team_id` (`sre-team` for `OPERATING_SYSTEM` & `CONTAINERIZATION_SOFTWARE`; `app-team` for the other 11 categories). Has a `1:1` extension in `software_version_crosswalk` (`component_id` PK/FK `ON DELETE CASCADE`), which joins to `public_eol_cycles` on `(eol_product_slug, eol_cycle_key)` and `public_cve_ranges` on `eol_product_slug`. |
| **5. Domains & TLS Endpoints** | `tracked_endpoints` + `certificate_inventory` (+ `cmdb_component_nodes` where `category_type = 'DOMAIN_ENDPOINT'`) | `tracked_endpoints.id` (`endpoint_uid` unique) | Each domain in `tracked_endpoints` references `owner_team_id -> team_owners.team_id` and associates with a service via `entity_ref` / `service_name`. Has a `1:N` relationship to `certificate_inventory` (`endpoint_id -> tracked_endpoints.id ON DELETE CASCADE`, unique on `(endpoint_id, serial_number)`) tracking active and historical rotated X.509 certificates. |

### Demonstrating the Quality Gates (Shift-Left)

Aegis enforces code quality and security checks natively. You can demo these capabilities directly on the backend service:

1. **Local Test & Lint Execution:** The backend service is bundled with standard quality gates.
   ```bash
   cd demo/backend
   npm install
   npm run test
   ```
   *(This ensures that any new commits successfully pass the unit tests and strict header policies).*

2. **Portal Backend, Frontend & Python SSL Compliance Automated Tests:**
   ```bash
   cd portal
   yarn tsc
   yarn --cwd packages/backend test haproxyTlsService.test.ts --watchAll=false
   yarn --cwd packages/backend test sslEndpointTrackerService.test.ts --watchAll=false
   yarn --cwd packages/app test --watchAll=false

   # Run the standalone Python SSL Compliance Tracker unit, integration, and E2E test suite
   cd ..
   .venv/bin/python -m pytest -q
   ```

3. **Catalog Integration:** In the Backstage Developer Portal (`http://localhost:3000`), the `aegis-backend` component is pre-configured with annotations (e.g., `sonarqube.org/project-key`) to pull live code quality and vulnerability metrics. Once the CI pipeline completes, Backstage will aggregate these results on the component's dashboard.

## 🗺️ Roadmap

- **Phase 1: Visibility:** Populate the Software Catalog with all existing CIAM microservices and set up TechDocs.
- **Phase 2: Standardization:** Release the first two "Golden Path" templates for Node.js and Java microservices.
- **Phase 3: Operations:** Integrate the Kubernetes plugin, roll out Dagger across all CIAM microservices to eliminate pipeline flakiness, and add CI status views.
- **Phase 4: Custom CIAM Tooling:** Custom internal plugins for HAProxy TLS certificate rotation visibility (`resiliency-tls`), zero-downtime Runtime Socket cutover, and auth token debugging.
- **Phase 5: Multi-Environment SSL/TLS Compliance Governance:** Fleet-wide 5-pillar X.509 compliance tracking (`ssl-tracker`), interactive Quality Gate certificate diffs, GCP Certificate Manager auto-renewal workflows, Private Cloud LB weak-crypto remediation, and serial rotation lineage auditing.

## 🤝 Contributing

We welcome contributions from the whole engineering team! If you want to add a new Software Template or integrate a new plugin, please check out our [Contributing Guide](CONTRIBUTING.md).

## 🛡️ Support & SRE

If you encounter issues with the platform, please reach out to the SRE/Platform team in the `#aegis-support` Slack channel or open an issue in this repository.
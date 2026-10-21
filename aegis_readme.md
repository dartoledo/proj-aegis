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
   - **REST & Observability Routes:** `GET /status`, `GET /fleet`, `GET /history`, `POST /scan`, `POST /gcp-preview-diff`, `POST /quality-gate/decide`, `POST /gcp-auto-renew`, `POST /remediate-crypto`, and Prometheus `GET /metrics` (`aegis_ssl_endpoint_expiry_days`, `aegis_ssl_endpoint_compliant`, `aegis_ssl_endpoint_key_bits`).

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
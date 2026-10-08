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
   The `catalog-info.yaml` definitions for the demo microservices are automatically loaded into Backstage on startup. Head over to the catalog page to see the dependency graph of `Aegis UI`, `Aegis Auth`, `Aegis Backend`, and `Aegis DB`!

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

### Demonstrating the Quality Gates (Shift-Left)

Aegis enforces code quality and security checks natively. You can demo these capabilities directly on the backend service:

1. **Local Test & Lint Execution:** The backend service is bundled with standard quality gates.
   ```bash
   cd demo/backend
   npm install
   npm run test
   ```
   *(This ensures that any new commits successfully pass the unit tests and strict header policies).*

2. **Catalog Integration:** In the Backstage Developer Portal (`http://localhost:3000`), the `aegis-backend` component is pre-configured with annotations (e.g., `sonarqube.org/project-key`) to pull live code quality and vulnerability metrics. Once the CI pipeline completes, Backstage will aggregate these results on the component's dashboard.

## 🗺️ Roadmap

- **Phase 1: Visibility:** Populate the Software Catalog with all existing CIAM microservices and set up TechDocs.
- **Phase 2: Standardization:** Release the first two "Golden Path" templates for Node.js and Java microservices.
- **Phase 3: Operations:** Integrate the Kubernetes plugin, roll out Dagger across all CIAM microservices to eliminate pipeline flakiness, and add CI status views.
- **Phase 4: Custom CIAM Tooling:** Build custom internal plugins for key rotation visibility and auth token debugging.

## 🤝 Contributing

We welcome contributions from the whole engineering team! If you want to add a new Software Template or integrate a new plugin, please check out our [Contributing Guide](CONTRIBUTING.md).

## 🛡️ Support & SRE

If you encounter issues with the platform, please reach out to the SRE/Platform team in the `#aegis-support` Slack channel or open an issue in this repository.
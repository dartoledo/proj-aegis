# Proposal & Implementation Plan: Kubernetes Day-2 Operations Automation (Scale Up/Down & Rolling Restart)

> **Reference Architecture:** Modeled on **Harness Internal Developer Portal (IDP)** Day-2 Self-Service Workflows + **Harness CD** Kubernetes Execution Steps (`K8sScale` & `K8sRollout`), adapted natively for **Project Aegis (Backstage + Local K3s + GitOps)**.

---

## 1. Executive Summary & Harness IDP Research Findings

In **Harness IDP**, routine Day-2 Kubernetes operations—such as **scaling workloads up/down** for traffic spikes or executing a **zero-downtime rolling restart** after a ConfigMap/Secret change—are automated without granting developers direct `kubectl` cluster access or relying on manual *TicketOps*.

### How Harness IDP Implements Day-2 K8s Automation

1. **Self-Service IDP Workflow (`workflow.yaml` / `template.yaml`):**
   - Built on Backstage's Scaffolder (`apiVersion: scaffolder.backstage.io/v1beta3`, `kind: Template`, `spec.type: workflow`).
   - Uses `EntityPicker` filtered to Kubernetes-backed `Component` entities and dynamic `dependencies` (`oneOf`) to switch form inputs based on `operationType` (`scale` vs. `rolling-restart`).
2. **Pipeline Orchestration Trigger (`trigger:harness-custom-pipeline`):**
   - The IDP workflow passes runtime inputs (`serviceName`, `namespace`, `operationType`, `instanceSelection`, `replicaCount` / `percentage`, `reason`) to a governed execution pipeline.
3. **Native Kubernetes Execution Primitives (Harness CD Steps):**
   - **`K8sScale` Step:** Scales a target workload (`[namespace/]Kind/Name`, e.g., `default/Deployment/backend`) using either:
     - `instanceSelection.type: Count` (explicit pod replica count, e.g., `3` pods), or
     - `instanceSelection.type: Percentage` (percentage of baseline manifest replicas, e.g., `200%`).
     - Enforces `skipSteadyStateCheck: false` to block until `kubectl rollout status` confirms all replicas are `Ready`.
   - **`K8sRollout` / Rolling Restart Step:** Executes `kubectl rollout restart deployment/<name> -n <namespace>` (updating `kubectl.kubernetes.io/restartedAt` on the pod template) followed by `kubectl rollout status` steady-state verification.
4. **OPA Policy Guardrails & GitOps Drift Prevention:**
   - **OPA Policy Engine:** Enforces replica bounds (`minReplicas: 1`, `maxReplicas: 10`), prevents scaling stateful single-instance databases (`aegis-db`), and requires an audit reason.
   - **Hybrid GitOps Sync:** Optionally updates `replicas:` in the GitOps manifest (`demo/k8s/manifest.yaml`) so ArgoCD/Flux does not revert the live replica change during its next reconciliation cycle.

---

## 2. Project Aegis Day-2 Architecture Blueprint (Backstage + K3s)

```text
┌─────────────────────────────────────────────────────────────────────────────────┐
│                         BACKSTAGE IDP (Control Plane)                           │
│                                                                                 │
│  ┌────────────────────────────────────┐  ┌───────────────────────────────────┐  │
│  │ 1. Software Catalog (K8s Entities) │  │ 2. Scaffolder (Day-2 Workflow)    │  │
│  │ • aegis-backend (Deployment/backend│  │ • Action 1: validate-policy (OPA) │  │
│  │ • aegis-auth    (Deployment/auth)  │  │ • Action 2: execute-day2-op       │  │
│  │ • aegis-ui      (Deployment/ui)    │  │   - K8sScale (Count / Percentage) │  │
│  │ • Tracks: Desired/Ready Replicas,  │  │   - K8sRollout (Rolling Restart)  │  │
│  │   Pod IPs, Generation, Last Op     │  │   - GitOps manifest.yaml Sync     │  │
│  │                                    │  │ • Action 3: verify-and-diff       │  │
│  └─────────────────▲──────────────────┘  └─────────────────┬─────────────────┘  │
└────────────────────┼───────────────────────────────────────┼────────────────────┘
                     │ Polls K3s Deployments & Pods          │ kubectl + Steady-State
┌────────────────────┴───────────────────────────────────────▼────────────────────┐
│                        LOCAL K3S CLUSTER (namespace: default)                   │
│                                                                                 │
│  [ Deployment/backend ]   [ Deployment/auth ]   [ Deployment/ui ]   [ db ]      │
│  • NodePort :30002        • NodePort :30001     • NodePort :30080   • :5432     │
│  • RollingUpdate Strategy • Readiness Probes    • GitOps: demo/k8s/manifest.yaml│
└─────────────────────────────────────────────────────────────────────────────────┘
```

---

## 3. Reference Comparison: Harness CD Pipeline YAML vs. Project Aegis Actions

### Harness CD Native Steps (Reference)

```yaml
# 1. Harness CD K8sScale Step
- step:
    type: K8sScale
    name: Scale Workload Replicas
    identifier: Scale_Workload_Count
    spec:
      workload: Deployment/<+pipeline.variables.deploymentName>
      skipSteadyStateCheck: false
      instanceSelection:
        type: Count # or Percentage
        spec:
          count: <+pipeline.variables.replicaCount>
      timeout: 10m

# 2. Harness CD K8sRollout Rolling Restart Step
- step:
    type: K8sRollout
    name: Rolling Restart Workload
    identifier: Rollout_Restart_Service
    spec:
      command: restart
      resources:
        type: Workload
        spec:
          workload: Deployment/<+pipeline.variables.deploymentName>
      timeout: 10m
```

### Project Aegis Equivalent Scaffolder Actions

1. **`resiliency:k8s:validate-policy`**
   - Maps `entityRef` (e.g., `component:default/aegis-backend`) to K3s `Deployment/backend` in namespace `default`.
   - Enforces OPA-style guardrails:
     - `1 <= targetReplicas <= 10` (blocks `0` replicas on CIAM services).
     - Blocks `scale` on stateful `aegis-db` (`Deployment/db`), allowing only `rolling-restart`.
2. **`resiliency:k8s:execute-day2-op`**
   - Captures a **Pre-Operation K8s Snapshot** (`desiredReplicas`, `readyReplicas`, `generation`, `podNames`, `podIPs`, `restartedAt`).
   - Executes either:
     - **Scale Up/Down:** `kubectl scale deployment/<name> --replicas=<count> -n <namespace>` (supporting both `Count` and `Percentage` modes) + optional `demo/k8s/manifest.yaml` sync.
     - **Rolling Restart:** `kubectl rollout restart deployment/<name> -n <namespace>`.
   - Enforces steady-state completion via `kubectl rollout status deployment/<name> -n <namespace> --timeout=90s`.
3. **`resiliency:k8s:verify-and-diff`**
   - Captures the **Post-Operation K8s Snapshot**, performs a live HTTP health check against the service NodePort (`:30001`, `:30002`, `:30080`), and generates a **Before vs. After K8s State Diff** (both Unified Diff and Markdown table).

---

## 4. Proposed Catalog Entity Model (`demo/*/catalog-info.yaml`)

Each microservice in `demo/{backend,auth,ui}/catalog-info.yaml` is enriched with Day-2 Kubernetes annotations and quick-action links:

```yaml
apiVersion: backstage.io/v1alpha1
kind: Component
metadata:
  name: aegis-backend
  description: Core backend service that connects to the database and serves CIAM data
  annotations:
    backstage.io/kubernetes-label-selector: 'app=backend'
    backstage.io/techdocs-ref: dir:.
    sonarqube.org/project-key: aegis-backend
    github.com/project-slug: internal-org/aegis-backend
    resiliency.idp/k8s-namespace: 'default'
    resiliency.idp/k8s-deployment: 'backend'
    resiliency.idp/k8s-baseline-replicas: '1'
    resiliency.idp/k8s-min-replicas: '1'
    resiliency.idp/k8s-max-replicas: '10'
    resiliency.idp/k8s-health-url: 'http://127.0.0.1:30002/items'
  links:
    - url: /create/templates/default/k8s-day2-operations?formData=%7B%22componentEntity%22%3A%22component%3Adefault%2Faegis-backend%22%2C%22operationType%22%3A%22scale%22%7D
      title: Scale K8s Replicas (Day-2)
      icon: dashboard
    - url: /create/templates/default/k8s-day2-operations?formData=%7B%22componentEntity%22%3A%22component%3Adefault%2Faegis-backend%22%2C%22operationType%22%3A%22rolling-restart%22%7D
      title: Rolling Restart Pods (Day-2)
      icon: refresh
spec:
  type: service
  lifecycle: experimental
  owner: team-aegis
  dependsOn:
    - component:aegis-auth
    - resource:aegis-db
```

---

## 5. Proposed Backstage Scaffolder Workflow (`portal/examples/k8s-day2-ops-template/template.yaml`)

```yaml
apiVersion: scaffolder.backstage.io/v1beta3
kind: Template
metadata:
  name: k8s-day2-operations
  title: Kubernetes Day-2 Operations (Scale & Rolling Restart)
  description: Harness IDP-style self-service workflow to scale Kubernetes replicas (by Count or Percentage) or trigger a zero-downtime rolling restart on K3s with OPA policy guardrails and steady-state verification.
  tags:
    - kubernetes
    - k3s
    - day-2
    - sre
    - harness-idp
spec:
  owner: group:resiliency-group
  type: workflow

  parameters:
    - title: 1. Target Kubernetes Service & Operation
      required: [componentEntity, namespace, operationType, reason]
      properties:
        componentEntity:
          title: Target Microservice
          type: string
          default: component:default/aegis-backend
          ui:field: EntityPicker
          ui:options:
            catalogFilter:
              kind: Component
        namespace:
          title: Kubernetes Namespace
          type: string
          default: default
          enum: [default]
        operationType:
          title: Day-2 Operation Type
          type: string
          default: scale
          enum: [scale, rolling-restart]
          enumNames:
            - "Scale Workload Up / Down (Harness K8sScale)"
            - "Zero-Downtime Rolling Restart (Harness K8sRollout)"
        reason:
          title: Audit Reason / Change Ticket
          type: string
          default: "Traffic spike capacity adjustment"

    - title: 2. Operation Parameters
      dependencies:
        operationType:
          oneOf:
            - properties:
                operationType:
                  enum: [scale]
                selectionMode:
                  title: Instance Selection Mode (Harness K8sScale)
                  type: string
                  default: Count
                  enum: [Count, Percentage]
                  enumNames:
                    - "Absolute Replica Count (Count)"
                    - "Percentage of Baseline Replicas (Percentage)"
                replicaCount:
                  title: Target Replicas (if Count) or Percentage (e.g. 200 for 200%)
                  type: integer
                  default: 2
                  minimum: 1
                syncGitOpsManifest:
                  title: Sync Replica Count to GitOps Manifest (demo/k8s/manifest.yaml)
                  type: boolean
                  default: true
              required: [selectionMode, replicaCount]
            - properties:
                operationType:
                  enum: [rolling-restart]
                waitTimeoutSeconds:
                  title: Rollout Steady-State Timeout (Seconds)
                  type: integer
                  default: 90

  steps:
    - id: validate-policy
      name: Evaluate OPA Guardrails & Resolve K8s Workload
      action: resiliency:k8s:validate-policy
      input:
        entityRef: ${{ parameters.componentEntity }}
        namespace: ${{ parameters.namespace }}
        operationType: ${{ parameters.operationType }}
        selectionMode: ${{ parameters.selectionMode }}
        replicaValue: ${{ parameters.replicaCount }}
        reason: ${{ parameters.reason }}

    - id: execute-day2-op
      name: Execute K8s Day-2 Operation & Wait for Steady-State
      action: resiliency:k8s:execute-day2-op
      input:
        entityRef: ${{ parameters.componentEntity }}
        deploymentName: ${{ steps['validate-policy'].output.deploymentName }}
        namespace: ${{ parameters.namespace }}
        operationType: ${{ parameters.operationType }}
        targetReplicas: ${{ steps['validate-policy'].output.targetReplicas }}
        syncGitOpsManifest: ${{ parameters.syncGitOpsManifest }}
        reason: ${{ parameters.reason }}

    - id: verify-and-diff
      name: Verify Pod Readiness, Service Health & Generate State Diff
      action: resiliency:k8s:verify-and-diff
      input:
        deploymentName: ${{ steps['validate-policy'].output.deploymentName }}
        namespace: ${{ parameters.namespace }}
        operationType: ${{ parameters.operationType }}
        expectedReplicas: ${{ steps['execute-day2-op'].output.targetReplicas }}
        previousStateJson: ${{ steps['execute-day2-op'].output.previousStateJson }}

    - id: refresh-catalog
      name: Sync Updated K8s Telemetry in Backstage Catalog
      action: catalog:refresh
      input:
        entityRef: ${{ parameters.componentEntity }}

  output:
    text:
      - title: Kubernetes Day-2 Operation Verified
        content: |
          ${{ steps['verify-and-diff'].output.k8sDiffMarkdown }}
```

---

## 6. Sample Before vs. After K8s State Diff Output

Every execution of `k8s-day2-operations` produces a side-by-side Markdown comparison table and unified `diff` block in both the Scaffolder task summary and the Catalog Entity page:

| K8s Workload Attribute | Pre-Operation State (Before) | Post-Operation State (After) |
| :--- | :--- | :--- |
| **Target Workload** | `default/Deployment/backend` | `default/Deployment/backend` |
| **Operation Executed** | — | `scale (Count -> 3 replicas)` |
| **Desired / Ready Replicas** | `1 / 1 Ready` | `3 / 3 Ready` |
| **Deployment Generation** | `Gen #1` | `Gen #2 (Steady-State Verified)` |
| **Active Pod Replicas** | `backend-9f9c89886-c9lh7 (10.42.0.5)` | `backend-9f9c89886-c9lh7 (10.42.0.5)`, `backend-9f9c89886-k4p2m (10.42.0.14)`, `backend-9f9c89886-x8v9q (10.42.0.15)` |
| **GitOps `manifest.yaml` Sync** | `replicas: 1` | `replicas: 3 (Synced)` |
| **Service Endpoint Check** | `HTTP 200` | `HTTP 200` |

```diff
--- Pre-Operation K8s Workload State (default/Deployment/backend)
+++ Post-Operation K8s Workload State (default/Deployment/backend)
@@ -1,7 +1,7 @@
   Workload            : default/Deployment/backend
-  Desired / Ready     : 1 / 1 Ready (Available: 1)
+  Desired / Ready     : 3 / 3 Ready (Available: 3)
-  Observed Generation : 1
+  Observed Generation : 2
-  Active Pods (1)     : backend-9f9c89886-c9lh7 [Running 1/1, IP: 10.42.0.5]
+  Active Pods (3)     : backend-9f9c89886-c9lh7 [Running 1/1, IP: 10.42.0.5], backend-9f9c89886-k4p2m [Running 1/1, IP: 10.42.0.14], backend-9f9c89886-x8v9q [Running 1/1, IP: 10.42.0.15]
-  GitOps Manifest     : replicas=1
+  GitOps Manifest     : replicas=3 (demo/k8s/manifest.yaml synced)
   Service Health Probe: HTTP 200 (http://127.0.0.1:30002/items)
```

---

## 7. Phased Implementation Plan

### Phase 1: K3s Day-2 Service & OPA Policy Guardrails (`packages/backend/src/modules/k8sDay2OpsService.ts`)
1. Implement `inspectK8sDeployment(deploymentName, namespace)` using `kubectl get deployment` and `kubectl get pods -l app=<name> -o json` to snapshot replica counts, pod names, pod IPs, container readiness, and rollout timestamps.
2. Implement `evaluateK8sDay2Policy(input)` enforcing replica bounds (`1..10`), percentage calculation, and stateful workload protection.
3. Implement `executeK8sDay2Operation(input)` supporting `scale` (`kubectl scale`) + `demo/k8s/manifest.yaml` sync and `rolling-restart` (`kubectl rollout restart`) + `kubectl rollout status` steady-state verification.
4. Implement `verifyK8sWorkloadAndBuildDiff(input)` performing live service HTTP probes and generating `unifiedDiff` + `markdownDiff`.

### Phase 2: Backstage Scaffolder Module, Catalog Enricher & Metrics (`packages/backend/src/modules/k8sDay2OpsModule.ts`)
1. Register custom Scaffolder actions (`resiliency:k8s:validate-policy`, `resiliency:k8s:execute-day2-op`, `resiliency:k8s:verify-and-diff`).
2. Register `K8sLiveWorkloadProcessor` to enrich `Component` entities in the Catalog with live K3s replica counts and last Day-2 operation status.
3. Expose `/api/resiliency-k8s/status` (live K3s deployment telemetry + latest Day-2 diffs) and `/api/resiliency-k8s/metrics` (Prometheus gauges `idp_k8s_deployment_desired_replicas` & `idp_k8s_deployment_ready_replicas`).

### Phase 3: Frontend Catalog UI Card & End-to-End Tests (`packages/app/src/modules/k8sOps/`)
1. Build `k8sOpsModule.tsx` displaying live K3s replica readiness, active Pod IPs, the **Before vs. After K8s State Diff** viewer, and one-click **Scale Workload** and **Rolling Restart** buttons.
2. Add comprehensive Jest unit and live K3s integration tests in `k8sDay2OpsService.test.ts`.

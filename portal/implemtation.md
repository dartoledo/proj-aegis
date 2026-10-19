Scoping the MVP down to a **single HAProxy instance fronting a `hello-world` app with a self-signed certificate** is the smartest way to launch your IDP. It strips away Kubernetes and external CA complexity so you can prove the core **Backstage Catalog + Scaffolder + Zero-Downtime Cutover** loop end-to-end in days rather than months.

One critical HAProxy nuance this workflow handles automatically: **HAProxy requires the Public Certificate and Private Key to be concatenated into a single `.pem` bundle file**, and updates can be applied with zero dropped connections via the **HAProxy Runtime Socket** (or graceful reload).

---

## 1. MVP Architecture Blueprint (HAProxy + Hello-World)

```
┌───────────────────────────────────────────────────────────────────────────┐
│                       BACKSTAGE IDP (Control Plane)                       │
│                                                                           │
│  ┌──────────────────────────────────┐  ┌───────────────────────────────┐  │
│  │ 1. Software Catalog (Visibility) │  │ 2. Scaffolder (Update Action) │  │
│  │ • Component: hello-world-app     │  │ • Input: Cert + Key (or Auto- │  │
│  │ • Resource: haproxy-edge-tls     │  │   Generate Self-Signed)       │  │
│  │ • Tracks: Expiry, Serial/Version,│  │ • Validates X.509 Key Match   │  │
│  │   Provider ("Self-Signed")       │  │ • Combines into single .pem   │  │
│  └─────────────────▲────────────────┘  └───────────────┬───────────────┘  │
└────────────────────┼───────────────────────────────────┼──────────────────┘
                     │ Polls Live TLS Handshake          │ Deploys & Reloads
┌────────────────────┴───────────────────────────────────▼──────────────────┐
│                         TARGET SANDBOX ENVIRONMENT                        │
│                                                                           │
│  [ Client ] ──HTTPS (443)──► [ HAProxy Edge ] ──HTTP (8080)──► [HelloApp] │
│                              • /etc/haproxy/certs/hello.pem               │
│                              • Runtime API Socket (/var/run/haproxy.sock) │
└───────────────────────────────────────────────────────────────────────────┘

```

---

## 2. Target Sandbox Setup (`haproxy.cfg` Baseline)

Your HAProxy instance terminates TLS using a unified `.pem` file (`fullchain.crt` + `private.key`) and exposes the Runtime Admin Socket so Backstage (or your automation runner) can hot-swap certificates in memory without restarting the proxy:

```haproxy
global
    # Enable Runtime API socket for zero-downtime cert updates
    stats socket /var/run/haproxy.sock mode 660 level admin expose-fd listeners

defaults
    mode http
    timeout connect 5s
    timeout client  50s
    timeout server  50s

frontend https_in
    bind *:443 ssl crt /etc/haproxy/certs/hello-world.pem
    default_backend hello_world_app

backend hello_world_app
    server app1 127.0.0.1:8080 check

```

---

## 3. Backstage Catalog Data Model (`catalog-info.yaml`)

Register both the `hello-world` service and its HAProxy TLS certificate in Backstage so you can track version, provider, and expiry directly in the UI:

```yaml
apiVersion: backstage.io/v1alpha1
kind: Component
metadata:
  name: hello-world-app
  description: Sandbox Hello World application fronted by HAProxy
spec:
  type: service
  lifecycle: experimental
  owner: group:resiliency-group
  dependsOn:
    - resource:default/haproxy-hello-world-tls
---
apiVersion: backstage.io/v1alpha1
kind: Resource
metadata:
  name: haproxy-hello-world-tls
  description: HAProxy Frontend TLS Certificate for Hello World App
  annotations:
    resiliency.idp/cert-provider: "Self-Signed (OpenSSL)"
    resiliency.idp/cert-version: "v1 (Serial: 7F:3B:91:02)"
    resiliency.idp/cert-expiry: "2026-11-20T00:00:00Z"
    resiliency.idp/days-remaining: "31"
    resiliency.idp/haproxy-host: "haproxy-sandbox.internal:443"
    resiliency.idp/haproxy-pem-path: "/etc/haproxy/certs/hello-world.pem"
spec:
  type: tls-certificate
  owner: group:resiliency-group

```

---

## 4. Phased MVP Implementation Plan

### Phase 1: Sandbox & Catalog Visibility (Days 1–3)

1. **Deploy the Target Stack:** Spin up the `hello-world` container and HAProxy container/VM with an initial self-signed certificate expiring in **15 days** (to immediately demonstrate a "Warning" state in Backstage).
2. **Register Entities in Backstage:** Import the `catalog-info.yaml` above so `hello-world-app` and `haproxy-hello-world-tls` appear in the Catalog with their dependency graph.
3. **Lightweight Live-Probe Provider:** Build a simple scheduled check (using Node's native `tls.connect(443, 'haproxy-sandbox.internal', { rejectUnauthorized: false })`) that inspects the live peer certificate directly from HAProxy's port 443 and updates the Backstage entity annotations (`cert-expiry`, `cert-version` via serial number, and `days-remaining`).

### Phase 2: Custom HAProxy Scaffolder Actions (Days 4–7)

Build two lightweight Backstage Scaffolder actions (or wrap them in an Ansible/SSH runner called by Backstage):

1. **`resiliency:cert:bundle-haproxy-pem`:**
* **Option A (Upload Existing Artifacts):** Takes the uploaded `cert.crt` and `private.key`, runs an `openssl x509 -noout -modulus` check to guarantee the key matches the cert, and concatenates them (`cert + "\n" + key`) into HAProxy's required single `.pem` format.
* **Option B (Auto-Generate Self-Signed):** Generates a fresh self-signed X.509 cert + key on the fly given a Common Name (`CN=hello.internal`) and validity days.


2. **`resiliency:haproxy:deploy-cert`:**
* Pushes the combined `hello-world.pem` to `/etc/haproxy/certs/hello-world.pem` on the HAProxy host.
* Executes a **zero-downtime reload** via HAProxy Runtime Socket (`set ssl cert` / `commit ssl cert`) or graceful systemd reload (`systemctl reload haproxy`).
* Runs a post-flight check (`curl -vk [https://haproxy-sandbox.internal](https://haproxy-sandbox.internal)`) to verify the new serial number is live before marking the Backstage task green.



### Phase 3: End-to-End Demo & KPI Hook (Days 8–10)

1. **Trigger Update from Catalog UI:** Add a template link on the `haproxy-hello-world-tls` entity page so clicking **"Rotate Certificate"** pre-fills the target HAProxy resource.
2. **Export Metric:** Expose a simple Prometheus gauge (`idp_certificate_expiry_days{service="hello-world", proxy="haproxy"}`) to show executives how this feeds into your monthly reliability KPIs.

---

## 5. Backstage Scaffolder Workflow (`template.yaml`)

This template supports **both** uploading pre-generated cert/key artifacts and one-click self-signed rotation for your HAProxy POC:

```yaml
apiVersion: scaffolder.backstage.io/v1beta3
kind: Template
metadata:
  name: update-haproxy-tls-cert
  title: Update HAProxy TLS Certificate (Self-Signed MVP)
  description: Validate, bundle, and hot-reload a TLS certificate and key on HAProxy fronting the Hello World app.
  tags:
    - haproxy
    - tls
    - mvp
spec:
  owner: group:resiliency-group
  type: workflow

  parameters:
    - title: 1. Target Certificate & Mode
      required: [certEntity, updateMode]
      properties:
        certEntity:
          title: Target HAProxy Certificate
          type: string
          default: resource:default/haproxy-hello-world-tls
          ui:field: EntityPicker
          ui:options:
            catalogFilter:
              kind: Resource
              spec.type: tls-certificate
        provider:
          title: Certificate Provider
          type: string
          default: Self-Signed
          enum: [Self-Signed]
        updateMode:
          title: Artifact Source
          type: string
          default: upload
          enum: [upload, auto-generate]
          enumNames:
            - "Upload Custom Self-Signed Cert & Private Key"
            - "Auto-Generate Fresh Self-Signed Cert & Key"

    - title: 2. Certificate Artifacts
      dependencies:
        updateMode:
          oneOf:
            - properties:
                updateMode:
                  enum: [upload]
                publicCert:
                  title: Public Certificate (PEM)
                  type: string
                  ui:widget: textarea
                privateKey:
                  title: Private Key (PEM - Redacted from logs)
                  type: string
                  ui:widget: password
              required: [publicCert, privateKey]
            - properties:
                updateMode:
                  enum: [auto-generate]
                commonName:
                  title: Common Name (CN)
                  type: string
                  default: hello.internal
                validDays:
                  title: Validity Period (Days)
                  type: integer
                  default: 90

  steps:
    - id: prepare-and-validate-pem
      name: Validate Key-Pair Match & Build HAProxy .pem Bundle
      action: resiliency:haproxy:build-pem
      input:
        mode: ${{ parameters.updateMode }}
        cert: ${{ parameters.publicCert }}
        key: ${{ parameters.privateKey }}
        commonName: ${{ parameters.commonName }}
        validDays: ${{ parameters.validDays }}

    - id: deploy-to-haproxy
      name: Push .pem & Hot-Reload HAProxy TLS
      action: resiliency:haproxy:deploy-cert
      input:
        entityRef: ${{ parameters.certEntity }}
        pemBundle: ${{ steps['prepare-and-validate-pem'].output.pemBundle }}

    - id: verify-live-handshake
      name: Verify New Certificate Serial on Port 443
      action: resiliency:haproxy:verify-tls
      input:
        expectedSerial: ${{ steps['prepare-and-validate-pem'].output.serialNumber }}

    - id: refresh-catalog
      name: Sync Updated Expiry & Version in Backstage Catalog
      action: catalog:refresh
      input:
        entityRef: ${{ parameters.certEntity }}

  output:
    text:
      - title: HAProxy Certificate Updated Successfully
        content: |
          - **New Version / Serial:** `${{ steps['prepare-and-validate-pem'].output.serialNumber }}`
          - **New Expiry Date:** `${{ steps['prepare-and-validate-pem'].output.expiryDate }}`
          - **Live Verification:** Passed on `https://hello.internal:443`

```

---

## 6. How the HAProxy Hot-Reload Step Works Under the Hood

Inside your `resiliency:haproxy:deploy-cert` step, you have two clean ways to apply the combined `hello-world.pem` without dropping active traffic to the `hello-world` app:

1. **Method A: In-Memory Runtime Socket (Zero Process Restart - Recommended)**
Streams the new `.pem` directly into HAProxy's memory over `/var/run/haproxy.sock` using `socat` and persists it to disk:
```bash
# 1. Write to disk so it survives future machine reboots
cat << 'EOF' > /etc/haproxy/certs/hello-world.pem
${PEM_BUNDLE}
EOF
chmod 600 /etc/haproxy/certs/hello-world.pem

# 2. Hot-swap in HAProxy memory with zero dropped packets
echo -e "set ssl cert /etc/haproxy/certs/hello-world.pem <<\n${PEM_BUNDLE}\n" | socat stdio /var/run/haproxy.sock
echo "commit ssl cert /etc/haproxy/certs/hello-world.pem" | socat stdio /var/run/haproxy.sock

```


2. **Method B: Graceful Config Reload (Simpler for initial POC)**
Writes `/etc/haproxy/certs/hello-world.pem`, verifies config syntax via `haproxy -c -f /etc/haproxy/haproxy.cfg`, and runs `systemctl reload haproxy` (or sends `SIGUSR2` to the HAProxy container).
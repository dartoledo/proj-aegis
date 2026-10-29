const http = require('node:http');
const PORT = Number(process.env.PORT || 8880);

const HARBOR_REPOSITORIES = {
  'aegis-ciam/aegis-ui': {
    repositorySlug: 'aegis-ciam/aegis-ui',
    projectName: 'aegis-ciam',
    repoName: 'aegis-ui',
    registryHost: 'harbor.aegis.internal:8880',
    activeTag: 'v2.4.0',
    digest: 'sha256:8f4e2c19a7b3d6054e1f90c2b8a4d7e6f123456789abcdef0123456789abcdef',
    baseImage: 'nginx:1.26-alpine3.20',
    sizeMB: 42.8,
    pushedAt: '2026-10-24T08:22:31.482Z',
    scanStatus: 'Success',
    scanner: 'Grype v0.121.0 + Syft v1.55.0 (Harbor Adapter)',
    vulnerabilitySummary: { critical: 0, high: 1, medium: 4, low: 5, fixable: 5 },
    topCves: ['CVE-2024-45806', 'CVE-2026-31042'],
    tags: ['v2.4.0', 'v2.3.9', 'latest'],
  },
  'aegis-ciam/aegis-backend': {
    repositorySlug: 'aegis-ciam/aegis-backend',
    projectName: 'aegis-ciam',
    repoName: 'aegis-backend',
    registryHost: 'harbor.aegis.internal:8880',
    activeTag: 'v1.9.2',
    digest: 'sha256:3a7b91c4e2f8d0561b4c7a9e2f6d83051c4b7a9e2f6d83051c4b7a9e2f6d8305',
    baseImage: 'node:18.20-alpine3.17',
    sizeMB: 138.4,
    pushedAt: '2026-10-23T19:45:07.113Z',
    scanStatus: 'Success',
    scanner: 'Grype v0.121.0 + Syft v1.55.0 (Harbor Adapter)',
    vulnerabilitySummary: { critical: 6, high: 2, medium: 4, low: 7, fixable: 8 },
    topCves: ['CVE-2026-111497', 'CVE-2026-56850', 'CVE-2025-1094', 'CVE-2024-0727'],
    tags: ['v1.9.2', 'v1.9.1', 'v1.8.0', 'latest'],
  },
  'aegis-ciam/aegis-auth': {
    repositorySlug: 'aegis-ciam/aegis-auth',
    projectName: 'aegis-ciam',
    repoName: 'aegis-auth',
    registryHost: 'harbor.aegis.internal:8880',
    activeTag: 'v3.1.0',
    digest: 'sha256:c5d8e2f1a4b7c9063d2e5f8a1b4c7d0e3f6a9b2c5d8e1f4a7b0c3d6e9f2a5b8c',
    baseImage: 'node:20.11-alpine3.18',
    sizeMB: 112.6,
    pushedAt: '2026-10-22T14:30:55.901Z',
    scanStatus: 'Success',
    scanner: 'Grype v0.121.0 + Syft v1.55.0 (Harbor Adapter)',
    vulnerabilitySummary: { critical: 1, high: 3, medium: 2, low: 3, fixable: 4 },
    topCves: ['CVE-2026-111497', 'CVE-2024-27980', 'CVE-2024-45492', 'CVE-2024-6119'],
    tags: ['v3.1.0', 'v3.0.4', 'v2.8.1', 'latest'],
  },
  'aegis-ciam/aegis-db': {
    repositorySlug: 'aegis-ciam/aegis-db',
    projectName: 'aegis-ciam',
    repoName: 'aegis-db',
    registryHost: 'harbor.aegis.internal:8880',
    activeTag: 'v16.2.0',
    digest: 'sha256:7e1f4a8b3c6d9025e8f1a4b7c0d3e6f9a2b5c8d1e4f7a0b3c6d9e2f5a8b1c4d7',
    baseImage: 'postgres:16.2-alpine3.19',
    sizeMB: 245.1,
    pushedAt: '2026-10-21T22:10:44.672Z',
    scanStatus: 'Success',
    scanner: 'Grype v0.121.0 + Syft v1.55.0 (Harbor Adapter)',
    vulnerabilitySummary: { critical: 2, high: 3, medium: 6, low: 9, fixable: 7 },
    topCves: ['CVE-2024-10979', 'CVE-2024-6119', 'CVE-2024-58251'],
    tags: ['v16.2.0', 'v16.1.3', 'v15.8.0', 'latest'],
  },
  'aegis-ciam/hello-world-app': {
    repositorySlug: 'aegis-ciam/hello-world-app',
    projectName: 'aegis-ciam',
    repoName: 'hello-world-app',
    registryHost: 'harbor.aegis.internal:8880',
    activeTag: 'v1.4.0',
    digest: 'sha256:2b5c8d1e4f7a0b3c6d9e2f5a8b1c4d7e0f3a6b9c2d5e8f1a4b7c0d3e6f9a2b5',
    baseImage: 'haproxy:3.0-alpine3.20',
    sizeMB: 68.3,
    pushedAt: '2026-10-20T09:55:18.334Z',
    scanStatus: 'Success',
    scanner: 'Grype v0.121.0 + Syft v1.55.0 (Harbor Adapter)',
    vulnerabilitySummary: { critical: 2, high: 1, medium: 2, low: 4, fixable: 3 },
    topCves: ['CVE-2023-25725', 'CVE-2023-40225', 'CVE-2024-4741'],
    tags: ['v1.4.0', 'v1.3.2', 'latest'],
  },
};

function sendJSON(res, statusCode, body) {
  res.writeHead(statusCode, {
    'Content-Type': 'application/json',
    'Access-Control-Allow-Origin': '*',
    'Access-Control-Allow-Methods': 'GET, POST, OPTIONS',
    'Access-Control-Allow-Headers': 'Content-Type, Authorization',
  });
  res.end(JSON.stringify(body, null, 2));
}

const server = http.createServer((req, res) => {
  const url = req.url;
  const method = req.method;

  // Route 1: GET /healthz or GET /api/v2.0/health
  if (method === 'GET' && (url === '/healthz' || url === '/api/v2.0/health')) {
    sendJSON(res, 200, {
      status: 'healthy',
      service: 'harbor-registry-sandbox',
      version: 'v2.11.0-aegis',
      registryUrl: 'http://127.0.0.1:8880',
    });
    return;
  }

  // Route 2: GET /v2/
  if (method === 'GET' && url === '/v2/') {
    sendJSON(res, 200, {
      ociVersion: 'v2',
      registry: 'harbor.aegis.internal:8880',
    });
    return;
  }

  // Route 3: GET /api/v2.0/repositories
  if (method === 'GET' && url === '/api/v2.0/repositories') {
    sendJSON(res, 200, {
      total: 5,
      repositories: Object.values(HARBOR_REPOSITORIES),
    });
    return;
  }

  // Route 4: GET /api/v2.0/repositories/:project/:repo
  const repoMatch = url.match(/^\/api\/v2\.0\/repositories\/([^/]+)\/([^/]+)$/);
  if (method === 'GET' && repoMatch) {
    const project = repoMatch[1];
    const repo = repoMatch[2];
    const slug = `${project}/${repo}`;
    const repoObj = HARBOR_REPOSITORIES[slug];
    if (repoObj) {
      sendJSON(res, 200, repoObj);
    } else {
      sendJSON(res, 404, { error: 'repository not found', slug });
    }
    return;
  }

  // Route 5: POST /api/v2.0/scan/:project/:repo
  const scanMatch = url.match(/^\/api\/v2\.0\/scan\/([^/]+)\/([^/]+)$/);
  if (method === 'POST' && scanMatch) {
    const project = scanMatch[1];
    const repo = scanMatch[2];
    const slug = `${project}/${repo}`;
    const repoObj = HARBOR_REPOSITORIES[slug];
    if (repoObj) {
      repoObj.lastScannedAt = new Date().toISOString();
      sendJSON(res, 200, { status: 'scanned', repository: repoObj });
    } else {
      sendJSON(res, 404, { error: 'repository not found', slug });
    }
    return;
  }

  // Fallback
  sendJSON(res, 404, { error: 'not found', path: url });
});

module.exports = { server, HARBOR_REPOSITORIES };

if (require.main === module) {
  server.listen(PORT, '0.0.0.0', () => {
    console.log(`[harbor-registry-sandbox] listening on 0.0.0.0:${PORT}`);
  });
}

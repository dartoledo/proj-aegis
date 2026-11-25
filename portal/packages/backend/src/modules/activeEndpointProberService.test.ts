import { execFileSync } from 'node:child_process';
import fs from 'node:fs';
import https from 'node:https';
import os from 'node:os';
import path from 'node:path';
import {
  classifySourceIpZscalerContext,
  detectWafFromHeadersAndCnames,
  isIpInCidr,
  normalizeTargetEndpointInput,
  probeEndpointListLive,
} from './activeEndpointProberService';
import { removeTrackedEndpointFromMemory } from './sslEndpointTrackerService';

describe('activeEndpointProberService', () => {
  describe('Zscaler Source IP & Network Origin Classification', () => {
    it('classifies Zscaler Public Service Edge CIDR IPs as PRIVATE_NETWORK_ZSCALER', () => {
      expect(isIpInCidr('165.225.72.45', '165.225.0.0/16')).toBe(true);
      expect(isIpInCidr('147.161.200.10', '147.161.128.0/17')).toBe(true);
      expect(isIpInCidr('203.0.113.50', '165.225.0.0/16')).toBe(false);

      const ctx = classifySourceIpZscalerContext({
        sourceIp: '165.225.72.45',
      });
      expect(ctx.isZscalerSourceIp).toBe(true);
      expect(ctx.networkOrigin).toBe('PRIVATE_NETWORK_ZSCALER');
      expect(ctx.detectionReason).toContain('165.225.0.0/16');
    });

    it('classifies Zscaler PTR hostname or ASN organization as PRIVATE_NETWORK_ZSCALER', () => {
      const ptrCtx = classifySourceIpZscalerContext({
        sourceIp: '198.51.100.12',
        ptrHostnames: ['zen-tyo2.zscloud.net'],
      });
      expect(ptrCtx.isZscalerSourceIp).toBe(true);
      expect(ptrCtx.networkOrigin).toBe('PRIVATE_NETWORK_ZSCALER');

      const orgCtx = classifySourceIpZscalerContext({
        sourceIp: '198.51.100.15',
        orgName: 'AS22616 Zscaler, Inc.',
      });
      expect(orgCtx.isZscalerSourceIp).toBe(true);
      expect(orgCtx.networkOrigin).toBe('PRIVATE_NETWORK_ZSCALER');
    });

    it('classifies non-Zscaler source IP as PUBLIC_INTERNET', () => {
      const pubCtx = classifySourceIpZscalerContext({
        sourceIp: '203.0.113.99',
        ptrHostnames: ['edge.public-isp.example.net'],
        orgName: 'Google Cloud',
      });
      expect(pubCtx.isZscalerSourceIp).toBe(false);
      expect(pubCtx.networkOrigin).toBe('PUBLIC_INTERNET');
    });
  });

  describe('WAF Protection Fingerprinting (Akamai, Fastly, Cloud Armor)', () => {
    it('detects Akamai WAF from headers, cookies, or CNAMEs', () => {
      const byHeader = detectWafFromHeadersAndCnames({
        headers: {
          server: 'AkamaiGHost',
          'x-akamai-transformed': '9 12345 0 pmb=mRUM,2',
        },
      });
      expect(byHeader.wafProvider).toBe('Akamai');
      expect(byHeader.wafDetected).toBe(true);

      const byCname = detectWafFromHeadersAndCnames({
        headers: {},
        cnames: ['e10492.dscx.akamaiedge.net'],
      });
      expect(byCname.wafProvider).toBe('Akamai');
      expect(byCname.wafDetected).toBe(true);
    });

    it('detects Fastly WAF from headers or CNAMEs', () => {
      const byHeader = detectWafFromHeadersAndCnames({
        headers: {
          'x-served-by': 'cache-tyo11928-TYO',
          'x-timer': 'S1712345678.123456,VS0,VE12',
          'x-fastly-request-id': 'abc-123-fastly',
        },
      });
      expect(byHeader.wafProvider).toBe('Fastly');
      expect(byHeader.wafDetected).toBe(true);

      const byCname = detectWafFromHeadersAndCnames({
        headers: {},
        cnames: ['dualstack.aegis.map.fastly.net'],
      });
      expect(byCname.wafProvider).toBe('Fastly');
      expect(byCname.wafDetected).toBe(true);
    });

    it('detects Google Cloud Armor from headers', () => {
      const byHeader = detectWafFromHeadersAndCnames({
        headers: {
          server: 'Google Frontend',
          via: '1.1 google',
          'x-cloud-trace-context': '105445aa7843bc8bf206b12000100000/1;o=1',
        },
      });
      expect(byHeader.wafProvider).toBe('Cloud Armor');
      expect(byHeader.wafDetected).toBe(true);
    });

    it('returns None when no WAF signatures are present', () => {
      const res = detectWafFromHeadersAndCnames({
        headers: { server: 'nginx/1.25.0' },
        cnames: [],
      });
      expect(res.wafProvider).toBe('None');
      expect(res.wafDetected).toBe(false);
    });
  });

  describe('Live TLS + HTTPS Endpoint List Probing', () => {
    let tmpDir: string;
    let server: https.Server;
    let port: number;
    let simulatedWafHeader: 'akamai' | 'fastly' | 'cloud-armor' = 'akamai';

    beforeAll(async () => {
      tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), 'aegis-prober-test-'));
      const keyPath = path.join(tmpDir, 'key.pem');
      const certPath = path.join(tmpDir, 'cert.pem');
      execFileSync('openssl', [
        'req',
        '-x509',
        '-newkey',
        'rsa:2048',
        '-nodes',
        '-sha256',
        '-days',
        '60',
        '-subj',
        '/CN=127.0.0.1/O=Aegis Edge Prober Test',
        '-addext',
        'subjectAltName=DNS:localhost,IP:127.0.0.1',
        '-keyout',
        keyPath,
        '-out',
        certPath,
      ]);

      const key = fs.readFileSync(keyPath);
      const cert = fs.readFileSync(certPath);

      server = https.createServer({ key, cert }, (_req, res) => {
        if (simulatedWafHeader === 'akamai') {
          res.setHeader('Server', 'AkamaiGHost');
          res.setHeader('X-Akamai-Transformed', '9 - 0');
        } else if (simulatedWafHeader === 'fastly') {
          res.setHeader('X-Served-By', 'cache-nrt-fastly');
          res.setHeader('X-Fastly-Request-ID', 'f-999');
        } else {
          res.setHeader('Server', 'Google Frontend');
          res.setHeader('Via', '1.1 google');
        }
        res.writeHead(200, { 'Content-Type': 'application/json' });
        res.end(JSON.stringify({ ok: true }));
      });

      await new Promise<void>(resolve => {
        server.listen(0, '127.0.0.1', () => {
          const addr = server.address();
          port = typeof addr === 'object' && addr ? addr.port : 0;
          resolve();
        });
      });
    });

    afterAll(async () => {
      await new Promise<void>(resolve => server.close(() => resolve()));
      fs.rmSync(tmpDir, { recursive: true, force: true });
    });

    it('probes live HTTPS endpoint from Non-Zscaler Public IP and populates SSL expiry, CN, Issuer, Serial, Key Size, WAF, and accessibleFromPublicInternet=true', async () => {
      simulatedWafHeader = 'akamai';
      const report = await probeEndpointListLive(
        [`https://127.0.0.1:${port}`],
        {
          sourceIpOverride: '203.0.113.88',
          persistToStore: true,
        },
      );

      expect(report.networkContext.isZscalerSourceIp).toBe(false);
      expect(report.networkContext.networkOrigin).toBe('PUBLIC_INTERNET');
      expect(report.totalProbed).toBe(1);
      expect(report.reachableCount).toBe(1);
      expect(report.publicAccessibleCount).toBe(1);
      expect(report.wafProtectedCount).toBe(1);

      const item = report.results[0];
      expect(item.reachable).toBe(true);
      expect(item.accessibleFromPublicInternet).toBe(true);
      expect(item.wafProvider).toBe('Akamai');
      expect(item.sslDetails).not.toBeNull();
      expect(item.sslDetails!.subjectCn).toBe('127.0.0.1');
      expect(item.sslDetails!.issuerCn).toBe('127.0.0.1');
      expect(item.sslDetails!.serialNumberHex).toMatch(/^[0-9A-F]{2}(:[0-9A-F]{2})*$/);
      expect(item.sslDetails!.publicKeyAlgorithm).toBe('RSA');
      expect(item.sslDetails!.publicKeyBits).toBe(2048);
      expect(item.sslDetails!.daysRemaining).toBeGreaterThan(50);

      removeTrackedEndpointFromMemory(item.endpointId);
    });

    it('marks accessibleFromPublicInternet=false when source IP is Zscaler (PRIVATE_NETWORK_ZSCALER)', async () => {
      simulatedWafHeader = 'cloud-armor';
      const report = await probeEndpointListLive(
        [`https://127.0.0.1:${port}`],
        {
          sourceIpOverride: '165.225.44.19',
          persistToStore: false,
        },
      );

      expect(report.networkContext.isZscalerSourceIp).toBe(true);
      expect(report.networkContext.networkOrigin).toBe('PRIVATE_NETWORK_ZSCALER');
      expect(report.reachableCount).toBe(1);
      expect(report.publicAccessibleCount).toBe(0);

      const item = report.results[0];
      expect(item.reachable).toBe(true);
      expect(item.isZscalerSourceIp).toBe(true);
      expect(item.accessibleFromPublicInternet).toBe(false);
      expect(item.exposureScope).toBe('strictly-private');
      expect(item.wafProvider).toBe('Cloud Armor');
    });

    it('normalizes bare domains and URLs accurately', () => {
      expect(normalizeTargetEndpointInput('api.aegis.cloud.goog')).toEqual({
        endpointUrl: 'https://api.aegis.cloud.goog',
        hostname: 'api.aegis.cloud.goog',
        port: 443,
      });
      expect(normalizeTargetEndpointInput('https://127.0.0.1:8443/healthz')).toEqual({
        endpointUrl: 'https://127.0.0.1:8443/healthz',
        hostname: '127.0.0.1',
        port: 8443,
      });
    });
  });
});

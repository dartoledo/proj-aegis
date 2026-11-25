import { execFileSync } from 'node:child_process';
import fs from 'node:fs';
import https from 'node:https';
import os from 'node:os';
import path from 'node:path';
import {
  importDomainsCsvToCmdb,
  normalizeEnvironmentTier,
  parseDomainsCsv,
  SAMPLE_DOMAINS_CSV_TEMPLATE,
} from './domainCsvImporterService';
import { removeTrackedEndpointFromMemory } from './sslEndpointTrackerService';

describe('domainCsvImporterService', () => {
  describe('parseDomainsCsv & Required Field Validation (endpoint, service_name, environment)', () => {
    it('rejects CSV when the required environment header column is missing', () => {
      const csv = [
        'endpoint,service_name',
        'https://auth.aegis.cloud.goog,aegis-auth',
      ].join('\n');

      const parsed = parseDomainsCsv(csv);
      expect(parsed.validRows.length).toBe(0);
      expect(parsed.errors.length).toBe(1);
      expect(parsed.errors[0].message).toContain(
        'Missing required CSV header column(s): environment',
      );
    });

    it('rejects rows with missing or invalid environment values while preserving valid rows', () => {
      const csv = [
        'endpoint,service_name,environment,notes',
        'https://auth.aegis.cloud.goog,aegis-auth,prod,"Valid prod row, with comma"',
        'https://missing-env.aegis.cloud.goog,aegis-auth,,Missing env row',
        'https://bad-env.aegis.cloud.goog,aegis-backend,sandbox-invalid,Bad env row',
        'https://stg.aegis.cloud.goog,aegis-ui,staging,Valid staging alias',
      ].join('\n');

      const parsed = parseDomainsCsv(csv);
      expect(parsed.totalDataRows).toBe(4);
      expect(parsed.validRows.length).toBe(2);
      expect(parsed.errors.length).toBe(2);
      expect(parsed.errors[0].message).toContain(
        "Missing required 'environment' value",
      );
      expect(parsed.errors[1].message).toContain(
        "Invalid 'environment' value 'sandbox-invalid'",
      );

      expect(parsed.validRows[0].environment).toBe('prod');
      expect(parsed.validRows[0].notes).toBe('Valid prod row, with comma');
      expect(parsed.validRows[1].environment).toBe('stg');
    });

    it('parses the SAMPLE_DOMAINS_CSV_TEMPLATE with zero errors', () => {
      const parsed = parseDomainsCsv(SAMPLE_DOMAINS_CSV_TEMPLATE);
      expect(parsed.errors.length).toBe(0);
      expect(parsed.validRows.length).toBe(3);
      expect(parsed.validRows.map(r => r.environment)).toEqual([
        'prod',
        'prod',
        'stg',
      ]);
    });

    it('normalizes environment tier aliases accurately', () => {
      expect(normalizeEnvironmentTier('prod')).toBe('prod');
      expect(normalizeEnvironmentTier('Production')).toBe('prod');
      expect(normalizeEnvironmentTier('staging')).toBe('stg');
      expect(normalizeEnvironmentTier('development')).toBe('dev');
      expect(normalizeEnvironmentTier('pre-prod')).toBe('preprod');
      expect(normalizeEnvironmentTier('stress')).toBe('stress-test');
      expect(normalizeEnvironmentTier('unknown')).toBeNull();
    });
  });

  describe('importDomainsCsvToCmdb (Offline & Live Active Probing)', () => {
    let tmpDir: string;
    let server: https.Server;
    let port: number;

    beforeAll(async () => {
      tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), 'aegis-csv-import-test-'));
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
        '45',
        '-subj',
        '/CN=127.0.0.1/O=Aegis CSV Import Test',
        '-keyout',
        keyPath,
        '-out',
        certPath,
      ]);

      const key = fs.readFileSync(keyPath);
      const cert = fs.readFileSync(certPath);

      server = https.createServer({ key, cert }, (_req, res) => {
        res.setHeader('X-Served-By', 'cache-tyo-fastly');
        res.setHeader('X-Fastly-Request-ID', 'fastly-csv-test');
        res.writeHead(200);
        res.end('ok');
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

    it('imports valid CSV rows and probes live SSL, WAF (Fastly), and Public Internet accessibility', async () => {
      const csv = [
        'endpoint,service_name,environment,endpoint_key,provider_type,notes',
        `https://127.0.0.1:${port},aegis-ui,stg,csv-live-probe,gcp-cloud-lb,CSV live probe test`,
      ].join('\n');

      const report = await importDomainsCsvToCmdb({
        csvText: csv,
        probeOnImport: true,
        sourceIpOverride: '203.0.113.44',
      });

      expect(report.importedCount).toBe(1);
      expect(report.probedReachableCount).toBe(1);
      expect(report.publicAccessibleCount).toBe(1);
      expect(report.wafProtectedCount).toBe(1);
      expect(report.probeResults[0].wafProvider).toBe('Fastly');
      expect(report.importedEndpoints[0].environment).toBe('stg');

      removeTrackedEndpointFromMemory(report.importedEndpoints[0].endpointId);
    });
  });
});

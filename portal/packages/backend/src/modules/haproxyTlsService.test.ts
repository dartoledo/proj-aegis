import {
  buildAndValidateHaproxyPem,
  computeCertStatus,
  deployCertToHaproxy,
  formatColonSerial,
  normalizeSerial,
  probeLiveTlsCertificate,
  renderPrometheusMetrics,
  verifyLiveTlsSerial,
} from './haproxyTlsService';

describe('haproxyTlsService', () => {
  describe('serial formatting and status helpers', () => {
    it('formats raw hex serials into uppercase colon-delimited byte pairs', () => {
      expect(formatColonSerial('serial=7f3b9102')).toBe('7F:3B:91:02');
      expect(formatColonSerial('7F:3B:91:02')).toBe('7F:3B:91:02');
      expect(formatColonSerial('abc')).toBe('0A:BC');
    });

    it('normalizes serials for comparison across formats', () => {
      expect(normalizeSerial('7F:3B:91:02')).toBe(
        normalizeSerial('serial=7f3b9102'),
      );
      expect(normalizeSerial('00:7F:3B')).toBe(normalizeSerial('7f3b'));
    });

    it('computes Healthy, Warning, and Critical status thresholds', () => {
      expect(computeCertStatus(90)).toBe('Healthy');
      expect(computeCertStatus(31)).toBe('Healthy');
      expect(computeCertStatus(30)).toBe('Warning');
      expect(computeCertStatus(15)).toBe('Warning');
      expect(computeCertStatus(7)).toBe('Critical');
      expect(computeCertStatus(0)).toBe('Critical');
    });
  });

  describe('buildAndValidateHaproxyPem', () => {
    it('auto-generates a valid 90-day self-signed X.509 cert + key PEM bundle', async () => {
      const result = await buildAndValidateHaproxyPem({
        mode: 'auto-generate',
        commonName: 'hello.internal',
        validDays: 90,
      });

      expect(result.pemBundle).toContain('-----BEGIN CERTIFICATE-----');
      expect(result.pemBundle).toContain('-----END CERTIFICATE-----');
      expect(result.pemBundle).toMatch(
        /-----BEGIN (?:RSA )?PRIVATE KEY-----/,
      );
      expect(result.serialNumber).toMatch(/^[0-9A-F]{2}(:[0-9A-F]{2})+$/);
      expect(result.daysRemaining).toBeGreaterThanOrEqual(89);
      expect(result.daysRemaining).toBeLessThanOrEqual(91);
    });

    it('validates and bundles matching uploaded certificate and private key', async () => {
      const generated = await buildAndValidateHaproxyPem({
        mode: 'auto-generate',
        commonName: 'upload-test.internal',
        validDays: 45,
      });

      const certMatch = generated.pemBundle.match(
        /-----BEGIN CERTIFICATE-----[\s\S]+?-----END CERTIFICATE-----/,
      );
      const keyMatch = generated.pemBundle.match(
        /-----BEGIN (?:RSA )?PRIVATE KEY-----[\s\S]+?-----END (?:RSA )?PRIVATE KEY-----/,
      );

      expect(certMatch).not.toBeNull();
      expect(keyMatch).not.toBeNull();

      const uploaded = await buildAndValidateHaproxyPem({
        mode: 'upload',
        cert: certMatch![0],
        key: keyMatch![0],
      });

      expect(uploaded.serialNumber).toBe(generated.serialNumber);
      expect(uploaded.expiryDate).toBe(generated.expiryDate);
      expect(uploaded.daysRemaining).toBeGreaterThanOrEqual(44);
    });

    it('rejects mismatched certificate and private key without leaking private key material', async () => {
      const pairA = await buildAndValidateHaproxyPem({
        mode: 'auto-generate',
        commonName: 'pair-a.internal',
        validDays: 30,
      });
      const pairB = await buildAndValidateHaproxyPem({
        mode: 'auto-generate',
        commonName: 'pair-b.internal',
        validDays: 30,
      });

      const certA = pairA.pemBundle.match(
        /-----BEGIN CERTIFICATE-----[\s\S]+?-----END CERTIFICATE-----/,
      )![0];
      const keyB = pairB.pemBundle.match(
        /-----BEGIN (?:RSA )?PRIVATE KEY-----[\s\S]+?-----END (?:RSA )?PRIVATE KEY-----/,
      )![0];

      await expect(
        buildAndValidateHaproxyPem({
          mode: 'upload',
          cert: certA,
          key: keyB,
        }),
      ).rejects.toThrow(
        /X\.509 validation failed: Private Key does not match Public Certificate/,
      );

      try {
        await buildAndValidateHaproxyPem({
          mode: 'upload',
          cert: certA,
          key: keyB,
        });
      } catch (err) {
        const message = err instanceof Error ? err.message : String(err);
        expect(message).not.toContain('BEGIN PRIVATE KEY');
        expect(message).not.toContain('BEGIN RSA PRIVATE KEY');
      }
    });
  });

  describe('Live HAProxy Sandbox TLS Probe, Hot-Reload, SSL Diff, and Prometheus Metrics', () => {
    it('rotates a 15-day Warning certificate to a 90-day Healthy certificate, verifies live HTTPS handshake, and outputs the Old vs New SSL certificate diff', async () => {
      // Step 1: Seed HAProxy with a known 15-day "Old" certificate (Warning state)
      const oldCert = await buildAndValidateHaproxyPem({
        mode: 'auto-generate',
        commonName: 'old-hello.internal',
        validDays: 15,
      });
      await deployCertToHaproxy({
        entityRef: 'resource:default/haproxy-hello-world-tls',
        pemBundle: oldCert.pemBundle,
      });

      const preRotationProbe = await probeLiveTlsCertificate('127.0.0.1:8443');
      expect(preRotationProbe.serialNumber).toBe(oldCert.serialNumber);
      expect(preRotationProbe.subjectCN).toBe('old-hello.internal');
      expect(preRotationProbe.status).toBe('Warning');
      expect(preRotationProbe.fingerprint256).toMatch(
        /^[0-9A-F]{2}(:[0-9A-F]{2})+$/,
      );
      expect(preRotationProbe.tlsProtocol).toMatch(/^TLSv1\.[23]$/);
      expect(preRotationProbe.httpStatus).toBe(200);
      expect(preRotationProbe.httpHealthPassed).toBe(true);

      // Step 2: Generate a fresh 90-day "New" certificate (Healthy state) and hot-reload HAProxy
      const freshCert = await buildAndValidateHaproxyPem({
        mode: 'auto-generate',
        commonName: 'hello.internal',
        validDays: 90,
      });

      expect(freshCert.serialNumber).not.toBe(preRotationProbe.serialNumber);

      const deployResult = await deployCertToHaproxy({
        entityRef: 'resource:default/haproxy-hello-world-tls',
        pemBundle: freshCert.pemBundle,
      });

      expect(deployResult.serialNumber).toBe(freshCert.serialNumber);
      expect(deployResult.reloadedVia).toBe('haproxy-runtime-socket');
      expect(deployResult.previousProbe?.serialNumber).toBe(
        oldCert.serialNumber,
      );

      // Step 3: Verify live TLS handshake serves the newly deployed serial and generates Old vs New SSL diff
      const verified = await verifyLiveTlsSerial(
        freshCert.serialNumber,
        '127.0.0.1:8443',
      );
      expect(verified.serialNumber).toBe(freshCert.serialNumber);
      expect(verified.subjectCN).toBe('hello.internal');
      expect(verified.status).toBe('Healthy');
      expect(verified.daysRemaining).toBeGreaterThanOrEqual(89);
      expect(verified.httpStatus).toBe(200);
      expect(verified.httpHealthPassed).toBe(true);

      // Verify SSL Certificate Rotation Diff (Old vs. New)
      const { rotationDiff } = verified;
      expect(rotationDiff.serialChanged).toBe(true);
      expect(rotationDiff.fingerprintChanged).toBe(true);
      expect(rotationDiff.httpsHealthVerified).toBe(true);
      expect(rotationDiff.unifiedDiff).toContain(
        `--- Old SSL Certificate Response (Pre-Rotation @ 127.0.0.1:8443)`,
      );
      expect(rotationDiff.unifiedDiff).toContain(
        `+++ New SSL Certificate Response (Post-Rotation @ 127.0.0.1:8443)`,
      );
      expect(rotationDiff.unifiedDiff).toContain(
        `-  Serial Number       : ${oldCert.serialNumber}`,
      );
      expect(rotationDiff.unifiedDiff).toContain(
        `+  Serial Number       : ${freshCert.serialNumber}`,
      );
      expect(rotationDiff.unifiedDiff).toContain(
        `-  SHA-256 Fingerprint : ${preRotationProbe.fingerprint256}`,
      );
      expect(rotationDiff.unifiedDiff).toContain(
        `+  SHA-256 Fingerprint : ${verified.fingerprint256}`,
      );
      expect(rotationDiff.unifiedDiff).toContain(
        `-  Status              : Warning (${preRotationProbe.daysRemaining} days remaining)`,
      );
      expect(rotationDiff.unifiedDiff).toContain(
        `+  Status              : Healthy (${verified.daysRemaining} days remaining)`,
      );
      expect(rotationDiff.markdownDiff).toContain(
        '| SSL Certificate Field | Old SSL Response (Before) | New SSL Response (After) |',
      );

      // Step 4: Verify Prometheus metrics reflect the rotated certificate
      const metrics = await renderPrometheusMetrics('127.0.0.1:8443');
      expect(metrics).toContain(
        `idp_certificate_expiry_days{service="hello-world",proxy="haproxy"} ${verified.daysRemaining}`,
      );
      expect(metrics).toContain(
        `idp_certificate_info{service="hello-world",proxy="haproxy",serial="${freshCert.serialNumber}",provider="Self-Signed (OpenSSL)",status="Healthy"} 1`,
      );
    });
  });
});

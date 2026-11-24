import {
  compareNormalizedSortTuples,
  crossCheckSoftwareVersion,
  decomposeRawVersion,
  parseAndNormalizeSoftwareVersion,
} from './softwareVersionNormalizerService';

describe('softwareVersionNormalizerService', () => {
  describe('parseAndNormalizeSoftwareVersion', () => {
    it('normalizes Node.js SemVer into MAJOR eolCycleKey, PURL, CPE 2.3, and 7-element sort tuple', () => {
      const record = parseAndNormalizeSoftwareVersion({
        productName: 'Node.js',
        rawVersion: 'v18.20.8',
      });

      expect(record.eolProductSlug).toBe('nodejs');
      expect(record.eolCycleStrategy).toBe('MAJOR');
      expect(record.eolCycleKey).toBe('18');
      expect(record.eolApiUrl).toBe('https://endoflife.date/api/v1/products/nodejs/releases/18');
      expect(record.purl).toBe('pkg:generic/nodejs@v18.20.8');
      expect(record.cpe23Uri).toBe('cpe:2.3:a:nodejs:node.js:18.20.8:*:*:*:*:*:*:*');
      expect(record.nvdCpeMatchString).toBe('cpe:2.3:a:nodejs:node.js');
      expect(record.osvEcosystem).toBe('Bitnami');
      expect(record.osvPackageName).toBe('node');
      expect(record.ghsaEcosystem).toBe('npm');
      expect(record.semverSortTuple).toEqual([0, 18, 20, 8, 0, 999, 0]);
    });

    it('handles OpenSSL 1.1.1w-r1 letter patches, legacy 1.1.1 cycle strategy, and Alpine distro revision', () => {
      const record = parseAndNormalizeSoftwareVersion({
        productName: 'OpenSSL',
        rawVersion: '1.1.1w-r1',
        distroQualifier: 'alpine:3.17',
      });

      expect(record.eolProductSlug).toBe('openssl');
      expect(record.eolCycleStrategy).toBe('MAJOR_MINOR_PATCH');
      expect(record.eolCycleKey).toBe('1.1.1');
      expect(record.upstreamVersion).toBe('1.1.1w');
      expect(record.letterPatchNum).toBe(23); // 'w' is 23rd letter
      expect(record.distroRevision).toBe('r1');
      expect(record.distroAdvisoryNamespace).toBe('alpine:3.17');
      expect(record.osvEcosystem).toBe('Alpine:v3.17');
      expect(record.purl).toBe('pkg:apk/alpine/openssl@1.1.1w-r1?distro=alpine-3.17');
      expect(record.semverSortTuple).toEqual([0, 1, 1, 1, 23, 999, 0]);
    });

    it('orders prerelease versions (alpha < beta < rc < GA) and Debian epochs correctly', () => {
      const rc = decomposeRawVersion('18.20.9-rc.1');
      const ga = decomposeRawVersion('18.20.9');
      const epochVer = decomposeRawVersion('1:3.0.13-1~deb12u1');

      expect(compareNormalizedSortTuples(rc.semverSortTuple, ga.semverSortTuple)).toBe(-1);
      expect(epochVer.epoch).toBe(1);
      expect(epochVer.upstreamVersion).toBe('3.0.13');
      expect(epochVer.distroRevision).toBe('1~deb12u1');
    });
  });

  describe('crossCheckSoftwareVersion', () => {
    it('detects EOL status and reachable CISA KEV CVE for Node.js 18.20.8', () => {
      const res = crossCheckSoftwareVersion(
        {
          productName: 'Node.js',
          rawVersion: '18.20.8',
        },
        '2026-11-24',
      );

      expect(res.eolMatch.isEol).toBe(true);
      expect(res.eolMatch.matchedCycle?.cycle).toBe('18');
      expect(res.hasReachableCisaKev).toBe(true);
      expect(res.highestCvssScore).toBe(9.8);
      expect(res.cveMatches.map(c => c.cveId)).toContain('CVE-2026-111497');
    });

    it('avoids false positives when Alpine backport revision fixes a CVE (3.0.13-r1 vs 3.0.13-r0)', () => {
      const vulnerableAlpine = crossCheckSoftwareVersion({
        productName: 'OpenSSL',
        rawVersion: '3.0.13-r0',
        distroQualifier: 'alpine:3.19',
      });
      const patchedAlpine = crossCheckSoftwareVersion({
        productName: 'OpenSSL',
        rawVersion: '3.0.13-r1',
        distroQualifier: 'alpine:3.19',
      });

      expect(vulnerableAlpine.cveMatches.some(c => c.cveId === 'CVE-2024-6119')).toBe(true);
      expect(patchedAlpine.cveMatches.some(c => c.cveId === 'CVE-2024-6119')).toBe(false);
    });

    it('flags outdated patch on an active LTS cycle (React 18.3.1 vs 18.3.2)', () => {
      const res = crossCheckSoftwareVersion(
        {
          productName: 'React',
          rawVersion: '18.3.1',
          ecosystem: 'npm',
        },
        '2026-11-24',
      );

      expect(res.eolMatch.isEol).toBe(false);
      expect(res.eolMatch.isOutdatedPatchOnCycle).toBe(true);
      expect(res.eolMatch.latestPatchVersionOnCycle).toBe('18.3.2');
      expect(res.cveMatches.some(c => c.cveId === 'CVE-2026-31042')).toBe(true);
    });
  });
});

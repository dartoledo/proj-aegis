import {
  calculateDaysUntilEol,
  classifyEolStatus,
  evaluateProductCycles,
  getEntityHarborEolReport,
  getFleetHarborEolSummary,
  remediateEntityEolPackages,
  renderHarborEolPrometheusMetrics,
} from './harborEolService';

describe('calculateDaysUntilEol', () => {
  it('returns a negative number when eolDate is before referenceDate', () => {
    expect(calculateDaysUntilEol('2025-01-01', '2026-10-28')).toBeLessThan(0);
  });

  it('returns 0 when eolDate equals referenceDate', () => {
    expect(calculateDaysUntilEol('2026-10-28', '2026-10-28')).toBe(0);
  });

  it('returns a number greater than 300 when eolDate is well after referenceDate', () => {
    expect(calculateDaysUntilEol('2027-10-28', '2026-10-28')).toBeGreaterThan(300);
  });
});

describe('classifyEolStatus', () => {
  it('returns END_OF_LIFE when daysUntilEol is negative and isLts is true', () => {
    expect(classifyEolStatus(-10, true)).toBe('END_OF_LIFE');
  });

  it('returns END_OF_LIFE when daysUntilEol is 0 and isLts is false', () => {
    expect(classifyEolStatus(0, false)).toBe('END_OF_LIFE');
  });

  it('returns APPROACHING_EOL when daysUntilEol is 90 and isLts is true', () => {
    expect(classifyEolStatus(90, true)).toBe('APPROACHING_EOL');
  });

  it('returns ACTIVE_LTS when daysUntilEol is 250 and isLts is true', () => {
    expect(classifyEolStatus(250, true)).toBe('ACTIVE_LTS');
  });

  it('returns MAINTENANCE when daysUntilEol is 250 and isLts is false', () => {
    expect(classifyEolStatus(250, false)).toBe('MAINTENANCE');
  });
});

describe('evaluateProductCycles', () => {
  it('evaluates product tokens and returns correct eolStatus and cves', () => {
    const results = evaluateProductCycles(['nodejs@18', 'openssl@1.1.1', 'react@18'], '2026-10-28');
    const nodejs = results.find(r => r.product === 'nodejs' && r.cycle === '18');
    expect(nodejs?.eolStatus).toBe('END_OF_LIFE');
    expect(nodejs?.cves.map(c => c.cveId)).toContain('CVE-2026-56850');
  });
});

describe('getEntityHarborEolReport', () => {
  it('returns a report with correct harbor artifact and summary', async () => {
    const report = await getEntityHarborEolReport('component:default/aegis-backend', { referenceDate: '2026-10-28' });
    expect(report.harborArtifact.repositorySlug).toBe('aegis-ciam/aegis-backend');
    expect(report.summary.eolCount).toBeGreaterThanOrEqual(2);
    expect(report.summary.criticalCves).toBeGreaterThanOrEqual(3);
    expect(report.summary.overallRisk).toBe('CRITICAL');
  });
});

describe('getFleetHarborEolSummary & renderHarborEolPrometheusMetrics', () => {
  it('returns fleet reports and renders prometheus metrics', async () => {
    const reports = await getFleetHarborEolSummary();
    expect(reports).toHaveLength(5);
    const metrics = renderHarborEolPrometheusMetrics(reports);
    expect(metrics).toContain('aegis_package_eol_days_remaining');
    expect(metrics).toContain('aegis_harbor_image_vulnerabilities_total');
  });
});

describe('remediateEntityEolPackages', () => {
  it('remediates EOL packages and returns a report with zero eolCount, zero criticalCves, and activeTag ending in -lts', async () => {
    const remediated = await remediateEntityEolPackages('component:default/hello-world-app');
    expect(remediated.summary.eolCount).toBe(0);
    expect(remediated.summary.criticalCves).toBe(0);
    expect(remediated.harborArtifact.activeTag).toMatch(/-lts$/);
  });
});

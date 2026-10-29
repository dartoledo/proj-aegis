import { useEffect, useState } from 'react';
import { createFrontendModule } from '@backstage/frontend-plugin-api';
import { EntityCardBlueprint } from '@backstage/plugin-catalog-react/alpha';
import { useEntity } from '@backstage/plugin-catalog-react';
import { InfoCard } from '@backstage/core-components';

export interface OsPackagePatchRecord {
  packageName: string;
  purl: string;
  packageManager: 'apt' | 'apk' | 'yum' | 'cos' | 'npm';
  layerScope: 'vm-host-os' | 'container-os-layer' | 'app-runtime-sbom';
  architecture: string;
  installedVersion: string;
  availablePatchVersion: string;
  patchState: 'PATCHED' | 'PATCH_AVAILABLE' | 'PENDING_REBOOT' | 'MITIGATED_VEX' | 'UNPATCHED_EOL';
  securityAdvisoryId: string;
  cveIds: string[];
  cvssScore: number;
  severity: 'CRITICAL' | 'HIGH' | 'MEDIUM' | 'LOW' | 'NONE';
  license: string;
  remediationAction: string;
}

export interface GcpVmInstanceInventory {
  instanceId: string;
  instanceName: string;
  gcpProject: string;
  zone: string;
  machineType: string;
  workloadRole: string;
  internalIp: string;
  osInfo: {
    hostname: string;
    longName: string;
    shortName: string;
    version: string;
    kernelRelease: string;
    architecture: string;
    osconfigAgentVersion: string;
  };
  patchComplianceState: 'COMPLIANT' | 'NON_COMPLIANT' | 'PENDING_REBOOT';
  rebootRequired: boolean;
  lastPatchJobId: string;
  lastPatchedAt: string;
  osPolicyAssignmentId: string;
}

export interface GrafeasContainerAnalysisReport {
  resourceUri: string;
  harborMirrorUri: string;
  digest: string;
  baseImageDistro: string;
  layerCount: number;
  slsaProvenanceLevel: string;
  buildBuilderId: string;
  binaryAuthorization: {
    policyStatus: 'ATTESTED' | 'ALLOWLISTED_WARN' | 'BLOCKED_VIOLATION';
    attestorName: string;
    verifiedAt: string;
  };
  occurrenceCounts: {
    packageOccurrences: number;
    vulnerabilityOccurrences: number;
    buildOccurrences: number;
    attestationOccurrences: number;
  };
  vexSummary: {
    affected: number;
    notAffectedVex: number;
    fixed: number;
  };
}

export interface EntityGcpCloudPostureReport {
  entityRef: string;
  serviceName: string;
  domainExposureTier: string;
  primaryDomain: string;
  vmInventory: GcpVmInstanceInventory;
  containerAnalysis: GrafeasContainerAnalysisReport;
  osPackages: OsPackagePatchRecord[];
  patchSummary: {
    totalTrackedPackages: number;
    patchedCount: number;
    patchAvailableCount: number;
    pendingRebootCount: number;
    mitigatedVexCount: number;
    unpatchedEolCount: number;
    overallPatchRisk: 'CRITICAL' | 'WARNING' | 'COMPLIANT';
  };
  sbomMetadata: {
    format: string;
    documentNamespace: string;
    generatedAt: string;
  };
  scannedAt: string;
}

export function getPatchStateColor(state: string): string {
  switch (state) {
    case 'UNPATCHED_EOL':
      return '#d32f2f';
    case 'PATCH_AVAILABLE':
    case 'PENDING_REBOOT':
      return '#ed6c02';
    case 'MITIGATED_VEX':
      return '#0288d1';
    case 'PATCHED':
    case 'COMPLIANT':
      return '#2e7d32';
    default:
      return '#757575';
  }
}

export const EntityGcpCloudPostureCard = () => {
  const { entity } = useEntity();
  const entityRef = `${entity.kind.toLowerCase()}:${entity.metadata.namespace || 'default'}/${entity.metadata.name}`;

  const [report, setReport] = useState<EntityGcpCloudPostureReport | null>(null);
  const [fleet, setFleet] = useState<EntityGcpCloudPostureReport[]>([]);
  const [sbomDoc, setSbomDoc] = useState<Record<string, unknown> | null>(null);
  const [activeTab, setActiveTab] = useState<'vm' | 'packages' | 'container' | 'sbom'>('packages');
  const [stateFilter, setStateFilter] = useState<string>('ALL');
  const [patching, setPatching] = useState<boolean>(false);

  const apiBase = 'http://127.0.0.1:7007/api/gcp-posture';

  const loadData = async () => {
    try {
      const [entityRes, fleetRes, sbomRes] = await Promise.all([
        fetch(`${apiBase}/entity?entityRef=${encodeURIComponent(entityRef)}`),
        fetch(`${apiBase}/fleet`),
        fetch(`${apiBase}/sbom?entityRef=${encodeURIComponent(entityRef)}`),
      ]);
      if (entityRes.ok) setReport(await entityRes.json());
      if (fleetRes.ok) {
        const data = await fleetRes.json();
        setFleet(data.reports || []);
      }
      if (sbomRes.ok) setSbomDoc(await sbomRes.json());
    } catch {
      // ignore
    }
  };

  useEffect(() => {
    loadData();
  }, [entityRef]);

  const handleExecutePatchJob = async () => {
    setPatching(true);
    try {
      const res = await fetch(`${apiBase}/patch-job`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ entityRef }),
      });
      if (res.ok) {
        await loadData();
      }
    } finally {
      setPatching(false);
    }
  };

  if (!report) {
    return (
      <InfoCard title="☁️ GCP OS Config & Container Analysis Posture">
        <div>Loading GCP OS Config & Grafeas v1 telemetry...</div>
      </InfoCard>
    );
  }

  const filteredPackages = report.osPackages.filter(
    (p) => stateFilter === 'ALL' || p.patchState === stateFilter
  );

  return (
    <InfoCard title={`☁️ GCP OS Config (VM Manager) & Container Analysis (Grafeas v1) — ${report.serviceName}`}>
      {/* Top Summary Bar */}
      <div style={{ display: 'flex', alignItems: 'center', gap: 16, flexWrap: 'wrap', marginBottom: 12 }}>
        <span>
          <strong>{report.primaryDomain}</strong> | {report.domainExposureTier}
        </span>
        <span
          style={{
            background: getPatchStateColor(report.vmInventory.patchComplianceState),
            color: '#fff',
            borderRadius: 4,
            padding: '2px 8px',
            fontSize: 12,
            fontWeight: 600,
          }}
        >
          VM: {report.vmInventory.patchComplianceState}
          {report.vmInventory.rebootRequired ? ' ⚠️ Reboot Required' : ''}
        </span>
        <span
          style={{
            background: getPatchStateColor(report.patchSummary.overallPatchRisk),
            color: '#fff',
            borderRadius: 4,
            padding: '2px 8px',
            fontSize: 12,
            fontWeight: 600,
          }}
        >
          Risk: {report.patchSummary.overallPatchRisk}
        </span>
        <button
          onClick={handleExecutePatchJob}
          disabled={patching}
          style={{
            background: '#1976d2',
            color: '#fff',
            border: 'none',
            borderRadius: 4,
            padding: '6px 12px',
            cursor: 'pointer',
            fontWeight: 600,
          }}
        >
          {patching ? '⏳ Executing GCP PatchJob...' : '🚀 Execute GCP OS Config PatchJob & Container Sync'}
        </button>
      </div>

      {/* Tab Bar */}
      <div style={{ display: 'flex', gap: 4, marginBottom: 12, borderBottom: '1px solid #e0e0e0' }}>
        <button
          onClick={() => setActiveTab('packages')}
          style={{
            padding: '8px 12px',
            border: 'none',
            background: activeTab === 'packages' ? '#e3f2fd' : 'transparent',
            fontWeight: activeTab === 'packages' ? 700 : 400,
            cursor: 'pointer',
            borderBottom: activeTab === 'packages' ? '2px solid #1976d2' : '2px solid transparent',
          }}
        >
          📦 OS Packages & Patch States ({report.patchSummary.totalTrackedPackages})
        </button>
        <button
          onClick={() => setActiveTab('vm')}
          style={{
            padding: '8px 12px',
            border: 'none',
            background: activeTab === 'vm' ? '#e3f2fd' : 'transparent',
            fontWeight: activeTab === 'vm' ? 700 : 400,
            cursor: 'pointer',
            borderBottom: activeTab === 'vm' ? '2px solid #1976d2' : '2px solid transparent',
          }}
        >
          🖥️ GCP OS Config VM ({report.vmInventory.osInfo.shortName})
        </button>
        <button
          onClick={() => setActiveTab('container')}
          style={{
            padding: '8px 12px',
            border: 'none',
            background: activeTab === 'container' ? '#e3f2fd' : 'transparent',
            fontWeight: activeTab === 'container' ? 700 : 400,
            cursor: 'pointer',
            borderBottom: activeTab === 'container' ? '2px solid #1976d2' : '2px solid transparent',
          }}
        >
          🐳 Container Analysis (Grafeas v1)
        </button>
        <button
          onClick={() => setActiveTab('sbom')}
          style={{
            padding: '8px 12px',
            border: 'none',
            background: activeTab === 'sbom' ? '#e3f2fd' : 'transparent',
            fontWeight: activeTab === 'sbom' ? 700 : 400,
            cursor: 'pointer',
            borderBottom: activeTab === 'sbom' ? '2px solid #1976d2' : '2px solid transparent',
          }}
        >
          📜 Unified SBOM & Fleet Matrix
        </button>
      </div>

      {/* Packages Tab */}
      {activeTab === 'packages' && (
        <div>
          <div style={{ display: 'flex', gap: 6, marginBottom: 12, flexWrap: 'wrap' }}>
            {['ALL', 'UNPATCHED_EOL', 'PATCH_AVAILABLE', 'PENDING_REBOOT', 'MITIGATED_VEX', 'PATCHED'].map(
              (s) => (
                <button
                  key={s}
                  onClick={() => setStateFilter(s)}
                  style={{
                    padding: '4px 10px',
                    borderRadius: 12,
                    border: stateFilter === s ? '2px solid #1976d2' : '1px solid #ccc',
                    background: stateFilter === s ? '#e3f2fd' : '#fff',
                    cursor: 'pointer',
                    fontSize: 12,
                  }}
                >
                  {s}
                </button>
              )
            )}
          </div>
          <table style={{ width: '100%', borderCollapse: 'collapse', fontSize: 13 }}>
            <thead>
              <tr style={{ borderBottom: '2px solid #e0e0e0' }}>
                <th style={{ padding: '6px 8px', textAlign: 'left' }}>Package & PURL</th>
                <th style={{ padding: '6px 8px', textAlign: 'left' }}>Mgr / Layer</th>
                <th style={{ padding: '6px 8px', textAlign: 'left' }}>Installed → Available</th>
                <th style={{ padding: '6px 8px', textAlign: 'left' }}>Patch State</th>
                <th style={{ padding: '6px 8px', textAlign: 'left' }}>Advisory & CVEs</th>
                <th style={{ padding: '6px 8px', textAlign: 'left' }}>Remediation Action</th>
              </tr>
            </thead>
            <tbody>
              {filteredPackages.map((pkg, i) => (
                <tr key={i} style={{ borderBottom: '1px solid #f0f0f0' }}>
                  <td style={{ padding: '6px 8px' }}>
                    <strong>{pkg.packageName}</strong>
                    <br />
                    <code style={{ fontSize: 11 }}>{pkg.purl}</code>
                  </td>
                  <td style={{ padding: '6px 8px' }}>
                    {pkg.packageManager} / {pkg.layerScope}
                  </td>
                  <td style={{ padding: '6px 8px' }}>
                    {pkg.installedVersion} → {pkg.availablePatchVersion}
                  </td>
                  <td style={{ padding: '6px 8px' }}>
                    <span
                      style={{
                        background: getPatchStateColor(pkg.patchState),
                        color: '#fff',
                        borderRadius: 4,
                        padding: '2px 6px',
                        fontSize: 11,
                        fontWeight: 600,
                      }}
                    >
                      {pkg.patchState}
                    </span>
                  </td>
                  <td style={{ padding: '6px 8px' }}>
                    {pkg.securityAdvisoryId}
                    {pkg.cveIds.length > 0 && (
                      <div style={{ fontSize: 11, color: '#666' }}>{pkg.cveIds.join(', ')}</div>
                    )}
                  </td>
                  <td style={{ padding: '6px 8px' }}>{pkg.remediationAction}</td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      )}

      {/* VM Tab */}
      {activeTab === 'vm' && (
        <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: 8, fontSize: 13 }}>
          <div><strong>Instance Name:</strong> {report.vmInventory.instanceName}</div>
          <div><strong>Instance ID:</strong> {report.vmInventory.instanceId}</div>
          <div><strong>GCP Project:</strong> {report.vmInventory.gcpProject}</div>
          <div><strong>Zone:</strong> {report.vmInventory.zone}</div>
          <div><strong>Machine Type:</strong> {report.vmInventory.machineType}</div>
          <div><strong>Workload Role:</strong> {report.vmInventory.workloadRole}</div>
          <div><strong>Internal IP:</strong> {report.vmInventory.internalIp}</div>
          <div><strong>OS Long Name:</strong> {report.vmInventory.osInfo.longName}</div>
          <div><strong>Kernel Release:</strong> {report.vmInventory.osInfo.kernelRelease}</div>
          <div><strong>OS Config Agent:</strong> {report.vmInventory.osInfo.osconfigAgentVersion}</div>
          <div><strong>OS Policy Assignment:</strong> {report.vmInventory.osPolicyAssignmentId}</div>
          <div><strong>Last Patch Job:</strong> {report.vmInventory.lastPatchJobId}</div>
          <div><strong>Last Patched At:</strong> {report.vmInventory.lastPatchedAt}</div>
          <div>
            <strong>Reboot Required:</strong>{' '}
            {report.vmInventory.rebootRequired ? '⚠️ Yes' : '✅ No'}
          </div>
        </div>
      )}

      {/* Container Tab */}
      {activeTab === 'container' && (
        <div style={{ fontSize: 13 }}>
          <div style={{ marginBottom: 12 }}>
            <strong>Resource URI:</strong> {report.containerAnalysis.resourceUri}
            <br />
            <strong>Harbor Mirror:</strong> {report.containerAnalysis.harborMirrorUri}
            <br />
            <strong>Digest:</strong> <code>{report.containerAnalysis.digest}</code>
            <br />
            <strong>Base Image Distro:</strong> {report.containerAnalysis.baseImageDistro}
            <br />
            <strong>SLSA Provenance Level:</strong> {report.containerAnalysis.slsaProvenanceLevel}
          </div>
          <div style={{ marginBottom: 12 }}>
            <strong>Binary Authorization:</strong>{' '}
            <span
              style={{
                background: getPatchStateColor(report.containerAnalysis.binaryAuthorization.policyStatus),
                color: '#fff',
                borderRadius: 4,
                padding: '2px 6px',
                fontSize: 11,
                fontWeight: 600,
              }}
            >
              {report.containerAnalysis.binaryAuthorization.policyStatus}
            </span>{' '}
            — Attestor: {report.containerAnalysis.binaryAuthorization.attestorName}
          </div>
          <div style={{ marginBottom: 12 }}>
            <strong>Occurrence Counts:</strong>
            <br />
            Packages: {report.containerAnalysis.occurrenceCounts.packageOccurrences} |
            Vulnerabilities: {report.containerAnalysis.occurrenceCounts.vulnerabilityOccurrences} |
            Builds: {report.containerAnalysis.occurrenceCounts.buildOccurrences} |
            Attestations: {report.containerAnalysis.occurrenceCounts.attestationOccurrences}
          </div>
          <div>
            <strong>VEX Summary:</strong> Affected: {report.containerAnalysis.vexSummary.affected} |
            Not Affected (VEX): {report.containerAnalysis.vexSummary.notAffectedVex} |
            Fixed: {report.containerAnalysis.vexSummary.fixed}
          </div>
        </div>
      )}

      {/* SBOM Tab */}
      {activeTab === 'sbom' && (
        <div>
          <h4 style={{ margin: '0 0 8px' }}>Fleet Matrix</h4>
          <table style={{ width: '100%', borderCollapse: 'collapse', fontSize: 12, marginBottom: 12 }}>
            <thead>
              <tr style={{ borderBottom: '2px solid #e0e0e0' }}>
                <th style={{ padding: '6px 8px', textAlign: 'left' }}>Service</th>
                <th style={{ padding: '6px 8px', textAlign: 'left' }}>Domain / Tier</th>
                <th style={{ padding: '6px 8px', textAlign: 'left' }}>OS</th>
                <th style={{ padding: '6px 8px', textAlign: 'left' }}>Compliance</th>
                <th style={{ padding: '6px 8px', textAlign: 'left' }}>EOL</th>
                <th style={{ padding: '6px 8px', textAlign: 'left' }}>Patch Avail</th>
                <th style={{ padding: '6px 8px', textAlign: 'left' }}>Pending Reboot</th>
                <th style={{ padding: '6px 8px', textAlign: 'left' }}>Risk</th>
              </tr>
            </thead>
            <tbody>
              {fleet.map((f, i) => (
                <tr key={i} style={{ borderBottom: '1px solid #f0f0f0' }}>
                  <td style={{ padding: '6px 8px' }}>{f.serviceName}</td>
                  <td style={{ padding: '6px 8px' }}>
                    {f.primaryDomain} ({f.domainExposureTier})
                  </td>
                  <td style={{ padding: '6px 8px' }}>{f.vmInventory.osInfo.longName}</td>
                  <td style={{ padding: '6px 8px' }}>
                    <span
                      style={{
                        background: getPatchStateColor(f.vmInventory.patchComplianceState),
                        color: '#fff',
                        borderRadius: 4,
                        padding: '2px 6px',
                        fontSize: 11,
                      }}
                    >
                      {f.vmInventory.patchComplianceState}
                    </span>
                  </td>
                  <td style={{ padding: '6px 8px' }}>{f.patchSummary.unpatchedEolCount}</td>
                  <td style={{ padding: '6px 8px' }}>{f.patchSummary.patchAvailableCount}</td>
                  <td style={{ padding: '6px 8px' }}>{f.patchSummary.pendingRebootCount}</td>
                  <td style={{ padding: '6px 8px' }}>
                    <span
                      style={{
                        background: getPatchStateColor(f.patchSummary.overallPatchRisk),
                        color: '#fff',
                        borderRadius: 4,
                        padding: '2px 6px',
                        fontSize: 11,
                        fontWeight: 600,
                      }}
                    >
                      {f.patchSummary.overallPatchRisk}
                    </span>
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
          <h4 style={{ margin: '0 0 8px' }}>SPDX 2.3 SBOM Preview</h4>
          <pre
            style={{
              background: '#f5f5f5',
              padding: 12,
              borderRadius: 4,
              fontSize: 11,
              overflow: 'auto',
              maxHeight: 300,
            }}
          >
            {sbomDoc ? JSON.stringify(sbomDoc, null, 2) : 'No SBOM document available.'}
          </pre>
        </div>
      )}
    </InfoCard>
  );
};

const gcpCloudPostureEntityCard = EntityCardBlueprint.make({
  name: 'gcp-cloud-posture-card',
  params: {
    filter: 'kind:component,resource',
    loader: async () => <EntityGcpCloudPostureCard />,
  },
});

export const gcpPostureModule = createFrontendModule({
  pluginId: 'catalog',
  extensions: [gcpCloudPostureEntityCard],
});

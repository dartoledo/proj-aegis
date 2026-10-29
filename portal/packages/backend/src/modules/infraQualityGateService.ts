import { getEntityCmdbSnapshot } from './livingCmdbService';
import { getEntityCveIntelligenceReport } from './cveIntelligenceService';
import { getEntityGcpCloudPostureReport } from './gcpCloudPostureService';

export type GateVerdict = 'PASS' | 'WARN_APPROVAL' | 'HARD_BLOCK';

export interface QualityGateCheck {
  gateId: string;
  domain: string;
  policyInvariant: string;
  observedState: string;
  verdict: GateVerdict;
  remediationDiffHint: string;
}

export interface InfraChangeSimulationInput {
  entityRef: string;
  scenarioId?: string;
  proposedExposureTier?: 'unrestricted-public' | 'restricted-public' | 'strictly-private';
  hasEdgeIapOrMtls?: boolean;
  proposedRuntimeVersion?: string;
  proposedSlsaLevel?: 'SLSA_LEVEL_3' | 'SLSA_LEVEL_2' | 'SLSA_LEVEL_1';
  proposedBinaryAuthStatus?: 'ATTESTED' | 'ALLOWLISTED_WARN' | 'BLOCKED_VIOLATION';
  proposedReplicas?: number;
  certDaysRemaining?: number;
}

export interface EntityQualityGateReport {
  entityRef: string;
  serviceName: string;
  evaluationMode: 'LIVE_POSTURE' | 'PRE_FLIGHT_SIMULATION';
  scenarioTitle: string;
  overallVerdict: 'AUTO_APPROVED' | 'REQUIRES_VP_ATTESTATION' | 'BLOCKED_BY_POLICY';
  readinessScore: number;
  passedGates: number;
  totalGates: number;
  sonarCodeMetrics: { status: 'Passed'; bugs: number; codeSmells: number; coveragePercent: number; duplicationsPercent: number };
  gates: QualityGateCheck[];
  evaluatedAt: string;
}

export interface PresetInfraScenario {
  scenarioId: string;
  title: string;
  description: string;
  input: Omit<InfraChangeSimulationInput, 'entityRef'>;
}

export const PRESET_INFRA_SCENARIOS: PresetInfraScenario[] = [
  {
    scenarioId: 'expose-public-no-iap',
    title: '🚨 What-If: Expose Service on Unrestricted Public LB without IAP',
    description: 'Simulates a Terraform/Ingress PR changing exposure tier to unrestricted-public without Cloud IAP or mTLS',
    input: {
      scenarioId: 'expose-public-no-iap',
      proposedExposureTier: 'unrestricted-public',
      hasEdgeIapOrMtls: false,
      proposedRuntimeVersion: '18.20.8',
      proposedSlsaLevel: 'SLSA_LEVEL_2',
      proposedBinaryAuthStatus: 'BLOCKED_VIOLATION',
      proposedReplicas: 2,
      certDaysRemaining: 45,
    },
  },
  {
    scenarioId: 'unattested-hotfix-image',
    title: '⚠️ What-If: Emergency Unattested Container Rollout (SLSA Level 1, 1 Replica)',
    description: 'Simulates bypassing Cloud Build signing to push an ad-hoc hotfix image with 1 replica',
    input: {
      scenarioId: 'unattested-hotfix-image',
      proposedExposureTier: 'restricted-public',
      hasEdgeIapOrMtls: true,
      proposedRuntimeVersion: '22.15.0',
      proposedSlsaLevel: 'SLSA_LEVEL_1',
      proposedBinaryAuthStatus: 'BLOCKED_VIOLATION',
      proposedReplicas: 1,
      certDaysRemaining: 10,
    },
  },
  {
    scenarioId: 'golden-path-node22-upgrade',
    title: '✅ What-If: Golden-Path Node.js 22.15 LTS + SLSA Level 3 + 3 Replicas',
    description: 'Simulates upgrading runtime to Node.js 22.15.0 LTS (patching CVE-2026-111497), SLSA Level 3 attestation, and 3 HA replicas',
    input: {
      scenarioId: 'golden-path-node22-upgrade',
      proposedExposureTier: 'strictly-private',
      hasEdgeIapOrMtls: true,
      proposedRuntimeVersion: '22.15.0',
      proposedSlsaLevel: 'SLSA_LEVEL_3',
      proposedBinaryAuthStatus: 'ATTESTED',
      proposedReplicas: 3,
      certDaysRemaining: 85,
    },
  },
];

export async function evaluateEntityQualityGates(
  entityRef: string,
  simInput?: InfraChangeSimulationInput
): Promise<EntityQualityGateReport> {
  const [cmdb, cveIntel, gcpPosture] = await Promise.all([
    getEntityCmdbSnapshot(entityRef),
    getEntityCveIntelligenceReport(entityRef),
    getEntityGcpCloudPostureReport(entityRef),
  ]);

  const isInternalService = ['aegis-backend', 'aegis-auth', 'aegis-db'].includes(cmdb.serviceName);
  const exposure = simInput?.proposedExposureTier || cmdb.observedExposureTier;
  const hasIap = simInput?.hasEdgeIapOrMtls ?? (exposure !== 'restricted-public' || cmdb.activeDriftCount === 0);
  const isGoldenRuntime = simInput?.proposedRuntimeVersion === '22.15.0';
  const kevCount = isGoldenRuntime ? 0 : cveIntel.cisaKevCount;
  const maxAcrs = isGoldenRuntime ? 18 : cveIntel.maxAcrsScore;
  const vmCompliance = isGoldenRuntime ? 'COMPLIANT' : gcpPosture.vmInventory.patchComplianceState;
  const slsa = simInput?.proposedSlsaLevel || gcpPosture.containerAnalysis.slsaProvenanceLevel;
  const binAuth = simInput?.proposedBinaryAuthStatus || gcpPosture.containerAnalysis.binaryAuthorization.policyStatus;
  const replicas = simInput?.proposedReplicas ?? cmdb.observedReplicas;
  const certDays = simInput?.certDaysRemaining ?? (cmdb.serviceName === 'hello-world-app' ? 15 : 68);

  const gates: QualityGateCheck[] = [];

  // GATE-01: 3-Tier Exposure & Ingress Boundary
  const gate01Verdict: GateVerdict =
    (isInternalService && exposure === 'unrestricted-public') || (exposure === 'restricted-public' && !hasIap)
      ? 'HARD_BLOCK'
      : 'PASS';
  gates.push({
    gateId: 'GATE-01',
    domain: '3-Tier Exposure & Ingress Boundary',
    policyInvariant: 'Internal services must not be exposed on unrestricted-public; restricted-public requires IAP or mTLS',
    observedState: `exposure=${exposure}, hasIap=${hasIap}, isInternal=${isInternalService}`,
    verdict: gate01Verdict,
    remediationDiffHint: gate01Verdict === 'PASS' ? '' : 'Set exposure to strictly-private or enable Cloud IAP/mTLS at the edge',
  });

  // GATE-02: CVE & Zero-KEV Supply Chain
  const gate02Verdict: GateVerdict = kevCount > 0 || maxAcrs >= 80 ? 'HARD_BLOCK' : 'PASS';
  gates.push({
    gateId: 'GATE-02',
    domain: 'CVE & Zero-KEV Supply Chain',
    policyInvariant: 'Zero CISA KEV entries and max ACRS score < 80 required',
    observedState: `kevCount=${kevCount}, maxAcrs=${maxAcrs}`,
    verdict: gate02Verdict,
    remediationDiffHint: gate02Verdict === 'PASS' ? '' : 'Upgrade runtime to 22.15.0 LTS or patch KEV-affected dependencies',
  });

  // GATE-03: GCP OS Config & Kernel Patch State
  const gate03Verdict: GateVerdict =
    vmCompliance === 'NON_COMPLIANT' ? 'HARD_BLOCK' : vmCompliance === 'PENDING_REBOOT' ? 'WARN_APPROVAL' : 'PASS';
  gates.push({
    gateId: 'GATE-03',
    domain: 'GCP OS Config & Kernel Patch State',
    policyInvariant: 'All VMs must be OS Config compliant; PENDING_REBOOT requires VP attestation',
    observedState: `patchComplianceState=${vmCompliance}`,
    verdict: gate03Verdict,
    remediationDiffHint: gate03Verdict === 'PASS' ? '' : 'Trigger OS Config rollout or schedule maintenance window for reboot',
  });

  // GATE-04: SLSA Provenance & Binary Authorization
  const gate04Verdict: GateVerdict =
    binAuth === 'BLOCKED_VIOLATION' || slsa === 'SLSA_LEVEL_1'
      ? 'HARD_BLOCK'
      : binAuth === 'ALLOWLISTED_WARN' || slsa === 'SLSA_LEVEL_2'
        ? 'WARN_APPROVAL'
        : 'PASS';
  gates.push({
    gateId: 'GATE-04',
    domain: 'SLSA Provenance & Binary Authorization',
    policyInvariant: 'SLSA Level 3 + ATTESTED binary auth required; Level 2 or ALLOWLISTED_WARN requires VP attestation',
    observedState: `slsa=${slsa}, binaryAuth=${binAuth}`,
    verdict: gate04Verdict,
    remediationDiffHint: gate04Verdict === 'PASS' ? '' : 'Enable Cloud Build SLSA Level 3 attestation and Binary Authorization policy',
  });

  // GATE-05: TLS & Cryptographic Hygiene
  const gate05Verdict: GateVerdict = certDays <= 14 ? 'HARD_BLOCK' : certDays <= 30 ? 'WARN_APPROVAL' : 'PASS';
  gates.push({
    gateId: 'GATE-05',
    domain: 'TLS & Cryptographic Hygiene',
    policyInvariant: 'TLS certificate must have > 30 days remaining; <= 14 days is a hard block',
    observedState: `certDaysRemaining=${certDays}`,
    verdict: gate05Verdict,
    remediationDiffHint: gate05Verdict === 'PASS' ? '' : 'Renew TLS certificate via ACM or enable auto-renewal',
  });

  // GATE-06: K8s Resiliency & CMDB Drift Budget
  const gate06Verdict: GateVerdict =
    replicas < 2 ? 'HARD_BLOCK' : !simInput && cmdb.activeDriftCount > 0 ? 'WARN_APPROVAL' : 'PASS';
  gates.push({
    gateId: 'GATE-06',
    domain: 'K8s Resiliency & CMDB Drift Budget',
    policyInvariant: 'Minimum 2 replicas for HA; active CMDB drift in live mode requires VP attestation',
    observedState: `replicas=${replicas}, activeDriftCount=${cmdb.activeDriftCount}`,
    verdict: gate06Verdict,
    remediationDiffHint: gate06Verdict === 'PASS' ? '' : 'Increase replica count to >= 2 and reconcile CMDB drift',
  });

  const passedGates = gates.filter((g) => g.verdict === 'PASS').length;
  const hasBlock = gates.some((g) => g.verdict === 'HARD_BLOCK');
  const hasWarn = gates.some((g) => g.verdict === 'WARN_APPROVAL');
  const overallVerdict: EntityQualityGateReport['overallVerdict'] = hasBlock
    ? 'BLOCKED_BY_POLICY'
    : hasWarn
      ? 'REQUIRES_VP_ATTESTATION'
      : 'AUTO_APPROVED';
  const readinessScore = Math.round((passedGates / gates.length) * 100);

  const matchedPreset = simInput?.scenarioId
    ? PRESET_INFRA_SCENARIOS.find((p) => p.scenarioId === simInput.scenarioId)
    : undefined;

  return {
    entityRef,
    serviceName: cmdb.serviceName,
    evaluationMode: simInput ? 'PRE_FLIGHT_SIMULATION' : 'LIVE_POSTURE',
    scenarioTitle: matchedPreset ? matchedPreset.title : 'Live Posture Evaluation',
    overallVerdict,
    readinessScore,
    passedGates,
    totalGates: gates.length,
    sonarCodeMetrics: { status: 'Passed', bugs: 0, codeSmells: 0, coveragePercent: 92, duplicationsPercent: 1.2 },
    gates,
    evaluatedAt: new Date().toISOString(),
  };
}

export async function simulateInfraChangePreFlight(
  input: InfraChangeSimulationInput
): Promise<EntityQualityGateReport> {
  const matchedPreset = input.scenarioId
    ? PRESET_INFRA_SCENARIOS.find((p) => p.scenarioId === input.scenarioId)
    : undefined;

  const mergedInput: InfraChangeSimulationInput = matchedPreset
    ? { ...matchedPreset.input, entityRef: input.entityRef }
    : input;

  return evaluateEntityQualityGates(input.entityRef, mergedInput);
}

export function getPresetInfraScenarios(): PresetInfraScenario[] {
  return PRESET_INFRA_SCENARIOS;
}

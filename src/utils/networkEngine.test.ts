import test from 'node:test';
import assert from 'node:assert/strict';
import {
  parseCidrRange,
  calculateAdaptiveHeartbeat,
  encryptCredentialSecret,
  validateCredentialForm,
  filterDevices,
  applyAgentDeployment,
  computeFleetSummary,
} from './networkEngine';
import { DeviceAsset } from '../types/network';

test('parseCidrRange validates standard IPv4 subnets and calculates host capacity', () => {
  const res24 = parseCidrRange('10.24.10.0/24');
  assert.equal(res24.valid, true);
  assert.equal(res24.prefixLength, 24);
  assert.equal(res24.estimatedHosts, 254);

  const resInvalid = parseCidrRange('192.168.999.0/24');
  assert.equal(resInvalid.valid, false);

  const resMissingSlash = parseCidrRange('10.0.0.1');
  assert.equal(resMissingSlash.valid, false);
});

test('calculateAdaptiveHeartbeat adjusts interval based on CPU/RAM load and spikes', () => {
  const eco = calculateAdaptiveHeartbeat({
    baseIntervalSec: 60,
    cpuUsagePct: 12,
    ramUsagePct: 35,
    previousCpuPct: 10,
    deltaThresholdPct: 25,
  });
  assert.equal(eco.mode, 'idle-eco');
  assert.equal(eco.nextIntervalSec, 90);

  const burst = calculateAdaptiveHeartbeat({
    baseIntervalSec: 60,
    cpuUsagePct: 91,
    ramUsagePct: 60,
    previousCpuPct: 40,
    deltaThresholdPct: 25,
  });
  assert.equal(burst.mode, 'burst-event');
  assert.equal(burst.nextIntervalSec, 10);
});

test('encryptCredentialSecret and validateCredentialForm enforce security inputs', () => {
  const bad = validateCredentialForm({
    label: 'A',
    username: 'admin',
    rawSecret: '123456',
    scopeSubnet: '10.24.10.0/24',
  });
  assert.equal(bad.valid, false);

  const good = validateCredentialForm({
    label: 'Prod WinRM Domain Admin',
    username: 'CORP\\svc_rmm_deploy',
    rawSecret: 'Str0ngP@ssw0rd!2026',
    scopeSubnet: '10.24.10.0/24',
  });
  assert.equal(good.valid, true);

  const encrypted = encryptCredentialSecret({
    label: 'Prod WinRM Domain Admin',
    protocol: 'WinRM-HTTPS',
    username: 'CORP\\svc_rmm_deploy',
    rawSecret: 'Str0ngP@ssw0rd!2026',
    port: 5986,
    scopeSubnet: '10.24.10.0/24',
  });
  assert.ok(encrypted.cipherPreview.startsWith('aes256gcm$'));
  assert.ok(encrypted.keyFingerprint.startsWith('SHA256:'));
});

test('filterDevices and applyAgentDeployment transition agentless endpoints to active', () => {
  const sampleDevices: DeviceAsset[] = [
    {
      id: 'dev-1',
      hostname: 'SRV-FIN-DB01',
      ipAddress: '10.24.10.21',
      macAddress: '00:1B:63:84:45:E6',
      os: 'Ubuntu Linux',
      osVersion: '24.04 LTS',
      kernelArch: '6.8.0-x86_64',
      role: 'server',
      status: 'online',
      agentState: 'agentless',
      cpuModel: 'AMD EPYC 7543P',
      cpuCores: 16,
      cpuUsagePct: 28,
      ramTotalGb: 64,
      ramUsedGb: 22,
      diskTotalGb: 1000,
      diskUsedGb: 410,
      lastSeen: '2m ago',
      subnet: '10.24.10.0/24',
      location: 'DC-JKT-Rack04',
      latencyMs: 1.4,
      interfaces: [],
      software: [],
    },
  ];

  const filtered = filterDevices(sampleDevices, {
    query: 'FIN-DB01',
    statusFilter: 'all',
    agentFilter: 'agentless',
  });
  assert.equal(filtered.length, 1);

  const deployed = applyAgentDeployment(sampleDevices, ['dev-1'], 'v2.4.1-go');
  assert.equal(deployed[0].agentState, 'active');
  assert.equal(deployed[0].agentVersion, 'v2.4.1-go');

  const summary = computeFleetSummary(deployed);
  assert.equal(summary.activeAgents, 1);
  assert.equal(summary.agentlessCount, 0);

  const emptySummary = computeFleetSummary([]);
  assert.equal(emptySummary.total, 0);
  assert.equal(emptySummary.activeAgents, 0);
  assert.equal(emptySummary.avgAgentRamMb, 0);
});

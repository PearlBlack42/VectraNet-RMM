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
  computeHeartbeatStats,
  formatIcmpPingStatus,
  matchesOsFilter,
  ipToComparableNumber,
  sortDevices,
  paginateDevices,
} from './networkEngine';
import { DeviceAsset, DeviceMetricPoint } from '../types/network';

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

test('encryptCredentialSecret and validateCredentialForm enforce security inputs and allow short local passwords', () => {
  const bad = validateCredentialForm({
    label: 'A',
    username: 'admin',
    rawSecret: '123',
    scopeSubnet: '10.24.10.0/24',
  });
  assert.equal(bad.valid, false);

  // Short 3-character password (e.g. local PC password) must pass without error
  const shortLocalPass = validateCredentialForm({
    label: 'PC Lokal Windows',
    username: 'UserPC',
    rawSecret: 'abc',
    scopeSubnet: '192.168.1.0/24',
  });
  assert.equal(shortLocalPass.valid, true);

  const encryptedShort = encryptCredentialSecret({
    label: 'PC Lokal Windows',
    protocol: 'WinRM-HTTPS',
    username: 'UserPC',
    rawSecret: 'abc',
    port: 5986,
    scopeSubnet: '192.168.1.0/24',
  });
  assert.ok(encryptedShort.cipherPreview.startsWith('aes256gcm$'));
  assert.ok(encryptedShort.keyFingerprint.startsWith('SHA256:'));

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

test('computeHeartbeatStats calculates current, average, and peak CPU/RAM usage over 1-hour series', () => {
  const emptyStats = computeHeartbeatStats([], 16);
  assert.equal(emptyStats.sampleCount, 0);
  assert.equal(emptyStats.currentCpuPct, 0);
  assert.equal(emptyStats.ramTotalGb, 16);

  const points: DeviceMetricPoint[] = [
    {
      timestamp: '2026-11-11T20:30:00Z',
      timeLabel: '20:30',
      cpuUsagePct: 20,
      ramUsedGb: 4,
      ramTotalGb: 16,
      ramUsagePct: 25,
      diskUsedGb: 100,
      netRxMbps: 1.2,
      netTxMbps: 0.8,
      heartbeatMode: 'idle-eco',
    },
    {
      timestamp: '2026-11-11T21:00:00Z',
      timeLabel: '21:00',
      cpuUsagePct: 40,
      ramUsedGb: 8,
      ramTotalGb: 16,
      ramUsagePct: 50,
      diskUsedGb: 100,
      netRxMbps: 3.4,
      netTxMbps: 1.9,
      heartbeatMode: 'standard',
    },
    {
      timestamp: '2026-11-11T21:25:00Z',
      timeLabel: '21:25',
      cpuUsagePct: 60,
      ramUsedGb: 12,
      ramTotalGb: 16,
      ramUsagePct: 75,
      diskUsedGb: 100,
      netRxMbps: 6.1,
      netTxMbps: 2.5,
      heartbeatMode: 'burst-event',
    },
  ];

  const stats = computeHeartbeatStats(points, 16);
  assert.equal(stats.sampleCount, 3);
  assert.equal(stats.currentCpuPct, 60);
  assert.equal(stats.avgCpuPct, 40);
  assert.equal(stats.peakCpuPct, 60);
  assert.equal(stats.currentRamPct, 75);
  assert.equal(stats.avgRamPct, 50);
  assert.equal(stats.peakRamPct, 75);
  assert.equal(stats.currentRamUsedGb, 12);
});

test('formatIcmpPingStatus formats reachable and unreachable agentless ICMP ping states', () => {
  const reachable = formatIcmpPingStatus(
    {
      deviceId: 'dev-1',
      hostname: 'HOST-17',
      ipAddress: '172.27.170.17',
      alive: true,
      latencyMs: 1.84,
      lastPingedAt: '21:27:10',
      method: 'ICMP Echo',
    },
    2.5,
    'online'
  );
  assert.equal(reachable.alive, true);
  assert.equal(reachable.latencyMs, 1.8);
  assert.ok(reachable.labelId.includes('1.8ms'));

  const unreachable = formatIcmpPingStatus(
    {
      deviceId: 'dev-2',
      hostname: 'HOST-99',
      ipAddress: '172.27.170.99',
      alive: false,
      latencyMs: 0,
      lastPingedAt: '21:27:10',
      method: 'ICMP Timeout',
    },
    0,
    'offline'
  );
  assert.equal(unreachable.alive, false);
  assert.equal(unreachable.latencyMs, 0);
  assert.ok(unreachable.labelEn.includes('Unreachable'));
});

test('matchesOsFilter, sortDevices, and paginateDevices handle OS filtering, numerical IP sorting, and pagination', () => {
  assert.equal(matchesOsFilter('Windows 11', 'windows'), true);
  assert.equal(matchesOsFilter('Ubuntu Linux', 'linux'), true);
  assert.equal(matchesOsFilter('macOS Sequoia', 'macos'), true);
  assert.equal(matchesOsFilter('Windows 11', 'linux'), false);

  assert.ok(ipToComparableNumber('172.27.170.2') < ipToComparableNumber('172.27.170.10'));
  assert.ok(ipToComparableNumber('172.27.170.10') < ipToComparableNumber('172.27.170.100'));

  const mockList: DeviceAsset[] = [
    {
      id: 'd-10',
      hostname: 'NODE-10',
      ipAddress: '172.27.170.10',
      macAddress: '00:50:56:00:00:10',
      os: 'Ubuntu Linux',
      osVersion: '24.04',
      kernelArch: 'x86_64',
      role: 'server',
      status: 'offline',
      agentState: 'agentless',
      cpuModel: '',
      cpuCores: 0,
      cpuUsagePct: 0,
      ramTotalGb: 0,
      ramUsedGb: 0,
      diskTotalGb: 0,
      diskUsedGb: 0,
      lastSeen: '1m',
      subnet: '172.27.170.0/24',
      location: 'Rack1',
      latencyMs: 0,
      interfaces: [],
      software: [],
    },
    {
      id: 'd-2',
      hostname: 'NODE-2',
      ipAddress: '172.27.170.2',
      macAddress: '00:50:56:00:00:02',
      os: 'Windows 11',
      osVersion: '23H2',
      kernelArch: 'amd64',
      role: 'workstation',
      status: 'online',
      agentState: 'active',
      cpuModel: 'i5',
      cpuCores: 6,
      cpuUsagePct: 20,
      ramTotalGb: 16,
      ramUsedGb: 8,
      diskTotalGb: 512,
      diskUsedGb: 100,
      lastSeen: 'now',
      subnet: '172.27.170.0/24',
      location: 'Rack1',
      latencyMs: 1.1,
      interfaces: [],
      software: [],
    },
  ];

  const byIpAsc = sortDevices(mockList, 'ip', 'asc');
  assert.equal(byIpAsc[0].ipAddress, '172.27.170.2');
  assert.equal(byIpAsc[1].ipAddress, '172.27.170.10');

  const byHostDesc = sortDevices(mockList, 'hostname', 'desc');
  assert.equal(byHostDesc[0].hostname, 'NODE-10');
  assert.equal(byHostDesc[1].hostname, 'NODE-2');

  const byStatusAsc = sortDevices(mockList, 'status', 'asc');
  assert.equal(byStatusAsc[0].status, 'online');
  assert.equal(byStatusAsc[1].status, 'offline');

  // Test pagination with 60 items at pageSize 25
  const sixtyItems = Array.from({ length: 60 }, (_, i) => i + 1);
  const page1 = paginateDevices(sixtyItems, 1, 25);
  assert.equal(page1.totalPages, 3);
  assert.equal(page1.startIndex, 1);
  assert.equal(page1.endIndex, 25);
  assert.equal(page1.pageItems.length, 25);
  assert.deepEqual(page1.pageNumbers, [1, 2, 3]);

  const page3 = paginateDevices(sixtyItems, 3, 25);
  assert.equal(page3.startIndex, 51);
  assert.equal(page3.endIndex, 60);
  assert.equal(page3.pageItems.length, 10);
});



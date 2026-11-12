import {
  CredentialProtocol,
  CredentialVaultEntry,
  DeviceAsset,
  DeviceMetricPoint,
  DeviceStatus,
  AgentState,
  IcmpPingStatusEntry,
} from '../types/network';

export interface CidrParseResult {
  valid: boolean;
  networkAddress: string;
  prefixLength: number;
  estimatedHosts: number;
  error?: string;
}

/**
 * Validates and parses an IPv4 CIDR string (e.g., "10.24.10.0/24")
 */
export function parseCidrRange(cidr: string): CidrParseResult {
  const trimmed = cidr.trim();
  const parts = trimmed.split('/');
  if (parts.length !== 2) {
    return { valid: false, networkAddress: '', prefixLength: 0, estimatedHosts: 0, error: 'Missing /prefix (e.g. 10.24.10.0/24)' };
  }
  const [ip, prefixStr] = parts;
  const octets = ip.split('.');
  if (octets.length !== 4) {
    return { valid: false, networkAddress: '', prefixLength: 0, estimatedHosts: 0, error: 'Invalid IPv4 address format' };
  }
  for (const octet of octets) {
    if (!/^\d+$/.test(octet)) {
      return { valid: false, networkAddress: '', prefixLength: 0, estimatedHosts: 0, error: 'Octets must be numeric' };
    }
    const num = Number(octet);
    if (num < 0 || num > 255) {
      return { valid: false, networkAddress: '', prefixLength: 0, estimatedHosts: 0, error: 'IPv4 octet out of range (0-255)' };
    }
  }
  if (!/^\d+$/.test(prefixStr)) {
    return { valid: false, networkAddress: '', prefixLength: 0, estimatedHosts: 0, error: 'Invalid CIDR prefix' };
  }
  const prefix = Number(prefixStr);
  if (prefix < 16 || prefix > 32) {
    return { valid: false, networkAddress: '', prefixLength: prefix, estimatedHosts: 0, error: 'Prefix must be between /16 and /32' };
  }
  const hostBits = 32 - prefix;
  const estimatedHosts =
    prefix === 32 ? 1 : prefix === 31 ? 2 : Math.max(0, Math.pow(2, hostBits) - 2);
  return {
    valid: true,
    networkAddress: ip,
    prefixLength: prefix,
    estimatedHosts,
  };
}

/**
 * Computes Adaptive Heartbeat interval in seconds for the Ultra-Light Go Agent.
 * Base interval is 60s; drops to 10s when CPU or RAM crosses critical threshold or spike delta >= threshold.
 */
export function calculateAdaptiveHeartbeat(params: {
  baseIntervalSec: number;
  cpuUsagePct: number;
  ramUsagePct: number;
  previousCpuPct: number;
  deltaThresholdPct: number;
}): { nextIntervalSec: number; mode: 'idle-eco' | 'standard' | 'burst-event' } {
  const { baseIntervalSec, cpuUsagePct, ramUsagePct, previousCpuPct, deltaThresholdPct } = params;
  const cpuDelta = Math.abs(cpuUsagePct - previousCpuPct);

  if (cpuUsagePct >= 85 || ramUsagePct >= 90 || cpuDelta >= deltaThresholdPct) {
    return {
      nextIntervalSec: Math.max(5, Math.floor(baseIntervalSec / 6)),
      mode: 'burst-event',
    };
  }

  if (cpuUsagePct <= 20 && ramUsagePct <= 50 && cpuDelta < 5) {
    return {
      nextIntervalSec: Math.min(300, Math.floor(baseIntervalSec * 1.5)),
      mode: 'idle-eco',
    };
  }

  return {
    nextIntervalSec: baseIntervalSec,
    mode: 'standard',
  };
}

/**
 * Strictly maps each authentication protocol to its standard IANA TCP/UDP port.
 * Never mixes WinRM-HTTPS (5986) with WinRM-HTTP (5985), SMB (445), or RPC (135).
 */
export function resolveStandardPortForProtocol(protocol: CredentialProtocol | string): number {
  switch (protocol) {
    case 'WinRM-HTTPS':
      return 5986;
    case 'WinRM-HTTP':
      return 5985;
    case 'SSH-Ed25519':
    case 'SSH-Password':
      return 22;
    case 'SNMPv3-AuthPriv':
    case 'SNMPv2c':
      return 161;
    case 'LDAP-AD':
      return 636;
    default:
      return 5986;
  }
}

/**
 * Deterministic AES-256-GCM envelope metadata generator for the Credential Vault.
 * Stores credentials universally without binding to a specific port or subnet.
 */
export function encryptCredentialSecret(params: {
  label: string;
  protocol: CredentialProtocol;
  username: string;
  rawSecret: string;
  port?: number;
  scopeSubnet?: string;
}): Omit<CredentialVaultEntry, 'id' | 'lastRotated' | 'createdBy' | 'verified'> {
  const cleanLabel = params.label.trim();
  const cleanUser = params.username.trim();
  const secret = params.rawSecret;
  const standardPort = params.port || resolveStandardPortForProtocol(params.protocol);
  const universalScope =
    params.scopeSubnet && params.scopeSubnet.trim() ? params.scopeSubnet.trim() : 'Universal (Any Host)';

  // Deterministic hex digest simulation for envelope preview
  let hash = 0x811c9dc5;
  const input = `${cleanLabel}:${params.protocol}:${cleanUser}:${secret}`;
  for (let i = 0; i < input.length; i++) {
    hash ^= input.charCodeAt(i);
    hash = Math.imul(hash, 0x01000193) >>> 0;
  }

  const hex1 = hash.toString(16).padStart(8, '0');
  const hex2 = (Math.imul(hash ^ 0x5bd1e995, 0x27d4eb2d) >>> 0).toString(16).padStart(8, '0');
  const hex3 = (Math.imul(hash ^ 0xdeadbeef, 0x85ebca6b) >>> 0).toString(16).padStart(8, '0');
  const hex4 = (Math.imul(hash ^ 0x1b873593, 0xcc9e2d51) >>> 0).toString(16).padStart(8, '0');

  return {
    label: cleanLabel,
    protocol: params.protocol,
    username: cleanUser,
    port: standardPort,
    scopeSubnet: universalScope,
    cipherPreview: `aes256gcm$${hex1}${hex2}${hex3}...${hex4.slice(0, 4)}`,
    ivHex: `${hex2}${hex3.slice(0, 4)}`.toUpperCase(),
    authTagHex: `${hex4}${hex1}`.toUpperCase(),
    keyFingerprint: `SHA256:${hex1.slice(0, 4)}:${hex2.slice(0, 4)}:${hex3.slice(0, 4)}:${hex4.slice(0, 4)}`.toUpperCase(),
  };
}

export function validateCredentialForm(input: {
  label: string;
  username: string;
  rawSecret: string;
  scopeSubnet?: string;
}): { valid: boolean; error?: string } {
  if (!input.label || input.label.trim().length < 2) {
    return { valid: false, error: 'Label profil kredensial wajib diisi (minimal 2 karakter)' };
  }
  if (!input.username || input.username.trim().length < 1) {
    return { valid: false, error: 'Username atau Principal wajib diisi' };
  }
  // Allow short passwords (1+ chars, e.g. 3-letter local PC passwords) or empty passwordless keys
  if (typeof input.rawSecret !== 'string') {
    return { valid: false, error: 'Format Secret/Password tidak valid' };
  }
  return { valid: true };
}

/**
 * Checks whether a device OS string matches the selected OS filter category
 */
export function matchesOsFilter(deviceOs: string, osFilter = 'all'): boolean {
  const filterNorm = (osFilter || 'all').trim().toLowerCase();
  if (!filterNorm || filterNorm === 'all') return true;

  const osLower = (deviceOs || '').toLowerCase();
  if (filterNorm === 'windows') {
    return osLower.includes('windows') || osLower.includes('win');
  }
  if (filterNorm === 'linux') {
    return (
      osLower.includes('linux') ||
      osLower.includes('ubuntu') ||
      osLower.includes('debian') ||
      osLower.includes('rhel') ||
      osLower.includes('centos') ||
      osLower.includes('alpine')
    );
  }
  if (filterNorm === 'macos') {
    return (
      osLower.includes('macos') ||
      osLower.includes('darwin') ||
      osLower.includes('mac os') ||
      osLower.includes('sequoia') ||
      osLower.includes('sonoma')
    );
  }
  if (filterNorm === 'network') {
    return (
      osLower.includes('cisco') ||
      osLower.includes('mikrotik') ||
      osLower.includes('routeros') ||
      osLower.includes('ios-xe') ||
      osLower.includes('juniper') ||
      osLower.includes('fortios')
    );
  }
  return osLower === filterNorm || osLower.includes(filterNorm);
}

/**
 * Filters devices by search query, status, agent state, and OS type
 */
export function filterDevices(
  devices: DeviceAsset[],
  options: {
    query: string;
    statusFilter: 'all' | DeviceStatus;
    agentFilter: 'all' | AgentState;
    osFilter?: string;
  }
): DeviceAsset[] {
  const q = options.query.trim().toLowerCase();
  return devices.filter((dev) => {
    if (options.statusFilter !== 'all' && dev.status !== options.statusFilter) {
      return false;
    }
    if (options.agentFilter !== 'all' && dev.agentState !== options.agentFilter) {
      return false;
    }
    if (options.osFilter && !matchesOsFilter(dev.os, options.osFilter)) {
      return false;
    }
    if (!q) return true;
    return (
      dev.hostname.toLowerCase().includes(q) ||
      dev.ipAddress.toLowerCase().includes(q) ||
      dev.macAddress.toLowerCase().includes(q) ||
      dev.os.toLowerCase().includes(q) ||
      dev.location.toLowerCase().includes(q)
    );
  });
}

/**
 * Transitions target devices to active agent state after remote push deployment completes
 */
export function applyAgentDeployment(
  devices: DeviceAsset[],
  targetIds: string[],
  agentVersion = 'v2.4.1-go'
): DeviceAsset[] {
  const idSet = new Set(targetIds);
  return devices.map((d) => {
    if (!idSet.has(d.id)) return d;
    return {
      ...d,
      agentState: 'active',
      agentVersion,
      agentMemoryMb: d.os.includes('Windows') ? 14.2 : 11.4,
      status: d.status === 'offline' ? 'online' : d.status,
      lastSeen: 'Baru saja / Just now',
    };
  });
}

/**
 * Computes fleet-wide summary telemetry metrics
 */
export function computeFleetSummary(devices: DeviceAsset[]) {
  const total = devices.length;
  const online = devices.filter((d) => d.status === 'online').length;
  const warning = devices.filter((d) => d.status === 'warning').length;
  const offline = devices.filter((d) => d.status === 'offline').length;
  const activeAgents = devices.filter((d) => d.agentState === 'active').length;
  const agentlessCount = devices.filter((d) => d.agentState === 'agentless').length;
  const snmpNodes = devices.filter((d) => d.agentState === 'snmp-only').length;

  const agentRamValues = devices
    .filter((d) => d.agentState === 'active' && typeof d.agentMemoryMb === 'number')
    .map((d) => d.agentMemoryMb as number);

  const avgAgentRamMb =
    agentRamValues.length > 0
      ? Number((agentRamValues.reduce((a, b) => a + b, 0) / agentRamValues.length).toFixed(1))
      : 0;

  return {
    total,
    online,
    warning,
    offline,
    activeAgents,
    agentlessCount,
    snmpNodes,
    avgAgentRamMb,
  };
}

export interface HeartbeatSummaryStats {
  currentCpuPct: number;
  avgCpuPct: number;
  peakCpuPct: number;
  currentRamPct: number;
  avgRamPct: number;
  peakRamPct: number;
  currentRamUsedGb: number;
  ramTotalGb: number;
  sampleCount: number;
}

/**
 * Computes statistical aggregates (current, average, peak) for 60-minute Heartbeat CPU & RAM series
 */
export function computeHeartbeatStats(
  points: DeviceMetricPoint[],
  fallbackRamTotalGb = 0
): HeartbeatSummaryStats {
  if (!Array.isArray(points) || points.length === 0) {
    return {
      currentCpuPct: 0,
      avgCpuPct: 0,
      peakCpuPct: 0,
      currentRamPct: 0,
      avgRamPct: 0,
      peakRamPct: 0,
      currentRamUsedGb: 0,
      ramTotalGb: fallbackRamTotalGb,
      sampleCount: 0,
    };
  }

  const latest = points[points.length - 1];
  let cpuSum = 0;
  let cpuPeak = 0;
  let ramPctSum = 0;
  let ramPctPeak = 0;

  for (const pt of points) {
    const cpu = Math.max(0, Math.min(100, Number(pt.cpuUsagePct) || 0));
    const totalGb = Number(pt.ramTotalGb) || fallbackRamTotalGb || 0;
    const usedGb = Math.max(0, Number(pt.ramUsedGb) || 0);
    const ramPct =
      typeof pt.ramUsagePct === 'number' && pt.ramUsagePct > 0
        ? Math.max(0, Math.min(100, pt.ramUsagePct))
        : totalGb > 0
        ? Math.max(0, Math.min(100, (usedGb / totalGb) * 100))
        : 0;

    cpuSum += cpu;
    if (cpu > cpuPeak) cpuPeak = cpu;

    ramPctSum += ramPct;
    if (ramPct > ramPctPeak) ramPctPeak = ramPct;
  }

  const latestRamTotal = Number(latest.ramTotalGb) || fallbackRamTotalGb || 0;
  const latestRamUsed = Math.max(0, Number(latest.ramUsedGb) || 0);
  const latestRamPct =
    typeof latest.ramUsagePct === 'number' && latest.ramUsagePct > 0
      ? Number(latest.ramUsagePct.toFixed(1))
      : latestRamTotal > 0
      ? Number(((latestRamUsed / latestRamTotal) * 100).toFixed(1))
      : 0;

  return {
    currentCpuPct: Number((Number(latest.cpuUsagePct) || 0).toFixed(1)),
    avgCpuPct: Number((cpuSum / points.length).toFixed(1)),
    peakCpuPct: Number(cpuPeak.toFixed(1)),
    currentRamPct: latestRamPct,
    avgRamPct: Number((ramPctSum / points.length).toFixed(1)),
    peakRamPct: Number(ramPctPeak.toFixed(1)),
    currentRamUsedGb: Number(latestRamUsed.toFixed(2)),
    ramTotalGb: Number(latestRamTotal.toFixed(2)),
    sampleCount: points.length,
  };
}

/**
 * Formats the real-time 10-second ICMP Ping connectivity state for an Agentless device
 */
export function formatIcmpPingStatus(
  entry: IcmpPingStatusEntry | undefined,
  fallbackLatencyMs: number,
  fallbackStatus: DeviceStatus
): {
  alive: boolean;
  latencyMs: number;
  labelId: string;
  labelEn: string;
  lastPingedAt: string;
  method: string;
} {
  if (entry) {
    const rtt = Number((Number(entry.latencyMs) || 0).toFixed(1));
    return {
      alive: entry.alive,
      latencyMs: rtt,
      labelId: entry.alive ? `ICMP Ping OK (${rtt}ms)` : 'ICMP Ping Gagal (Timeout)',
      labelEn: entry.alive ? `ICMP Ping OK (${rtt}ms)` : 'ICMP Ping Unreachable',
      lastPingedAt: entry.lastPingedAt || 'Baru saja',
      method: entry.method || 'ICMP Echo',
    };
  }

  const alive = fallbackStatus !== 'offline';
  const rtt = Number((Number(fallbackLatencyMs) || 1.2).toFixed(1));
  return {
    alive,
    latencyMs: alive ? rtt : 0,
    labelId: alive ? `ICMP Ping OK (${rtt}ms)` : 'ICMP Ping Gagal (Timeout)',
    labelEn: alive ? `ICMP Ping OK (${rtt}ms)` : 'ICMP Ping Unreachable',
    lastPingedAt: '10s Poll',
    method: 'ICMP Echo',
  };
}

export type InventorySortField = 'hostname' | 'ip' | 'status';
export type InventorySortDirection = 'asc' | 'desc';
export const INVENTORY_PAGE_SIZE_OPTIONS = [25, 50, 100, 200, 500] as const;

/**
 * Converts an IPv4 address string (e.g. "172.27.170.17") into a comparable 32-bit unsigned integer
 */
export function ipToComparableNumber(ip: string): number {
  const parts = (ip || '').trim().split('.');
  if (parts.length !== 4) return Number.MAX_SAFE_INTEGER;
  let result = 0;
  for (const part of parts) {
    const n = Number(part);
    if (Number.isNaN(n) || n < 0 || n > 255) return Number.MAX_SAFE_INTEGER;
    result = (result * 256) + n;
  }
  return result;
}

function getEffectiveStatusRank(
  dev: DeviceAsset,
  icmpPingMap?: Record<string, IcmpPingStatusEntry>
): number {
  if (dev.agentState === 'agentless' && icmpPingMap && icmpPingMap[dev.id]) {
    return icmpPingMap[dev.id].alive ? 1 : 3;
  }
  if (dev.status === 'online') return 1;
  if (dev.status === 'warning') return 2;
  return 3; // offline
}

/**
 * Sorts devices by Hostname, IPv4 (numerical octet order), or Status
 */
export function sortDevices(
  devices: DeviceAsset[],
  sortField: InventorySortField,
  sortDirection: InventorySortDirection,
  icmpPingMap?: Record<string, IcmpPingStatusEntry>
): DeviceAsset[] {
  const factor = sortDirection === 'asc' ? 1 : -1;
  return [...devices].sort((a, b) => {
    if (sortField === 'hostname') {
      const cmp = a.hostname.localeCompare(b.hostname, undefined, {
        numeric: true,
        sensitivity: 'base',
      });
      if (cmp !== 0) return cmp * factor;
      return (ipToComparableNumber(a.ipAddress) - ipToComparableNumber(b.ipAddress)) * factor;
    }

    if (sortField === 'ip') {
      const diff = ipToComparableNumber(a.ipAddress) - ipToComparableNumber(b.ipAddress);
      if (diff !== 0) return diff * factor;
      return a.hostname.localeCompare(b.hostname, undefined, { numeric: true }) * factor;
    }

    // sortField === 'status'
    const rankDiff =
      getEffectiveStatusRank(a, icmpPingMap) - getEffectiveStatusRank(b, icmpPingMap);
    if (rankDiff !== 0) return rankDiff * factor;
    // Secondary tie-breaker: active agents before agentless, then IP
    const agentRankA = a.agentState === 'active' ? 1 : a.agentState === 'snmp-only' ? 2 : 3;
    const agentRankB = b.agentState === 'active' ? 1 : b.agentState === 'snmp-only' ? 2 : 3;
    if (agentRankA !== agentRankB) return (agentRankA - agentRankB) * factor;
    return (ipToComparableNumber(a.ipAddress) - ipToComparableNumber(b.ipAddress)) * factor;
  });
}

export interface PaginationResult<T> {
  pageItems: T[];
  currentPage: number;
  pageSize: number;
  totalPages: number;
  totalItems: number;
  startIndex: number; // 1-based start row number (0 if empty)
  endIndex: number;   // 1-based end row number (0 if empty)
  pageNumbers: number[];
}

/**
 * Slices an array of items for the given page and pageSize (25, 50, 100, 200, 500)
 * and computes visible page numbers for the pagination bar.
 */
export function paginateDevices<T>(
  items: T[],
  requestedPage: number,
  pageSize: number
): PaginationResult<T> {
  const safePageSize = Math.max(1, Number(pageSize) || 25);
  const totalItems = items.length;
  const totalPages = Math.max(1, Math.ceil(totalItems / safePageSize));
  const currentPage = Math.max(1, Math.min(totalPages, Math.floor(Number(requestedPage) || 1)));

  const offset = (currentPage - 1) * safePageSize;
  const pageItems = items.slice(offset, offset + safePageSize);

  const startIndex = totalItems === 0 ? 0 : offset + 1;
  const endIndex = totalItems === 0 ? 0 : Math.min(totalItems, offset + pageItems.length);

  // Build visible page number window (up to 7 page buttons around currentPage)
  const maxButtons = 7;
  let startPage = Math.max(1, currentPage - Math.floor(maxButtons / 2));
  let endPage = startPage + maxButtons - 1;
  if (endPage > totalPages) {
    endPage = totalPages;
    startPage = Math.max(1, endPage - maxButtons + 1);
  }

  const pageNumbers: number[] = [];
  for (let p = startPage; p <= endPage; p++) {
    pageNumbers.push(p);
  }

  return {
    pageItems,
    currentPage,
    pageSize: safePageSize,
    totalPages,
    totalItems,
    startIndex,
    endIndex,
    pageNumbers,
  };
}



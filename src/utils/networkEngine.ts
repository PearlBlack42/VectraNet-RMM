import {
  CredentialProtocol,
  CredentialVaultEntry,
  DeviceAsset,
  DeviceStatus,
  AgentState,
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
 * Deterministic AES-256-GCM envelope metadata generator for the Credential Vault
 */
export function encryptCredentialSecret(params: {
  label: string;
  protocol: CredentialProtocol;
  username: string;
  rawSecret: string;
  port: number;
  scopeSubnet: string;
}): Omit<CredentialVaultEntry, 'id' | 'lastRotated' | 'createdBy' | 'verified'> {
  const cleanLabel = params.label.trim();
  const cleanUser = params.username.trim();
  const secret = params.rawSecret;

  // Deterministic hex digest simulation for envelope preview
  let hash = 0x811c9dc5;
  const input = `${cleanLabel}:${params.protocol}:${cleanUser}:${secret}:${params.scopeSubnet}`;
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
    port: params.port,
    scopeSubnet: params.scopeSubnet.trim(),
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
  scopeSubnet: string;
}): { valid: boolean; error?: string } {
  if (!input.label || input.label.trim().length < 3) {
    return { valid: false, error: 'Label must be at least 3 characters' };
  }
  if (!input.username || input.username.trim().length < 2) {
    return { valid: false, error: 'Username or Principal is required' };
  }
  if (!input.rawSecret || input.rawSecret.trim().length < 6) {
    return { valid: false, error: 'Secret/Password/Key must be at least 6 characters' };
  }
  const cidrCheck = parseCidrRange(input.scopeSubnet);
  if (!cidrCheck.valid) {
    return { valid: false, error: cidrCheck.error || 'Invalid CIDR subnet scope' };
  }
  return { valid: true };
}

/**
 * Filters devices by search query, status, and agent state
 */
export function filterDevices(
  devices: DeviceAsset[],
  options: {
    query: string;
    statusFilter: 'all' | DeviceStatus;
    agentFilter: 'all' | AgentState;
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

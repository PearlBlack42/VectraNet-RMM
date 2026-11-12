export type DeviceOS =
  | 'Windows Server'
  | 'Windows 11'
  | 'Ubuntu Linux'
  | 'RHEL Linux'
  | 'macOS Sequoia'
  | 'Cisco IOS-XE'
  | 'MikroTik RouterOS'
  | 'Android Enterprise'
  | 'iOS Managed'
  | string;

export type DeviceRole =
  | 'core-router'
  | 'dist-switch'
  | 'access-switch'
  | 'server'
  | 'workstation'
  | 'mobile';

export type DeviceStatus = 'online' | 'warning' | 'offline';

export type AgentState = 'active' | 'agentless' | 'deploying' | 'snmp-only';

export interface NetworkInterfaceItem {
  id: string;
  name: string;
  ipAddress: string;
  macAddress: string;
  speedMbps: number;
  vlan: number;
  rxMbps: number;
  txMbps: number;
  isPrimary: boolean;
}

export interface InstalledSoftwareItem {
  name: string;
  version: string;
  publisher: string;
  installDate: string;
}

export interface DeviceAsset {
  id: string;
  hostname: string;
  ipAddress: string;
  macAddress: string;
  os: DeviceOS;
  osVersion: string;
  kernelArch: string;
  role: DeviceRole;
  status: DeviceStatus;
  agentState: AgentState;
  agentVersion?: string;
  agentMemoryMb?: number;
  cpuModel: string;
  cpuCores: number;
  cpuUsagePct: number;
  ramTotalGb: number;
  ramUsedGb: number;
  diskTotalGb: number;
  diskUsedGb: number;
  lastSeen: string;
  subnet: string;
  location: string;
  uplinkDeviceId?: string;
  uplinkPort?: string;
  latencyMs: number;
  interfaces: NetworkInterfaceItem[];
  software: InstalledSoftwareItem[];
}

export type CredentialProtocol =
  | 'WinRM-HTTPS'
  | 'SSH-Ed25519'
  | 'SSH-Password'
  | 'SNMPv3-AuthPriv'
  | 'SNMPv2c'
  | 'LDAP-AD';

export interface CredentialVaultEntry {
  id: string;
  label: string;
  protocol: CredentialProtocol;
  username: string;
  port: number;
  scopeSubnet: string;
  cipherPreview: string;
  ivHex: string;
  authTagHex: string;
  keyFingerprint: string;
  lastRotated: string;
  createdBy: string;
  verified: boolean;
}

export interface DeploymentJob {
  id: string;
  targetDeviceIds: string[];
  credentialId: string;
  transport: string;
  status: 'running' | 'completed' | 'failed';
  progressPct: number;
  startedAt: string;
  completedAt?: string;
  logs: string[];
}

export interface ScanProgressState {
  jobId: string;
  status: 'idle' | 'running' | 'completed' | 'failed';
  cidr: string;
  totalHosts: number;
  scannedHosts: number;
  progressPct: number;
  discoveredCount: number;
  discoveredHosts: string[];
  currentPhase: string;
  message: string;
  elapsedMs: number;
  error?: string;
}

export interface SystemLogEntry {
  id: string;
  timestamp: string;
  level: 'INFO' | 'WARN' | 'ERROR';
  module:
    | 'INGEST-TLS'
    | 'SWEEPER-ICMP'
    | 'PUSH-WINRM'
    | 'PUSH-SSH'
    | 'SNMP-POLLER'
    | 'VAULT-AES256';
  deviceHostname?: string;
  message: string;
  latencyMs?: number;
}

export interface SystemMetricsSummary {
  activeGoroutines: number;
  maxGoroutines: number;
  heapRssMb: number;
  compressionRatioPct: number;
  avgIngestPacketKb: number;
  avgAgentRamMb: number;
  totalTelemetryRows: number;
  dbConnected: boolean;
  dbDsnMasked: string;
  lastPolledAt: string;
  logs: SystemLogEntry[];
}

export interface NotificationItem {
  id: string;
  timestamp: string;
  severity: 'info' | 'warning' | 'critical' | 'success';
  titleId: string;
  titleEn: string;
  descId: string;
  descEn: string;
  read: boolean;
}

export interface AdminUserEntry {
  id: string;
  fullName: string;
  email: string;
  role: 'Super Admin' | 'SecOps Engineer' | 'NOC Operator' | 'Read-Only Auditor';
  mfaEnabled: boolean;
  lastLogin: string;
  status: 'Active' | 'Suspended';
}

export interface EngineConfigState {
  baseHeartbeatSec: number;
  adaptiveDeltaThresholdPct: number;
  maxAgentRamMb: number;
  maxScannerGoroutines: number;
  icmpTimeoutMs: number;
  snmpRetries: number;
  tlsMinVersion: 'TLS 1.3' | 'TLS 1.2';
  gzipCompressionLevel: number;
  autoPushNewSubnets: boolean;
  timescaleRetentionDays: number;
}

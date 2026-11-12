import {
  AdminUserEntry,
  CredentialVaultEntry,
  DeviceAsset,
  EngineConfigState,
  NotificationItem,
  SystemLogEntry,
  SystemMetricsSummary,
} from '../types/network';

/**
 * Zero-State Initialization:
 * Static seed data has been emptied so the dashboard starts in a clean zero-state
 * and populates exclusively via real-time REST API polling (/api/v1/devices, /api/v1/metrics)
 * and live agent ingestion (/api/v1/agent/ingest).
 */
export const INITIAL_DEVICES: DeviceAsset[] = [];

export const INITIAL_CREDENTIALS: CredentialVaultEntry[] = [];

export const INITIAL_LOGS: SystemLogEntry[] = [];

export const INITIAL_NOTIFICATIONS: NotificationItem[] = [];

export const INITIAL_ADMIN_USERS: AdminUserEntry[] = [];

export const INITIAL_ENGINE_CONFIG: EngineConfigState = {
  baseHeartbeatSec: 60,
  adaptiveDeltaThresholdPct: 25,
  maxAgentRamMb: 18,
  maxScannerGoroutines: 256,
  icmpTimeoutMs: 800,
  snmpRetries: 2,
  tlsMinVersion: 'TLS 1.3',
  gzipCompressionLevel: 6,
  autoPushNewSubnets: false,
  timescaleRetentionDays: 90,
};

export const INITIAL_SYSTEM_METRICS: SystemMetricsSummary = {
  activeGoroutines: 0,
  maxGoroutines: 256,
  heapRssMb: 0,
  compressionRatioPct: 0,
  avgIngestPacketKb: 0,
  avgAgentRamMb: 0,
  totalTelemetryRows: 0,
  dbConnected: false,
  dbDsnMasked: 'postgres://postgres:***@localhost:5432/vectranet_rmm',
  lastPolledAt: '-',
  logs: [],
};

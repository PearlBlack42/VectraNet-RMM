import React, { useState, useMemo, useEffect, useCallback } from 'react';
import {
  Server,
  Network,
  Lock,
  Activity,
  Settings,
  Code2,
  Search,
  Rocket,
  Radar,
  Bell,
  Globe,
  Eye,
  CheckCircle2,
  AlertTriangle,
  ShieldCheck,
  RefreshCw,
  PlusCircle,
  Trash2,
  Wifi,
  WifiOff,
  XCircle,
  ArrowUpDown,
  ArrowUp,
  ArrowDown,
} from 'lucide-react';
import {
  AdminUserEntry,
  AgentState,
  CredentialVaultEntry,
  DeployExecutionResult,
  DeviceAsset,
  DeviceStatus,
  EngineConfigState,
  IcmpPingBatchResponse,
  IcmpPingStatusEntry,
  NotificationItem,
  ScanProgressState,
  SystemLogEntry,
  SystemMetricsSummary,
} from './types/network';
import {
  INITIAL_ENGINE_CONFIG,
  INITIAL_SYSTEM_METRICS,
} from './data/seedNetworkData';
import {
  INVENTORY_PAGE_SIZE_OPTIONS,
  InventorySortDirection,
  InventorySortField,
  applyAgentDeployment,
  computeFleetSummary,
  filterDevices,
  formatIcmpPingStatus,
  paginateDevices,
  parseCidrRange,
  sortDevices,
} from './utils/networkEngine';
import { TopologyView } from './components/TopologyView';
import { CredentialVaultView } from './components/CredentialVaultView';
import { SystemHealthLogsView } from './components/SystemHealthLogsView';
import { AdminConfigView } from './components/AdminConfigView';
import { BlueprintDocsView } from './components/BlueprintDocsView';
import { PushDeployModal } from './components/PushDeployModal';
import { DeviceDetailModal } from './components/DeviceDetailModal';

type ActiveTab =
  | 'inventory'
  | 'topology'
  | 'vault'
  | 'health'
  | 'admin'
  | 'blueprints';

const API_BASE = (import.meta.env.VITE_API_BASE_URL as string) || '';

export default function App() {
  const [activeTab, setActiveTab] = useState<ActiveTab>('inventory');
  const [lang, setLang] = useState<'id' | 'en'>('id');

  // Zero-state initialization: no static fake data
  const [devices, setDevices] = useState<DeviceAsset[]>([]);
  const [credentials, setCredentials] = useState<CredentialVaultEntry[]>([]);
  const [logs, setLogs] = useState<SystemLogEntry[]>([]);
  const [metrics, setMetrics] = useState<SystemMetricsSummary>(INITIAL_SYSTEM_METRICS);
  const [notifications, setNotifications] = useState<NotificationItem[]>([]);
  const [adminUsers, setAdminUsers] = useState<AdminUserEntry[]>([]);
  const [engineConfig, setEngineConfig] =
    useState<EngineConfigState>(INITIAL_ENGINE_CONFIG);

  // Real-time polling state
  const [isPolling, setIsPolling] = useState<boolean>(false);
  const [apiStatus, setApiStatus] = useState<'connected' | 'syncing' | 'offline'>('syncing');

  // Real-time 10-second ICMP Ping status for Agentless devices
  const [icmpPingMap, setIcmpPingMap] = useState<Record<string, IcmpPingStatusEntry>>({});
  const [lastIcmpSweepAt, setLastIcmpSweepAt] = useState<string>('--:--:--');
  const [isIcmpSweeping, setIsIcmpSweeping] = useState<boolean>(false);

  // Inventory filters, sorting, pagination & selection
  const [searchQuery, setSearchQuery] = useState('');
  const [statusFilter, setStatusFilter] = useState<'all' | DeviceStatus>('all');
  const [agentFilter, setAgentFilter] = useState<'all' | AgentState>('all');
  const [osFilter, setOsFilter] = useState<string>('all');
  const [sortField, setSortField] = useState<InventorySortField>('ip');
  const [sortDirection, setSortDirection] = useState<InventorySortDirection>('asc');
  const [pageSize, setPageSize] = useState<number>(25);
  const [currentPage, setCurrentPage] = useState<number>(1);
  const [selectedDeviceIds, setSelectedDeviceIds] = useState<string[]>([]);

  // Subnet CIDR Scanner & Real-Time Progress state
  const [scanCidrInput, setScanCidrInput] = useState('127.0.0.1/32');
  const [scanProgress, setScanProgress] = useState<ScanProgressState | null>(null);
  const [scanMessage, setScanMessage] = useState<string | null>(null);
  const [scanError, setScanError] = useState<string | null>(null);

  // Modals & Drawers
  const [deployTargetIds, setDeployTargetIds] = useState<string[]>([]);
  const [isDeployModalOpen, setIsDeployModalOpen] = useState(false);
  const [inspectDevice, setInspectDevice] = useState<DeviceAsset | null>(null);
  const [isNotifOpen, setIsNotifOpen] = useState(false);

  // Periodic Real-Time API Fetching (Every 5 seconds)
  const fetchLiveTelemetry = useCallback(async () => {
    setIsPolling(true);
    try {
      const [devRes, metRes, credRes] = await Promise.all([
        fetch(`${API_BASE}/api/v1/devices`),
        fetch(`${API_BASE}/api/v1/metrics`),
        fetch(`${API_BASE}/api/v1/credentials`),
      ]);

      if (devRes.ok) {
        const devData = (await devRes.json()) as DeviceAsset[];
        if (Array.isArray(devData)) {
          setDevices((prevDevices) => {
            if (prevDevices.length === 0) return devData;
            const prevByIp = new Map<string, DeviceAsset>();
            for (const p of prevDevices) {
              prevByIp.set(p.ipAddress, p);
            }
            return devData.map((d) => {
              const incomingName = (d.hostname || '').trim();
              const incomingIsFallback =
                !incomingName ||
                incomingName.toUpperCase().startsWith('HOST-') ||
                incomingName === d.ipAddress;
              if (incomingIsFallback) {
                const prev = prevByIp.get(d.ipAddress);
                const prevName = (prev?.hostname || '').trim();
                if (
                  prevName &&
                  !prevName.toUpperCase().startsWith('HOST-') &&
                  prevName !== d.ipAddress
                ) {
                  return { ...d, hostname: prevName };
                }
              }
              return d;
            });
          });
        }
      }

      if (metRes.ok) {
        const metData = (await metRes.json()) as SystemMetricsSummary;
        if (metData && typeof metData === 'object') {
          setMetrics(metData);
          if (Array.isArray(metData.logs)) {
            setLogs(metData.logs);
          }
        }
      }

      if (credRes.ok) {
        const credData = (await credRes.json()) as CredentialVaultEntry[];
        if (Array.isArray(credData)) {
          setCredentials(credData);
        }
      }

      setApiStatus('connected');
    } catch {
      setApiStatus('offline');
    } finally {
      setIsPolling(false);
    }
  }, []);

  // Auto-detect local OS interface CIDR on initial mount
  useEffect(() => {
    fetch(`${API_BASE}/api/v1/network/local-cidr`)
      .then((res) => (res.ok ? res.json() : null))
      .then((data: { cidr?: string } | null) => {
        if (data?.cidr) {
          setScanCidrInput(data.cidr);
        }
      })
      .catch(() => {
        // Keep default if endpoint unavailable
      });
  }, []);

  // Real-time 10-second ICMP Ping Sweeper for Agentless Devices
  const fetchAgentlessIcmpPing = useCallback(async () => {
    setIsIcmpSweeping(true);
    try {
      const res = await fetch(`${API_BASE}/api/v1/devices/ping`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({}),
      });
      if (res.ok) {
        const data = (await res.json()) as IcmpPingBatchResponse;
        if (data && data.results) {
          setIcmpPingMap(data.results);
          if (data.timestamp) {
            setLastIcmpSweepAt(data.timestamp);
          }
        }
      }
    } catch {
      // Ignore transient network error during ICMP sweep
    } finally {
      setIsIcmpSweeping(false);
    }
  }, []);

  useEffect(() => {
    void fetchLiveTelemetry();
    const pollTimer = window.setInterval(() => {
      void fetchLiveTelemetry();
    }, 5000);
    return () => window.clearInterval(pollTimer);
  }, [fetchLiveTelemetry]);

  // Poll ICMP Ping for Agentless devices every 10 seconds (and trigger when agentless devices change)
  const agentlessKey = useMemo(
    () =>
      devices
        .filter((d) => d.agentState === 'agentless')
        .map((d) => d.id)
        .join(','),
    [devices]
  );

  useEffect(() => {
    void fetchAgentlessIcmpPing();
    const icmpTimer = window.setInterval(() => {
      void fetchAgentlessIcmpPing();
    }, 10000);
    return () => window.clearInterval(icmpTimer);
  }, [fetchAgentlessIcmpPing, agentlessKey]);

  // Poll /api/v1/scan/status every 300ms while a subnet scan is actively running
  useEffect(() => {
    if (!scanProgress || scanProgress.status !== 'running') {
      return;
    }

    let lastDiscoveredCount = scanProgress.discoveredCount;
    const statusTimer = window.setInterval(async () => {
      try {
        const res = await fetch(`${API_BASE}/api/v1/scan/status`);
        if (!res.ok) return;
        const statusData = (await res.json()) as ScanProgressState;
        setScanProgress(statusData);

        if (statusData.discoveredCount > lastDiscoveredCount) {
          lastDiscoveredCount = statusData.discoveredCount;
          void fetchLiveTelemetry();
        }

        if (statusData.status === 'completed' || statusData.status === 'failed') {
          window.clearInterval(statusTimer);
          void fetchLiveTelemetry();
          if (statusData.status === 'completed') {
            setScanMessage(statusData.message);
          } else if (statusData.error) {
            setScanError(statusData.error);
          }
        }
      } catch {
        // Ignore transient status poll error
      }
    }, 300);

    return () => window.clearInterval(statusTimer);
  }, [scanProgress, fetchLiveTelemetry]);

  const fleetSummary = useMemo(() => computeFleetSummary(devices), [devices]);

  const filteredDevices = useMemo(
    () =>
      filterDevices(devices, {
        query: searchQuery,
        statusFilter,
        agentFilter,
        osFilter,
      }),
    [devices, searchQuery, statusFilter, agentFilter, osFilter]
  );

  const sortedDevices = useMemo(
    () => sortDevices(filteredDevices, sortField, sortDirection, icmpPingMap),
    [filteredDevices, sortField, sortDirection, icmpPingMap]
  );

  const pagination = useMemo(
    () => paginateDevices(sortedDevices, currentPage, pageSize),
    [sortedDevices, currentPage, pageSize]
  );

  const handleSortColumn = (field: InventorySortField) => {
    if (sortField === field) {
      setSortDirection((prev) => (prev === 'asc' ? 'desc' : 'asc'));
    } else {
      setSortField(field);
      setSortDirection('asc');
    }
    setCurrentPage(1);
  };

  const unreadNotifCount = useMemo(
    () => notifications.filter((n) => !n.read).length,
    [notifications]
  );

  const handleToggleSelectDevice = (id: string) => {
    setSelectedDeviceIds((prev) =>
      prev.includes(id) ? prev.filter((item) => item !== id) : [...prev, id]
    );
  };

  const handleOpenDeployModal = (targetIds: string[]) => {
    setDeployTargetIds(targetIds);
    setIsDeployModalOpen(true);
  };

  const handleConfirmDeploy = async (
    targetIds: string[],
    credentialId: string,
    targetDevicesList: DeviceAsset[]
  ): Promise<DeployExecutionResult> => {
    const targetsPayload = targetDevicesList.map((d) => ({
      id: d.id,
      ipAddress: d.ipAddress,
      hostname: d.hostname,
      os: d.os,
    }));

    try {
      const res = await fetch(`${API_BASE}/api/v1/deploy`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          targetIds,
          targets: targetsPayload,
          credentialId,
        }),
      });

      const data = (await res.json().catch(() => ({}))) as DeployExecutionResult;
      await fetchLiveTelemetry();

      const succeededIds = Array.isArray(data.deployedIds) ? data.deployedIds : [];

      if (res.ok && data.status === 'deployed' && succeededIds.length > 0) {
        setDevices((prev) => applyAgentDeployment(prev, succeededIds, 'v2.4.1-go'));

        const deployedNames = targetDevicesList
          .filter((d) => succeededIds.includes(d.id))
          .map((d) => `${d.hostname} (${d.ipAddress})`)
          .join(', ');

        setNotifications((prev) => [
          {
            id: `notif-${Date.now()}`,
            timestamp: 'Just now',
            severity: 'success',
            titleId: `Push Deployment Berhasil (${succeededIds.length} Host)`,
            titleEn: `Push Deployment Succeeded (${succeededIds.length} Hosts)`,
            descId: `Agen Go v2.4.1 aktif pada: ${deployedNames}. Memory cap: ${engineConfig.maxAgentRamMb} MB.`,
            descEn: `Go Agent v2.4.1 active on: ${deployedNames}. Memory cap: ${engineConfig.maxAgentRamMb} MB.`,
            read: false,
          },
          ...prev,
        ]);

        setSelectedDeviceIds((prev) => prev.filter((id) => !succeededIds.includes(id)));

        return {
          status: 'deployed',
          deployedCount: data.deployedCount ?? succeededIds.length,
          failedCount: data.failedCount ?? 0,
          deployedIds: succeededIds,
          logs: data.logs || [],
        };
      }

      const failedTargetsStr = targetDevicesList
        .map((d) => `${d.hostname} (${d.ipAddress})`)
        .join(', ');

      setNotifications((prev) => [
        {
          id: `notif-${Date.now()}`,
          timestamp: 'Just now',
          severity: 'warning',
          titleId: `Push Deployment Gagal (${targetDevicesList.length} Host)`,
          titleEn: `Push Deployment Failed (${targetDevicesList.length} Hosts)`,
          descId:
            data.error ||
            `Gagal menghubungi atau mengautentikasi target: ${failedTargetsStr}. Status tetap Agentless.`,
          descEn:
            data.error ||
            `Failed to reach or authenticate target: ${failedTargetsStr}. Status remains Agentless.`,
          read: false,
        },
        ...prev,
      ]);

      return {
        status: 'failed',
        deployedCount: 0,
        failedCount: data.failedCount ?? targetDevicesList.length,
        deployedIds: [],
        logs: data.logs || [],
        error:
          data.error ||
          `Koneksi / otentikasi WinRM/SSH ke ${failedTargetsStr} gagal.`,
      };
    } catch (err) {
      const errMsg = (err as Error).message || 'Gagal menghubungi /api/v1/deploy';
      return {
        status: 'failed',
        deployedCount: 0,
        failedCount: targetDevicesList.length,
        deployedIds: [],
        logs: [`[ERROR] Gagal menghubungi endpoint /api/v1/deploy: ${errMsg}`],
        error: errMsg,
      };
    }
  };

  const handleRunSubnetScan = async (e: React.FormEvent) => {
    e.preventDefault();
    setScanError(null);
    setScanMessage(null);

    const parsed = parseCidrRange(scanCidrInput);
    if (!parsed.valid) {
      setScanError(parsed.error || 'Format CIDR tidak valid');
      return;
    }

    try {
      const res = await fetch(`${API_BASE}/api/v1/scan`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ cidr: scanCidrInput.trim() }),
      });

      if (!res.ok) {
        const errBody = await res.json().catch(() => ({}));
        setScanError(errBody.error || 'Gagal memulai pemindaian subnet');
        return;
      }

      const initialProgress = (await res.json()) as ScanProgressState;
      setScanProgress(initialProgress);
      if (initialProgress.status === 'completed') {
        setScanMessage(initialProgress.message);
        await fetchLiveTelemetry();
      }
    } catch (err) {
      setScanError(`Gagal menghubungi endpoint /api/v1/scan: ${(err as Error).message}`);
    }
  };

  const handleAddCredential = async (entry: CredentialVaultEntry) => {
    setCredentials((prev) => [entry, ...prev]);
    try {
      await fetch(`${API_BASE}/api/v1/credentials`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(entry),
      });
      await fetchLiveTelemetry();
    } catch {
      // Keep local state if offline
    }
  };

  const handleDeleteCredential = async (id: string) => {
    setCredentials((prev) => prev.filter((c) => c.id !== id));
    try {
      await fetch(`${API_BASE}/api/v1/credentials?id=${encodeURIComponent(id)}`, {
        method: 'DELETE',
      });
      await fetchLiveTelemetry();
    } catch {
      // Keep local state
    }
  };

  const handleRotateCredentialKey = (id: string) => {
    setCredentials((prev) =>
      prev.map((c) => {
        if (c.id !== id) return c;
        const suffix = Math.floor(1000 + Math.random() * 8999)
          .toString(16)
          .toUpperCase();
        return {
          ...c,
          ivHex: `A9${suffix}7F0182`,
          keyFingerprint: `SHA256:${suffix}:B401:99E2:11C0`,
          lastRotated:
            new Date().toISOString().slice(0, 16).replace('T', ' ') + ' UTC',
        };
      })
    );
  };

  const handleEmitTestIngest = async () => {
    setScanError(null);
    try {
      // Collect real live OS hardware telemetry (CPU %, RAM Used/Total GB, Disk GB, CPU Model & Cores)
      const res = await fetch(`${API_BASE}/api/v1/agent/collect-local`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ trigger: 'manual-local-hardware-ingest' }),
      });

      if (res.ok) {
        const data = (await res.json().catch(() => ({}))) as {
          hardware?: {
            cpuModel?: string;
            cpuCores?: number;
            cpuUsagePct?: number;
            ramUsedGb?: number;
            ramTotalGb?: number;
          };
        };
        if (data.hardware) {
          setScanMessage(
            lang === 'id'
              ? `Telemetri hardware asli berhasil dikirim: ${data.hardware.cpuModel || 'CPU'} (${data.hardware.cpuCores || 1} Core) · CPU ${data.hardware.cpuUsagePct}% · RAM ${data.hardware.ramUsedGb}/${data.hardware.ramTotalGb} GB.`
              : `Real hardware telemetry ingested: ${data.hardware.cpuModel || 'CPU'} (${data.hardware.cpuCores || 1} Cores) · CPU ${data.hardware.cpuUsagePct}% · RAM ${data.hardware.ramUsedGb}/${data.hardware.ramTotalGb} GB.`
          );
        }
      }
      await fetchLiveTelemetry();
    } catch {
      // Ignore network error
    }
  };

  const handleClearDatabase = async () => {
    const confirmPrompt =
      lang === 'id'
        ? 'Apakah Anda yakin ingin menghapus seluruh data inventaris perangkat, interface jaringan, dan log sistem dari database PostgreSQL (vectranet_rmm)?'
        : 'Are you sure you want to delete all device inventory, network interfaces, and system logs from PostgreSQL (vectranet_rmm)?';

    let confirmed = true;
    try {
      if (typeof window !== 'undefined' && typeof window.confirm === 'function') {
        confirmed = window.confirm(confirmPrompt);
      }
    } catch {
      confirmed = true;
    }

    if (!confirmed) {
      return;
    }

    setScanError(null);
    setScanMessage(null);

    try {
      let res = await fetch(`${API_BASE}/api/v1/devices/clear`, {
        method: 'DELETE',
      });
      if (!res.ok) {
        res = await fetch(`${API_BASE}/api/v1/devices/clear`, {
          method: 'POST',
        });
      }

      if (!res.ok) {
        const errBody = await res.json().catch(() => ({}));
        setScanError(errBody.error || 'Gagal mengosongkan database PostgreSQL');
        return;
      }

      // Immediately reset local state to 0 devices and refresh from backend
      setDevices([]);
      setLogs([]);
      setIcmpPingMap({});
      setSelectedDeviceIds([]);
      setInspectDevice(null);
      setScanProgress(null);
      setScanMessage(
        lang === 'id'
          ? '🧹 Database PostgreSQL (vectranet_rmm) berhasil dikosongkan. Tabel inventaris kembali ke 0 perangkat.'
          : '🧹 PostgreSQL database (vectranet_rmm) cleared. Inventory reset to 0 devices.'
      );
      await fetchLiveTelemetry();
    } catch (err) {
      setScanError(`Gagal menghubungi endpoint /api/v1/devices/clear: ${(err as Error).message}`);
    }
  };

  const deployTargets = useMemo(
    () => devices.filter((d) => deployTargetIds.includes(d.id)),
    [devices, deployTargetIds]
  );

  const isScanning = scanProgress?.status === 'running';

  return (
    <div className="min-h-screen bg-[#0B0F17] text-slate-100 flex flex-col">
      {/* Top Bar Contract: Zone 1 Brand Wordmark — Zone 2 Concise Nav Links — Zone 3 Primary Action */}
      <header className="flex items-center justify-between gap-8 px-6 py-3.5 bg-[#0B0F17] border-b border-[#1E293B] sticky top-0 z-30">
        <a
          href="#top"
          onClick={(e) => {
            e.preventDefault();
            setActiveTab('inventory');
          }}
          className="text-base font-bold tracking-tight text-white whitespace-nowrap shrink-0"
        >
          VectraNet RMM
        </a>

        <nav
          aria-label="Primary Navigation"
          className="hidden lg:flex items-center gap-6 text-xs font-medium text-slate-300"
        >
          <button
            type="button"
            onClick={() => setActiveTab('inventory')}
            className={`hover:text-white transition-colors whitespace-nowrap shrink-0 cursor-pointer pb-0.5 ${
              activeTab === 'inventory'
                ? 'text-emerald-400 border-b border-emerald-400'
                : ''
            }`}
          >
            {lang === 'id' ? 'Inventaris & Push' : 'Asset Inventory'}
          </button>
          <button
            type="button"
            onClick={() => setActiveTab('topology')}
            className={`hover:text-white transition-colors whitespace-nowrap shrink-0 cursor-pointer pb-0.5 ${
              activeTab === 'topology'
                ? 'text-emerald-400 border-b border-emerald-400'
                : ''
            }`}
          >
            {lang === 'id' ? 'Topologi Jaringan' : 'Network Topology'}
          </button>
          <button
            type="button"
            onClick={() => setActiveTab('vault')}
            className={`hover:text-white transition-colors whitespace-nowrap shrink-0 cursor-pointer pb-0.5 ${
              activeTab === 'vault'
                ? 'text-emerald-400 border-b border-emerald-400'
                : ''
            }`}
          >
            {lang === 'id' ? 'Credential Vault' : 'Credential Vault'}
          </button>
          <button
            type="button"
            onClick={() => setActiveTab('health')}
            className={`hover:text-white transition-colors whitespace-nowrap shrink-0 cursor-pointer pb-0.5 ${
              activeTab === 'health'
                ? 'text-emerald-400 border-b border-emerald-400'
                : ''
            }`}
          >
            {lang === 'id' ? 'Kesehatan & Log' : 'System Health'}
          </button>
          <button
            type="button"
            onClick={() => setActiveTab('blueprints')}
            className={`hover:text-white transition-colors whitespace-nowrap shrink-0 cursor-pointer pb-0.5 ${
              activeTab === 'blueprints'
                ? 'text-emerald-400 border-b border-emerald-400'
                : ''
            }`}
          >
            {lang === 'id' ? 'Kode Produksi & DDL' : 'Production Code & DDL'}
          </button>
        </nav>

        <div className="flex items-center gap-3 shrink-0">
          <button
            type="button"
            onClick={() => void fetchLiveTelemetry()}
            title="Poll /api/v1/devices & /api/v1/metrics (Auto-poll 5s)"
            className="px-3 py-2 text-xs font-mono text-slate-300 hover:text-white bg-[#161F30] border border-[#1E293B] rounded-lg transition-colors flex items-center gap-1.5 whitespace-nowrap cursor-pointer"
          >
            <RefreshCw className={`w-3.5 h-3.5 text-emerald-400 ${isPolling ? 'animate-spin' : ''}`} />
            <span>
              {apiStatus === 'connected'
                ? `API 5s (${metrics.lastPolledAt})`
                : apiStatus === 'syncing'
                ? 'Syncing...'
                : 'API Offline'}
            </span>
          </button>

          <button
            type="button"
            onClick={() =>
              handleOpenDeployModal(
                selectedDeviceIds.length > 0
                  ? selectedDeviceIds
                  : devices
                      .filter((d) => d.agentState === 'agentless')
                      .map((d) => d.id)
              )
            }
            className="px-3.5 py-2 text-xs font-semibold bg-emerald-500 hover:bg-emerald-400 text-slate-950 rounded-lg transition-colors whitespace-nowrap shrink-0 cursor-pointer"
          >
            {lang === 'id' ? 'Deploy Agen Massal' : 'Bulk Deploy Agent'}
          </button>
        </div>
      </header>

      {/* Main Workspace Layout: Left Sidebar + Viewport */}
      <div className="flex-1 flex flex-col lg:flex-row">
        {/* Sidebar Navigation (256px on desktop) */}
        <aside className="w-full lg:w-64 bg-[#0B0F17] border-b lg:border-b-0 lg:border-r border-[#1E293B] p-4 flex flex-col justify-between shrink-0">
          <div className="space-y-1.5">
            <div className="px-2.5 py-1.5 text-[11px] font-mono text-slate-400">
              {lang === 'id' ? 'MODUL OPERASIONAL' : 'OPERATIONAL MODULES'}
            </div>

            <button
              type="button"
              onClick={() => setActiveTab('inventory')}
              className={`w-full flex items-center justify-between gap-2 px-3 py-2.5 rounded-lg text-xs font-medium transition-colors cursor-pointer whitespace-nowrap ${
                activeTab === 'inventory'
                  ? 'bg-[#161F30] text-emerald-400 border border-[#1E293B]'
                  : 'text-slate-300 hover:bg-[#161F30]/60'
              }`}
            >
              <span className="flex items-center gap-2.5 truncate">
                <Server className="w-4 h-4 shrink-0" />
                <span className="truncate">
                  {lang === 'id' ? 'Inventaris & Push' : 'Inventory & Push'}
                </span>
              </span>
              <span className="font-mono tabular-nums text-[11px] text-slate-400 shrink-0">
                {devices.length}
              </span>
            </button>

            <button
              type="button"
              onClick={() => setActiveTab('topology')}
              className={`w-full flex items-center justify-between gap-2 px-3 py-2.5 rounded-lg text-xs font-medium transition-colors cursor-pointer whitespace-nowrap ${
                activeTab === 'topology'
                  ? 'bg-[#161F30] text-emerald-400 border border-[#1E293B]'
                  : 'text-slate-300 hover:bg-[#161F30]/60'
              }`}
            >
              <span className="flex items-center gap-2.5 truncate">
                <Network className="w-4 h-4 shrink-0" />
                <span className="truncate">
                  {lang === 'id' ? 'Topologi L2/L3' : 'L2/L3 Topology'}
                </span>
              </span>
              <span className="font-mono text-[11px] text-cyan-400 shrink-0">LLDP</span>
            </button>

            <button
              type="button"
              onClick={() => setActiveTab('vault')}
              className={`w-full flex items-center justify-between gap-2 px-3 py-2.5 rounded-lg text-xs font-medium transition-colors cursor-pointer whitespace-nowrap ${
                activeTab === 'vault'
                  ? 'bg-[#161F30] text-emerald-400 border border-[#1E293B]'
                  : 'text-slate-300 hover:bg-[#161F30]/60'
              }`}
            >
              <span className="flex items-center gap-2.5 truncate">
                <Lock className="w-4 h-4 shrink-0" />
                <span className="truncate">Credential Vault</span>
              </span>
              <span className="font-mono tabular-nums text-[11px] text-slate-400 shrink-0">
                {credentials.length}
              </span>
            </button>

            <button
              type="button"
              onClick={() => setActiveTab('health')}
              className={`w-full flex items-center justify-between gap-2 px-3 py-2.5 rounded-lg text-xs font-medium transition-colors cursor-pointer whitespace-nowrap ${
                activeTab === 'health'
                  ? 'bg-[#161F30] text-emerald-400 border border-[#1E293B]'
                  : 'text-slate-300 hover:bg-[#161F30]/60'
              }`}
            >
              <span className="flex items-center gap-2.5 truncate">
                <Activity className="w-4 h-4 shrink-0" />
                <span className="truncate">
                  {lang === 'id' ? 'Kesehatan & Log' : 'Health & Logs'}
                </span>
              </span>
              <span className="font-mono tabular-nums text-[11px] text-emerald-400 shrink-0">
                {fleetSummary.avgAgentRamMb}MB
              </span>
            </button>

            <button
              type="button"
              onClick={() => setActiveTab('admin')}
              className={`w-full flex items-center justify-between gap-2 px-3 py-2.5 rounded-lg text-xs font-medium transition-colors cursor-pointer whitespace-nowrap ${
                activeTab === 'admin'
                  ? 'bg-[#161F30] text-emerald-400 border border-[#1E293B]'
                  : 'text-slate-300 hover:bg-[#161F30]/60'
              }`}
            >
              <span className="flex items-center gap-2.5 truncate">
                <Settings className="w-4 h-4 shrink-0" />
                <span className="truncate">
                  {lang === 'id' ? 'Admin & Konfigurasi' : 'Admin & Config'}
                </span>
              </span>
            </button>

            <button
              type="button"
              onClick={() => setActiveTab('blueprints')}
              className={`w-full flex items-center justify-between gap-2 px-3 py-2.5 rounded-lg text-xs font-medium transition-colors cursor-pointer whitespace-nowrap ${
                activeTab === 'blueprints'
                  ? 'bg-[#161F30] text-emerald-400 border border-[#1E293B]'
                  : 'text-slate-300 hover:bg-[#161F30]/60'
              }`}
            >
              <span className="flex items-center gap-2.5 truncate">
                <Code2 className="w-4 h-4 shrink-0" />
                <span className="truncate">
                  {lang === 'id' ? 'Blueprint Kode (14)' : 'Code Blueprints (14)'}
                </span>
              </span>
              <span className="font-mono text-[11px] text-emerald-400 shrink-0">SQL/GO</span>
            </button>
          </div>

          {/* Language & Notification Utility Panel */}
          <div className="pt-4 mt-4 border-t border-[#1E293B] space-y-2.5">
            <div className="flex items-center justify-between gap-2">
              <button
                type="button"
                onClick={() => setLang((l) => (l === 'id' ? 'en' : 'id'))}
                className="flex-1 px-3 py-2 rounded-lg bg-[#161F30] border border-[#1E293B] text-xs font-medium text-slate-200 hover:text-white flex items-center justify-center gap-1.5 cursor-pointer"
              >
                <Globe className="w-3.5 h-3.5 text-cyan-400" />
                <span>{lang === 'id' ? 'Bahasa: ID' : 'Language: EN'}</span>
              </button>

              <button
                type="button"
                aria-label="Toggle Real-Time Notifications"
                onClick={() => {
                  setIsNotifOpen((o) => !o);
                  setNotifications((prev) =>
                    prev.map((n) => ({ ...n, read: true }))
                  );
                }}
                className="px-3 py-2 rounded-lg bg-[#161F30] border border-[#1E293B] text-xs font-mono text-slate-200 hover:text-white flex items-center gap-1.5 cursor-pointer"
              >
                <Bell className="w-3.5 h-3.5 text-emerald-400" />
                <span className="tabular-nums">{unreadNotifCount}</span>
              </button>
            </div>

            {isNotifOpen && (
              <div className="p-3 rounded-lg bg-[#161F30] border border-[#1E293B] space-y-2 max-h-60 overflow-y-auto text-xs">
                <div className="font-semibold text-slate-200 pb-1 border-b border-[#1E293B]">
                  {lang === 'id' ? 'Notifikasi Real-Time' : 'Real-Time Activity Feed'}
                </div>
                {notifications.length === 0 ? (
                  <p className="text-[11px] text-slate-400 py-1">
                    {lang === 'id'
                      ? 'Belum ada aktivitas baru.'
                      : 'No recent activity notifications.'}
                  </p>
                ) : (
                  notifications.map((n) => (
                    <div key={n.id} className="pb-2 border-b border-[#1E293B]/60 last:border-none">
                      <div className="flex items-center justify-between text-[11px] text-slate-400">
                        <span
                          className={
                            n.severity === 'warning'
                              ? 'text-rose-400 font-medium'
                              : n.severity === 'success'
                              ? 'text-emerald-400 font-medium'
                              : 'text-cyan-400 font-medium'
                          }
                        >
                          {lang === 'id' ? n.titleId : n.titleEn}
                        </span>
                        <span className="font-mono">{n.timestamp}</span>
                      </div>
                      <p className="text-[11px] text-slate-300 mt-0.5">
                        {lang === 'id' ? n.descId : n.descEn}
                      </p>
                    </div>
                  ))
                )}
              </div>
            )}
          </div>
        </aside>

        {/* Main Content Viewport */}
        <main className="flex-1 p-6 space-y-6 max-w-[1440px] w-full mx-auto">
          {/* Fleet Telemetry Summary Strip */}
          <section
            aria-label="Fleet Summary Metrics"
            className="grid grid-cols-2 lg:grid-cols-4 gap-4"
          >
            <div className="bg-[#161F30] border border-[#1E293B] rounded-xl p-4">
              <span className="text-xs text-slate-400 block">
                {lang === 'id' ? 'Total Perangkat Terdeteksi' : 'Total Discovered Assets'}
              </span>
              <div className="text-2xl font-bold font-mono tabular-nums text-white mt-1">
                {fleetSummary.total}
              </div>
              <div className="text-xs text-slate-400 mt-1">
                Online: {fleetSummary.online} · Peringatan: {fleetSummary.warning}
              </div>
            </div>

            <div className="bg-[#161F30] border border-[#1E293B] rounded-xl p-4">
              <span className="text-xs text-slate-400 block">
                {lang === 'id' ? 'Agen Native Aktif (Go)' : 'Active Native Go Agents'}
              </span>
              <div className="text-2xl font-bold font-mono tabular-nums text-emerald-400 mt-1">
                {fleetSummary.activeAgents}
              </div>
              <div className="text-xs text-slate-400 mt-1">
                Rata-rata RSS: {fleetSummary.avgAgentRamMb} MB · CPU &lt; 0.5%
              </div>
            </div>

            <div className="bg-[#161F30] border border-[#1E293B] rounded-xl p-4">
              <span className="text-xs text-slate-400 block">
                {lang === 'id'
                  ? 'Target Siap Push Deploy'
                  : 'Agentless Targets Ready for Push'}
              </span>
              <div className="text-2xl font-bold font-mono tabular-nums text-cyan-400 mt-1">
                {fleetSummary.agentlessCount}
              </div>
              <div className="text-xs text-slate-400 mt-1">
                WinRM-HTTPS (5986) &amp; SSH-Ed25519 (22)
              </div>
            </div>

            <div className="bg-[#161F30] border border-[#1E293B] rounded-xl p-4">
              <span className="text-xs text-slate-400 block">
                {lang === 'id' ? 'Node Jaringan SNMPv3' : 'SNMPv3 Backbone Nodes'}
              </span>
              <div className="text-2xl font-bold font-mono tabular-nums text-white mt-1">
                {fleetSummary.snmpNodes}
              </div>
              <div className="text-xs text-slate-400 mt-1">
                Cisco IOS-XE &amp; MikroTik RouterOS
              </div>
            </div>
          </section>

          {/* Active View Router */}
          {activeTab === 'inventory' && (
            <div className="space-y-6">
              {/* Real Concurrent IP Subnet Sweeper Bar */}
              <section className="bg-[#161F30] border border-[#1E293B] rounded-xl p-5">
                <form
                  onSubmit={handleRunSubnetScan}
                  className="flex flex-col md:flex-row md:items-end justify-between gap-4"
                  noValidate
                >
                  <div className="flex-1">
                    <label
                      htmlFor="cidr-scan-input"
                      className="block text-xs font-semibold text-slate-200 mb-1 flex items-center gap-1.5"
                    >
                      <Radar className={`w-4 h-4 text-emerald-400 ${isScanning ? 'animate-spin' : ''}`} />
                      {lang === 'id'
                        ? 'Pemindai Subnet Jaringan Nyata (TCP Dial + ICMP Ping + OS ARP Cache -> PostgreSQL)'
                        : 'Real Network Subnet Scanner (TCP Dial + ICMP Ping + OS ARP Cache -> PostgreSQL)'}
                    </label>
                    <p className="text-xs text-slate-400 mb-2">
                      {lang === 'id'
                        ? 'Memindai host aktif nyata di jaringan lokal secara paralel (Port 22, 80, 135, 443, 445, 3389, 5985 + Ping + ARP Table) dan menyimpannya ke database.'
                        : 'Concurrently probes real active hosts on the local network (TCP 22, 80, 135, 443, 445, 3389, 5985 + Ping + ARP Table) and persists them to PostgreSQL.'}
                    </p>
                    <div className="flex flex-col sm:flex-row gap-2.5">
                      <input
                        id="cidr-scan-input"
                        type="text"
                        value={scanCidrInput}
                        onChange={(e) => setScanCidrInput(e.target.value)}
                        placeholder="192.168.1.0/24"
                        disabled={isScanning}
                        className="flex-1 px-3.5 py-2 text-sm font-mono bg-[#0B0F17] border border-[#1E293B] rounded-lg text-slate-100 focus:outline-none focus:border-emerald-500 disabled:opacity-60"
                      />
                      <button
                        type="submit"
                        disabled={isScanning}
                        className="px-4 py-2 text-xs font-semibold bg-emerald-500 hover:bg-emerald-400 disabled:opacity-60 text-slate-950 rounded-lg transition-colors flex items-center justify-center gap-2 whitespace-nowrap cursor-pointer"
                      >
                        <Radar className={`w-4 h-4 ${isScanning ? 'animate-spin' : ''}`} />
                        {isScanning
                          ? lang === 'id'
                            ? `Memindai... (${scanProgress?.progressPct ?? 0}%)`
                            : `Scanning... (${scanProgress?.progressPct ?? 0}%)`
                          : lang === 'id'
                          ? 'Pindai Subnet Sekarang'
                          : 'Scan Subnet Now'}
                      </button>
                      <button
                        type="button"
                        onClick={() => void handleEmitTestIngest()}
                        className="px-4 py-2 text-xs font-medium bg-[#0B0F17] hover:bg-slate-800 text-emerald-400 border border-[#1E293B] rounded-lg transition-colors flex items-center justify-center gap-1.5 whitespace-nowrap cursor-pointer"
                      >
                        <PlusCircle className="w-4 h-4" />
                        {lang === 'id' ? 'Uji Ingest Agen Lokal' : 'Test Local Agent Ingest'}
                      </button>
                      <button
                        type="button"
                        onClick={() => void handleClearDatabase()}
                        disabled={isScanning}
                        className="px-4 py-2 text-xs font-semibold bg-rose-500/15 hover:bg-rose-500/25 disabled:opacity-50 text-rose-300 border border-rose-500/40 rounded-lg transition-colors flex items-center justify-center gap-1.5 whitespace-nowrap cursor-pointer"
                      >
                        <Trash2 className="w-3.5 h-3.5 text-rose-400" />
                        <span>🧹 Clear Database / Reset Inventaris</span>
                      </button>
                    </div>
                  </div>
                </form>

                {/* Animated Real-Time Scan Progress Bar */}
                {scanProgress && scanProgress.status !== 'idle' && (
                  <div
                    role="region"
                    aria-label="Subnet Scan Progress"
                    className="mt-4 p-3.5 rounded-lg bg-[#0B0F17] border border-[#1E293B] space-y-2"
                  >
                    <div className="flex flex-wrap items-center justify-between gap-2 text-xs">
                      <span className="font-mono text-slate-200">
                        {scanProgress.status === 'running'
                          ? scanProgress.currentPhase
                          : scanProgress.message}
                      </span>
                      <span className="font-mono tabular-nums text-emerald-400 font-semibold">
                        {scanProgress.scannedHosts} / {scanProgress.totalHosts} IP ({scanProgress.progressPct}%) ·{' '}
                        {lang === 'id' ? 'Host Aktif:' : 'Live Hosts:'} {scanProgress.discoveredCount}
                      </span>
                    </div>

                    <div className="w-full h-2 bg-slate-800 rounded-full overflow-hidden">
                      <div
                        className="h-full bg-emerald-500 transition-all duration-300 ease-out"
                        style={{ width: `${Math.min(100, Math.max(2, scanProgress.progressPct))}%` }}
                      />
                    </div>

                    {scanProgress.discoveredHosts.length > 0 && (
                      <div className="text-[11px] font-mono text-cyan-400 truncate">
                        {lang === 'id' ? 'Terdeteksi:' : 'Discovered:'}{' '}
                        {scanProgress.discoveredHosts.join(' · ')}
                      </div>
                    )}
                  </div>
                )}

                {scanError && (
                  <p role="alert" className="text-xs text-rose-400 mt-2.5">
                    {scanError}
                  </p>
                )}
                {scanMessage && !isScanning && (
                  <p role="status" className="text-xs text-emerald-400 mt-2.5">
                    {scanMessage}
                  </p>
                )}
              </section>

              {/* Asset Inventory & Remote Push Deployment Table */}
              <section className="bg-[#161F30] border border-[#1E293B] rounded-xl p-5 space-y-4">
                <div className="flex flex-col xl:flex-row xl:items-center justify-between gap-4 pb-4 border-b border-[#1E293B]">
                  <div>
                    <h2 className="text-base font-semibold text-white">
                      {lang === 'id'
                        ? 'Inventaris Aset TI Real-Time (Polling /api/v1/devices setiap 5 detik)'
                        : 'Real-Time IT Asset Inventory (Polling /api/v1/devices every 5s)'}
                    </h2>
                    <p className="text-xs text-slate-400 mt-0.5">
                      {lang === 'id'
                        ? 'Menampilkan perangkat nyata yang merespons di jaringan lokal atau mengirim telemetri agen ke PostgreSQL (vectranet_rmm).'
                        : 'Displays real devices responding on the local network or sending agent telemetry to PostgreSQL (vectranet_rmm).'}
                    </p>
                  </div>

                  <div className="flex flex-wrap items-center gap-2.5">
                    <div className="relative">
                      <Search className="w-3.5 h-3.5 text-slate-400 absolute left-3 top-1/2 -translate-y-1/2" />
                      <input
                        type="search"
                        aria-label="Search Hostname, IP, MAC, or OS"
                        value={searchQuery}
                        onChange={(e) => {
                          setSearchQuery(e.target.value);
                          setCurrentPage(1);
                        }}
                        placeholder={
                          lang === 'id'
                            ? 'Cari Hostname, IP, MAC, OS...'
                            : 'Search Hostname, IP, MAC, OS...'
                        }
                        className="pl-8 pr-3 py-1.5 text-xs bg-[#0B0F17] border border-[#1E293B] rounded-lg text-slate-100 placeholder-slate-500 focus:outline-none focus:border-emerald-500"
                      />
                    </div>

                    {/* OS Type Dropdown Filter */}
                    <select
                      id="os-type-filter"
                      aria-label="Filter by OS Type"
                      value={osFilter}
                      onChange={(e) => {
                        setOsFilter(e.target.value);
                        setCurrentPage(1);
                      }}
                      className="px-3 py-1.5 text-xs bg-[#0B0F17] border border-[#1E293B] rounded-lg text-slate-200 focus:outline-none focus:border-emerald-500 cursor-pointer"
                    >
                      <option value="all">
                        {lang === 'id' ? 'Semua OS (All)' : 'All OS Types'}
                      </option>
                      <option value="windows">Windows (Server / 11 / 10)</option>
                      <option value="linux">Linux (Ubuntu / RHEL / Debian)</option>
                      <option value="macos">macOS (Apple Silicon / Intel)</option>
                      <option value="network">Network OS (Cisco / MikroTik)</option>
                    </select>

                    {/* Interactive Filter Buttons */}
                    <div className="flex items-center gap-1 bg-[#0B0F17] p-1 rounded-lg border border-[#1E293B]">
                      {(['all', 'active', 'agentless', 'snmp-only'] as const).map(
                        (af) => (
                          <button
                            key={af}
                            type="button"
                            onClick={() => {
                              setAgentFilter(af);
                              setCurrentPage(1);
                            }}
                            className={`px-2.5 py-1 text-xs font-medium rounded transition-colors whitespace-nowrap cursor-pointer ${
                              agentFilter === af
                                ? 'bg-emerald-500/20 text-emerald-300 border border-emerald-500/40'
                                : 'text-slate-400 hover:text-slate-200'
                            }`}
                          >
                            {af === 'all'
                              ? lang === 'id'
                                ? 'Semua'
                                : 'All'
                              : af === 'active'
                              ? 'Native Agent'
                              : af === 'agentless'
                              ? 'Agentless'
                              : 'SNMPv3'}
                          </button>
                        )
                      )}
                    </div>

                    <button
                      type="button"
                      onClick={() => void fetchAgentlessIcmpPing()}
                      title="Real-Time Agentless ICMP Ping Status (Updates every 10s)"
                      className="px-2.5 py-1.5 text-xs font-mono text-slate-300 hover:text-white bg-[#0B0F17] border border-[#1E293B] rounded-lg transition-colors flex items-center gap-1.5 whitespace-nowrap cursor-pointer"
                    >
                      <Wifi
                        className={`w-3.5 h-3.5 text-emerald-400 ${
                          isIcmpSweeping ? 'animate-pulse' : ''
                        }`}
                      />
                      <span>ICMP 10s ({lastIcmpSweepAt})</span>
                    </button>

                    {selectedDeviceIds.length > 0 && (
                      <button
                        type="button"
                        onClick={() => handleOpenDeployModal(selectedDeviceIds)}
                        className="px-3.5 py-1.5 text-xs font-semibold bg-emerald-500 hover:bg-emerald-400 text-slate-950 rounded-lg transition-colors flex items-center gap-1.5 whitespace-nowrap cursor-pointer"
                      >
                        <Rocket className="w-3.5 h-3.5" />
                        {lang === 'id'
                          ? `Push Deploy Terpilih (${selectedDeviceIds.length})`
                          : `Push Selected (${selectedDeviceIds.length})`}
                      </button>
                    )}
                  </div>
                </div>

                {/* High-Density Data Table */}
                <div className="overflow-x-auto">
                  <table className="w-full text-left text-xs">
                    <thead className="border-b border-[#1E293B] text-slate-400">
                      <tr>
                        <th className="py-2.5 px-3 w-8">
                          <span className="sr-only">Pilih</span>
                        </th>
                        <th
                          className="py-2.5 px-3"
                          aria-sort={
                            sortField === 'hostname'
                              ? sortDirection === 'asc'
                                ? 'ascending'
                                : 'descending'
                              : 'none'
                          }
                        >
                          <button
                            type="button"
                            onClick={() => handleSortColumn('hostname')}
                            className="inline-flex items-center gap-1.5 font-semibold text-slate-300 hover:text-white transition-colors cursor-pointer whitespace-nowrap"
                          >
                            <span>Hostname &amp; Lokasi</span>
                            {sortField === 'hostname' ? (
                              sortDirection === 'asc' ? (
                                <ArrowUp className="w-3.5 h-3.5 text-emerald-400" />
                              ) : (
                                <ArrowDown className="w-3.5 h-3.5 text-emerald-400" />
                              )
                            ) : (
                              <ArrowUpDown className="w-3.5 h-3.5 text-slate-500" />
                            )}
                          </button>
                        </th>
                        <th
                          className="py-2.5 px-3"
                          aria-sort={
                            sortField === 'ip'
                              ? sortDirection === 'asc'
                                ? 'ascending'
                                : 'descending'
                              : 'none'
                          }
                        >
                          <button
                            type="button"
                            onClick={() => handleSortColumn('ip')}
                            className="inline-flex items-center gap-1.5 font-semibold text-slate-300 hover:text-white transition-colors cursor-pointer whitespace-nowrap"
                          >
                            <span>IPv4 &amp; MAC</span>
                            {sortField === 'ip' ? (
                              sortDirection === 'asc' ? (
                                <ArrowUp className="w-3.5 h-3.5 text-emerald-400" />
                              ) : (
                                <ArrowDown className="w-3.5 h-3.5 text-emerald-400" />
                              )
                            ) : (
                              <ArrowUpDown className="w-3.5 h-3.5 text-slate-500" />
                            )}
                          </button>
                        </th>
                        <th className="py-2.5 px-3">Sistem Operasi</th>
                        <th
                          className="py-2.5 px-3"
                          aria-sort={
                            sortField === 'status'
                              ? sortDirection === 'asc'
                                ? 'ascending'
                                : 'descending'
                              : 'none'
                          }
                        >
                          <button
                            type="button"
                            onClick={() => handleSortColumn('status')}
                            className="inline-flex items-center gap-1.5 font-semibold text-slate-300 hover:text-white transition-colors cursor-pointer whitespace-nowrap"
                          >
                            <span>Status &amp; Kolektor</span>
                            {sortField === 'status' ? (
                              sortDirection === 'asc' ? (
                                <ArrowUp className="w-3.5 h-3.5 text-emerald-400" />
                              ) : (
                                <ArrowDown className="w-3.5 h-3.5 text-emerald-400" />
                              )
                            ) : (
                              <ArrowUpDown className="w-3.5 h-3.5 text-slate-500" />
                            )}
                          </button>
                        </th>
                        <th className="py-2.5 px-3 text-right">CPU / RAM</th>
                        <th className="py-2.5 px-3 text-right">Aksi Deployment</th>
                      </tr>
                    </thead>
                    <tbody className="divide-y divide-[#1E293B]">
                      {pagination.pageItems.length === 0 ? (
                        <tr>
                          <td colSpan={7} className="py-10 px-4 text-center">
                            <div className="max-w-lg mx-auto space-y-2">
                              <div className="text-sm font-semibold text-slate-200">
                                {lang === 'id'
                                  ? 'Zero-State: Belum Ada Perangkat Terdeteksi di Database'
                                  : 'Zero-State: No Devices Discovered in Database Yet'}
                              </div>
                              <p className="text-xs text-slate-400 leading-relaxed">
                                {lang === 'id'
                                  ? 'Tabel inventaris saat ini kosong ([]). Klik "Pindai Subnet Sekarang" untuk memindai jaringan lokal Anda secara nyata, atau jalankan agen Go lokal yang mengarah ke /api/v1/agent/ingest.'
                                  : 'The inventory table is currently empty ([]). Click "Scan Subnet Now" to probe your real local network, or start a local Go agent pointing to /api/v1/agent/ingest.'}
                              </p>
                            </div>
                          </td>
                        </tr>
                      ) : (
                        pagination.pageItems.map((dev) => {
                          const isChecked = selectedDeviceIds.includes(dev.id);
                          const isAgentActive = dev.agentState === 'active';
                          const cpuVal = isAgentActive ? dev.cpuUsagePct : 0;
                          const ramUsedVal = isAgentActive ? dev.ramUsedGb : 0;
                          const ramTotalVal = isAgentActive ? dev.ramTotalGb : 0;
                          const ramPct =
                            isAgentActive && ramTotalVal > 0
                              ? Math.round((ramUsedVal / ramTotalVal) * 100)
                              : 0;

                          return (
                            <tr
                              key={dev.id}
                              className="hover:bg-[#0B0F17]/60 transition-colors"
                            >
                              <td className="py-3 px-3">
                                <input
                                  type="checkbox"
                                  aria-label={`Select ${dev.hostname}`}
                                  checked={isChecked}
                                  onChange={() => handleToggleSelectDevice(dev.id)}
                                  className="w-3.5 h-3.5 accent-emerald-500 cursor-pointer"
                                />
                              </td>

                              <td className="py-3 px-3">
                                <div className="font-semibold text-slate-100">
                                  {dev.hostname}
                                </div>
                                <div className="text-[11px] text-slate-400">
                                  {dev.location} · {dev.lastSeen}
                                </div>
                              </td>

                              <td className="py-3 px-3 font-mono tabular-nums">
                                <div className="text-slate-200">{dev.ipAddress}</div>
                                <div className="text-[11px] text-slate-400">
                                  {dev.macAddress}
                                </div>
                              </td>

                              <td className="py-3 px-3">
                                <div className="text-slate-200">{dev.os}</div>
                                <div className="text-[11px] text-slate-400 font-mono">
                                  {dev.osVersion}
                                </div>
                              </td>

                              <td className="py-3 px-3">
                                {dev.agentState === 'agentless' ? (
                                  (() => {
                                    const icmp = formatIcmpPingStatus(
                                      icmpPingMap[dev.id],
                                      dev.latencyMs,
                                      dev.status
                                    );
                                    return (
                                      <div
                                        data-testid={`agentless-icmp-status-${dev.id}`}
                                        className="space-y-0.5"
                                      >
                                        <div className="flex items-center gap-1.5">
                                          {icmp.alive ? (
                                            <Wifi
                                              aria-label="ICMP Ping Reachable (Green)"
                                              className="w-3.5 h-3.5 text-emerald-400 shrink-0"
                                            />
                                          ) : (
                                            <WifiOff
                                              aria-label="ICMP Ping Unreachable (Red)"
                                              className="w-3.5 h-3.5 text-rose-400 shrink-0"
                                            />
                                          )}
                                          <span
                                            className={
                                              icmp.alive
                                                ? 'text-emerald-400 font-semibold font-mono'
                                                : 'text-rose-400 font-semibold font-mono'
                                            }
                                          >
                                            {lang === 'id' ? icmp.labelId : icmp.labelEn}
                                          </span>
                                          <span className="text-slate-500">·</span>
                                          <span className="font-mono text-slate-300">
                                            Agentless
                                          </span>
                                        </div>
                                        <div className="text-[11px] font-mono text-slate-400 flex items-center gap-1.5">
                                          {icmp.alive ? (
                                            <CheckCircle2 className="w-3 h-3 text-emerald-400 shrink-0" />
                                          ) : (
                                            <XCircle className="w-3 h-3 text-rose-400 shrink-0" />
                                          )}
                                          <span>
                                            {icmp.method} · Poll 10s ({icmp.lastPingedAt})
                                          </span>
                                        </div>
                                      </div>
                                    );
                                  })()
                                ) : (
                                  <div className="flex items-center gap-1.5">
                                    {dev.status === 'warning' ? (
                                      <AlertTriangle className="w-3.5 h-3.5 text-rose-400 shrink-0" />
                                    ) : (
                                      <CheckCircle2 className="w-3.5 h-3.5 text-emerald-400 shrink-0" />
                                    )}
                                    <span
                                      className={
                                        dev.status === 'warning'
                                          ? 'text-rose-400 font-medium'
                                          : 'text-emerald-400 font-medium'
                                      }
                                    >
                                      {dev.status.toUpperCase()}
                                    </span>
                                    <span className="text-slate-500">·</span>
                                    <span className="font-mono text-slate-300">
                                      {dev.agentState === 'active'
                                        ? `Agent ${dev.agentVersion} (${dev.agentMemoryMb}MB)`
                                        : 'SNMPv3 Poll'}
                                    </span>
                                  </div>
                                )}
                              </td>

                              <td className="py-3 px-3 text-right font-mono tabular-nums">
                                <div
                                  className={
                                    !isAgentActive
                                      ? 'text-slate-500'
                                      : cpuVal > 80
                                      ? 'text-rose-400 font-semibold'
                                      : 'text-slate-200'
                                  }
                                >
                                  CPU {cpuVal}%
                                </div>
                                <div className="text-[11px] text-slate-400">
                                  RAM {ramPct}% ({ramUsedVal}/{ramTotalVal}GB)
                                </div>
                              </td>

                              <td className="py-3 px-3 text-right">
                                <div className="inline-flex items-center justify-end gap-2">
                                  <button
                                    type="button"
                                    aria-label={`Inspect Heartbeat and Details for ${dev.hostname}`}
                                    onClick={() => setInspectDevice(dev)}
                                    className="px-2.5 py-1.5 text-xs font-medium text-slate-200 hover:text-white bg-[#0B0F17] border border-[#1E293B] hover:border-emerald-500/50 rounded-lg transition-colors inline-flex items-center gap-1.5 whitespace-nowrap cursor-pointer"
                                  >
                                    <Activity className="w-3.5 h-3.5 text-emerald-400" />
                                    <Eye className="w-3.5 h-3.5 text-slate-400" />
                                    <span>Heartbeat &amp; Detail</span>
                                  </button>

                                  {dev.agentState === 'agentless' ? (
                                    <button
                                      type="button"
                                      onClick={() => handleOpenDeployModal([dev.id])}
                                      className="px-3 py-1.5 text-xs font-semibold bg-emerald-500 hover:bg-emerald-400 text-slate-950 rounded-lg transition-colors inline-flex items-center gap-1 whitespace-nowrap cursor-pointer"
                                    >
                                      <Rocket className="w-3.5 h-3.5" />
                                      <span>Deploy Agent</span>
                                    </button>
                                  ) : (
                                    <span className="px-2.5 py-1.5 text-xs font-mono text-emerald-400 inline-flex items-center gap-1 whitespace-nowrap shrink-0">
                                      <ShieldCheck className="w-3.5 h-3.5 shrink-0" />
                                      <span>
                                        {dev.agentState === 'active'
                                          ? 'Agent Active'
                                          : 'SNMPv3 Synced'}
                                      </span>
                                    </span>
                                  )}
                                </div>
                              </td>
                            </tr>
                          );
                        })
                      )}
                    </tbody>
                  </table>
                </div>

                {/* Pagination & Page Size Control Bar (25, 50, 100, 200, 500 + <, >, and Page Numbers) */}
                <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-4 pt-3 border-t border-[#1E293B] text-xs">
                  <div className="flex flex-wrap items-center gap-3 text-slate-400">
                    <div className="flex items-center gap-2">
                      <label
                        htmlFor="inventory-page-size"
                        className="text-slate-300 font-medium whitespace-nowrap"
                      >
                        {lang === 'id' ? 'Maksimal Data:' : 'Show Rows:'}
                      </label>
                      <select
                        id="inventory-page-size"
                        aria-label="Maksimal Data per Halaman"
                        value={pageSize}
                        onChange={(e) => {
                          setPageSize(Number(e.target.value));
                          setCurrentPage(1);
                        }}
                        className="px-2.5 py-1.5 font-mono tabular-nums bg-[#0B0F17] border border-[#1E293B] rounded-lg text-slate-100 focus:outline-none focus:border-emerald-500 cursor-pointer"
                      >
                        {INVENTORY_PAGE_SIZE_OPTIONS.map((size) => (
                          <option key={size} value={size}>
                            {size}
                          </option>
                        ))}
                      </select>
                    </div>

                    <span className="text-slate-500">·</span>

                    <span className="font-mono tabular-nums text-slate-300">
                      {lang === 'id'
                        ? `Menampilkan ${pagination.startIndex}–${pagination.endIndex} dari ${pagination.totalItems} perangkat (Hal. ${pagination.currentPage}/${pagination.totalPages})`
                        : `Showing ${pagination.startIndex}–${pagination.endIndex} of ${pagination.totalItems} devices (Page ${pagination.currentPage}/${pagination.totalPages})`}
                    </span>
                  </div>

                  {/* Page Navigation Controls: <, Page Numbers, > */}
                  <nav
                    aria-label="Inventory Table Pagination"
                    className="flex items-center gap-1.5 font-mono tabular-nums"
                  >
                    <button
                      type="button"
                      aria-label="Previous Page"
                      disabled={pagination.currentPage <= 1}
                      onClick={() =>
                        setCurrentPage((p) => Math.max(1, p - 1))
                      }
                      className="px-3 py-1.5 rounded-lg bg-[#0B0F17] border border-[#1E293B] text-slate-200 hover:text-white hover:border-emerald-500/50 disabled:opacity-40 disabled:pointer-events-none transition-colors inline-flex items-center justify-center font-bold cursor-pointer"
                    >
                      &lt;
                    </button>

                    {pagination.pageNumbers[0] > 1 && (
                      <>
                        <button
                          type="button"
                          onClick={() => setCurrentPage(1)}
                          className="px-2.5 py-1.5 rounded-lg bg-[#0B0F17] border border-[#1E293B] text-slate-300 hover:text-white transition-colors cursor-pointer"
                        >
                          1
                        </button>
                        {pagination.pageNumbers[0] > 2 && (
                          <span className="px-1 text-slate-500">…</span>
                        )}
                      </>
                    )}

                    {pagination.pageNumbers.map((pageNum) => {
                      const isCurrent = pageNum === pagination.currentPage;
                      return (
                        <button
                          key={pageNum}
                          type="button"
                          aria-label={`Page ${pageNum}`}
                          aria-current={isCurrent ? 'page' : undefined}
                          onClick={() => setCurrentPage(pageNum)}
                          className={`px-3 py-1.5 rounded-lg border transition-colors cursor-pointer ${
                            isCurrent
                              ? 'bg-emerald-500 text-slate-950 font-bold border-emerald-400'
                              : 'bg-[#0B0F17] border-[#1E293B] text-slate-300 hover:text-white hover:border-slate-700'
                          }`}
                        >
                          {pageNum}
                        </button>
                      );
                    })}

                    {pagination.pageNumbers[pagination.pageNumbers.length - 1] <
                      pagination.totalPages && (
                      <>
                        {pagination.pageNumbers[pagination.pageNumbers.length - 1] <
                          pagination.totalPages - 1 && (
                          <span className="px-1 text-slate-500">…</span>
                        )}
                        <button
                          type="button"
                          onClick={() => setCurrentPage(pagination.totalPages)}
                          className="px-2.5 py-1.5 rounded-lg bg-[#0B0F17] border border-[#1E293B] text-slate-300 hover:text-white transition-colors cursor-pointer"
                        >
                          {pagination.totalPages}
                        </button>
                      </>
                    )}

                    <button
                      type="button"
                      aria-label="Next Page"
                      disabled={pagination.currentPage >= pagination.totalPages}
                      onClick={() =>
                        setCurrentPage((p) =>
                          Math.min(pagination.totalPages, p + 1)
                        )
                      }
                      className="px-3 py-1.5 rounded-lg bg-[#0B0F17] border border-[#1E293B] text-slate-200 hover:text-white hover:border-emerald-500/50 disabled:opacity-40 disabled:pointer-events-none transition-colors inline-flex items-center justify-center font-bold cursor-pointer"
                    >
                      &gt;
                    </button>
                  </nav>
                </div>
              </section>
            </div>
          )}

          {activeTab === 'topology' && (
            <TopologyView
              devices={devices}
              lang={lang}
              onOpenDeployModal={handleOpenDeployModal}
            />
          )}

          {activeTab === 'vault' && (
            <CredentialVaultView
              credentials={credentials}
              lang={lang}
              onAddCredential={(entry) => void handleAddCredential(entry)}
              onRotateKey={handleRotateCredentialKey}
              onDeleteCredential={(id) => void handleDeleteCredential(id)}
            />
          )}

          {activeTab === 'health' && (
            <SystemHealthLogsView
              devices={devices}
              logs={logs}
              metrics={metrics}
              config={engineConfig}
              lang={lang}
              onEmitTestIngest={() => void handleEmitTestIngest()}
            />
          )}

          {activeTab === 'admin' && (
            <AdminConfigView
              users={adminUsers}
              config={engineConfig}
              lang={lang}
              deviceCount={devices.length}
              onAddUser={(u) => setAdminUsers((prev) => [u, ...prev])}
              onToggleUserStatus={(id) =>
                setAdminUsers((prev) =>
                  prev.map((u) =>
                    u.id === id
                      ? {
                          ...u,
                          status: u.status === 'Active' ? 'Suspended' : 'Active',
                        }
                      : u
                  )
                )
              }
              onUpdateConfig={setEngineConfig}
              onClearDatabase={() => void handleClearDatabase()}
            />
          )}

          {activeTab === 'blueprints' && <BlueprintDocsView lang={lang} />}
        </main>
      </div>

      {/* Modals */}
      <PushDeployModal
        isOpen={isDeployModalOpen}
        targetDevices={deployTargets}
        credentials={credentials}
        lang={lang}
        onClose={() => setIsDeployModalOpen(false)}
        onConfirmDeploy={(targetIds, credId, targetDevs) =>
          handleConfirmDeploy(targetIds, credId, targetDevs)
        }
      />

      <DeviceDetailModal
        device={inspectDevice}
        lang={lang}
        onClose={() => setInspectDevice(null)}
      />
    </div>
  );
}

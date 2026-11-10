import React, { useState, useMemo } from 'react';
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
} from 'lucide-react';
import {
  AdminUserEntry,
  AgentState,
  CredentialVaultEntry,
  DeviceAsset,
  DeviceStatus,
  EngineConfigState,
  NotificationItem,
  SystemLogEntry,
} from './types/network';
import {
  INITIAL_ADMIN_USERS,
  INITIAL_CREDENTIALS,
  INITIAL_DEVICES,
  INITIAL_ENGINE_CONFIG,
  INITIAL_LOGS,
  INITIAL_NOTIFICATIONS,
} from './data/seedNetworkData';
import {
  applyAgentDeployment,
  computeFleetSummary,
  filterDevices,
  parseCidrRange,
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

export default function App() {
  const [activeTab, setActiveTab] = useState<ActiveTab>('inventory');
  const [lang, setLang] = useState<'id' | 'en'>('id');

  const [devices, setDevices] = useState<DeviceAsset[]>(INITIAL_DEVICES);
  const [credentials, setCredentials] =
    useState<CredentialVaultEntry[]>(INITIAL_CREDENTIALS);
  const [logs, setLogs] = useState<SystemLogEntry[]>(INITIAL_LOGS);
  const [notifications, setNotifications] =
    useState<NotificationItem[]>(INITIAL_NOTIFICATIONS);
  const [adminUsers, setAdminUsers] =
    useState<AdminUserEntry[]>(INITIAL_ADMIN_USERS);
  const [engineConfig, setEngineConfig] =
    useState<EngineConfigState>(INITIAL_ENGINE_CONFIG);

  // Inventory filters & selection
  const [searchQuery, setSearchQuery] = useState('');
  const [statusFilter, setStatusFilter] = useState<'all' | DeviceStatus>('all');
  const [agentFilter, setAgentFilter] = useState<'all' | AgentState>('all');
  const [selectedDeviceIds, setSelectedDeviceIds] = useState<string[]>([
    'dev-srv-03',
    'dev-srv-04',
  ]);

  // Subnet CIDR Scanner state
  const [scanCidrInput, setScanCidrInput] = useState('10.24.10.0/24');
  const [scanMessage, setScanMessage] = useState<string | null>(null);
  const [scanError, setScanError] = useState<string | null>(null);

  // Modals & Drawers
  const [deployTargetIds, setDeployTargetIds] = useState<string[]>([]);
  const [isDeployModalOpen, setIsDeployModalOpen] = useState(false);
  const [inspectDevice, setInspectDevice] = useState<DeviceAsset | null>(null);
  const [isNotifOpen, setIsNotifOpen] = useState(false);

  const fleetSummary = useMemo(() => computeFleetSummary(devices), [devices]);

  const filteredDevices = useMemo(
    () =>
      filterDevices(devices, {
        query: searchQuery,
        statusFilter,
        agentFilter,
      }),
    [devices, searchQuery, statusFilter, agentFilter]
  );

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

  const handleConfirmDeploy = (targetIds: string[], credentialId: string) => {
    const cred = credentials.find((c) => c.id === credentialId);
    setDevices((prev) => applyAgentDeployment(prev, targetIds, 'v2.4.1-go'));

    const deployedNames = devices
      .filter((d) => targetIds.includes(d.id))
      .map((d) => d.hostname)
      .join(', ');

    const nowStamp = new Date().toTimeString().slice(0, 8) + '.420';
    setLogs((prev) => [
      {
        id: `log-${Date.now()}`,
        timestamp: nowStamp,
        level: 'INFO',
        module: cred?.protocol.includes('WinRM') ? 'PUSH-WINRM' : 'PUSH-SSH',
        deviceHostname: deployedNames,
        message: `Remote Agent Push v2.4.1-go succeeded (${targetIds.length} endpoints) using Vault key ${cred?.keyFingerprint}`,
        latencyMs: 18.4,
      },
      ...prev,
    ]);

    setNotifications((prev) => [
      {
        id: `notif-${Date.now()}`,
        timestamp: 'Just now',
        severity: 'success',
        titleId: `Push Deployment Berhasil (${targetIds.length} Host)`,
        titleEn: `Push Deployment Succeeded (${targetIds.length} Hosts)`,
        descId: `Agen Go v2.4.1 aktif pada: ${deployedNames}. Memory cap: ${engineConfig.maxAgentRamMb} MB.`,
        descEn: `Go Agent v2.4.1 active on: ${deployedNames}. Memory cap: ${engineConfig.maxAgentRamMb} MB.`,
        read: false,
      },
      ...prev,
    ]);

    setSelectedDeviceIds((prev) => prev.filter((id) => !targetIds.includes(id)));
  };

  const handleRunSubnetScan = (e: React.FormEvent) => {
    e.preventDefault();
    setScanError(null);
    setScanMessage(null);

    const parsed = parseCidrRange(scanCidrInput);
    if (!parsed.valid) {
      setScanError(parsed.error || 'Format CIDR tidak valid');
      return;
    }

    const octetPrefix = parsed.networkAddress.split('.').slice(0, 3).join('.');
    const randomHost = Math.floor(110 + (devices.length * 17) % 120);
    const newIp = `${octetPrefix}.${randomHost}`;
    const newHost = `SRV-AUTO-NODE${devices.length + 1}`;

    const newDevice: DeviceAsset = {
      id: `dev-scan-${Date.now()}`,
      hostname: newHost,
      ipAddress: newIp,
      macAddress: `00:15:5D:8A:${randomHost.toString(16).toUpperCase().padStart(2, '0')}:F1`,
      os: 'Ubuntu Linux',
      osVersion: '24.04 LTS',
      kernelArch: '6.8.0-generic x86_64',
      role: 'server',
      status: 'online',
      agentState: 'agentless',
      cpuModel: 'AMD EPYC 7543P',
      cpuCores: 8,
      cpuUsagePct: 24,
      ramTotalGb: 32,
      ramUsedGb: 9.8,
      diskTotalGb: 512,
      diskUsedGb: 124.0,
      lastSeen: 'Baru ditemukan / Just discovered',
      subnet: scanCidrInput.trim(),
      location: 'DC-Jakarta-AutoSweep',
      uplinkDeviceId: 'dev-sw-01',
      uplinkPort: 'eth0 -> ether19',
      latencyMs: 1.5,
      interfaces: [
        {
          id: `if-scan-${Date.now()}`,
          name: 'eth0',
          ipAddress: newIp,
          macAddress: `00:15:5D:8A:${randomHost.toString(16).toUpperCase().padStart(2, '0')}:F1`,
          speedMbps: 10000,
          vlan: 10,
          rxMbps: 84.2,
          txMbps: 61.5,
          isPrimary: true,
        },
      ],
      software: [
        {
          name: 'OpenSSH Server',
          version: '9.6p1',
          publisher: 'OpenBSD',
          installDate: '2026-10-01',
        },
      ],
    };

    setDevices((prev) => [newDevice, ...prev]);
    setSelectedDeviceIds((prev) => [newDevice.id, ...prev]);

    setScanMessage(
      lang === 'id'
        ? `Sweep CIDR ${scanCidrInput} selesai (${parsed.estimatedHosts} IP dipindai dengan ${engineConfig.maxScannerGoroutines} goroutine): ditemukan host agentless baru ${newHost} (${newIp}).`
        : `CIDR Sweep ${scanCidrInput} completed (${parsed.estimatedHosts} IPs scanned via ${engineConfig.maxScannerGoroutines} goroutines): discovered new agentless host ${newHost} (${newIp}).`
    );

    setLogs((prev) => [
      {
        id: `log-scan-${Date.now()}`,
        timestamp: new Date().toTimeString().slice(0, 8) + '.112',
        level: 'INFO',
        module: 'SWEEPER-ICMP',
        deviceHostname: newHost,
        message: `Discovered host ${newIp} on ${scanCidrInput} (TCP 22/SSH open, RTT 1.5ms)`,
        latencyMs: 1.5,
      },
      ...prev,
    ]);
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

  const handleEmitTestIngest = () => {
    const sampleDev = devices[0];
    setLogs((prev) => [
      {
        id: `log-ingest-${Date.now()}`,
        timestamp: new Date().toTimeString().slice(0, 8) + '.804',
        level: 'INFO',
        module: 'INGEST-TLS',
        deviceHostname: sampleDev.hostname,
        message: `POST /api/v1/agent/ingest TLS 1.3 Gzip frame (1.58 KB) stored in TimescaleDB chunk`,
        latencyMs: 1.7,
      },
      ...prev,
    ]);
  };

  const deployTargets = useMemo(
    () => devices.filter((d) => deployTargetIds.includes(d.id)),
    [devices, deployTargetIds]
  );

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
                {notifications.map((n) => (
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
                ))}
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
              {/* Concurrent IP Subnet Sweeper Bar */}
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
                      <Radar className="w-4 h-4 text-emerald-400" />
                      {lang === 'id'
                        ? 'Pemindai Subnet IP Konkuren & Sinkronisasi Active Directory (Golang Goroutine Sweeper)'
                        : 'Concurrent CIDR IP Sweeper & Active Directory Sync (Golang Goroutine Sweeper)'}
                    </label>
                    <p className="text-xs text-slate-400 mb-2">
                      {lang === 'id'
                        ? 'Memindai rentang CIDR secara paralel (ICMP + ARP + TCP Port 22/161/445/5986) untuk menemukan host tanpa agen.'
                        : 'Concurrently sweeps CIDR subnets (ICMP + ARP + TCP 22/161/445/5986) to discover agentless endpoints.'}
                    </p>
                    <div className="flex flex-col sm:flex-row gap-2.5">
                      <input
                        id="cidr-scan-input"
                        type="text"
                        value={scanCidrInput}
                        onChange={(e) => setScanCidrInput(e.target.value)}
                        placeholder="10.24.10.0/24"
                        className="flex-1 px-3.5 py-2 text-sm font-mono bg-[#0B0F17] border border-[#1E293B] rounded-lg text-slate-100 focus:outline-none focus:border-emerald-500"
                      />
                      <button
                        type="submit"
                        className="px-4 py-2 text-xs font-semibold bg-emerald-500 hover:bg-emerald-400 text-slate-950 rounded-lg transition-colors flex items-center justify-center gap-2 whitespace-nowrap cursor-pointer"
                      >
                        <Radar className="w-4 h-4" />
                        {lang === 'id' ? 'Pindai Subnet Sekarang' : 'Scan Subnet Now'}
                      </button>
                    </div>
                  </div>
                </form>

                {scanError && (
                  <p role="alert" className="text-xs text-rose-400 mt-2.5">
                    {scanError}
                  </p>
                )}
                {scanMessage && (
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
                        ? 'Inventaris Aset TI & Tabel Remote Push Deployment'
                        : 'IT Asset Inventory & Remote Push Deployment Table'}
                    </h2>
                    <p className="text-xs text-slate-400 mt-0.5">
                      {lang === 'id'
                        ? 'Pilih host Agentless untuk menginstal agen native secara silent melalui WinRM atau SSH.'
                        : 'Select agentless endpoints to silently push the native Go agent via WinRM or SSH.'}
                    </p>
                  </div>

                  <div className="flex flex-wrap items-center gap-2.5">
                    <div className="relative">
                      <Search className="w-3.5 h-3.5 text-slate-400 absolute left-3 top-1/2 -translate-y-1/2" />
                      <input
                        type="search"
                        aria-label="Search Hostname, IP, MAC, or OS"
                        value={searchQuery}
                        onChange={(e) => setSearchQuery(e.target.value)}
                        placeholder={
                          lang === 'id'
                            ? 'Cari Hostname, IP, MAC, OS...'
                            : 'Search Hostname, IP, MAC, OS...'
                        }
                        className="pl-8 pr-3 py-1.5 text-xs bg-[#0B0F17] border border-[#1E293B] rounded-lg text-slate-100 placeholder-slate-500 focus:outline-none focus:border-emerald-500"
                      />
                    </div>

                    {/* Interactive Filter Buttons */}
                    <div className="flex items-center gap-1 bg-[#0B0F17] p-1 rounded-lg border border-[#1E293B]">
                      {(['all', 'active', 'agentless', 'snmp-only'] as const).map(
                        (af) => (
                          <button
                            key={af}
                            type="button"
                            onClick={() => setAgentFilter(af)}
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
                        <th className="py-2.5 px-3">Hostname &amp; Lokasi</th>
                        <th className="py-2.5 px-3">IPv4 &amp; MAC</th>
                        <th className="py-2.5 px-3">Sistem Operasi</th>
                        <th className="py-2.5 px-3">Status &amp; Kolektor</th>
                        <th className="py-2.5 px-3 text-right">CPU / RAM</th>
                        <th className="py-2.5 px-3 text-right">Aksi Deployment</th>
                      </tr>
                    </thead>
                    <tbody className="divide-y divide-[#1E293B]">
                      {filteredDevices.map((dev) => {
                        const isChecked = selectedDeviceIds.includes(dev.id);
                        const ramPct = Math.round(
                          (dev.ramUsedGb / Math.max(1, dev.ramTotalGb)) * 100
                        );

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
                                    : dev.agentState === 'snmp-only'
                                    ? 'SNMPv3 Poll'
                                    : 'Agentless'}
                                </span>
                              </div>
                            </td>

                            <td className="py-3 px-3 text-right font-mono tabular-nums">
                              <div
                                className={
                                  dev.cpuUsagePct > 80
                                    ? 'text-rose-400 font-semibold'
                                    : 'text-slate-200'
                                }
                              >
                                CPU {dev.cpuUsagePct}%
                              </div>
                              <div className="text-[11px] text-slate-400">
                                RAM {ramPct}% ({dev.ramUsedGb}/{dev.ramTotalGb}GB)
                              </div>
                            </td>

                            <td className="py-3 px-3 text-right">
                              <div className="inline-flex items-center justify-end gap-2">
                                <button
                                  type="button"
                                  onClick={() => setInspectDevice(dev)}
                                  className="px-2.5 py-1.5 text-xs font-medium text-slate-300 hover:text-white bg-[#0B0F17] border border-[#1E293B] rounded-lg transition-colors inline-flex items-center gap-1 whitespace-nowrap cursor-pointer"
                                >
                                  <Eye className="w-3.5 h-3.5" />
                                  <span>Detail</span>
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
                      })}
                    </tbody>
                  </table>
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
              onAddCredential={(entry) =>
                setCredentials((prev) => [entry, ...prev])
              }
              onRotateKey={handleRotateCredentialKey}
              onDeleteCredential={(id) =>
                setCredentials((prev) => prev.filter((c) => c.id !== id))
              }
            />
          )}

          {activeTab === 'health' && (
            <SystemHealthLogsView
              devices={devices}
              logs={logs}
              config={engineConfig}
              lang={lang}
              onEmitTestIngest={handleEmitTestIngest}
            />
          )}

          {activeTab === 'admin' && (
            <AdminConfigView
              users={adminUsers}
              config={engineConfig}
              lang={lang}
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
        onConfirmDeploy={handleConfirmDeploy}
      />

      <DeviceDetailModal
        device={inspectDevice}
        lang={lang}
        onClose={() => setInspectDevice(null)}
      />
    </div>
  );
}

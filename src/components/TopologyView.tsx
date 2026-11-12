import React, { useState, useMemo } from 'react';
import {
  Server,
  Router,
  Network,
  Laptop,
  Smartphone,
  ZoomIn,
  ZoomOut,
  RotateCcw,
  Rocket,
  Activity,
  ShieldCheck,
} from 'lucide-react';
import { DeviceAsset } from '../types/network';

interface TopologyViewProps {
  devices: DeviceAsset[];
  lang: 'id' | 'en';
  onOpenDeployModal: (targetIds: string[]) => void;
}

interface PositionedNode {
  device: DeviceAsset;
  x: number;
  y: number;
}

export const TopologyView: React.FC<TopologyViewProps> = ({
  devices,
  lang,
  onOpenDeployModal,
}) => {
  const [selectedId, setSelectedId] = useState<string>(devices[0]?.id || 'dev-core-01');
  const [subnetFilter, setSubnetFilter] = useState<string>('all');
  const [zoom, setZoom] = useState<number>(1);

  const filteredDevices = useMemo(() => {
    if (subnetFilter === 'all') return devices;
    return devices.filter(
      (d) => d.role === 'core-router' || d.subnet === subnetFilter
    );
  }, [devices, subnetFilter]);

  const positionedNodes = useMemo<PositionedNode[]>(() => {
    const core = filteredDevices.filter((d) => d.role === 'core-router');
    const switches = filteredDevices.filter(
      (d) => d.role === 'dist-switch' || d.role === 'access-switch'
    );
    const endpoints = filteredDevices.filter(
      (d) => d.role === 'server' || d.role === 'workstation' || d.role === 'mobile'
    );

    const nodes: PositionedNode[] = [];
    const canvasWidth = 960;

    core.forEach((d, idx) => {
      nodes.push({
        device: d,
        x: canvasWidth / 2 + (idx - (core.length - 1) / 2) * 220,
        y: 86,
      });
    });

    switches.forEach((d, idx) => {
      const step = canvasWidth / (switches.length + 1);
      nodes.push({
        device: d,
        x: step * (idx + 1),
        y: 235,
      });
    });

    endpoints.forEach((d, idx) => {
      const step = canvasWidth / (endpoints.length + 1);
      nodes.push({
        device: d,
        x: Math.max(72, Math.min(canvasWidth - 72, step * (idx + 1))),
        y: idx % 2 === 0 ? 395 : 475,
      });
    });

    return nodes;
  }, [filteredDevices]);

  const nodeMap = useMemo(() => {
    const map = new Map<string, PositionedNode>();
    positionedNodes.forEach((n) => map.set(n.device.id, n));
    return map;
  }, [positionedNodes]);

  const selectedDevice = useMemo(
    () => devices.find((d) => d.id === selectedId) || devices[0],
    [devices, selectedId]
  );

  const renderRoleIcon = (role: DeviceAsset['role']) => {
    switch (role) {
      case 'core-router':
        return <Router className="w-5 h-5 text-cyan-400" />;
      case 'dist-switch':
      case 'access-switch':
        return <Network className="w-5 h-5 text-emerald-400" />;
      case 'server':
        return <Server className="w-5 h-5 text-emerald-400" />;
      case 'workstation':
        return <Laptop className="w-5 h-5 text-sky-400" />;
      case 'mobile':
        return <Smartphone className="w-5 h-5 text-amber-400" />;
    }
  };

  return (
    <div className="grid grid-cols-1 xl:grid-cols-12 gap-6 items-start">
      {/* Topology SVG Canvas */}
      <div className="xl:col-span-8 bg-[#161F30] border border-[#1E293B] rounded-xl p-5">
        <div className="flex flex-wrap items-center justify-between gap-4 pb-4 mb-4 border-b border-[#1E293B]">
          <div>
            <h2 className="text-base font-semibold text-slate-100">
              {lang === 'id'
                ? 'Peta Topologi L2/L3 Interaktif (LLDP / ARP / SNMP)'
                : 'Interactive L2/L3 Network Topology Map (LLDP / ARP / SNMP)'}
            </h2>
            <p className="text-xs text-slate-400 mt-0.5">
              {lang === 'id'
                ? 'Klik perangkat untuk menginspeksi interface, latensi uplink, dan status agen.'
                : 'Select any node to inspect interfaces, uplink latency, and agent telemetry.'}
            </p>
          </div>

          <div className="flex items-center gap-2">
            <div className="flex items-center gap-1 bg-[#0B0F17] p-1 rounded-lg border border-[#1E293B]">
              {(['all', '10.24.10.0/24', '10.24.20.0/24'] as const).map((sub) => (
                <button
                  key={sub}
                  type="button"
                  onClick={() => setSubnetFilter(sub)}
                  className={`px-2.5 py-1 text-xs font-medium rounded-md transition-colors whitespace-nowrap shrink-0 ${
                    subnetFilter === sub
                      ? 'bg-emerald-500/20 text-emerald-300 border border-emerald-500/40'
                      : 'text-slate-400 hover:text-slate-200'
                  }`}
                >
                  {sub === 'all' ? (lang === 'id' ? 'Semua VLAN' : 'All VLANs') : sub}
                </button>
              ))}
            </div>

            <div className="flex items-center gap-1 bg-[#0B0F17] p-1 rounded-lg border border-[#1E293B]">
              <button
                type="button"
                aria-label="Zoom In Topology"
                onClick={() => setZoom((z) => Math.min(1.35, Number((z + 0.1).toFixed(2))))}
                className="p-1.5 text-slate-300 hover:text-white rounded"
              >
                <ZoomIn className="w-4 h-4" />
              </button>
              <button
                type="button"
                aria-label="Zoom Out Topology"
                onClick={() => setZoom((z) => Math.max(0.75, Number((z - 0.1).toFixed(2))))}
                className="p-1.5 text-slate-300 hover:text-white rounded"
              >
                <ZoomOut className="w-4 h-4" />
              </button>
              <button
                type="button"
                aria-label="Reset Topology Zoom"
                onClick={() => setZoom(1)}
                className="p-1.5 text-slate-300 hover:text-white rounded"
              >
                <RotateCcw className="w-4 h-4" />
              </button>
            </div>
          </div>
        </div>

        {/* SVG Graph Surface */}
        <div
          data-testid="topology-canvas"
          className="relative w-full overflow-x-auto bg-[#0B0F17] border border-[#1E293B] rounded-lg"
        >
          <svg
            viewBox="0 0 960 540"
            className="w-full h-[460px] select-none"
            style={{ transform: `scale(${zoom})`, transformOrigin: 'center center' }}
          >
            <defs>
              <pattern id="tech-grid" width="32" height="32" patternUnits="userSpaceOnUse">
                <path
                  d="M 32 0 L 0 0 0 32"
                  fill="none"
                  stroke="#1E293B"
                  strokeWidth="0.6"
                  strokeOpacity="0.55"
                />
              </pattern>
            </defs>
            <rect width="960" height="540" fill="url(#tech-grid)" />

            {/* Tier Labels */}
            <text x="20" y="42" fill="#64748B" fontSize="11" fontFamily="JetBrains Mono">
              L3 CORE BACKBONE (SNMPv3)
            </text>
            <text x="20" y="195" fill="#64748B" fontSize="11" fontFamily="JetBrains Mono">
              L2 DISTRIBUTION &amp; ACCESS SWITCHES
            </text>
            <text x="20" y="355" fill="#64748B" fontSize="11" fontFamily="JetBrains Mono">
              ENDPOINTS &amp; SERVERS (NATIVE AGENT / WINRM / SSH)
            </text>

            {/* Links */}
            {positionedNodes.map((node) => {
              if (!node.device.uplinkDeviceId) return null;
              const parent = nodeMap.get(node.device.uplinkDeviceId);
              if (!parent) return null;
              const isSelectedLink =
                selectedId === node.device.id || selectedId === parent.device.id;
              const strokeColor =
                node.device.status === 'warning'
                  ? '#F43F5E'
                  : isSelectedLink
                  ? '#10B981'
                  : '#334155';

              return (
                <g key={`link-${node.device.id}`}>
                  <line
                    x1={parent.x}
                    y1={parent.y + 26}
                    x2={node.x}
                    y2={node.y - 26}
                    stroke={strokeColor}
                    strokeWidth={isSelectedLink ? 2.2 : 1.4}
                    strokeDasharray={node.device.agentState === 'agentless' ? '5 4' : undefined}
                  />
                  <text
                    x={(parent.x + node.x) / 2}
                    y={(parent.y + node.y) / 2 - 4}
                    textAnchor="middle"
                    fill="#94A3B8"
                    fontSize="10"
                    fontFamily="JetBrains Mono"
                  >
                    {node.device.latencyMs}ms
                  </text>
                </g>
              );
            })}

            {/* Zero-State Message when no devices are ingested yet */}
            {positionedNodes.length === 0 && (
              <g transform="translate(480, 270)">
                <rect
                  x="-250"
                  y="-46"
                  width="500"
                  height="92"
                  rx="10"
                  fill="#161F30"
                  stroke="#1E293B"
                  strokeWidth="1.5"
                />
                <text
                  x="0"
                  y="-8"
                  textAnchor="middle"
                  fill="#F8FAFC"
                  fontSize="13"
                  fontWeight="600"
                >
                  {lang === 'id'
                    ? 'Zero-State: Belum Ada Node Jaringan Terdeteksi'
                    : 'Zero-State: No Network Nodes Discovered Yet'}
                </text>
                <text
                  x="0"
                  y="16"
                  textAnchor="middle"
                  fill="#94A3B8"
                  fontSize="11"
                  fontFamily="JetBrains Mono"
                >
                  {lang === 'id'
                    ? 'Menunggu data real-time dari GET /api/v1/devices atau agen lokal'
                    : 'Waiting for real-time telemetry from GET /api/v1/devices'}
                </text>
              </g>
            )}

            {/* Nodes */}
            {positionedNodes.map(({ device, x, y }) => {
              const isSelected = device.id === selectedId;
              const borderStroke =
                device.status === 'warning'
                  ? '#F43F5E'
                  : device.agentState === 'active'
                  ? '#10B981'
                  : '#38BDF8';

              return (
                <g
                  key={device.id}
                  transform={`translate(${x}, ${y})`}
                  onClick={() => setSelectedId(device.id)}
                  className="cursor-pointer"
                  role="button"
                  tabIndex={0}
                  aria-label={`Select topology node ${device.hostname}`}
                >
                  <rect
                    x="-68"
                    y="-28"
                    width="136"
                    height="56"
                    rx="8"
                    fill={isSelected ? '#1E293B' : '#161F30'}
                    stroke={borderStroke}
                    strokeWidth={isSelected ? '2.4' : '1.2'}
                  />
                  <text
                    x="0"
                    y="-6"
                    textAnchor="middle"
                    fill="#F8FAFC"
                    fontSize="11"
                    fontWeight="600"
                  >
                    {device.hostname.length > 16
                      ? device.hostname.slice(0, 15) + '…'
                      : device.hostname}
                  </text>
                  <text
                    x="0"
                    y="10"
                    textAnchor="middle"
                    fill="#94A3B8"
                    fontSize="10"
                    fontFamily="JetBrains Mono"
                  >
                    {device.ipAddress}
                  </text>
                  <text
                    x="0"
                    y="22"
                    textAnchor="middle"
                    fill={
                      device.status === 'warning'
                        ? '#FDA4AF'
                        : device.agentState === 'active'
                        ? '#6EE7B7'
                        : '#7DD3FC'
                    }
                    fontSize="9"
                    fontFamily="JetBrains Mono"
                  >
                    {device.agentState === 'active'
                      ? `AGENT ${device.agentMemoryMb ?? 12}MB`
                      : device.agentState === 'snmp-only'
                      ? 'SNMPv3'
                      : 'AGENTLESS'}
                  </text>
                </g>
              );
            })}
          </svg>
        </div>

        {/* Legend */}
        <div className="flex flex-wrap items-center justify-between gap-4 mt-3 text-xs text-slate-400">
          <div className="flex flex-wrap items-center gap-4">
            <span>Garis Utuh: Telemetri Aktif (Agent/SNMPv3)</span>
            <span>·</span>
            <span>Garis Putus: Endpoint Agentless (Siap Push Deploy)</span>
            <span>·</span>
            <span className="text-rose-400">Garis Merah: Peringatan Utilisasi &gt; 85%</span>
          </div>
          <span className="font-mono tabular-nums">
            Total Node: {filteredDevices.length}
          </span>
        </div>
      </div>

      {/* Selected Node Inspector */}
      {selectedDevice ? (
        <div className="xl:col-span-4 bg-[#161F30] border border-[#1E293B] rounded-xl p-5 space-y-5">
          <div className="flex items-start justify-between gap-3 border-b border-[#1E293B] pb-4">
            <div className="flex items-center gap-3">
              <div className="p-2.5 rounded-lg bg-[#0B0F17] border border-[#1E293B]">
                {renderRoleIcon(selectedDevice.role)}
              </div>
              <div>
                <h3 className="text-base font-semibold text-white">
                  {selectedDevice.hostname}
                </h3>
                <p className="text-xs font-mono text-slate-400 mt-0.5">
                  {selectedDevice.ipAddress} · {selectedDevice.macAddress}
                </p>
              </div>
            </div>
          </div>

          <div className="grid grid-cols-2 gap-3 text-xs">
            <div className="p-3 rounded-lg bg-[#0B0F17] border border-[#1E293B]">
              <span className="text-slate-400 block">Sistem Operasi</span>
              <span className="text-slate-100 font-medium mt-1 block">
                {selectedDevice.os} {selectedDevice.osVersion}
              </span>
            </div>
            <div className="p-3 rounded-lg bg-[#0B0F17] border border-[#1E293B]">
              <span className="text-slate-400 block">Status Kolektor</span>
              <span className="text-emerald-400 font-mono font-medium mt-1 block">
                {selectedDevice.agentState.toUpperCase()}
                {selectedDevice.agentMemoryMb
                  ? ` (${selectedDevice.agentMemoryMb} MB)`
                  : ''}
              </span>
            </div>
            <div className="p-3 rounded-lg bg-[#0B0F17] border border-[#1E293B]">
              <span className="text-slate-400 block">CPU &amp; Core</span>
              <span className="text-slate-100 font-mono tabular-nums mt-1 block">
                {selectedDevice.cpuUsagePct}% ({selectedDevice.cpuCores} Cores)
              </span>
            </div>
            <div className="p-3 rounded-lg bg-[#0B0F17] border border-[#1E293B]">
              <span className="text-slate-400 block">Penggunaan RAM</span>
              <span className="text-slate-100 font-mono tabular-nums mt-1 block">
                {selectedDevice.ramUsedGb} / {selectedDevice.ramTotalGb} GB
              </span>
            </div>
          </div>

          <div>
            <h4 className="text-xs font-semibold text-slate-300 mb-2 flex items-center gap-1.5">
              <Activity className="w-3.5 h-3.5 text-emerald-400" />
              {lang === 'id' ? 'Interface Jaringan & Throughput' : 'Network Interfaces & Throughput'}
            </h4>
            <div className="space-y-2">
              {selectedDevice.interfaces.map((iface) => (
                <div
                  key={iface.id}
                  className="p-2.5 rounded-lg bg-[#0B0F17] border border-[#1E293B] text-xs flex items-center justify-between"
                >
                  <div>
                    <div className="font-mono text-slate-200 font-medium">
                      {iface.name} (VLAN {iface.vlan})
                    </div>
                    <div className="font-mono text-slate-400 text-[11px]">
                      {iface.ipAddress} · {iface.speedMbps} Mbps
                    </div>
                  </div>
                  <div className="text-right font-mono tabular-nums text-[11px]">
                    <div className="text-emerald-400">RX {iface.rxMbps} Mbps</div>
                    <div className="text-cyan-400">TX {iface.txMbps} Mbps</div>
                  </div>
                </div>
              ))}
            </div>
          </div>

          {selectedDevice.agentState === 'agentless' ? (
            <button
              type="button"
              onClick={() => onOpenDeployModal([selectedDevice.id])}
              className="w-full py-2.5 px-4 bg-emerald-500 hover:bg-emerald-400 text-slate-950 font-semibold text-xs rounded-lg transition-colors flex items-center justify-center gap-2 cursor-pointer"
            >
              <Rocket className="w-4 h-4" />
              {lang === 'id'
                ? `Push Deploy Agen ke ${selectedDevice.hostname}`
                : `Push Deploy Agent to ${selectedDevice.hostname}`}
            </button>
          ) : (
            <div className="p-3 rounded-lg bg-[#0B0F17] border border-[#1E293B] flex items-center gap-2.5 text-xs text-slate-300">
              <ShieldCheck className="w-4 h-4 text-emerald-400 shrink-0" />
              <span>
                {selectedDevice.agentState === 'active'
                  ? lang === 'id'
                    ? `Agen Native ${selectedDevice.agentVersion} aktif dengan TLS 1.3 Gzip.`
                    : `Native Agent ${selectedDevice.agentVersion} active with TLS 1.3 Gzip.`
                  : lang === 'id'
                  ? 'Dipantau secara agentless via SNMPv3 AuthPriv.'
                  : 'Monitored agentlessly via SNMPv3 AuthPriv.'}
              </span>
            </div>
          )}
        </div>
      ) : (
        <div className="xl:col-span-4 bg-[#161F30] border border-[#1E293B] rounded-xl p-6 space-y-3">
          <h3 className="text-sm font-semibold text-white">
            {lang === 'id' ? 'Inspektor Node Topologi' : 'Topology Node Inspector'}
          </h3>
          <p className="text-xs text-slate-400 leading-relaxed">
            {lang === 'id'
              ? 'Belum ada perangkat yang terdaftar di database PostgreSQL (vectranet_rmm). Jalankan agen native lokal atau lakukan pemindaian subnet CIDR untuk melihat topologi L2/L3.'
              : 'No devices registered in PostgreSQL (vectranet_rmm) yet. Run a local native agent or execute a CIDR subnet scan to populate the L2/L3 topology.'}
          </p>
        </div>
      )}
    </div>
  );
};

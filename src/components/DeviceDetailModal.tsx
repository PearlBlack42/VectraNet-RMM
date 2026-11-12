import React, { useEffect, useState, useCallback, useMemo } from 'react';
import {
  X,
  Cpu,
  HardDrive,
  Network,
  Package,
  Activity,
  RefreshCw,
  AlertCircle,
} from 'lucide-react';
import {
  DeviceAsset,
  DeviceMetricPoint,
  DeviceMetricsHistoryResponse,
} from '../types/network';
import { computeHeartbeatStats } from '../utils/networkEngine';

interface DeviceDetailModalProps {
  device: DeviceAsset | null;
  lang: 'id' | 'en';
  onClose: () => void;
}

const API_BASE = (import.meta.env.VITE_API_BASE_URL as string) || '';

export const DeviceDetailModal: React.FC<DeviceDetailModalProps> = ({
  device,
  lang,
  onClose,
}) => {
  const [historyData, setHistoryData] = useState<DeviceMetricsHistoryResponse | null>(null);
  const [isLoadingMetrics, setIsLoadingMetrics] = useState(false);
  const [metricsError, setMetricsError] = useState<string | null>(null);
  const [activePointIdx, setActivePointIdx] = useState<number | null>(null);

  const fetchDeviceMetrics = useCallback(async (deviceId: string) => {
    setIsLoadingMetrics(true);
    setMetricsError(null);
    try {
      const res = await fetch(
        `${API_BASE}/api/v1/devices/${encodeURIComponent(deviceId)}/metrics`
      );
      if (!res.ok) {
        throw new Error(`HTTP ${res.status}`);
      }
      const data = (await res.json()) as DeviceMetricsHistoryResponse;
      setHistoryData(data);
    } catch (err) {
      setMetricsError((err as Error).message || 'Failed to fetch device metrics');
    } finally {
      setIsLoadingMetrics(false);
    }
  }, []);

  useEffect(() => {
    if (!device) {
      setHistoryData(null);
      setActivePointIdx(null);
      return;
    }

    void fetchDeviceMetrics(device.id);
    const timer = window.setInterval(() => {
      void fetchDeviceMetrics(device.id);
    }, 5000);

    return () => window.clearInterval(timer);
  }, [device?.id, fetchDeviceMetrics]);

  // Allow closing the modal anytime via Escape key
  useEffect(() => {
    if (!device) return;
    const handleKeyDown = (e: KeyboardEvent) => {
      if (e.key === 'Escape') {
        onClose();
      }
    };
    window.addEventListener('keydown', handleKeyDown);
    return () => window.removeEventListener('keydown', handleKeyDown);
  }, [device, onClose]);

  const points: DeviceMetricPoint[] = useMemo(() => {
    if (historyData && Array.isArray(historyData.points) && historyData.points.length > 0) {
      return historyData.points;
    }
    return [];
  }, [historyData]);

  const stats = useMemo(
    () => computeHeartbeatStats(points, device?.ramTotalGb || 0),
    [points, device?.ramTotalGb]
  );

  if (!device) return null;

  const isAgentActive = device.agentState === 'active';
  const inspectedPoint =
    activePointIdx !== null && points[activePointIdx]
      ? points[activePointIdx]
      : points.length > 0
      ? points[points.length - 1]
      : null;

  // SVG Chart Geometry (720 x 210)
  const chartWidth = 720;
  const chartHeight = 210;
  const padLeft = 44;
  const padRight = 18;
  const padTop = 18;
  const padBottom = 30;
  const plotWidth = chartWidth - padLeft - padRight;
  const plotHeight = chartHeight - padTop - padBottom;

  const getX = (idx: number, total: number) => {
    if (total <= 1) return padLeft + plotWidth / 2;
    return Number((padLeft + (idx / (total - 1)) * plotWidth).toFixed(1));
  };

  const getY = (pct: number) => {
    const clamped = Math.max(0, Math.min(100, Number(pct) || 0));
    return Number((padTop + plotHeight - (clamped / 100) * plotHeight).toFixed(1));
  };

  const cpuCoords = points.map((pt, idx) => ({
    x: getX(idx, points.length),
    y: getY(pt.cpuUsagePct),
    pct: Number(pt.cpuUsagePct) || 0,
  }));

  const ramCoords = points.map((pt, idx) => {
    const totalGb = Number(pt.ramTotalGb) || device.ramTotalGb || 0;
    const ramPct =
      typeof pt.ramUsagePct === 'number' && pt.ramUsagePct > 0
        ? pt.ramUsagePct
        : totalGb > 0
        ? (Number(pt.ramUsedGb) / totalGb) * 100
        : 0;
    return {
      x: getX(idx, points.length),
      y: getY(ramPct),
      pct: Number(ramPct.toFixed(1)),
    };
  });

  const cpuPolyline = cpuCoords.map((c) => `${c.x},${c.y}`).join(' ');
  const ramPolyline = ramCoords.map((c) => `${c.x},${c.y}`).join(' ');

  const baselineY = padTop + plotHeight;
  const cpuAreaPath =
    cpuCoords.length > 1
      ? `M ${cpuCoords[0].x},${baselineY} L ${cpuCoords
          .map((c) => `${c.x},${c.y}`)
          .join(' L ')} L ${cpuCoords[cpuCoords.length - 1].x},${baselineY} Z`
      : '';

  const ramAreaPath =
    ramCoords.length > 1
      ? `M ${ramCoords[0].x},${baselineY} L ${ramCoords
          .map((c) => `${c.x},${c.y}`)
          .join(' L ')} L ${ramCoords[ramCoords.length - 1].x},${baselineY} Z`
      : '';

  return (
    <div
      className="fixed inset-0 z-50 flex items-center justify-center bg-black/80 backdrop-blur-xs p-4"
      role="dialog"
      aria-modal="true"
      aria-labelledby="device-detail-title"
      onClick={onClose}
    >
      <div
        className="relative w-full max-w-4xl bg-[#161F30] border border-[#1E293B] rounded-xl shadow-2xl max-h-[90vh] flex flex-col overflow-hidden"
        onClick={(e) => e.stopPropagation()}
      >
        {/* Sticky Modal Header with Prominent Top-Right Close (X) Button */}
        <div className="sticky top-0 z-30 flex items-start justify-between gap-4 bg-[#161F30]/95 backdrop-blur-md border-b border-[#1E293B] px-6 py-4 shrink-0">
          <div className="min-w-0">
            <div className="flex items-center gap-2.5">
              <Activity className="w-5 h-5 text-emerald-400 shrink-0" />
              <h2 id="device-detail-title" className="text-base font-semibold text-white truncate">
                {device.hostname} —{' '}
                {lang === 'id'
                  ? 'Detail Perangkat & Grafik Heartbeat Historis (1 Jam)'
                  : 'Device Details & Historical Heartbeat Chart (1 Hour)'}
              </h2>
            </div>
            <p className="text-xs font-mono text-slate-400 mt-1 flex flex-wrap items-center gap-x-1.5 gap-y-0.5">
              <span>{device.ipAddress}</span>
              <span>·</span>
              <span>{device.macAddress}</span>
              <span>·</span>
              <span>
                {device.os} {device.osVersion} ({device.kernelArch})
              </span>
              <span>·</span>
              <span
                className={`whitespace-nowrap ${
                  isAgentActive ? 'text-emerald-400' : 'text-cyan-400'
                }`}
              >
                {isAgentActive
                  ? `Native Agent ${device.agentVersion || 'v2.4.2-go'}`
                  : 'Agentless (ICMP Monitored)'}
              </span>
            </p>
          </div>
          <div className="flex items-center gap-2.5 shrink-0">
            <button
              type="button"
              onClick={() => void fetchDeviceMetrics(device.id)}
              className="px-3 py-1.5 text-xs font-mono text-slate-200 hover:text-white bg-[#0B0F17] border border-[#1E293B] hover:border-slate-600 rounded-lg transition-colors flex items-center gap-1.5 cursor-pointer whitespace-nowrap"
            >
              <RefreshCw
                className={`w-3.5 h-3.5 text-emerald-400 ${
                  isLoadingMetrics ? 'animate-spin' : ''
                }`}
              />
              <span>{lang === 'id' ? 'Segarkan Heartbeat' : 'Refresh Heartbeat'}</span>
            </button>
            <button
              type="button"
              aria-label="Close Device Detail Modal"
              title={lang === 'id' ? 'Tutup Modal (ESC)' : 'Close Modal (ESC)'}
              onClick={onClose}
              className="px-3 py-1.5 text-xs font-semibold bg-rose-500/15 hover:bg-rose-500 text-rose-300 hover:text-white border border-rose-500/40 rounded-lg transition-colors inline-flex items-center gap-1.5 cursor-pointer whitespace-nowrap"
            >
              <X className="w-4 h-4 stroke-[2.5]" />
              <span>{lang === 'id' ? 'Tutup' : 'Close'}</span>
            </button>
          </div>
        </div>

        {/* Scrollable Modal Body */}
        <div className="p-6 space-y-5 overflow-y-auto flex-1">
          {/* Dedicated Historical 'Heartbeat' Chart Section (Last 60 Minutes CPU & RAM) */}
          <section
          aria-label="Historical Heartbeat Chart"
          className="p-4 rounded-xl bg-[#0B0F17] border border-[#1E293B] space-y-4"
        >
          <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-2 border-b border-[#1E293B] pb-3">
            <div className="min-w-0">
              <h3 className="text-xs font-semibold text-white flex items-center gap-2">
                <Activity className="w-4 h-4 text-emerald-400 shrink-0" />
                <span className="truncate">
                  {lang === 'id'
                    ? 'Historical Heartbeat Telemetry — Utilisasi CPU & RAM (60 Menit Terakhir)'
                    : 'Historical Heartbeat Telemetry — CPU & RAM Usage (Last 60 Minutes)'}
                </span>
              </h3>
              <p className="text-[11px] font-mono text-slate-400 mt-0.5 truncate">
                GET /api/v1/devices/{device.id}/metrics · Window: 60m ({stats.sampleCount}{' '}
                {lang === 'id' ? 'sampel' : 'samples'})
              </p>
            </div>

            {/* Chart Series Legend */}
            <div className="flex items-center gap-4 text-xs font-mono shrink-0">
              <span className="inline-flex items-center gap-1.5 text-emerald-400">
                <span className="w-2.5 h-0.5 bg-emerald-400 inline-block" />
                <span>CPU Usage (%)</span>
              </span>
              <span className="inline-flex items-center gap-1.5 text-cyan-400">
                <span className="w-2.5 h-0.5 bg-cyan-400 inline-block" />
                <span>RAM Usage (%)</span>
              </span>
            </div>
          </div>

          {/* 1-Hour Heartbeat Statistical Aggregates */}
          <div className="grid grid-cols-2 sm:grid-cols-4 gap-3 text-xs font-mono tabular-nums">
            <div className="p-2.5 rounded-lg bg-[#161F30] border border-[#1E293B]">
              <div className="text-[11px] text-slate-400">
                {lang === 'id' ? 'CPU Saat Ini / Puncak' : 'Current / Peak CPU'}
              </div>
              <div className="text-sm font-bold text-emerald-400 mt-0.5">
                {isAgentActive ? `${stats.currentCpuPct}%` : '0%'}
                <span className="text-xs font-normal text-slate-400">
                  {' '}
                  · Peak {isAgentActive ? `${stats.peakCpuPct}%` : '0%'}
                </span>
              </div>
              <div className="text-[11px] text-slate-400">
                Avg 1h: {isAgentActive ? `${stats.avgCpuPct}%` : '0%'}
              </div>
            </div>

            <div className="p-2.5 rounded-lg bg-[#161F30] border border-[#1E293B]">
              <div className="text-[11px] text-slate-400">
                {lang === 'id' ? 'RAM Saat Ini / Puncak' : 'Current / Peak RAM'}
              </div>
              <div className="text-sm font-bold text-cyan-400 mt-0.5">
                {isAgentActive ? `${stats.currentRamPct}%` : '0%'}
                <span className="text-xs font-normal text-slate-400">
                  {' '}
                  · Peak {isAgentActive ? `${stats.peakRamPct}%` : '0%'}
                </span>
              </div>
              <div className="text-[11px] text-slate-400">
                {isAgentActive
                  ? `${stats.currentRamUsedGb} / ${stats.ramTotalGb} GB (Avg ${stats.avgRamPct}%)`
                  : '0 / 0 GB (Agentless)'}
              </div>
            </div>

            <div className="p-2.5 rounded-lg bg-[#161F30] border border-[#1E293B]">
              <div className="text-[11px] text-slate-400">
                {lang === 'id' ? 'Mode Heartbeat Adaptif' : 'Adaptive Heartbeat Mode'}
              </div>
              <div className="text-sm font-bold text-slate-100 mt-0.5">
                {inspectedPoint?.heartbeatMode || (isAgentActive ? 'standard' : 'agentless')}
              </div>
              <div className="text-[11px] text-slate-400">
                {isAgentActive ? 'TLS 1.3 Gzip Frame' : '10s ICMP Ping Only'}
              </div>
            </div>

            <div className="p-2.5 rounded-lg bg-[#161F30] border border-[#1E293B]">
              <div className="text-[11px] text-slate-400">
                {lang === 'id' ? 'Titik Waktu Inspeksi' : 'Inspected Sample Time'}
              </div>
              <div className="text-sm font-bold text-white mt-0.5">
                {inspectedPoint?.timeLabel || '--:--'}
              </div>
              <div className="text-[11px] text-slate-400">
                RX {inspectedPoint?.netRxMbps ?? 0} / TX {inspectedPoint?.netTxMbps ?? 0} Mbps
              </div>
            </div>
          </div>

          {!isAgentActive && (
            <div className="p-3 rounded-lg bg-slate-900/90 border border-[#1E293B] text-xs text-slate-300 flex items-center gap-2">
              <AlertCircle className="w-4 h-4 text-cyan-400 shrink-0" />
              <span>
                {lang === 'id'
                  ? 'Perangkat ini berstatus Agentless (dipantau via ICMP Ping setiap 10 detik). Deploy Agen Native Go pada host ini untuk merekam metrik CPU & RAM real-time ke grafik Heartbeat.'
                  : 'This endpoint is currently Agentless (monitored via 10s ICMP Ping). Deploy the Native Go Agent to stream live CPU & RAM metrics into the Heartbeat chart.'}
              </span>
            </div>
          )}

          {metricsError && (
            <div role="alert" className="text-xs text-rose-400 font-mono">
              {metricsError}
            </div>
          )}

          {/* SVG Time-Series Chart */}
          <div className="relative w-full overflow-x-auto">
            <svg
              data-testid="heartbeat-history-chart"
              viewBox={`0 0 ${chartWidth} ${chartHeight}`}
              className="w-full h-52 select-none"
              role="img"
              aria-label={`Historical 1-Hour CPU and RAM Heartbeat Chart for ${device.hostname}`}
            >
              <defs>
                <linearGradient id="cpuHeartbeatGrad" x1="0" y1="0" x2="0" y2="1">
                  <stop offset="0%" stopColor="#10B981" stopOpacity="0.32" />
                  <stop offset="100%" stopColor="#10B981" stopOpacity="0.02" />
                </linearGradient>
                <linearGradient id="ramHeartbeatGrad" x1="0" y1="0" x2="0" y2="1">
                  <stop offset="0%" stopColor="#06B6D4" stopOpacity="0.26" />
                  <stop offset="100%" stopColor="#06B6D4" stopOpacity="0.02" />
                </linearGradient>
              </defs>

              {/* Horizontal Grid Lines (0%, 25%, 50%, 75%, 100%) */}
              {[0, 25, 50, 75, 100].map((tick) => {
                const y = getY(tick);
                return (
                  <g key={tick}>
                    <line
                      x1={padLeft}
                      y1={y}
                      x2={chartWidth - padRight}
                      y2={y}
                      stroke="#1E293B"
                      strokeDasharray={tick === 0 ? undefined : '3 3'}
                      strokeWidth="1"
                    />
                    <text
                      x={padLeft - 8}
                      y={y + 3}
                      textAnchor="end"
                      className="fill-slate-500 text-[10px] font-mono"
                    >
                      {tick}%
                    </text>
                  </g>
                );
              })}

              {/* RAM Area & Line */}
              {ramAreaPath && <path d={ramAreaPath} fill="url(#ramHeartbeatGrad)" />}
              {ramPolyline && (
                <polyline
                  fill="none"
                  stroke="#06B6D4"
                  strokeWidth="2"
                  strokeLinecap="round"
                  strokeLinejoin="round"
                  points={ramPolyline}
                />
              )}

              {/* CPU Area & Line */}
              {cpuAreaPath && <path d={cpuAreaPath} fill="url(#cpuHeartbeatGrad)" />}
              {cpuPolyline && (
                <polyline
                  fill="none"
                  stroke="#10B981"
                  strokeWidth="2.2"
                  strokeLinecap="round"
                  strokeLinejoin="round"
                  points={cpuPolyline}
                />
              )}

              {/* Interactive Sample Points & X-Axis Labels */}
              {points.map((pt, idx) => {
                const cx = cpuCoords[idx]?.x ?? padLeft;
                const cpuY = cpuCoords[idx]?.y ?? baselineY;
                const ramY = ramCoords[idx]?.y ?? baselineY;
                const isSelected =
                  activePointIdx === idx ||
                  (activePointIdx === null && idx === points.length - 1);
                const showLabel =
                  points.length <= 8 ||
                  idx === 0 ||
                  idx === points.length - 1 ||
                  idx % Math.max(1, Math.floor(points.length / 6)) === 0;

                return (
                  <g
                    key={`${pt.timestamp}-${idx}`}
                    className="cursor-pointer"
                    onMouseEnter={() => setActivePointIdx(idx)}
                    onClick={() => setActivePointIdx(idx)}
                  >
                    {isSelected && (
                      <line
                        x1={cx}
                        y1={padTop}
                        x2={cx}
                        y2={baselineY}
                        stroke="#475569"
                        strokeDasharray="2 2"
                        strokeWidth="1"
                      />
                    )}
                    <circle
                      cx={cx}
                      cy={ramY}
                      r={isSelected ? 4.5 : 2.8}
                      fill="#06B6D4"
                      stroke="#0B0F17"
                      strokeWidth="1.2"
                    />
                    <circle
                      cx={cx}
                      cy={cpuY}
                      r={isSelected ? 4.5 : 2.8}
                      fill="#10B981"
                      stroke="#0B0F17"
                      strokeWidth="1.2"
                    />
                    {showLabel && (
                      <text
                        x={cx}
                        y={chartHeight - 8}
                        textAnchor="middle"
                        className="fill-slate-400 text-[10px] font-mono"
                      >
                        {pt.timeLabel}
                      </text>
                    )}
                  </g>
                );
              })}
            </svg>
          </div>
        </section>

        {/* Hardware & Location Summary Cards */}
        <div className="grid grid-cols-1 sm:grid-cols-3 gap-3 text-xs">
          <div className="p-3.5 rounded-lg bg-[#0B0F17] border border-[#1E293B]">
            <div className="flex items-center gap-1.5 text-slate-400 mb-1">
              <Cpu className="w-3.5 h-3.5 text-emerald-400" />
              <span>Prosesor &amp; Beban</span>
            </div>
            <div className="font-semibold text-slate-100">
              {device.agentState === 'active'
                ? device.cpuModel
                : 'Belum Terbaca (Menunggu Agen Native)'}
            </div>
            <div className="font-mono tabular-nums text-emerald-400 mt-0.5">
              {device.agentState === 'active'
                ? `Utilisasi: ${device.cpuUsagePct}% (${device.cpuCores} Cores)`
                : 'Utilisasi: 0% (0 Cores · Agentless)'}
            </div>
          </div>

          <div className="p-3.5 rounded-lg bg-[#0B0F17] border border-[#1E293B]">
            <div className="flex items-center gap-1.5 text-slate-400 mb-1">
              <HardDrive className="w-3.5 h-3.5 text-cyan-400" />
              <span>Memori &amp; Penyimpanan</span>
            </div>
            <div className="font-mono tabular-nums text-slate-100">
              {device.agentState === 'active'
                ? `RAM: ${device.ramUsedGb} / ${device.ramTotalGb} GB`
                : 'RAM: 0 / 0 GB (Menunggu Agen)'}
            </div>
            <div className="font-mono tabular-nums text-slate-400 mt-0.5">
              {device.agentState === 'active'
                ? `Disk: ${device.diskUsedGb} / ${device.diskTotalGb} GB`
                : 'Disk: 0 / 0 GB (Agentless)'}
            </div>
          </div>

          <div className="p-3.5 rounded-lg bg-[#0B0F17] border border-[#1E293B]">
            <div className="flex items-center gap-1.5 text-slate-400 mb-1">
              <Network className="w-3.5 h-3.5 text-emerald-400" />
              <span>Lokasi &amp; Uplink</span>
            </div>
            <div className="font-semibold text-slate-100">{device.location}</div>
            <div className="font-mono text-slate-400 mt-0.5">
              {device.uplinkPort || 'Core Backbone Root'} ({device.latencyMs} ms)
            </div>
          </div>
        </div>

        {/* Network Interfaces Table */}
        <div>
          <h3 className="text-xs font-semibold text-slate-200 mb-2 flex items-center gap-1.5">
            <Network className="w-3.5 h-3.5 text-emerald-400" />
            {lang === 'id'
              ? 'Tabel Interface Jaringan (network_interfaces)'
              : 'Network Interfaces Table (network_interfaces)'}
          </h3>
          <div className="overflow-x-auto rounded-lg border border-[#1E293B] bg-[#0B0F17]">
            <table className="w-full text-left text-xs">
              <thead className="border-b border-[#1E293B] text-slate-400">
                <tr>
                  <th className="py-2 px-3">Interface</th>
                  <th className="py-2 px-3">IPv4</th>
                  <th className="py-2 px-3">MAC</th>
                  <th className="py-2 px-3 text-right">VLAN</th>
                  <th className="py-2 px-3 text-right">Speed</th>
                  <th className="py-2 px-3 text-right">RX / TX (Mbps)</th>
                </tr>
              </thead>
              <tbody className="divide-y divide-[#1E293B] font-mono tabular-nums">
                {device.interfaces.map((iface) => (
                  <tr key={iface.id}>
                    <td className="py-2 px-3 text-slate-200">{iface.name}</td>
                    <td className="py-2 px-3 text-slate-300">{iface.ipAddress}</td>
                    <td className="py-2 px-3 text-slate-400">{iface.macAddress}</td>
                    <td className="py-2 px-3 text-right text-slate-300">{iface.vlan}</td>
                    <td className="py-2 px-3 text-right text-slate-300">
                      {iface.speedMbps} Mbps
                    </td>
                    <td className="py-2 px-3 text-right text-emerald-400">
                      {iface.rxMbps} / {iface.txMbps}
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        </div>

        {/* Installed Software Table */}
        <div>
          <h3 className="text-xs font-semibold text-slate-200 mb-2 flex items-center gap-1.5">
            <Package className="w-3.5 h-3.5 text-cyan-400" />
            {lang === 'id'
              ? 'Daftar Perangkat Lunak Terinstal (installed_software)'
              : 'Installed Software Packages (installed_software)'}
          </h3>
          <div className="overflow-x-auto rounded-lg border border-[#1E293B] bg-[#0B0F17]">
            <table className="w-full text-left text-xs">
              <thead className="border-b border-[#1E293B] text-slate-400">
                <tr>
                  <th className="py-2 px-3">Nama Paket</th>
                  <th className="py-2 px-3">Versi</th>
                  <th className="py-2 px-3">Publisher</th>
                  <th className="py-2 px-3 text-right">Tanggal Instal</th>
                </tr>
              </thead>
              <tbody className="divide-y divide-[#1E293B]">
                {device.software.length === 0 ? (
                  <tr>
                    <td colSpan={4} className="py-4 px-3 text-center text-slate-500 font-mono">
                      {lang === 'id'
                        ? 'Belum ada daftar paket perangkat lunak (Membutuhkan Agen Native Aktif).'
                        : 'No software inventory collected yet (Requires Active Native Agent).'}
                    </td>
                  </tr>
                ) : (
                  device.software.map((sw, idx) => (
                    <tr key={idx}>
                      <td className="py-2 px-3 text-slate-200 font-medium">{sw.name}</td>
                      <td className="py-2 px-3 font-mono text-emerald-400">{sw.version}</td>
                      <td className="py-2 px-3 text-slate-400">{sw.publisher}</td>
                      <td className="py-2 px-3 text-right font-mono tabular-nums text-slate-400">
                        {sw.installDate}
                      </td>
                    </tr>
                  ))
                )}
              </tbody>
            </table>
          </div>
        </div>
        </div>

        {/* Sticky Modal Footer with Close Button */}
        <div className="sticky bottom-0 z-30 flex items-center justify-between gap-4 bg-[#0B0F17]/95 backdrop-blur-md border-t border-[#1E293B] px-6 py-3 shrink-0 text-xs">
          <span className="font-mono text-slate-400">
            {lang === 'id'
              ? 'Tekan tombol ESC atau klik Tutup untuk kembali ke tabel inventaris.'
              : 'Press ESC or click Close to return to the inventory table.'}
          </span>
          <button
            type="button"
            onClick={onClose}
            className="px-4 py-1.5 text-xs font-semibold bg-[#161F30] hover:bg-rose-500 text-slate-200 hover:text-white border border-[#1E293B] hover:border-rose-500 rounded-lg transition-colors inline-flex items-center gap-1.5 cursor-pointer"
          >
            <X className="w-3.5 h-3.5" />
            <span>{lang === 'id' ? 'Tutup Detail Perangkat' : 'Close Device Details'}</span>
          </button>
        </div>
      </div>
    </div>
  );
};


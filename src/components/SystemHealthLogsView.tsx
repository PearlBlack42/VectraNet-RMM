import React, { useState, useMemo } from 'react';
import {
  Activity,
  Terminal,
  Cpu,
  Database,
  Gauge,
  PlusCircle,
} from 'lucide-react';
import { DeviceAsset, EngineConfigState, SystemLogEntry } from '../types/network';
import { calculateAdaptiveHeartbeat } from '../utils/networkEngine';

interface SystemHealthLogsViewProps {
  devices: DeviceAsset[];
  logs: SystemLogEntry[];
  config: EngineConfigState;
  lang: 'id' | 'en';
  onEmitTestIngest: () => void;
}

export const SystemHealthLogsView: React.FC<SystemHealthLogsViewProps> = ({
  devices,
  logs,
  config,
  lang,
  onEmitTestIngest,
}) => {
  const [levelFilter, setLevelFilter] = useState<'ALL' | 'INFO' | 'WARN' | 'ERROR'>('ALL');
  const [simCpuPct, setSimCpuPct] = useState<number>(18);
  const [simRamPct, setSimRamPct] = useState<number>(42);

  const adaptiveResult = useMemo(
    () =>
      calculateAdaptiveHeartbeat({
        baseIntervalSec: config.baseHeartbeatSec,
        cpuUsagePct: simCpuPct,
        ramUsagePct: simRamPct,
        previousCpuPct: 16,
        deltaThresholdPct: config.adaptiveDeltaThresholdPct,
      }),
    [config.baseHeartbeatSec, config.adaptiveDeltaThresholdPct, simCpuPct, simRamPct]
  );

  const filteredLogs = useMemo(() => {
    if (levelFilter === 'ALL') return logs;
    return logs.filter((l) => l.level === levelFilter);
  }, [logs, levelFilter]);

  return (
    <div className="space-y-6">
      {/* Core Engine & TimescaleDB Health Metrics */}
      <div className="grid grid-cols-1 md:grid-cols-4 gap-4">
        <div className="bg-[#161F30] border border-[#1E293B] rounded-xl p-4">
          <div className="flex items-center justify-between text-xs text-slate-400">
            <span>Go Engine Worker Pool</span>
            <Cpu className="w-4 h-4 text-emerald-400" />
          </div>
          <div className="text-2xl font-bold font-mono tabular-nums text-white mt-2">
            28 / {config.maxScannerGoroutines}
          </div>
          <p className="text-xs text-slate-400 mt-1">
            Goroutines Aktif · Heap RSS: 34.2 MB
          </p>
        </div>

        <div className="bg-[#161F30] border border-[#1E293B] rounded-xl p-4">
          <div className="flex items-center justify-between text-xs text-slate-400">
            <span>TimescaleDB Hypertable</span>
            <Database className="w-4 h-4 text-cyan-400" />
          </div>
          <div className="text-2xl font-bold font-mono tabular-nums text-white mt-2">
            92.4%
          </div>
          <p className="text-xs text-slate-400 mt-1">
            Rasio Kompresi Kolumnar · Retensi {config.timescaleRetentionDays}h
          </p>
        </div>

        <div className="bg-[#161F30] border border-[#1E293B] rounded-xl p-4">
          <div className="flex items-center justify-between text-xs text-slate-400">
            <span>Gzip TLS 1.3 Ingest Rate</span>
            <Activity className="w-4 h-4 text-emerald-400" />
          </div>
          <div className="text-2xl font-bold font-mono tabular-nums text-white mt-2">
            1.64 KB/pkt
          </div>
          <p className="text-xs text-slate-400 mt-1">
            Hemat Bandwidth 78% dibanding JSON mentah
          </p>
        </div>

        <div className="bg-[#161F30] border border-[#1E293B] rounded-xl p-4">
          <div className="flex items-center justify-between text-xs text-slate-400">
            <span>Rata-Rata Memori Agen</span>
            <Gauge className="w-4 h-4 text-emerald-400" />
          </div>
          <div className="text-2xl font-bold font-mono tabular-nums text-emerald-400 mt-2">
            11.9 MB
          </div>
          <p className="text-xs text-slate-400 mt-1">
            Batas Cgroup/Runtime: {config.maxAgentRamMb} MB (CPU &lt; 0.5%)
          </p>
        </div>
      </div>

      <div className="grid grid-cols-1 xl:grid-cols-12 gap-6 items-start">
        {/* Adaptive Heartbeat Simulator */}
        <div className="xl:col-span-5 bg-[#161F30] border border-[#1E293B] rounded-xl p-5 space-y-4">
          <div className="border-b border-[#1E293B] pb-3">
            <h2 className="text-base font-semibold text-white">
              {lang === 'id'
                ? 'Simulator Adaptive Heartbeat & Low-Resource Agent'
                : 'Adaptive Heartbeat & Low-Resource Agent Simulator'}
            </h2>
            <p className="text-xs text-slate-400 mt-0.5">
              {lang === 'id'
                ? 'Uji bagaimana agen menyesuaikan interval pengiriman berdasarkan beban CPU/RAM endpoint.'
                : 'Test how the native Go agent scales its ingestion interval based on endpoint CPU/RAM load.'}
            </p>
          </div>

          <div className="space-y-3">
            <div>
              <div className="flex justify-between text-xs mb-1">
                <label htmlFor="sim-cpu" className="text-slate-300 font-medium">
                  Simulasi Beban CPU Endpoint
                </label>
                <span className="font-mono tabular-nums text-emerald-400">{simCpuPct}%</span>
              </div>
              <input
                id="sim-cpu"
                type="range"
                min={2}
                max={98}
                value={simCpuPct}
                onChange={(e) => setSimCpuPct(Number(e.target.value))}
                className="w-full accent-emerald-500 cursor-pointer"
              />
            </div>

            <div>
              <div className="flex justify-between text-xs mb-1">
                <label htmlFor="sim-ram" className="text-slate-300 font-medium">
                  Simulasi Beban RAM Endpoint
                </label>
                <span className="font-mono tabular-nums text-cyan-400">{simRamPct}%</span>
              </div>
              <input
                id="sim-ram"
                type="range"
                min={10}
                max={98}
                value={simRamPct}
                onChange={(e) => setSimRamPct(Number(e.target.value))}
                className="w-full accent-cyan-400 cursor-pointer"
              />
            </div>
          </div>

          <div className="p-4 rounded-lg bg-[#0B0F17] border border-[#1E293B] space-y-2 text-xs">
            <div className="flex items-center justify-between">
              <span className="text-slate-400">Mode Telemetri Agen:</span>
              <span
                className={`font-mono font-semibold ${
                  adaptiveResult.mode === 'burst-event'
                    ? 'text-rose-400'
                    : adaptiveResult.mode === 'idle-eco'
                    ? 'text-emerald-400'
                    : 'text-cyan-400'
                }`}
              >
                {adaptiveResult.mode.toUpperCase()}
              </span>
            </div>
            <div className="flex items-center justify-between">
              <span className="text-slate-400">Interval Heartbeat Berikutnya:</span>
              <span className="font-mono tabular-nums text-white font-semibold">
                Setiap {adaptiveResult.nextIntervalSec} detik
              </span>
            </div>
            <div className="flex items-center justify-between">
              <span className="text-slate-400"> Kompresi Payload:</span>
              <span className="font-mono text-slate-300">
                Gzip Level {config.gzipCompressionLevel} via {config.tlsMinVersion}
              </span>
            </div>
          </div>

          {/* Per-Device Resource Bars */}
          <div className="pt-2 space-y-2.5">
            <h3 className="text-xs font-semibold text-slate-300">
              {lang === 'id'
                ? 'Utilisasi Real-Time Perangkat Teratas (TimescaleDB)'
                : 'Top Endpoint Real-Time Utilization (TimescaleDB)'}
            </h3>
            {devices.slice(0, 5).map((dev) => {
              const ramPct = Math.round((dev.ramUsedGb / Math.max(1, dev.ramTotalGb)) * 100);
              return (
                <div
                  key={dev.id}
                  className="p-2.5 rounded-lg bg-[#0B0F17] border border-[#1E293B] text-xs space-y-1.5"
                >
                  <div className="flex items-center justify-between">
                    <span className="font-medium text-slate-200">{dev.hostname}</span>
                    <span className="font-mono tabular-nums text-slate-400">
                      CPU {dev.cpuUsagePct}% · RAM {ramPct}%
                    </span>
                  </div>
                  <div className="w-full h-1.5 bg-slate-800 rounded-full overflow-hidden">
                    <div
                      className={`h-full ${
                        dev.cpuUsagePct > 80 ? 'bg-rose-500' : 'bg-emerald-500'
                      }`}
                      style={{ width: `${Math.min(100, dev.cpuUsagePct)}%` }}
                    />
                  </div>
                </div>
              );
            })}
          </div>
        </div>

        {/* Centralized Structured Log Stream */}
        <div className="xl:col-span-7 bg-[#161F30] border border-[#1E293B] rounded-xl p-5">
          <div className="flex flex-wrap items-center justify-between gap-3 pb-4 mb-4 border-b border-[#1E293B]">
            <div className="flex items-center gap-2">
              <Terminal className="w-5 h-5 text-emerald-400" />
              <div>
                <h2 className="text-base font-semibold text-white">
                  {lang === 'id'
                    ? 'Aliran Log Terpusat (Centralized Telemetry & Audit Logs)'
                    : 'Centralized Structured Telemetry & Audit Log Stream'}
                </h2>
                <p className="text-xs text-slate-400">
                  {lang === 'id'
                    ? 'Mencakup aktivitas Ingest TLS, ICMP Sweeper, SNMPv3, dan AES-256 Vault.'
                    : 'Streams TLS Ingest, ICMP Sweeper, SNMPv3 Poller, and AES-256 Vault events.'}
                </p>
              </div>
            </div>

            <div className="flex items-center gap-2">
              <div className="flex items-center gap-1 bg-[#0B0F17] p-1 rounded-lg border border-[#1E293B]">
                {(['ALL', 'INFO', 'WARN', 'ERROR'] as const).map((lvl) => (
                  <button
                    key={lvl}
                    type="button"
                    onClick={() => setLevelFilter(lvl)}
                    className={`px-2.5 py-1 text-xs font-mono rounded transition-colors cursor-pointer ${
                      levelFilter === lvl
                        ? 'bg-emerald-500/20 text-emerald-300 border border-emerald-500/40'
                        : 'text-slate-400 hover:text-slate-200'
                    }`}
                  >
                    {lvl}
                  </button>
                ))}
              </div>

              <button
                type="button"
                onClick={onEmitTestIngest}
                className="px-3 py-1.5 text-xs font-medium bg-emerald-500 hover:bg-emerald-400 text-slate-950 rounded-lg transition-colors flex items-center gap-1.5 whitespace-nowrap cursor-pointer"
              >
                <PlusCircle className="w-3.5 h-3.5" />
                {lang === 'id' ? 'Simulasi Ingest Agen' : 'Simulate Agent Ingest'}
              </button>
            </div>
          </div>

          <div className="space-y-2 max-h-[460px] overflow-y-auto font-mono text-xs">
            {filteredLogs.map((entry) => (
              <div
                key={entry.id}
                className="p-3 rounded-lg bg-[#0B0F17] border border-[#1E293B] flex flex-col sm:flex-row sm:items-center justify-between gap-2"
              >
                <div className="space-y-1">
                  <div className="flex flex-wrap items-center gap-2">
                    <span className="text-slate-500 tabular-nums">{entry.timestamp}</span>
                    <span
                      className={`font-semibold ${
                        entry.level === 'ERROR'
                          ? 'text-rose-400'
                          : entry.level === 'WARN'
                          ? 'text-amber-400'
                          : 'text-emerald-400'
                      }`}
                    >
                      [{entry.level}]
                    </span>
                    <span className="text-cyan-400">{entry.module}</span>
                    {entry.deviceHostname && (
                      <>
                        <span className="text-slate-600">·</span>
                        <span className="text-slate-200">{entry.deviceHostname}</span>
                      </>
                    )}
                  </div>
                  <p className="text-slate-300 font-sans text-xs">{entry.message}</p>
                </div>

                {typeof entry.latencyMs === 'number' && (
                  <span className="text-[11px] text-slate-400 tabular-nums shrink-0">
                    {entry.latencyMs} ms
                  </span>
                )}
              </div>
            ))}
          </div>
        </div>
      </div>
    </div>
  );
};

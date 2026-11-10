import React from 'react';
import {
  X,
  Cpu,
  HardDrive,
  Network,
  Package,
} from 'lucide-react';
import { DeviceAsset } from '../types/network';

interface DeviceDetailModalProps {
  device: DeviceAsset | null;
  lang: 'id' | 'en';
  onClose: () => void;
}

export const DeviceDetailModal: React.FC<DeviceDetailModalProps> = ({
  device,
  lang,
  onClose,
}) => {
  if (!device) return null;

  return (
    <div
      className="fixed inset-0 z-50 flex items-center justify-center bg-black/75 p-4"
      role="dialog"
      aria-modal="true"
      aria-labelledby="device-detail-title"
    >
      <div className="w-full max-w-2xl bg-[#161F30] border border-[#1E293B] rounded-xl p-6 space-y-5 shadow-2xl max-h-[88vh] overflow-y-auto">
        <div className="flex items-start justify-between gap-4 border-b border-[#1E293B] pb-4">
          <div>
            <h2 id="device-detail-title" className="text-base font-semibold text-white">
              {device.hostname}
            </h2>
            <p className="text-xs font-mono text-slate-400 mt-0.5">
              {device.ipAddress} · {device.macAddress} · {device.os} {device.osVersion} (
              {device.kernelArch})
            </p>
          </div>
          <button
            type="button"
            aria-label="Close Device Detail Modal"
            onClick={onClose}
            className="p-1.5 text-slate-400 hover:text-white rounded-lg cursor-pointer"
          >
            <X className="w-4 h-4" />
          </button>
        </div>

        <div className="grid grid-cols-1 sm:grid-cols-3 gap-3 text-xs">
          <div className="p-3.5 rounded-lg bg-[#0B0F17] border border-[#1E293B]">
            <div className="flex items-center gap-1.5 text-slate-400 mb-1">
              <Cpu className="w-3.5 h-3.5 text-emerald-400" />
              <span>Prosesor &amp; Beban</span>
            </div>
            <div className="font-semibold text-slate-100">{device.cpuModel}</div>
            <div className="font-mono tabular-nums text-emerald-400 mt-0.5">
              Utilisasi: {device.cpuUsagePct}% ({device.cpuCores} Cores)
            </div>
          </div>

          <div className="p-3.5 rounded-lg bg-[#0B0F17] border border-[#1E293B]">
            <div className="flex items-center gap-1.5 text-slate-400 mb-1">
              <HardDrive className="w-3.5 h-3.5 text-cyan-400" />
              <span>Memori &amp; Penyimpanan</span>
            </div>
            <div className="font-mono tabular-nums text-slate-100">
              RAM: {device.ramUsedGb} / {device.ramTotalGb} GB
            </div>
            <div className="font-mono tabular-nums text-slate-400 mt-0.5">
              Disk: {device.diskUsedGb} / {device.diskTotalGb} GB
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
                {device.software.map((sw, idx) => (
                  <tr key={idx}>
                    <td className="py-2 px-3 text-slate-200 font-medium">{sw.name}</td>
                    <td className="py-2 px-3 font-mono text-emerald-400">{sw.version}</td>
                    <td className="py-2 px-3 text-slate-400">{sw.publisher}</td>
                    <td className="py-2 px-3 text-right font-mono tabular-nums text-slate-400">
                      {sw.installDate}
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        </div>
      </div>
    </div>
  );
};

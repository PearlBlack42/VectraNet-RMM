import React, { useState } from 'react';
import {
  Users,
  Sliders,
  UserPlus,
  CheckCircle2,
  Shield,
} from 'lucide-react';
import { AdminUserEntry, EngineConfigState } from '../types/network';

interface AdminConfigViewProps {
  users: AdminUserEntry[];
  config: EngineConfigState;
  lang: 'id' | 'en';
  onAddUser: (user: AdminUserEntry) => void;
  onToggleUserStatus: (id: string) => void;
  onUpdateConfig: (next: EngineConfigState) => void;
}

export const AdminConfigView: React.FC<AdminConfigViewProps> = ({
  users,
  config,
  lang,
  onAddUser,
  onToggleUserStatus,
  onUpdateConfig,
}) => {
  const [fullName, setFullName] = useState('');
  const [email, setEmail] = useState('');
  const [role, setRole] = useState<AdminUserEntry['role']>('SecOps Engineer');
  const [userError, setUserError] = useState<string | null>(null);
  const [configSaved, setConfigSaved] = useState(false);

  const [draftConfig, setDraftConfig] = useState<EngineConfigState>(config);

  const handleCreateUser = (e: React.FormEvent) => {
    e.preventDefault();
    setUserError(null);
    if (fullName.trim().length < 3 || !email.includes('@')) {
      setUserError(
        lang === 'id'
          ? 'Masukkan nama lengkap (min. 3 karakter) dan email korporat yang valid.'
          : 'Please enter a valid full name (min. 3 chars) and corporate email.'
      );
      return;
    }

    onAddUser({
      id: `usr-${Date.now()}`,
      fullName: fullName.trim(),
      email: email.trim(),
      role,
      mfaEnabled: true,
      lastLogin: 'Belum pernah / Never',
      status: 'Active',
    });
    setFullName('');
    setEmail('');
  };

  const handleSaveConfig = (e: React.FormEvent) => {
    e.preventDefault();
    onUpdateConfig(draftConfig);
    setConfigSaved(true);
    setTimeout(() => setConfigSaved(false), 3000);
  };

  return (
    <div className="grid grid-cols-1 xl:grid-cols-12 gap-6 items-start">
      {/* RBAC User Management */}
      <div className="xl:col-span-6 bg-[#161F30] border border-[#1E293B] rounded-xl p-6 space-y-5">
        <div className="flex items-center gap-2.5 border-b border-[#1E293B] pb-4">
          <Users className="w-5 h-5 text-emerald-400" />
          <div>
            <h2 className="text-base font-semibold text-white">
              {lang === 'id'
                ? 'Manajemen Pengguna & Kontrol Akses (RBAC)'
                : 'Operator User Management & RBAC'}
            </h2>
            <p className="text-xs text-slate-400">
              {lang === 'id'
                ? 'Kelola hak akses operator untuk Push Deployment dan Credential Vault.'
                : 'Manage operator permissions for Remote Push Deployment and Credential Vault.'}
            </p>
          </div>
        </div>

        <form onSubmit={handleCreateUser} className="grid grid-cols-1 sm:grid-cols-3 gap-3" noValidate>
          <div>
            <label htmlFor="admin-fullname" className="block text-xs text-slate-300 mb-1">
              {lang === 'id' ? 'Nama Lengkap' : 'Full Name'}
            </label>
            <input
              id="admin-fullname"
              type="text"
              value={fullName}
              onChange={(e) => setFullName(e.target.value)}
              placeholder="Budi Santoso"
              className="w-full px-3 py-2 text-xs bg-[#0B0F17] border border-[#1E293B] rounded-lg text-slate-100"
            />
          </div>
          <div>
            <label htmlFor="admin-email" className="block text-xs text-slate-300 mb-1">
              Email Korporat
            </label>
            <input
              id="admin-email"
              type="email"
              value={email}
              onChange={(e) => setEmail(e.target.value)}
              placeholder="budi@vectranet.io"
              className="w-full px-3 py-2 text-xs bg-[#0B0F17] border border-[#1E293B] rounded-lg text-slate-100"
            />
          </div>
          <div>
            <label htmlFor="admin-role" className="block text-xs text-slate-300 mb-1">
              Peran (Role)
            </label>
            <select
              id="admin-role"
              value={role}
              onChange={(e) => setRole(e.target.value as AdminUserEntry['role'])}
              className="w-full px-3 py-2 text-xs bg-[#0B0F17] border border-[#1E293B] rounded-lg text-slate-100"
            >
              <option value="Super Admin">Super Admin</option>
              <option value="SecOps Engineer">SecOps Engineer</option>
              <option value="NOC Operator">NOC Operator</option>
              <option value="Read-Only Auditor">Read-Only Auditor</option>
            </select>
          </div>

          {userError && (
            <div className="sm:col-span-3 text-xs text-rose-400">{userError}</div>
          )}

          <div className="sm:col-span-3">
            <button
              type="submit"
              className="px-4 py-2 bg-emerald-500 hover:bg-emerald-400 text-slate-950 font-semibold text-xs rounded-lg transition-colors flex items-center gap-1.5 cursor-pointer"
            >
              <UserPlus className="w-3.5 h-3.5" />
              {lang === 'id' ? 'Tambah Operator RBAC' : 'Add RBAC Operator'}
            </button>
          </div>
        </form>

        <div className="space-y-2.5 pt-2">
          {users.map((u) => (
            <div
              key={u.id}
              className="p-3.5 rounded-lg bg-[#0B0F17] border border-[#1E293B] flex items-center justify-between gap-3"
            >
              <div>
                <div className="flex items-center gap-2">
                  <span className="text-sm font-semibold text-slate-100">{u.fullName}</span>
                  <span className="text-xs text-slate-400">·</span>
                  <span className="text-xs font-mono text-emerald-400">{u.role}</span>
                </div>
                <div className="text-xs text-slate-400 mt-0.5">
                  {u.email} · MFA: {u.mfaEnabled ? 'FIDO2/TOTP' : 'Off'} · Login: {u.lastLogin}
                </div>
              </div>

              <button
                type="button"
                onClick={() => onToggleUserStatus(u.id)}
                className={`px-3 py-1.5 text-xs font-medium rounded-lg border transition-colors cursor-pointer ${
                  u.status === 'Active'
                    ? 'bg-emerald-500/10 text-emerald-300 border-emerald-500/30'
                    : 'bg-rose-500/10 text-rose-300 border-rose-500/30'
                }`}
              >
                {u.status}
              </button>
            </div>
          ))}
        </div>
      </div>

      {/* Core Engine & Agent Policy Configuration */}
      <div className="xl:col-span-6 bg-[#161F30] border border-[#1E293B] rounded-xl p-6">
        <div className="flex items-center gap-2.5 border-b border-[#1E293B] pb-4 mb-5">
          <Sliders className="w-5 h-5 text-cyan-400" />
          <div>
            <h2 className="text-base font-semibold text-white">
              {lang === 'id'
                ? 'Konfigurasi Core Engine & Kebijakan Agen'
                : 'Core Engine & Agent Resource Policy Configuration'}
            </h2>
            <p className="text-xs text-slate-400">
              {lang === 'id'
                ? 'Parameter disinkronkan langsung ke semua agen melalui respons ingest berikutnya.'
                : 'Parameters sync automatically to connected agents on their next heartbeat frame.'}
            </p>
          </div>
        </div>

        <form onSubmit={handleSaveConfig} className="space-y-4">
          <div className="grid grid-cols-1 sm:grid-cols-2 gap-4">
            <div>
              <label
                htmlFor="cfg-heartbeat"
                className="block text-xs font-medium text-slate-300 mb-1"
              >
                Base Heartbeat Interval (detik)
              </label>
              <input
                id="cfg-heartbeat"
                type="number"
                value={draftConfig.baseHeartbeatSec}
                onChange={(e) =>
                  setDraftConfig({ ...draftConfig, baseHeartbeatSec: Number(e.target.value) })
                }
                className="w-full px-3 py-2 text-sm font-mono tabular-nums bg-[#0B0F17] border border-[#1E293B] rounded-lg text-slate-100"
              />
            </div>

            <div>
              <label
                htmlFor="cfg-ramcap"
                className="block text-xs font-medium text-slate-300 mb-1"
              >
                Batas Memori Agen / MemoryMax (MB)
              </label>
              <input
                id="cfg-ramcap"
                type="number"
                value={draftConfig.maxAgentRamMb}
                onChange={(e) =>
                  setDraftConfig({ ...draftConfig, maxAgentRamMb: Number(e.target.value) })
                }
                className="w-full px-3 py-2 text-sm font-mono tabular-nums bg-[#0B0F17] border border-[#1E293B] rounded-lg text-slate-100"
              />
            </div>

            <div>
              <label
                htmlFor="cfg-goroutines"
                className="block text-xs font-medium text-slate-300 mb-1"
              >
                Maksimal Goroutine IP Sweeper
              </label>
              <input
                id="cfg-goroutines"
                type="number"
                value={draftConfig.maxScannerGoroutines}
                onChange={(e) =>
                  setDraftConfig({
                    ...draftConfig,
                    maxScannerGoroutines: Number(e.target.value),
                  })
                }
                className="w-full px-3 py-2 text-sm font-mono tabular-nums bg-[#0B0F17] border border-[#1E293B] rounded-lg text-slate-100"
              />
            </div>

            <div>
              <label
                htmlFor="cfg-retention"
                className="block text-xs font-medium text-slate-300 mb-1"
              >
                Retensi Hypertable TimescaleDB (Hari)
              </label>
              <input
                id="cfg-retention"
                type="number"
                value={draftConfig.timescaleRetentionDays}
                onChange={(e) =>
                  setDraftConfig({
                    ...draftConfig,
                    timescaleRetentionDays: Number(e.target.value),
                  })
                }
                className="w-full px-3 py-2 text-sm font-mono tabular-nums bg-[#0B0F17] border border-[#1E293B] rounded-lg text-slate-100"
              />
            </div>
          </div>

          <div className="flex items-center justify-between p-3.5 rounded-lg bg-[#0B0F17] border border-[#1E293B]">
            <div>
              <div className="text-xs font-medium text-slate-200">
                Auto-Push Deployment pada Subnet Baru
              </div>
              <div className="text-[11px] text-slate-400">
                Deploy agen otomatis jika host baru merespons WinRM (5986) atau SSH (22)
              </div>
            </div>
            <input
              id="cfg-autopush"
              aria-label="Auto-Push Deployment pada Subnet Baru"
              type="checkbox"
              checked={draftConfig.autoPushNewSubnets}
              onChange={(e) =>
                setDraftConfig({ ...draftConfig, autoPushNewSubnets: e.target.checked })
              }
              className="w-4 h-4 accent-emerald-500 cursor-pointer"
            />
          </div>

          {configSaved && (
            <div className="p-3 rounded-lg bg-emerald-500/10 border border-emerald-500/30 text-xs text-emerald-300 flex items-center gap-2">
              <CheckCircle2 className="w-4 h-4 text-emerald-400" />
              <span>
                {lang === 'id'
                  ? 'Konfigurasi berhasil disimpan dan dipublikasikan ke agen aktif.'
                  : 'Configuration saved and broadcast to active agents.'}
              </span>
            </div>
          )}

          <button
            type="submit"
            className="w-full py-2.5 px-4 bg-emerald-500 hover:bg-emerald-400 text-slate-950 font-semibold text-xs rounded-lg transition-colors flex items-center justify-center gap-2 cursor-pointer"
          >
            <Shield className="w-4 h-4" />
            {lang === 'id'
              ? 'Terapkan Kebijakan Engine & Agen'
              : 'Apply Engine & Agent Policy'}
          </button>
        </form>
      </div>
    </div>
  );
};

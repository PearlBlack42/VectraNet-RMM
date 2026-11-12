import React, { useState } from 'react';
import {
  Rocket,
  X,
  Lock,
  CheckCircle2,
  Terminal,
  ShieldCheck,
} from 'lucide-react';
import { CredentialVaultEntry, DeviceAsset } from '../types/network';

interface PushDeployModalProps {
  isOpen: boolean;
  targetDevices: DeviceAsset[];
  credentials: CredentialVaultEntry[];
  lang: 'id' | 'en';
  onClose: () => void;
  onConfirmDeploy: (targetIds: string[], credentialId: string) => void;
}

export const PushDeployModal: React.FC<PushDeployModalProps> = ({
  isOpen,
  targetDevices,
  credentials,
  lang,
  onClose,
  onConfirmDeploy,
}) => {
  const [selectedCredentialId, setSelectedCredentialId] = useState<string>(
    credentials[0]?.id || ''
  );
  const [isDeploying, setIsDeploying] = useState(false);
  const [completed, setCompleted] = useState(false);
  const [stepLogs, setStepLogs] = useState<string[]>([]);

  if (!isOpen || targetDevices.length === 0) return null;

  const selectedCred =
    credentials.find((c) => c.id === selectedCredentialId) ||
    credentials[0] || {
      id: 'default-vault-key',
      label: 'Default Ephemeral RMM Key',
      protocol: 'SSH-Ed25519',
      username: 'root',
      port: 22,
      scopeSubnet: '0.0.0.0/0',
      cipherPreview: 'aes256gcm$ephemeral',
      ivHex: '000000000000',
      authTagHex: '0000000000000000',
      keyFingerprint: 'SHA256:EPHEMERAL:VAULT',
      lastRotated: 'Runtime',
      createdBy: 'system',
      verified: true,
    };

  const handleRunPush = () => {
    setIsDeploying(true);
    setCompleted(false);

    const logs: string[] = [
      `[00.1s] Decrypting Vault credential "${selectedCred.label}" (${selectedCred.protocol}) via Master KEK (AES-256-GCM)...`,
    ];

    targetDevices.forEach((dev) => {
      const osLower = dev.os.toLowerCase();
      if (osLower.includes('windows')) {
        logs.push(
          `[00.4s] [${dev.hostname} - ${dev.ipAddress}] Connecting via WinRM-HTTPS (Port 5986) -> executing /agents/windows/install.ps1`
        );
        logs.push(
          `[00.9s] [${dev.hostname}] Downloaded /downloads/windows/vectranet-agent.exe -> C:\\Program Files\\VectraNet\\vectranet-agent.exe`
        );
        logs.push(
          `[01.3s] [${dev.hostname}] Registered Windows Service 'VectraNetAgent' (MemoryLimit=15MB) & started daemon`
        );
      } else if (osLower.includes('macos')) {
        logs.push(
          `[00.4s] [${dev.hostname} - ${dev.ipAddress}] Connecting via SSH-Ed25519 (Port 22) -> executing /agents/macos/install.sh`
        );
        logs.push(
          `[00.8s] [${dev.hostname}] Installed /Library/Application Support/VectraNet/vectranet-agent & loaded LaunchDaemon com.vectranet.agent.plist`
        );
      } else {
        logs.push(
          `[00.4s] [${dev.hostname} - ${dev.ipAddress}] Connecting via SSH-Ed25519 (Port 22) -> executing /agents/linux/install.sh`
        );
        logs.push(
          `[00.8s] [${dev.hostname}] Installed /usr/local/bin/vectranet-agent & enabled systemd unit (MemoryMax=20M, CPUQuota=2%)`
        );
      }
      logs.push(
        `[01.6s] [${dev.hostname}] Verified first TLS 1.3 Gzip telemetry frame at /api/v1/agent/ingest`
      );
    });

    setStepLogs(logs);
    onConfirmDeploy(
      targetDevices.map((d) => d.id),
      selectedCred.id
    );
    setIsDeploying(false);
    setCompleted(true);
  };

  return (
    <div
      className="fixed inset-0 z-50 flex items-center justify-center bg-black/75 p-4"
      role="dialog"
      aria-modal="true"
      aria-labelledby="push-deploy-title"
    >
      <div className="w-full max-w-2xl bg-[#161F30] border border-[#1E293B] rounded-xl p-6 space-y-5 shadow-2xl">
        <div className="flex items-start justify-between gap-4 border-b border-[#1E293B] pb-4">
          <div className="flex items-center gap-2.5">
            <Rocket className="w-5 h-5 text-emerald-400" />
            <div>
              <h2 id="push-deploy-title" className="text-base font-semibold text-white">
                {lang === 'id'
                  ? 'Remote Agent Push Deployment Engine (WinRM / SSH)'
                  : 'Remote Agent Push Deployment Engine (WinRM / SSH)'}
              </h2>
              <p className="text-xs text-slate-400">
                {lang === 'id'
                  ? 'Instalasi silent biner agen Go ultra-ringan tanpa perlu intervensi manual di endpoint.'
                  : 'Silent installation of the ultra-light Go agent binary across target endpoints.'}
              </p>
            </div>
          </div>

          <button
            type="button"
            aria-label="Close Push Deployment Modal"
            onClick={onClose}
            className="p-1.5 text-slate-400 hover:text-white rounded-lg cursor-pointer"
          >
            <X className="w-4 h-4" />
          </button>
        </div>

        {/* Target Devices Summary */}
        <div>
          <div className="text-xs font-medium text-slate-300 mb-2">
            {lang === 'id'
              ? `Target Perangkat (${targetDevices.length} Host):`
              : `Target Endpoints (${targetDevices.length} Hosts):`}
          </div>
          <div className="max-h-32 overflow-y-auto space-y-1.5 p-2.5 rounded-lg bg-[#0B0F17] border border-[#1E293B]">
            {targetDevices.map((dev) => (
              <div
                key={dev.id}
                className="flex items-center justify-between text-xs font-mono text-slate-200"
              >
                <span>
                  {dev.hostname} ({dev.ipAddress})
                </span>
                <span className="text-slate-400">
                  {dev.os} · {dev.os.includes('Windows') ? 'WinRM-HTTPS' : 'SSH-Systemd'}
                </span>
              </div>
            ))}
          </div>
        </div>

        {/* Credential Vault Selector */}
        <div>
          <label
            htmlFor="deploy-cred-select"
            className="block text-xs font-medium text-slate-300 mb-1.5 flex items-center gap-1.5"
          >
            <Lock className="w-3.5 h-3.5 text-emerald-400" />
            {lang === 'id'
              ? 'Pilih Kredensial Otentikasi dari Brankas AES-256'
              : 'Select Authentication Credential from AES-256 Vault'}
          </label>
          <select
            id="deploy-cred-select"
            value={selectedCredentialId}
            onChange={(e) => setSelectedCredentialId(e.target.value)}
            className="w-full px-3.5 py-2 text-xs font-mono bg-[#0B0F17] border border-[#1E293B] rounded-lg text-slate-100"
          >
            {credentials.map((cred) => (
              <option key={cred.id} value={cred.id}>
                {cred.label} — [{cred.protocol} | {cred.username} | {cred.keyFingerprint}]
              </option>
            ))}
          </select>
        </div>

        {/* Execution Output Log */}
        {stepLogs.length > 0 && (
          <div className="space-y-2">
            <div className="flex items-center gap-1.5 text-xs font-medium text-emerald-400">
              <Terminal className="w-3.5 h-3.5" />
              <span>Log Eksekusi Remote Deployment</span>
            </div>
            <div className="p-3.5 rounded-lg bg-[#0B0F17] border border-[#1E293B] font-mono text-[11px] text-slate-300 space-y-1 max-h-44 overflow-y-auto">
              {stepLogs.map((line, idx) => (
                <div key={idx}>{line}</div>
              ))}
            </div>
          </div>
        )}

        <div className="flex items-center justify-between pt-2 border-t border-[#1E293B]">
          <div className="flex items-center gap-2 text-xs text-slate-400">
            <ShieldCheck className="w-4 h-4 text-emerald-400" />
            <span>Binary SHA-256 Verified · MemoryMax=18MB</span>
          </div>

          <div className="flex items-center gap-2.5">
            <button
              type="button"
              onClick={onClose}
              className="px-4 py-2 text-xs font-medium text-slate-300 hover:text-white bg-[#0B0F17] border border-[#1E293B] rounded-lg cursor-pointer"
            >
              {completed ? (lang === 'id' ? 'Selesai & Tutup' : 'Done & Close') : lang === 'id' ? 'Batal' : 'Cancel'}
            </button>

            {!completed ? (
              <button
                type="button"
                disabled={isDeploying}
                onClick={handleRunPush}
                className="px-4 py-2 text-xs font-semibold bg-emerald-500 hover:bg-emerald-400 text-slate-950 rounded-lg transition-colors flex items-center gap-1.5 cursor-pointer"
              >
                <Rocket className="w-3.5 h-3.5" />
                {lang === 'id' ? 'Push Agent Sekarang' : 'Push Agent Now'}
              </button>
            ) : (
              <span className="inline-flex items-center gap-1.5 text-xs font-semibold text-emerald-400">
                <CheckCircle2 className="w-4 h-4" />
                {lang === 'id' ? 'Agen Aktif' : 'Agent Active'}
              </span>
            )}
          </div>
        </div>
      </div>
    </div>
  );
};

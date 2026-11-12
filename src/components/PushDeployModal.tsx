import React, { useState, useEffect } from 'react';
import {
  Rocket,
  X,
  Lock,
  CheckCircle2,
  AlertTriangle,
  Terminal,
  ShieldCheck,
  RefreshCw,
  Copy,
  Check,
  Wrench,
  Radar,
  Code2,
} from 'lucide-react';
import {
  CredentialVaultEntry,
  DeployExecutionResult,
  DeviceAsset,
} from '../types/network';
import { resolveStandardPortForProtocol } from '../utils/networkEngine';

interface PushDeployModalProps {
  isOpen: boolean;
  targetDevices: DeviceAsset[];
  credentials: CredentialVaultEntry[];
  lang: 'id' | 'en';
  onClose: () => void;
  onConfirmDeploy: (
    targetIds: string[],
    credentialId: string,
    targetDevices: DeviceAsset[]
  ) => Promise<DeployExecutionResult>;
}

const DEFAULT_POWERSHELL_FIREWALL_FIX = `Enable-PSRemoting -Force; Set-Item WSMan:\\localhost\\Client\\TrustedHosts -Value '*' -Force; reg add HKLM\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Policies\\System /v LocalAccountTokenFilterPolicy /t REG_DWORD /d 1 /f; Enable-NetFirewallRule -DisplayGroup "Windows Management Instrumentation (WMI)","Windows Remote Management" -ErrorAction SilentlyContinue; New-NetFirewallRule -DisplayName "VectraNet-RMM-Ports" -Direction Inbound -LocalPort 5985,5986,135,445 -Protocol TCP -Action Allow`;

function buildManualAgentOneLiner(serverOrigin: string, targetIp?: string): string {
  const ipExpr = targetIp
    ? `'${targetIp}'`
    : `(Get-NetIPAddress -AddressFamily IPv4 | Where-Object { $_.IPAddress -notlike '127.*' -and $_.IPAddress -notlike '169.254.*' } | Select-Object -First 1).IPAddress`;
  return `$srv='${serverOrigin}'; $cs=Get-CimInstance Win32_ComputerSystem; $os=Get-CimInstance Win32_OperatingSystem; $cpu=@(Get-CimInstance Win32_Processor)[0]; $dk=Get-CimInstance Win32_LogicalDisk -Filter "DeviceID='C:'"; $body=@{agent_version='v2.4.2-ps-manual';hostname=$env:COMPUTERNAME;ip_address=${ipExpr};os_family='Windows';os_version=$os.Caption;kernel_arch='windows/amd64';cpu_model=$cpu.Name;cpu_cores=[int]$cs.NumberOfLogicalProcessors;cpu_usage_pct=[double]$cpu.LoadPercentage;ram_total_gb=[math]::Round($os.TotalVisibleMemorySize/1MB,2);ram_used_gb=[math]::Round(($os.TotalVisibleMemorySize-$os.FreePhysicalMemory)/1MB,2);disk_total_gb=[math]::Round($dk.Size/1GB,2);disk_used_gb=[math]::Round(($dk.Size-$dk.FreeSpace)/1GB,2);agent_rss_mb=11.8} | ConvertTo-Json -Compress; Invoke-RestMethod -Uri "$srv/api/v1/agent/ingest" -Method Post -ContentType 'application/json' -Body $body`;
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
  const [deployFailed, setDeployFailed] = useState(false);
  const [deployErrorText, setDeployErrorText] = useState<string | null>(null);
  const [stepLogs, setStepLogs] = useState<string[]>([]);
  const [copiedFirewallCmd, setCopiedFirewallCmd] = useState(false);
  const [copiedManualAgentCmd, setCopiedManualAgentCmd] = useState(false);

  // Reset modal execution state ONLY when modal opens or target device list changes
  const targetKey = targetDevices.map((d) => `${d.id}:${d.ipAddress}`).join(',');
  useEffect(() => {
    if (isOpen) {
      setIsDeploying(false);
      setCompleted(false);
      setDeployFailed(false);
      setDeployErrorText(null);
      setStepLogs([]);
      setCopiedFirewallCmd(false);
      setCopiedManualAgentCmd(false);
    }
  }, [isOpen, targetKey]);

  // Keep selectedCredentialId synced when credentials list updates without resetting logs
  useEffect(() => {
    if (
      credentials.length > 0 &&
      (!selectedCredentialId || !credentials.some((c) => c.id === selectedCredentialId))
    ) {
      setSelectedCredentialId(credentials[0].id);
    }
  }, [credentials, selectedCredentialId]);

  if (!isOpen || targetDevices.length === 0) return null;

  const selectedCred =
    credentials.find((c) => c.id === selectedCredentialId) || credentials[0] || null;

  const serverOrigin =
    typeof window !== 'undefined' && window.location?.origin
      ? window.location.origin
      : 'http://localhost:8080';
  const primaryTargetIp = targetDevices.length === 1 ? targetDevices[0].ipAddress : undefined;
  const manualInstallScript = buildManualAgentOneLiner(serverOrigin, primaryTargetIp);

  const handleCopyText = async (text: string, type: 'firewall' | 'manual') => {
    try {
      await navigator.clipboard.writeText(text);
      if (type === 'firewall') {
        setCopiedFirewallCmd(true);
        setTimeout(() => setCopiedFirewallCmd(false), 2500);
      } else {
        setCopiedManualAgentCmd(true);
        setTimeout(() => setCopiedManualAgentCmd(false), 2500);
      }
    } catch {
      // Ignore clipboard permission errors
    }
  };

  const handleRunPush = async () => {
    if (!selectedCred) {
      setDeployFailed(true);
      setDeployErrorText(
        lang === 'id'
          ? 'Brankas Kredensial (Credential Vault) masih kosong. Silakan tambahkan profil kredensial universal terlebih dahulu di tab Credential Vault.'
          : 'Credential Vault is empty. Please add a universal credential profile in the Credential Vault tab first.'
      );
      setStepLogs([
        `[00.0s] [ERROR] Tidak ada profil kredensial di Credential Vault. Membatalkan Push Deployment ke ${targetDevices
          .map((d) => `${d.hostname} (${d.ipAddress})`)
          .join(', ')}.`,
      ]);
      return;
    }

    setIsDeploying(true);
    setCompleted(false);
    setDeployFailed(false);
    setDeployErrorText(null);

    const stdPort = resolveStandardPortForProtocol(selectedCred.protocol);
    const targetListStr = targetDevices
      .map((d) => `${d.hostname} (${d.ipAddress})`)
      .join(', ');

    setStepLogs([
      `[00.1s] Mengirim instruksi Push Deployment ke backend (/api/v1/deploy)...`,
      `[00.1s] Target Dinamis: ${targetListStr}`,
      `[00.1s] Kredensial Universal: "${selectedCred.label}" [User: ${selectedCred.username} | Protokol: ${selectedCred.protocol} (Port Standar: ${stdPort})]`,
      `[00.2s] [SMART-PROBE] Memetakan port sesuai protokol standar (5986/WinRM-HTTPS, 5985/WinRM-HTTP, 135/DCOM-RPC, 445/Native-Go-SMB-Service, 22/SSH)...`,
    ]);

    try {
      const result = await onConfirmDeploy(
        targetDevices.map((d) => d.id),
        selectedCred.id,
        targetDevices
      );

      if (Array.isArray(result.logs) && result.logs.length > 0) {
        setStepLogs(result.logs);
      }

      if (result.status === 'deployed' && result.deployedCount > 0) {
        setCompleted(true);
        setDeployFailed(result.failedCount ? result.failedCount > 0 : false);
        if (result.failedCount && result.failedCount > 0) {
          setDeployErrorText(
            lang === 'id'
              ? `Berhasil pada ${result.deployedCount} host, gagal pada ${result.failedCount} host.`
              : `Succeeded on ${result.deployedCount} host(s), failed on ${result.failedCount} host(s).`
          );
        }
      } else {
        setCompleted(false);
        setDeployFailed(true);
        setDeployErrorText(
          result.error ||
            (lang === 'id'
              ? 'Koneksi atau otentikasi ke target gagal. Gunakan salah satu skrip PowerShell 1-baris di bawah pada PC target.'
              : 'Target connection or authentication failed. Use one of the 1-line PowerShell scripts below on the target PC.')
        );
      }
    } catch (err) {
      setCompleted(false);
      setDeployFailed(true);
      const errMsg = (err as Error).message || 'Network error';
      setDeployErrorText(errMsg);
      setStepLogs((prev) => [...prev, `[ERROR] Eksekusi gagal: ${errMsg}`]);
    } finally {
      setIsDeploying(false);
    }
  };

  return (
    <div
      className="fixed inset-0 z-50 flex items-center justify-center bg-black/75 p-4 overflow-y-auto"
      role="dialog"
      aria-modal="true"
      aria-labelledby="push-deploy-title"
    >
      <div className="w-full max-w-2xl bg-[#161F30] border border-[#1E293B] rounded-xl p-6 space-y-4 shadow-2xl my-auto max-h-[92vh] overflow-y-auto">
        <div className="flex items-start justify-between gap-4 border-b border-[#1E293B] pb-4">
          <div className="flex items-center gap-2.5">
            <Rocket className="w-5 h-5 text-emerald-400" />
            <div>
              <h2 id="push-deploy-title" className="text-base font-semibold text-white">
                {lang === 'id'
                  ? 'Smart Port Mapping & Multi-Protocol Push Deployment'
                  : 'Smart Port Mapping & Multi-Protocol Push Deployment'}
              </h2>
              <p className="text-xs text-slate-400">
                {lang === 'id'
                  ? 'Pemetaan ketat protokol-ke-port (WinRM-HTTPS:5986, HTTP:5985, RPC:135, Native Go SMB/SCM:445, SSH:22).'
                  : 'Strict protocol-to-port mapping (WinRM-HTTPS:5986, HTTP:5985, RPC:135, Native Go SMB/SCM:445, SSH:22).'}
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
          <div className="flex items-center justify-between mb-2">
            <span className="text-xs font-medium text-slate-300">
              {lang === 'id'
                ? `Target Perangkat Dinamis (${targetDevices.length} Host):`
                : `Dynamic Target Endpoints (${targetDevices.length} Hosts):`}
            </span>
            <span className="inline-flex items-center gap-1 text-[11px] font-mono text-cyan-300 bg-cyan-500/10 px-2 py-0.5 rounded border border-cyan-500/20">
              <Radar className="w-3 h-3" />
              Strict Map: 5986(HTTPS) · 5985(HTTP) · 135(RPC) · 445(SMB-Go) · 22(SSH)
            </span>
          </div>
          <div className="max-h-28 overflow-y-auto space-y-1.5 p-2.5 rounded-lg bg-[#0B0F17] border border-[#1E293B]">
            {targetDevices.map((dev) => {
              const stdPort = selectedCred
                ? resolveStandardPortForProtocol(selectedCred.protocol)
                : 5986;
              return (
                <div
                  key={dev.id}
                  className="flex items-center justify-between text-xs font-mono text-slate-200"
                >
                  <span className="text-emerald-300 font-semibold">
                    {dev.hostname} ({dev.ipAddress})
                  </span>
                  <span className="text-slate-400">
                    {dev.os} ·{' '}
                    {selectedCred
                      ? `${selectedCred.protocol} (Standar :${stdPort}) + Native RPC/SMB Fallback`
                      : 'Auto-Detect (5986/5985/135/445/22)'}
                  </span>
                </div>
              );
            })}
          </div>
        </div>

        {/* Universal Credential Vault Selector */}
        <div>
          <label
            htmlFor="deploy-cred-select"
            className="block text-xs font-medium text-slate-300 mb-1.5 flex items-center gap-1.5"
          >
            <Lock className="w-3.5 h-3.5 text-emerald-400" />
            {lang === 'id'
              ? 'Pilih Kredensial Universal dari Brankas AES-256-GCM'
              : 'Select Universal Credential from AES-256-GCM Vault'}
          </label>
          {credentials.length === 0 ? (
            <div className="p-3 rounded-lg bg-rose-500/10 border border-rose-500/30 text-xs text-rose-300">
              {lang === 'id'
                ? 'Brankas Kredensial masih kosong. Tambahkan kredensial universal (misal profil edp07) di menu Credential Vault terlebih dahulu.'
                : 'Credential Vault is empty. Please add a universal credential profile in Credential Vault first.'}
            </div>
          ) : (
            <select
              id="deploy-cred-select"
              value={selectedCredentialId}
              disabled={isDeploying}
              onChange={(e) => {
                setSelectedCredentialId(e.target.value);
                setCompleted(false);
                setDeployFailed(false);
                setDeployErrorText(null);
              }}
              className="w-full px-3.5 py-2 text-xs font-mono bg-[#0B0F17] border border-[#1E293B] rounded-lg text-slate-100 focus:outline-none focus:border-emerald-500"
            >
              {credentials.map((cred) => {
                const stdPort = resolveStandardPortForProtocol(cred.protocol);
                return (
                  <option key={cred.id} value={cred.id}>
                    {cred.label} — [{cred.protocol} (Standar :{stdPort}) | User: {cred.username} |
                    Universal | {cred.keyFingerprint}]
                  </option>
                );
              })}
            </select>
          )}
        </div>

        {/* Execution Output Log */}
        {stepLogs.length > 0 && (
          <div className="space-y-2">
            <div className="flex items-center justify-between text-xs font-medium">
              <span className="flex items-center gap-1.5 text-emerald-400">
                <Terminal className="w-3.5 h-3.5" />
                <span>
                  {lang === 'id'
                    ? 'Log Eksekusi Remote Deployment & Smart Port Mapping'
                    : 'Live Remote Deployment & Smart Port Mapping Log'}
                </span>
              </span>
              {selectedCred && (
                <span className="font-mono text-[11px] text-slate-400">
                  Target: {targetDevices.map((d) => d.ipAddress).join(', ')} · Profile:{' '}
                  {selectedCred.label}
                </span>
              )}
            </div>
            <div className="p-3.5 rounded-lg bg-[#0B0F17] border border-[#1E293B] font-mono text-[11px] space-y-1.5 max-h-44 overflow-y-auto">
              {stepLogs.map((line, idx) => {
                const isErr = line.includes('[ERROR]');
                const isOk = line.includes('[OK]') || line.includes('[SUCCESS]');
                const isProbe = line.includes('[SMART-PROBE]');
                const isFallback =
                  line.includes('[AUTO-FALLBACK]') || line.includes('[SMB-RPC-NATIVE]');
                const isRemediation =
                  line.includes('[REMEDIATION-POWERSHELL]') || line.includes('[MANUAL-INSTALL]');
                return (
                  <div
                    key={idx}
                    className={
                      isErr
                        ? 'text-rose-400 font-medium'
                        : isOk
                        ? 'text-emerald-400 font-medium'
                        : isFallback
                        ? 'text-amber-300 font-medium'
                        : isRemediation
                        ? 'text-amber-200 bg-amber-500/10 p-1.5 rounded border border-amber-500/30'
                        : isProbe
                        ? 'text-cyan-300'
                        : 'text-slate-300'
                    }
                  >
                    {line}
                  </div>
                );
              })}
            </div>
          </div>
        )}

        {/* Error Banner when automatic push is blocked by target firewall */}
        {deployFailed && deployErrorText && (
          <div
            role="alert"
            className="p-3 rounded-lg bg-rose-500/10 border border-rose-500/30 text-xs text-rose-300 flex items-start gap-2"
          >
            <AlertTriangle className="w-4 h-4 text-rose-400 shrink-0 mt-0.5" />
            <div>
              <div className="font-semibold text-rose-300">
                {lang === 'id'
                  ? 'Push Otomatis Tertahan Firewall / Otentikasi Target — Gunakan Salah Satu Opsi PowerShell di Bawah'
                  : 'Automated Push Blocked by Target Firewall / Auth — Use Either PowerShell Option Below'}
              </div>
              <div className="text-[11px] text-rose-200/90 mt-0.5 font-mono">
                {deployErrorText}
              </div>
            </div>
          </div>
        )}

        {/* Manual One-Liner Agent Install & Firewall Remediation Section (Always available or highlighted on failure) */}
        <div className="space-y-3 pt-1">
          {/* Option 1: Direct One-Line Manual Agent Install (Bypasses Target Incoming Firewall) */}
          <div className="p-3.5 rounded-lg bg-[#0B0F17] border border-emerald-500/30 space-y-2">
            <div className="flex items-center justify-between gap-2">
              <div className="flex items-center gap-1.5 text-xs font-semibold text-emerald-300">
                <Code2 className="w-3.5 h-3.5 text-emerald-400" />
                <span>
                  {lang === 'id'
                    ? `Alternatif 1: Instalasi & Push Agen Manual 1-Baris di PC Target (Tanpa Perlu Buka Port Masuk)`
                    : `Option 1: One-Line Manual Agent Install on Target PC (Bypasses Incoming Firewall)`}
                </span>
              </div>
              <button
                type="button"
                onClick={() => void handleCopyText(manualInstallScript, 'manual')}
                className="inline-flex items-center gap-1.5 px-2.5 py-1 rounded bg-emerald-500/20 hover:bg-emerald-500/30 text-emerald-200 border border-emerald-500/40 text-[11px] font-medium transition-colors cursor-pointer"
              >
                {copiedManualAgentCmd ? (
                  <>
                    <Check className="w-3 h-3 text-emerald-400" />
                    <span className="text-emerald-300">
                      {lang === 'id' ? 'Skrip Agen Tersalin!' : 'Agent Script Copied!'}
                    </span>
                  </>
                ) : (
                  <>
                    <Copy className="w-3 h-3" />
                    <span>
                      {lang === 'id'
                        ? 'Salin Skrip Agen 1-Baris'
                        : 'Copy 1-Line Agent Script'}
                    </span>
                  </>
                )}
              </button>
            </div>
            <p className="text-[11px] text-slate-300">
              {lang === 'id'
                ? 'Jika Push otomatis tertahan firewall PC target, jalankan perintah PowerShell 1-baris ini langsung di PC target untuk membaca CPU/RAM/Disk asli dan mengaktifkan agen secara instan:'
                : 'If automated Push is blocked by the target firewall, run this 1-line PowerShell script on the target PC to read real CPU/RAM/Disk metrics and activate the agent immediately:'}
            </p>
            <pre className="p-2.5 rounded bg-[#161F30] border border-[#1E293B] text-[10px] font-mono text-emerald-300 overflow-x-auto whitespace-pre-wrap break-all select-all">
              {manualInstallScript}
            </pre>
          </div>

          {/* Option 2: Enable WinRM & Open Firewall on Target PC */}
          {deployFailed && (
            <div className="p-3.5 rounded-lg bg-[#0B0F17] border border-amber-500/40 space-y-2">
              <div className="flex items-center justify-between gap-2">
                <div className="flex items-center gap-1.5 text-xs font-semibold text-amber-300">
                  <Wrench className="w-3.5 h-3.5 text-amber-400" />
                  <span>
                    {lang === 'id'
                      ? `Alternatif 2: Buka Firewall & Aktifkan WinRM/RPC di PC Target (${targetDevices
                          .map((d) => d.ipAddress)
                          .join(', ')})`
                      : `Option 2: Enable WinRM/RPC & Firewall on Target PC (${targetDevices
                          .map((d) => d.ipAddress)
                          .join(', ')})`}
                  </span>
                </div>
                <button
                  type="button"
                  onClick={() => void handleCopyText(DEFAULT_POWERSHELL_FIREWALL_FIX, 'firewall')}
                  className="inline-flex items-center gap-1.5 px-2.5 py-1 rounded bg-amber-500/20 hover:bg-amber-500/30 text-amber-200 border border-amber-500/40 text-[11px] font-medium transition-colors cursor-pointer"
                >
                  {copiedFirewallCmd ? (
                    <>
                      <Check className="w-3 h-3 text-emerald-400" />
                      <span className="text-emerald-300">
                        {lang === 'id' ? 'Tersalin!' : 'Copied!'}
                      </span>
                    </>
                  ) : (
                    <>
                      <Copy className="w-3 h-3" />
                      <span>
                        {lang === 'id' ? 'Salin Perintah Firewall' : 'Copy Firewall Command'}
                      </span>
                    </>
                  )}
                </button>
              </div>
              <p className="text-[11px] text-slate-300">
                {lang === 'id'
                  ? 'Buka PowerShell (Run as Administrator) pada komputer target untuk membuka port standar WinRM (5985/5986) dan RPC/SMB (135/445), lalu klik "Coba Push Ulang":'
                  : 'Run in PowerShell (Admin) on the target PC to open standard WinRM (5985/5986) & RPC/SMB (135/445) ports, then click "Retry Push Agent":'}
              </p>
              <pre className="p-2.5 rounded bg-[#161F30] border border-[#1E293B] text-[10px] font-mono text-amber-200 overflow-x-auto whitespace-pre-wrap break-all select-all">
                {DEFAULT_POWERSHELL_FIREWALL_FIX}
              </pre>
            </div>
          )}
        </div>

        <div className="flex items-center justify-between pt-2 border-t border-[#1E293B]">
          <div className="flex items-center gap-2 text-xs text-slate-400">
            <ShieldCheck className="w-4 h-4 text-emerald-400" />
            <span>AES-256-GCM Unseal · Strict Protocol-Port Map + Native Go SMB/RPC</span>
          </div>

          <div className="flex items-center gap-2.5">
            <button
              type="button"
              onClick={onClose}
              className="px-4 py-2 text-xs font-medium text-slate-300 hover:text-white bg-[#0B0F17] border border-[#1E293B] rounded-lg cursor-pointer"
            >
              {completed || deployFailed
                ? lang === 'id'
                  ? 'Tutup'
                  : 'Close'
                : lang === 'id'
                ? 'Batal'
                : 'Cancel'}
            </button>

            {!completed ? (
              <button
                type="button"
                disabled={isDeploying || credentials.length === 0}
                onClick={() => void handleRunPush()}
                className="px-4 py-2 text-xs font-semibold bg-emerald-500 hover:bg-emerald-400 disabled:opacity-50 text-slate-950 rounded-lg transition-colors flex items-center gap-1.5 cursor-pointer"
              >
                {isDeploying ? (
                  <>
                    <RefreshCw className="w-3.5 h-3.5 animate-spin" />
                    <span>
                      {lang === 'id'
                        ? 'Memetakan Port & Deploy...'
                        : 'Mapping Ports & Deploying...'}
                    </span>
                  </>
                ) : (
                  <>
                    <Rocket className="w-3.5 h-3.5" />
                    <span>
                      {deployFailed
                        ? lang === 'id'
                          ? 'Coba Push Ulang'
                          : 'Retry Push Agent'
                        : lang === 'id'
                        ? 'Push Agent Sekarang'
                        : 'Push Agent Now'}
                    </span>
                  </>
                )}
              </button>
            ) : (
              <span className="inline-flex items-center gap-1.5 text-xs font-semibold text-emerald-400">
                <CheckCircle2 className="w-4 h-4" />
                {lang === 'id' ? 'Agen Aktif (Terverifikasi)' : 'Agent Active (Verified)'}
              </span>
            )}
          </div>
        </div>
      </div>
    </div>
  );
};

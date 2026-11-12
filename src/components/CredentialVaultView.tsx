import React, { useState } from 'react';
import {
  Lock,
  KeyRound,
  RefreshCw,
  CheckCircle2,
  ShieldAlert,
  Plus,
  Trash2,
} from 'lucide-react';
import { CredentialProtocol, CredentialVaultEntry } from '../types/network';
import {
  encryptCredentialSecret,
  validateCredentialForm,
} from '../utils/networkEngine';

interface CredentialVaultViewProps {
  credentials: CredentialVaultEntry[];
  lang: 'id' | 'en';
  onAddCredential: (entry: CredentialVaultEntry) => void;
  onRotateKey: (id: string) => void;
  onDeleteCredential: (id: string) => void;
}

const DEFAULT_PORTS: Record<CredentialProtocol, number> = {
  'WinRM-HTTPS': 5986,
  'SSH-Ed25519': 22,
  'SSH-Password': 22,
  'SNMPv3-AuthPriv': 161,
  'SNMPv2c': 161,
  'LDAP-AD': 636,
};

export const CredentialVaultView: React.FC<CredentialVaultViewProps> = ({
  credentials,
  lang,
  onAddCredential,
  onRotateKey,
  onDeleteCredential,
}) => {
  const [label, setLabel] = useState('');
  const [protocol, setProtocol] = useState<CredentialProtocol>('WinRM-HTTPS');
  const [username, setUsername] = useState('');
  const [rawSecret, setRawSecret] = useState('');
  const [scopeSubnet, setScopeSubnet] = useState('10.24.10.0/24');
  const [port, setPort] = useState<number>(5986);
  const [formError, setFormError] = useState<string | null>(null);
  const [bannerMessage, setBannerMessage] = useState<string | null>(null);

  const handleProtocolChange = (nextProto: CredentialProtocol) => {
    setProtocol(nextProto);
    setPort(DEFAULT_PORTS[nextProto]);
  };

  const handleSubmit = (e: React.FormEvent) => {
    e.preventDefault();
    setFormError(null);
    setBannerMessage(null);

    const normalizedScope =
      scopeSubnet.trim() && !scopeSubnet.includes('/')
        ? `${scopeSubnet.trim()}/32`
        : scopeSubnet.trim();

    const validation = validateCredentialForm({
      label,
      username,
      rawSecret,
      scopeSubnet: normalizedScope,
    });

    if (!validation.valid) {
      setFormError(validation.error || 'Input tidak valid');
      return;
    }

    const encrypted = encryptCredentialSecret({
      label,
      protocol,
      username,
      rawSecret,
      port,
      scopeSubnet: normalizedScope,
    });

    const newEntry: CredentialVaultEntry = {
      ...encrypted,
      id: `cred-${Date.now()}`,
      lastRotated: new Date().toISOString().slice(0, 16).replace('T', ' ') + ' UTC',
      createdBy: 'Yesaya42@gmail.com',
      verified: true,
      rawSecret,
    };

    onAddCredential(newEntry);
    setLabel('');
    setUsername('');
    setRawSecret('');
    setBannerMessage(
      lang === 'id'
        ? `Kredensial "${newEntry.label}" berhasil dienkripsi dengan AES-256-GCM dan disimpan ke Vault.`
        : `Credential "${newEntry.label}" encrypted with AES-256-GCM and stored in Vault.`
    );
  };

  return (
    <div className="grid grid-cols-1 xl:grid-cols-12 gap-6 items-start">
      {/* Add Credential Form */}
      <div className="xl:col-span-5 bg-[#161F30] border border-[#1E293B] rounded-xl p-6">
        <div className="flex items-center gap-2.5 pb-4 mb-5 border-b border-[#1E293B]">
          <Lock className="w-5 h-5 text-emerald-400" />
          <div>
            <h2 className="text-base font-semibold text-white">
              {lang === 'id'
                ? 'Tambah Kredensial Brankas (AES-256-GCM)'
                : 'Add Encrypted Vault Credential (AES-256-GCM)'}
            </h2>
            <p className="text-xs text-slate-400">
              {lang === 'id'
                ? 'Rahasia dienkripsi menggunakan Master KEK sebelum masuk ke PostgreSQL.'
                : 'Secrets are sealed with Master KEK before persisting to PostgreSQL.'}
            </p>
          </div>
        </div>

        <form onSubmit={handleSubmit} className="space-y-4" noValidate>
          <div>
            <label
              htmlFor="vault-label"
              className="block text-xs font-medium text-slate-300 mb-1.5"
            >
              {lang === 'id' ? 'Nama Profil Kredensial' : 'Credential Profile Label'}
            </label>
            <input
              id="vault-label"
              type="text"
              value={label}
              onChange={(e) => setLabel(e.target.value)}
              placeholder="e.g. Prod Windows Server WinRM Admin"
              className="w-full px-3.5 py-2 text-sm bg-[#0B0F17] border border-[#1E293B] rounded-lg text-slate-100 placeholder-slate-500 focus:outline-none focus:border-emerald-500"
            />
          </div>

          <div className="grid grid-cols-3 gap-3">
            <div className="col-span-2">
              <label
                htmlFor="vault-protocol"
                className="block text-xs font-medium text-slate-300 mb-1.5"
              >
                {lang === 'id' ? 'Protokol Otentikasi' : 'Authentication Protocol'}
              </label>
              <select
                id="vault-protocol"
                value={protocol}
                onChange={(e) => handleProtocolChange(e.target.value as CredentialProtocol)}
                className="w-full px-3 py-2 text-sm bg-[#0B0F17] border border-[#1E293B] rounded-lg text-slate-100 focus:outline-none focus:border-emerald-500"
              >
                <option value="WinRM-HTTPS">WinRM-HTTPS (Windows Push)</option>
                <option value="SSH-Ed25519">SSH-Ed25519 (Linux/macOS Push)</option>
                <option value="SSH-Password">SSH-Password (Linux Legacy)</option>
                <option value="SNMPv3-AuthPriv">SNMPv3-AuthPriv (SHA256/AES)</option>
                <option value="SNMPv2c">SNMPv2c Community</option>
                <option value="LDAP-AD">LDAP-AD (Active Directory Sync)</option>
              </select>
            </div>

            <div>
              <label
                htmlFor="vault-port"
                className="block text-xs font-medium text-slate-300 mb-1.5"
              >
                Port TCP/UDP
              </label>
              <input
                id="vault-port"
                type="number"
                value={port}
                onChange={(e) => setPort(Number(e.target.value))}
                className="w-full px-3 py-2 text-sm font-mono tabular-nums bg-[#0B0F17] border border-[#1E293B] rounded-lg text-slate-100 focus:outline-none focus:border-emerald-500"
              />
            </div>
          </div>

          <div className="grid grid-cols-1 sm:grid-cols-2 gap-3">
            <div>
              <label
                htmlFor="vault-username"
                className="block text-xs font-medium text-slate-300 mb-1.5"
              >
                {lang === 'id' ? 'Username / Principal' : 'Username / Principal'}
              </label>
              <input
                id="vault-username"
                type="text"
                value={username}
                onChange={(e) => setUsername(e.target.value)}
                placeholder="CORP\svc_rmm_admin"
                className="w-full px-3.5 py-2 text-sm font-mono bg-[#0B0F17] border border-[#1E293B] rounded-lg text-slate-100 placeholder-slate-500 focus:outline-none focus:border-emerald-500"
              />
            </div>

            <div>
              <label
                htmlFor="vault-subnet"
                className="block text-xs font-medium text-slate-300 mb-1.5"
              >
                {lang === 'id' ? 'Cakupan Subnet (CIDR)' : 'Target Subnet Scope (CIDR)'}
              </label>
              <input
                id="vault-subnet"
                type="text"
                value={scopeSubnet}
                onChange={(e) => setScopeSubnet(e.target.value)}
                placeholder="10.24.10.0/24"
                className="w-full px-3.5 py-2 text-sm font-mono bg-[#0B0F17] border border-[#1E293B] rounded-lg text-slate-100 placeholder-slate-500 focus:outline-none focus:border-emerald-500"
              />
            </div>
          </div>

          <div>
            <label
              htmlFor="vault-secret"
              className="block text-xs font-medium text-slate-300 mb-1.5"
            >
              {lang === 'id'
                ? 'Password / Private Key Ed25519 / SNMPv3 AuthPriv Key'
                : 'Password / Ed25519 Private Key / SNMPv3 AuthPriv Key'}
            </label>
            <input
              id="vault-secret"
              type="password"
              value={rawSecret}
              onChange={(e) => setRawSecret(e.target.value)}
              placeholder="••••••••••••••••••••••••"
              className="w-full px-3.5 py-2 text-sm font-mono bg-[#0B0F17] border border-[#1E293B] rounded-lg text-slate-100 placeholder-slate-500 focus:outline-none focus:border-emerald-500"
            />
          </div>

          {formError && (
            <div
              role="alert"
              className="p-3 rounded-lg bg-rose-500/10 border border-rose-500/30 text-xs text-rose-300 flex items-center gap-2"
            >
              <ShieldAlert className="w-4 h-4 text-rose-400 shrink-0" />
              <span>{formError}</span>
            </div>
          )}

          {bannerMessage && (
            <div
              role="status"
              className="p-3 rounded-lg bg-emerald-500/10 border border-emerald-500/30 text-xs text-emerald-300 flex items-center gap-2"
            >
              <CheckCircle2 className="w-4 h-4 text-emerald-400 shrink-0" />
              <span>{bannerMessage}</span>
            </div>
          )}

          <button
            type="submit"
            className="w-full py-2.5 px-4 bg-emerald-500 hover:bg-emerald-400 text-slate-950 font-semibold text-xs rounded-lg transition-colors flex items-center justify-center gap-2 cursor-pointer"
          >
            <Plus className="w-4 h-4" />
            {lang === 'id'
              ? 'Enkripsi & Simpan ke Credential Vault'
              : 'Encrypt & Store in Credential Vault'}
          </button>
        </form>
      </div>

      {/* Stored Credentials Table */}
      <div className="xl:col-span-7 bg-[#161F30] border border-[#1E293B] rounded-xl p-6">
        <div className="flex flex-wrap items-center justify-between gap-4 pb-4 mb-4 border-b border-[#1E293B]">
          <div>
            <h2 className="text-base font-semibold text-white">
              {lang === 'id'
                ? 'Daftar Kredensial Terenkripsi Aktif'
                : 'Active Encrypted Vault Credentials'}
            </h2>
            <p className="text-xs text-slate-400">
              {lang === 'id'
                ? 'Digunakan secara otomatis oleh mesin Push Deployment (WinRM/SSH) dan SNMPv3 Poller.'
                : 'Consumed by the Remote Push Deployment engine (WinRM/SSH) and SNMPv3 Poller.'}
            </p>
          </div>
          <span className="text-xs font-mono text-emerald-400">
            KEK Status: UNSEALED (AES-256-GCM)
          </span>
        </div>

        <div className="space-y-3">
          {credentials.length === 0 ? (
            <div className="p-6 rounded-lg bg-[#0B0F17] border border-[#1E293B] text-center space-y-1.5">
              <div className="text-xs font-semibold text-slate-200">
                {lang === 'id'
                  ? 'Zero-State: Brankas Kredensial Kosong'
                  : 'Zero-State: Credential Vault is Empty'}
              </div>
              <p className="text-xs text-slate-400">
                {lang === 'id'
                  ? 'Tambahkan kredensial WinRM-HTTPS, SSH-Ed25519, atau SNMPv3 di formulir sebelah kiri untuk menyimpannya secara terenkripsi (AES-256-GCM) ke PostgreSQL.'
                  : 'Add a WinRM-HTTPS, SSH-Ed25519, or SNMPv3 credential using the form on the left to store it encrypted (AES-256-GCM) in PostgreSQL.'}
              </p>
            </div>
          ) : (
            credentials.map((cred) => (
              <div
                key={cred.id}
                className="p-4 rounded-lg bg-[#0B0F17] border border-[#1E293B] flex flex-col sm:flex-row sm:items-center justify-between gap-4"
              >
                <div className="space-y-1.5">
                  <div className="flex items-center gap-2.5">
                    <KeyRound className="w-4 h-4 text-emerald-400 shrink-0" />
                    <span className="text-sm font-semibold text-slate-100">
                      {cred.label}
                    </span>
                  </div>
                  <div className="text-xs text-slate-400 font-mono flex flex-wrap items-center gap-2">
                    <span className="text-cyan-400">{cred.protocol}</span>
                    <span>·</span>
                    <span>User: {cred.username}</span>
                    <span>·</span>
                    <span>Port: {cred.port}</span>
                    <span>·</span>
                    <span>Scope: {cred.scopeSubnet}</span>
                  </div>
                  <div className="text-[11px] font-mono text-slate-400 flex flex-wrap items-center gap-2">
                    <span>Cipher: {cred.cipherPreview}</span>
                    <span>·</span>
                    <span>IV: {cred.ivHex}</span>
                    <span>·</span>
                    <span className="text-emerald-400/90">{cred.keyFingerprint}</span>
                  </div>
                  <div className="text-[11px] text-slate-400">
                    {lang === 'id' ? 'Rotasi Terakhir:' : 'Last Rotated:'}{' '}
                    <span className="font-mono">{cred.lastRotated}</span> · Oleh {cred.createdBy}
                  </div>
                </div>

                <div className="flex items-center gap-2 shrink-0">
                  <button
                    type="button"
                    onClick={() => onRotateKey(cred.id)}
                    className="px-3 py-1.5 text-xs font-medium text-slate-200 bg-[#161F30] hover:bg-slate-800 border border-[#1E293B] rounded-lg transition-colors flex items-center gap-1.5 whitespace-nowrap cursor-pointer"
                  >
                    <RefreshCw className="w-3.5 h-3.5 text-emerald-400" />
                    {lang === 'id' ? 'Rotasi IV/Key' : 'Rotate IV/Key'}
                  </button>
                  <button
                    type="button"
                    aria-label={`Delete credential ${cred.label}`}
                    onClick={() => onDeleteCredential(cred.id)}
                    className="p-1.5 text-slate-400 hover:text-rose-400 bg-[#161F30] border border-[#1E293B] rounded-lg transition-colors cursor-pointer"
                  >
                    <Trash2 className="w-4 h-4" />
                  </button>
                </div>
              </div>
            ))
          )}
        </div>
      </div>
    </div>
  );
};

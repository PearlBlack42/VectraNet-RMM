import React, { useState } from 'react';
import {
  Code2,
  Copy,
  Check,
  Download,
  FileCode,
} from 'lucide-react';
import { PRODUCTION_BLUEPRINTS, BlueprintModule } from '../data/productionBlueprints';

interface BlueprintDocsViewProps {
  lang: 'id' | 'en';
}

export const BlueprintDocsView: React.FC<BlueprintDocsViewProps> = ({ lang }) => {
  const [activeId, setActiveId] = useState<string>(PRODUCTION_BLUEPRINTS[0].id);
  const [copiedId, setCopiedId] = useState<string | null>(null);

  const currentModule: BlueprintModule =
    PRODUCTION_BLUEPRINTS.find((m) => m.id === activeId) || PRODUCTION_BLUEPRINTS[0];

  const handleCopy = async (mod: BlueprintModule) => {
    try {
      await navigator.clipboard.writeText(mod.code);
      setCopiedId(mod.id);
      setTimeout(() => setCopiedId(null), 2000);
    } catch {
      setCopiedId(mod.id);
      setTimeout(() => setCopiedId(null), 2000);
    }
  };

  const handleDownload = (mod: BlueprintModule) => {
    const blob = new Blob([mod.code], { type: 'text/plain;charset=utf-8' });
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = mod.filename.split('/').pop() || 'vectranet_module.txt';
    document.body.appendChild(a);
    a.click();
    document.body.removeChild(a);
    URL.revokeObjectURL(url);
  };

  return (
    <div className="grid grid-cols-1 xl:grid-cols-12 gap-6 items-start">
      {/* Module Selector Sidebar */}
      <div className="xl:col-span-4 bg-[#161F30] border border-[#1E293B] rounded-xl p-4 space-y-2">
        <div className="pb-3 mb-2 border-b border-[#1E293B]">
          <h2 className="text-sm font-semibold text-white flex items-center gap-2">
            <Code2 className="w-4 h-4 text-emerald-400" />
            {lang === 'id'
              ? 'Arsitektur & Kode Produksi Utuh'
              : 'Production Architecture & Full Source Code'}
          </h2>
          <p className="text-xs text-slate-400 mt-0.5">
            {lang === 'id'
              ? 'Pilih modul untuk melihat atau mengunduh skrip produksi siap pakai.'
              : 'Select any module to inspect or download battle-tested production code.'}
          </p>
        </div>

        {PRODUCTION_BLUEPRINTS.map((mod) => {
          const isSelected = mod.id === activeId;
          return (
            <button
              key={mod.id}
              type="button"
              onClick={() => setActiveId(mod.id)}
              className={`w-full text-left p-3 rounded-lg border transition-colors cursor-pointer ${
                isSelected
                  ? 'bg-[#0B0F17] border-emerald-500/50 text-white'
                  : 'bg-[#0B0F17]/40 border-[#1E293B] text-slate-300 hover:bg-[#0B0F17]'
              }`}
            >
              <div className="flex items-center justify-between gap-2 text-xs font-mono text-emerald-400">
                <span className="truncate">{mod.stepNumber}. {mod.filename}</span>
                <span className="uppercase text-[10px] text-slate-400 shrink-0">{mod.language}</span>
              </div>
              <div className="text-xs font-semibold text-slate-100 mt-1">
                {lang === 'id' ? mod.titleId : mod.titleEn}
              </div>
            </button>
          );
        })}
      </div>

      {/* Code Viewer */}
      <div className="xl:col-span-8 bg-[#161F30] border border-[#1E293B] rounded-xl p-5">
        <div className="flex flex-wrap items-center justify-between gap-4 pb-4 mb-4 border-b border-[#1E293B]">
          <div>
            <div className="flex items-center gap-2 text-xs font-mono text-emerald-400">
              <FileCode className="w-4 h-4" />
              <span>{currentModule.filename}</span>
            </div>
            <h3 className="text-base font-semibold text-white mt-1">
              {lang === 'id' ? currentModule.titleId : currentModule.titleEn}
            </h3>
            <p className="text-xs text-slate-400 mt-0.5">
              {lang === 'id' ? currentModule.subtitleId : currentModule.subtitleEn}
            </p>
          </div>

          <div className="flex items-center gap-2 shrink-0">
            <button
              type="button"
              onClick={() => handleCopy(currentModule)}
              className="px-3 py-1.5 text-xs font-medium bg-[#0B0F17] hover:bg-slate-900 text-slate-200 border border-[#1E293B] rounded-lg transition-colors flex items-center gap-1.5 cursor-pointer"
            >
              {copiedId === currentModule.id ? (
                <>
                  <Check className="w-3.5 h-3.5 text-emerald-400" />
                  <span>{lang === 'id' ? 'Tersalin' : 'Copied'}</span>
                </>
              ) : (
                <>
                  <Copy className="w-3.5 h-3.5 text-emerald-400" />
                  <span>{lang === 'id' ? 'Salin Kode' : 'Copy Code'}</span>
                </>
              )}
            </button>

            <button
              type="button"
              onClick={() => handleDownload(currentModule)}
              className="px-3 py-1.5 text-xs font-medium bg-emerald-500 hover:bg-emerald-400 text-slate-950 font-semibold rounded-lg transition-colors flex items-center gap-1.5 cursor-pointer"
            >
              <Download className="w-3.5 h-3.5" />
              <span>{lang === 'id' ? 'Unduh File' : 'Download'}</span>
            </button>
          </div>
        </div>

        <pre className="p-4 rounded-lg bg-[#0B0F17] border border-[#1E293B] text-xs font-mono text-slate-200 overflow-x-auto max-h-[560px] leading-relaxed">
          <code>{currentModule.code}</code>
        </pre>
      </div>
    </div>
  );
};

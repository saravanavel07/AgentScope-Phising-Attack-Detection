import { useMemo, useState } from 'react';
import { Search, Shield, Trash2 } from 'lucide-react';
import type { ScanReport, ThreatClassification } from '../types/scanner';
import { ClassificationMark } from './ClassificationMark';
import { DetectionReportView } from './DetectionReportView';

interface ReportsArchiveViewProps {
  reports: ScanReport[];
  selectedReport: ScanReport | null;
  onSelectReport: (report: ScanReport | null) => void;
  onDeleteReport: (id: string) => void;
  onClearAll: () => void;
  onInspectUrl: (url: string) => void;
}

type FilterTab = 'All' | ThreatClassification;

export function ReportsArchiveView({
  reports,
  selectedReport,
  onSelectReport,
  onDeleteReport,
  onClearAll,
  onInspectUrl,
}: ReportsArchiveViewProps) {
  const [filter, setFilter] = useState<FilterTab>('All');
  const [query, setQuery] = useState('');
  const [confirmClear, setConfirmClear] = useState(false);

  const filtered = useMemo(() => {
    const q = query.trim().toLowerCase();
    return reports.filter((r) => {
      if (filter !== 'All' && r.classification !== filter) return false;
      if (!q) return true;
      return (
        r.target.toLowerCase().includes(q) ||
        r.threatCategory.toLowerCase().includes(q) ||
        r.kind.toLowerCase().includes(q)
      );
    });
  }, [reports, filter, query]);

  const activeReport = selectedReport ?? filtered[0] ?? null;

  return (
    <div className="space-y-8">
      <div className="flex flex-col gap-4 sm:flex-row sm:items-end sm:justify-between">
        <div className="space-y-2">
          <h1 className="font-display text-2xl font-bold tracking-tight text-[#F8FAFC] sm:text-3xl aegis-heading-glow">
            Security Reports Archive
          </h1>
          <p className="max-w-2xl text-sm leading-relaxed text-[#94A3B8]">
            Review historical URL and email inspections, filter by threat classification, or export structured reports.
          </p>
        </div>

        {reports.length > 0 && (
          <div className="flex items-center gap-2">
            {confirmClear ? (
              <>
                <button
                  type="button"
                  onClick={() => {
                    onClearAll();
                    setConfirmClear(false);
                  }}
                  className="rounded-lg border border-[#38BDF8]/50 bg-[#1B2B44] px-3 py-2 text-xs font-semibold text-[#BAE6FD] hover:bg-[#2563EB]/30 cursor-pointer whitespace-nowrap"
                >
                  Confirm Clear All
                </button>
                <button
                  type="button"
                  onClick={() => setConfirmClear(false)}
                  className="rounded-lg border border-[#94A3B8]/20 bg-[#121722] px-3 py-2 text-xs font-medium text-[#94A3B8] hover:text-[#E2E8F0] cursor-pointer whitespace-nowrap"
                >
                  Cancel
                </button>
              </>
            ) : (
              <button
                type="button"
                onClick={() => setConfirmClear(true)}
                className="inline-flex items-center gap-1.5 rounded-lg border border-[#94A3B8]/20 bg-[#121722] px-3.5 py-2 text-xs font-medium text-[#94A3B8] hover:border-[#3B82F6]/40 hover:text-[#E2E8F0] cursor-pointer whitespace-nowrap"
              >
                <Trash2 className="h-3.5 w-3.5" aria-hidden="true" />
                Clear History
              </button>
            )}
          </div>
        )}
      </div>

      {/* Filter & Search Bar */}
      <div className="aegis-surface rounded-2xl p-4 flex flex-col gap-4 sm:flex-row sm:items-center sm:justify-between">
        <div className="flex items-center gap-1 rounded-xl bg-[#0B0E14] p-1 border border-[#94A3B8]/12 overflow-x-auto">
          {(['All', 'Safe', 'Suspicious', 'Malicious'] as FilterTab[]).map((tab) => {
            const active = filter === tab;
            return (
              <button
                key={tab}
                type="button"
                onClick={() => setFilter(tab)}
                className={`rounded-lg px-3 py-1.5 text-xs font-medium transition-colors whitespace-nowrap shrink-0 cursor-pointer ${
                  active
                    ? 'bg-[#2563EB] text-[#F8FAFC] shadow-[0_0_14px_rgba(37,99,235,0.5)]'
                    : 'text-[#94A3B8] hover:text-[#E2E8F0]'
                }`}
              >
                {tab}
              </button>
            );
          })}
        </div>

        <div className="relative w-full sm:w-72">
          <Search
            className="pointer-events-none absolute left-3 top-1/2 h-4 w-4 -translate-y-1/2 text-[#64748B]"
            aria-hidden="true"
          />
          <input
            type="text"
            value={query}
            onChange={(e) => setQuery(e.target.value)}
            placeholder="Filter by target or category..."
            className="w-full rounded-xl border border-[#94A3B8]/18 bg-[#0B0E14] py-2 pl-9 pr-3 text-xs text-[#F1F5F9] placeholder-[#475569] focus:border-[#3B82F6] focus:outline-none focus:ring-2 focus:ring-[#3B82F6]/35"
          />
        </div>
      </div>

      {filtered.length === 0 ? (
        <div className="aegis-surface rounded-2xl flex flex-col items-center justify-center py-16 text-center px-6">
          <Shield className="mb-3 h-8 w-8 text-[#3B82F6]/70" aria-hidden="true" />
          <p className="text-sm font-medium text-[#E2E8F0]">
            {reports.length === 0 ? 'No threat reports recorded yet' : 'No matching reports found'}
          </p>
          <p className="mt-1 text-xs text-[#94A3B8]">
            {reports.length === 0
              ? 'Run a URL or Email inspection to generate your first security report.'
              : 'Adjust your search query or classification filter.'}
          </p>
        </div>
      ) : (
        <div className="grid grid-cols-1 gap-6 xl:grid-cols-12">
          {/* Left Report List */}
          <div className="xl:col-span-4 space-y-2.5">
            {filtered.map((rep) => {
              const isSelected = activeReport?.id === rep.id;
              return (
                <div
                  key={rep.id}
                  onClick={() => onSelectReport(rep)}
                  role="button"
                  tabIndex={0}
                  onKeyDown={(e) => {
                    if (e.key === 'Enter' || e.key === ' ') {
                      e.preventDefault();
                      onSelectReport(rep);
                    }
                  }}
                  className={`rounded-xl p-4 cursor-pointer transition-all duration-150 ${
                    isSelected
                      ? 'aegis-surface-active'
                      : 'aegis-surface aegis-card-hover'
                  }`}
                >
                  <div className="flex items-start justify-between gap-2">
                    <ClassificationMark classification={rep.classification} size="sm" />
                    <div className="flex items-center gap-2">
                      <span className="font-mono text-xs font-semibold text-[#60A5FA] tabular-nums">
                        {rep.riskScore}%
                      </span>
                      <button
                        type="button"
                        aria-label={`Delete report for ${rep.target}`}
                        onClick={(e) => {
                          e.stopPropagation();
                          onDeleteReport(rep.id);
                        }}
                        className="rounded p-1 text-[#64748B] hover:bg-[#1E293B] hover:text-[#CBD5E1] cursor-pointer"
                      >
                        <Trash2 className="h-3.5 w-3.5" aria-hidden="true" />
                      </button>
                    </div>
                  </div>
                  <p className="mt-2 font-mono text-xs text-[#E2E8F0] truncate" title={rep.target}>
                    {rep.target}
                  </p>
                  <div className="mt-1.5 flex items-center gap-2 text-[11px] text-[#64748B]">
                    <span className="uppercase">{rep.kind}</span>
                    <span aria-hidden="true">·</span>
                    <span className="truncate">{rep.threatCategory}</span>
                  </div>
                </div>
              );
            })}
          </div>

          {/* Right Selected Report Detail */}
          <div className="xl:col-span-8">
            {activeReport && (
              <DetectionReportView report={activeReport} onInspectUrl={onInspectUrl} />
            )}
          </div>
        </div>
      )}
    </div>
  );
}

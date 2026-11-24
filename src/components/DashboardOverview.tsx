import { useState } from 'react';
import {
  Activity,
  ArrowUpRight,
  BarChart3,
  Globe,
  Mail,
  Search,
  Shield,
  ShieldAlert,
  ShieldCheck,
} from 'lucide-react';
import type { DashboardStats, ScanReport } from '../types/scanner';
import { ClassificationMark } from './ClassificationMark';

interface DashboardOverviewProps {
  stats: DashboardStats | null;
  loading: boolean;
  onQuickScanUrl: (url: string) => void;
  onOpenEmailAnalyzer: () => void;
  onSelectReport: (report: ScanReport) => void;
}

function formatRelativeTime(iso: string): string {
  const ts = Date.parse(iso);
  if (Number.isNaN(ts)) return iso;
  const diffSec = Math.max(0, Math.floor((Date.now() - ts) / 1000));
  if (diffSec < 60) return `${diffSec}s ago`;
  const diffMin = Math.floor(diffSec / 60);
  if (diffMin < 60) return `${diffMin}m ago`;
  const diffHr = Math.floor(diffMin / 60);
  if (diffHr < 24) return `${diffHr}h ago`;
  return new Date(ts).toLocaleDateString();
}

export function DashboardOverview({
  stats,
  loading,
  onQuickScanUrl,
  onOpenEmailAnalyzer,
  onSelectReport,
}: DashboardOverviewProps) {
  const [quickUrl, setQuickUrl] = useState('');
  const [hoveredBucket, setHoveredBucket] = useState<string | null>(null);
  const [hoveredVector, setHoveredVector] = useState<string | null>(null);

  const handleQuickSubmit = (e: React.FormEvent) => {
    e.preventDefault();
    if (!quickUrl.trim()) return;
    onQuickScanUrl(quickUrl.trim());
  };

  const total = stats?.totalScans ?? 0;
  const safe = stats?.safeCount ?? 0;
  const suspicious = stats?.suspiciousCount ?? 0;
  const malicious = stats?.maliciousCount ?? 0;

  const maxBucket = Math.max(1, ...(stats?.riskHistogram.map((b) => b.count) ?? [1]));
  const maxVector = Math.max(1, ...(stats?.vectorBreakdown.map((v) => v.hits) ?? [1]));

  return (
    <div className="space-y-8">
      {/* Hero / Command Strip */}
      <section className="aegis-surface-active rounded-2xl p-6 sm:p-8">
        <div className="flex flex-col gap-6 lg:flex-row lg:items-center lg:justify-between">
          <div className="max-w-2xl space-y-2.5">
            <h1 className="font-display text-2xl font-bold tracking-tight text-[#F8FAFC] sm:text-4xl aegis-heading-glow">
              Phishing Threat Detection Console
            </h1>
            <p className="text-sm leading-relaxed text-[#94A3B8] sm:text-[15px]">
              Real-time inspection of suspicious URLs, domain infrastructure, SSL/TLS certificate posture, and phishing emails. All dashboard telemetry reflects verified scans executed in this workspace.
            </p>
          </div>

          <form onSubmit={handleQuickSubmit} className="w-full max-w-lg space-y-2.5">
            <label htmlFor="overview-quick-url" className="block text-xs font-medium text-[#CBD5E1]">
              Quick URL Inspection
            </label>
            <div className="flex flex-col gap-2.5 sm:flex-row">
              <div className="relative flex-1">
                <Search
                  className="pointer-events-none absolute left-3 top-1/2 h-4 w-4 -translate-y-1/2 text-[#64748B]"
                  aria-hidden="true"
                />
                <input
                  id="overview-quick-url"
                  type="text"
                  value={quickUrl}
                  onChange={(e) => setQuickUrl(e.target.value)}
                  placeholder="https://suspicious-domain.example/login"
                  className="w-full rounded-xl border border-[#94A3B8]/20 bg-[#0B0E14] py-2.5 pl-9 pr-3 font-mono text-xs text-[#F1F5F9] placeholder-[#475569] focus:border-[#3B82F6] focus:outline-none focus:ring-2 focus:ring-[#3B82F6]/35"
                />
              </div>
              <button
                type="submit"
                className="aegis-btn-primary inline-flex min-h-[40px] items-center justify-center gap-1.5 rounded-xl px-4 py-2 text-xs font-semibold text-[#F8FAFC] whitespace-nowrap shrink-0 cursor-pointer"
              >
                <span>Scan Link</span>
                <ArrowUpRight className="h-3.5 w-3.5" aria-hidden="true" />
              </button>
            </div>
          </form>
        </div>
      </section>

      {/* 4-Column Real Telemetry KPI Strip */}
      <section aria-label="Detection summary metrics" className="grid grid-cols-1 gap-4 sm:grid-cols-2 xl:grid-cols-4">
        <div className="aegis-surface aegis-card-hover rounded-2xl p-5">
          <div className="flex items-center justify-between">
            <span className="text-xs font-medium text-[#94A3B8]">Total Targets Scanned</span>
            <Activity className="h-4 w-4 text-[#60A5FA]" aria-hidden="true" />
          </div>
          <p className="mt-3 font-mono text-3xl font-semibold text-[#F8FAFC] tabular-nums">
            {loading ? '—' : total.toLocaleString()}
          </p>
          <p className="mt-1.5 text-xs text-[#64748B] tabular-nums">
            {stats ? `${stats.urlScanCount} URL · ${stats.emailScanCount} Email` : 'Awaiting scans'}
          </p>
        </div>

        <div className="aegis-surface aegis-card-hover rounded-2xl p-5">
          <div className="flex items-center justify-between">
            <span className="text-xs font-medium text-[#94A3B8]">Safe Verified</span>
            <ShieldCheck className="h-4 w-4 text-[#93C5FD]" aria-hidden="true" />
          </div>
          <p className="mt-3 font-mono text-3xl font-semibold text-[#E2E8F0] tabular-nums">
            {loading ? '—' : safe.toLocaleString()}
          </p>
          <p className="mt-1.5 text-xs text-[#64748B] tabular-nums">
            {total > 0 ? `${Math.round((safe / total) * 100)}% of completed scans` : 'Low-risk targets (< 30%)'}
          </p>
        </div>

        <div className="aegis-surface aegis-card-hover rounded-2xl p-5">
          <div className="flex items-center justify-between">
            <span className="text-xs font-medium text-[#94A3B8]">Suspicious Flagged</span>
            <Shield className="h-4 w-4 text-[#60A5FA]" aria-hidden="true" />
          </div>
          <p className="mt-3 font-mono text-3xl font-semibold text-[#93C5FD] tabular-nums">
            {loading ? '—' : suspicious.toLocaleString()}
          </p>
          <p className="mt-1.5 text-xs text-[#64748B] tabular-nums">
            {total > 0 ? `${Math.round((suspicious / total) * 100)}% moderate risk` : 'Moderate-risk (30–59%)'}
          </p>
        </div>

        <div className="aegis-surface aegis-card-hover rounded-2xl p-5">
          <div className="flex items-center justify-between">
            <span className="text-xs font-medium text-[#94A3B8]">High-Risk Threats</span>
            <ShieldAlert className="h-4 w-4 text-[#38BDF8]" aria-hidden="true" />
          </div>
          <p className="mt-3 font-mono text-3xl font-semibold text-[#38BDF8] tabular-nums">
            {loading ? '—' : malicious.toLocaleString()}
          </p>
          <p className="mt-1.5 text-xs text-[#64748B] tabular-nums">
            {total > 0 ? `Avg risk score ${stats?.averageRiskScore ?? 0}%` : 'Malicious targets (60%+)'}
          </p>
        </div>
      </section>

      {/* Interactive Threat Analytics Charts */}
      <section className="grid grid-cols-1 gap-6 lg:grid-cols-2">
        {/* Risk Score Histogram */}
        <div className="aegis-surface rounded-2xl p-6">
          <div className="mb-5 flex items-center justify-between border-b border-[#94A3B8]/12 pb-3">
            <div className="flex items-center gap-2.5">
              <BarChart3 className="h-4 w-4 text-[#60A5FA]" aria-hidden="true" />
              <h2 className="font-display text-base font-semibold text-[#F1F5F9]">
                Risk Score Distribution
              </h2>
            </div>
            <span className="font-mono text-xs text-[#94A3B8] tabular-nums">
              {hoveredBucket
                ? `${hoveredBucket}% band`
                : `Avg ${stats?.averageRiskScore ?? 0}%`}
            </span>
          </div>

          {total === 0 ? (
            <div className="flex h-44 flex-col items-center justify-center text-center text-xs text-[#64748B]">
              <p>No scan telemetry recorded yet.</p>
              <p className="mt-1">Run a URL or email scan to generate live risk distribution.</p>
            </div>
          ) : (
            <div className="grid h-44 grid-cols-5 items-end gap-3 pt-4">
              {stats?.riskHistogram.map((item) => {
                const heightPct = item.count === 0 ? 6 : Math.max(14, Math.round((item.count / maxBucket) * 100));
                const isHovered = hoveredBucket === item.bucket;
                return (
                  <div
                    key={item.bucket}
                    onMouseEnter={() => setHoveredBucket(`${item.bucket} (${item.count})`)}
                    onMouseLeave={() => setHoveredBucket(null)}
                    className="flex h-full flex-col items-center justify-end gap-2"
                  >
                    <span className="font-mono text-xs text-[#CBD5E1] tabular-nums">
                      {item.count}
                    </span>
                    <div className="relative flex w-full flex-1 items-end">
                      <div
                        style={{ height: `${heightPct}%` }}
                        className={`w-full rounded-t-lg transition-all duration-200 ${
                          item.count === 0
                            ? 'bg-[#1A2130]'
                            : isHovered
                              ? 'bg-gradient-to-t from-[#2563EB] to-[#38BDF8] shadow-[0_0_20px_rgba(56,189,248,0.45)]'
                              : 'bg-gradient-to-t from-[#1E3A8A]/80 via-[#2563EB]/85 to-[#60A5FA]/90'
                        }`}
                      />
                    </div>
                    <span className="font-mono text-[11px] text-[#94A3B8] tabular-nums whitespace-nowrap">
                      {item.bucket}
                    </span>
                  </div>
                );
              })}
            </div>
          )}
        </div>

        {/* Threat Vector Frequency */}
        <div className="aegis-surface rounded-2xl p-6">
          <div className="mb-5 flex items-center justify-between border-b border-[#94A3B8]/12 pb-3">
            <div className="flex items-center gap-2.5">
              <Shield className="h-4 w-4 text-[#60A5FA]" aria-hidden="true" />
              <h2 className="font-display text-base font-semibold text-[#F1F5F9]">
                Detection Vector Breakdown
              </h2>
            </div>
            <span className="font-mono text-xs text-[#94A3B8] tabular-nums">
              {hoveredVector ?? 'Triggered categories'}
            </span>
          </div>

          {total === 0 ? (
            <div className="flex h-44 flex-col items-center justify-center text-center text-xs text-[#64748B]">
              <p>Vector breakdown populates as inspections run.</p>
            </div>
          ) : (
            <div className="space-y-3">
              {stats?.vectorBreakdown.map((vec) => {
                const widthPct = vec.hits === 0 ? 0 : Math.max(8, Math.round((vec.hits / maxVector) * 100));
                const isHovered = hoveredVector === `${vec.category}: ${vec.hits}`;
                return (
                  <div
                    key={vec.category}
                    onMouseEnter={() => setHoveredVector(`${vec.category}: ${vec.hits}`)}
                    onMouseLeave={() => setHoveredVector(null)}
                    className="space-y-1"
                  >
                    <div className="flex items-center justify-between text-xs">
                      <span className="text-[#CBD5E1]">{vec.category}</span>
                      <span className="font-mono text-[#94A3B8] tabular-nums">{vec.hits}</span>
                    </div>
                    <div className="h-2 w-full overflow-hidden rounded-full bg-[#161D2B]">
                      <div
                        style={{ width: `${widthPct}%` }}
                        className={`h-full rounded-full transition-all duration-200 ${
                          isHovered
                            ? 'bg-gradient-to-r from-[#2563EB] to-[#38BDF8] shadow-[0_0_12px_rgba(56,189,248,0.6)]'
                            : 'bg-gradient-to-r from-[#1D4ED8] to-[#60A5FA]'
                        }`}
                      />
                    </div>
                  </div>
                );
              })}
            </div>
          )}
        </div>
      </section>

      {/* Recent Scanning Activity */}
      <section className="aegis-surface rounded-2xl p-6">
        <div className="mb-4 flex flex-wrap items-center justify-between gap-4 border-b border-[#94A3B8]/12 pb-3">
          <div>
            <h2 className="font-display text-base font-semibold text-[#F1F5F9]">
              Recent Scanning Activity
            </h2>
            <p className="text-xs text-[#64748B]">
              Select any recorded inspection to view its full security report.
            </p>
          </div>
          <div className="flex items-center gap-2">
            <button
              type="button"
              onClick={() => onQuickScanUrl('https://github.com')}
              className="inline-flex items-center gap-1.5 rounded-lg border border-[#3B82F6]/30 bg-[#141C2B] px-3 py-1.5 text-xs font-medium text-[#60A5FA] hover:border-[#60A5FA] hover:text-[#F8FAFC] cursor-pointer"
            >
              <Globe className="h-3.5 w-3.5" aria-hidden="true" />
              Test Live URL
            </button>
            <button
              type="button"
              onClick={onOpenEmailAnalyzer}
              className="inline-flex items-center gap-1.5 rounded-lg border border-[#94A3B8]/20 bg-[#121722] px-3 py-1.5 text-xs font-medium text-[#CBD5E1] hover:border-[#60A5FA] hover:text-[#F8FAFC] cursor-pointer"
            >
              <Mail className="h-3.5 w-3.5" aria-hidden="true" />
              Analyze Email
            </button>
          </div>
        </div>

        {total === 0 ? (
          <div className="flex flex-col items-center justify-center py-12 text-center">
            <Shield className="mb-3 h-8 w-8 text-[#3B82F6]/70" aria-hidden="true" />
            <p className="text-sm font-medium text-[#E2E8F0]">No scans recorded in workspace</p>
            <p className="mt-1 max-w-md text-xs text-[#94A3B8]">
              Enter a website URL above or open the Email Analyzer to run your first live phishing detection check.
            </p>
          </div>
        ) : (
          <div className="overflow-x-auto">
            <table className="w-full text-left text-xs">
              <thead>
                <tr className="border-b border-[#94A3B8]/12 text-[#64748B]">
                  <th className="py-2.5 pr-4 font-medium">Target</th>
                  <th className="py-2.5 px-3 font-medium">Type</th>
                  <th className="py-2.5 px-3 font-medium">Classification</th>
                  <th className="py-2.5 px-3 font-medium text-right">Risk</th>
                  <th className="py-2.5 pl-3 font-medium text-right">Scanned</th>
                </tr>
              </thead>
              <tbody className="divide-y divide-[#94A3B8]/8">
                {stats?.recentReports.map((rep) => (
                  <tr
                    key={rep.id}
                    onClick={() => onSelectReport(rep)}
                    className="h-10 cursor-pointer transition-colors hover:bg-[#182132]/75"
                  >
                    <td className="max-w-[320px] py-2.5 pr-4 font-mono text-[#E2E8F0] truncate">
                      {rep.target}
                    </td>
                    <td className="py-2.5 px-3 text-[#94A3B8] uppercase">
                      {rep.kind}
                    </td>
                    <td className="py-2.5 px-3">
                      <ClassificationMark classification={rep.classification} size="sm" />
                    </td>
                    <td className="py-2.5 px-3 text-right font-mono font-semibold text-[#60A5FA] tabular-nums">
                      {rep.riskScore}%
                    </td>
                    <td className="py-2.5 pl-3 text-right font-mono text-[#64748B] tabular-nums whitespace-nowrap">
                      {formatRelativeTime(rep.scannedAt)}
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        )}
      </section>
    </div>
  );
}

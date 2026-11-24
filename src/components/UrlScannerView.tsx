import { useEffect, useState } from 'react';
import { ArrowRight, Globe, Lock, Search, ShieldCheck } from 'lucide-react';
import type { ScanReport } from '../types/scanner';
import { DetectionReportView } from './DetectionReportView';

interface UrlScannerViewProps {
  initialUrl?: string;
  onScanStateChange: (scanning: boolean) => void;
  onScanComplete: (report: ScanReport) => void;
}

const SCAN_STAGES = [
  'Parsing URL structure, Punycode labels, and entropy',
  'Resolving DNS records & checking RDAP domain age',
  'Performing TLS handshake & X.509 certificate inspection',
  'Scoring threat vectors & generating security report',
];

const QUICK_EXAMPLES = [
  { label: 'Official Domain (github.com)', url: 'https://github.com' },
  { label: 'Suspicious Pattern (unencrypted + shortener)', url: 'http://bit.ly/3xVerifyLogin' },
  { label: 'Simulated Brand Spoof Pattern', url: 'http://paypa1-secure-verify.xyz/login?session=8912a&update=billing' },
];

export function UrlScannerView({
  initialUrl,
  onScanStateChange,
  onScanComplete,
}: UrlScannerViewProps) {
  const [urlInput, setUrlInput] = useState(initialUrl ?? '');
  const [isScanning, setIsScanning] = useState(false);
  const [activeStage, setActiveStage] = useState(0);
  const [error, setError] = useState<string | null>(null);
  const [latestReport, setLatestReport] = useState<ScanReport | null>(null);

  useEffect(() => {
    if (initialUrl) {
      setUrlInput(initialUrl);
      void runScan(initialUrl);
    }
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [initialUrl]);

  useEffect(() => {
    if (!isScanning) return;
    setActiveStage(0);
    const interval = setInterval(() => {
      setActiveStage((prev) => (prev < SCAN_STAGES.length - 1 ? prev + 1 : prev));
    }, 550);
    return () => clearInterval(interval);
  }, [isScanning]);

  const runScan = async (targetUrl: string) => {
    const trimmed = targetUrl.trim();
    if (!trimmed) {
      setError('Enter a website URL or suspicious link to inspect.');
      return;
    }

    setError(null);
    setIsScanning(true);
    onScanStateChange(true);

    try {
      const res = await fetch('/api/scan/url', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ url: trimmed }),
      });
      const data = (await res.json()) as { report?: ScanReport; error?: string };
      if (!res.ok || !data.report) {
        throw new Error(data.error || 'URL scan failed.');
      }
      setLatestReport(data.report);
      onScanComplete(data.report);
    } catch (err) {
      setError(err instanceof Error ? err.message : 'Unable to analyze URL.');
    } finally {
      setIsScanning(false);
      onScanStateChange(false);
    }
  };

  const handleSubmit = (e: React.FormEvent) => {
    e.preventDefault();
    void runScan(urlInput);
  };

  return (
    <div className="space-y-8">
      <div className="space-y-2">
        <h1 className="font-display text-2xl font-bold tracking-tight text-[#F8FAFC] sm:text-3xl aegis-heading-glow">
          URL &amp; Domain Phishing Scanner
        </h1>
        <p className="max-w-2xl text-sm leading-relaxed text-[#94A3B8]">
          Inspect suspicious links across lexical patterns, homograph spoofing, live DNS and RDAP age records, TLS certificate chains, and redirect behavior.
        </p>
      </div>

      {/* Scanner Input Surface */}
      <form
        onSubmit={handleSubmit}
        className={`rounded-2xl p-5 sm:p-6 transition-all duration-200 ${
          isScanning ? 'aegis-surface-active aegis-pulse-glow' : 'aegis-surface'
        }`}
      >
        <label htmlFor="url-scanner-input" className="block text-xs font-medium text-[#CBD5E1] mb-2.5">
          Target Website URL or Suspicious Link
        </label>
        <div className="flex flex-col gap-3 sm:flex-row">
          <div className="relative flex-1">
            <Search
              className="pointer-events-none absolute left-3.5 top-1/2 h-4 w-4 -translate-y-1/2 text-[#64748B]"
              aria-hidden="true"
            />
            <input
              id="url-scanner-input"
              type="text"
              value={urlInput}
              onChange={(e) => setUrlInput(e.target.value)}
              placeholder="https://example.com/login or paste suspicious link"
              disabled={isScanning}
              className="w-full rounded-xl border border-[#94A3B8]/18 bg-[#0B0E14] py-3 pl-10 pr-4 font-mono text-sm text-[#F1F5F9] placeholder-[#475569] focus:border-[#3B82F6] focus:outline-none focus:ring-2 focus:ring-[#3B82F6]/35 disabled:opacity-60"
            />
          </div>
          <button
            type="submit"
            disabled={isScanning}
            className="aegis-btn-primary inline-flex min-h-[46px] items-center justify-center gap-2 rounded-xl px-6 py-3 text-sm font-semibold text-[#F8FAFC] whitespace-nowrap shrink-0 cursor-pointer disabled:opacity-60"
          >
            <span>{isScanning ? 'Scanning Target...' : 'Analyze URL'}</span>
            <ArrowRight className="h-4 w-4" aria-hidden="true" />
          </button>
        </div>

        {/* Live Examples Bar */}
        <div className="mt-4 flex flex-wrap items-center gap-x-4 gap-y-2 border-t border-[#94A3B8]/10 pt-3.5 text-xs">
          <span className="text-[#64748B]">Test with live analysis:</span>
          {QUICK_EXAMPLES.map((ex) => (
            <button
              key={ex.url}
              type="button"
              disabled={isScanning}
              onClick={() => {
                setUrlInput(ex.url);
                void runScan(ex.url);
              }}
              className="text-left font-medium text-[#60A5FA] hover:text-[#93C5FD] hover:underline underline-offset-4 transition-colors cursor-pointer disabled:opacity-50"
            >
              {ex.label}
            </button>
          ))}
        </div>

        {/* Animated Scanning Indicator */}
        {isScanning && (
          <div className="mt-5 space-y-3 border-t border-[#3B82F6]/25 pt-4">
            <div className="relative h-1.5 w-full overflow-hidden rounded-full bg-[#171E2C]">
              <div className="aegis-scan-beam h-full w-1/2 rounded-full bg-gradient-to-r from-transparent via-[#38BDF8] to-transparent shadow-[0_0_16px_#38BDF8]" />
            </div>
            <div className="grid grid-cols-1 gap-2 sm:grid-cols-2 lg:grid-cols-4">
              {SCAN_STAGES.map((stage, idx) => {
                const done = idx < activeStage;
                const current = idx === activeStage;
                return (
                  <div
                    key={stage}
                    className={`flex items-start gap-2 rounded-lg border px-3 py-2 text-xs transition-colors ${
                      current
                        ? 'border-[#3B82F6]/50 bg-[#172236] text-[#E2E8F0]'
                        : done
                          ? 'border-[#94A3B8]/15 bg-[#111622] text-[#93C5FD]'
                          : 'border-[#94A3B8]/10 bg-[#0D1119] text-[#64748B]'
                    }`}
                  >
                    <span className="font-mono text-[11px] tabular-nums text-[#60A5FA]">
                      0{idx + 1}
                    </span>
                    <span className="leading-snug">{stage}</span>
                  </div>
                );
              })}
            </div>
          </div>
        )}

        {error && (
          <div
            role="alert"
            className="mt-4 rounded-xl border border-[#38BDF8]/40 bg-[#162238] px-4 py-3 text-xs text-[#BAE6FD]"
          >
            {error}
          </div>
        )}
      </form>

      {/* Capability Notes when idle and no report yet */}
      {!latestReport && !isScanning && (
        <div className="grid grid-cols-1 gap-4 sm:grid-cols-3">
          <div className="aegis-surface rounded-xl p-5">
            <div className="mb-2 flex items-center gap-2 text-sm font-semibold text-[#E2E8F0]">
              <Globe className="h-4 w-4 text-[#60A5FA]" aria-hidden="true" />
              <span>DNS &amp; Domain Age</span>
            </div>
            <p className="text-xs leading-relaxed text-[#94A3B8]">
              Queries live A/AAAA/MX/SPF/DMARC records and RDAP registration dates to surface newly created throwaway infrastructure.
            </p>
          </div>
          <div className="aegis-surface rounded-xl p-5">
            <div className="mb-2 flex items-center gap-2 text-sm font-semibold text-[#E2E8F0]">
              <Lock className="h-4 w-4 text-[#60A5FA]" aria-hidden="true" />
              <span>TLS Chain Verification</span>
            </div>
            <p className="text-xs leading-relaxed text-[#94A3B8]">
              Inspects live X.509 certificates for expiration, hostname mismatches, and untrusted issuers—without assuming HTTPS equals safety.
            </p>
          </div>
          <div className="aegis-surface rounded-xl p-5">
            <div className="mb-2 flex items-center gap-2 text-sm font-semibold text-[#E2E8F0]">
              <ShieldCheck className="h-4 w-4 text-[#60A5FA]" aria-hidden="true" />
              <span>Typosquat &amp; Lexical Audit</span>
            </div>
            <p className="text-xs leading-relaxed text-[#94A3B8]">
              Evaluates Punycode IDNs, homoglyph substitutions, edit distance against major brands, entropy, and credential-harvesting paths.
            </p>
          </div>
        </div>
      )}

      {latestReport && <DetectionReportView report={latestReport} />}
    </div>
  );
}

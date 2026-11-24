import {
  CheckCircle2,
  Download,
  ExternalLink,
  Globe,
  Info,
  Lock,
  Mail,
  Search,
  Shield,
} from 'lucide-react';
import type { ScanReport } from '../types/scanner';
import { ClassificationMark } from './ClassificationMark';

interface DetectionReportViewProps {
  report: ScanReport;
  onInspectUrl?: (url: string) => void;
}

function formatDateTime(iso: string): string {
  const date = new Date(iso);
  if (Number.isNaN(date.getTime())) return iso;
  return date.toLocaleString(undefined, {
    year: 'numeric',
    month: 'short',
    day: 'numeric',
    hour: '2-digit',
    minute: '2-digit',
  });
}

function buildMarkdownReport(report: ScanReport): string {
  const lines = [
    `# AegisTrace Security Report`,
    ``,
    `- **Target:** ${report.target}`,
    `- **Scan Type:** ${report.kind.toUpperCase()}`,
    `- **Classification:** ${report.classification}`,
    `- **Risk Score:** ${report.riskScore}%`,
    `- **Threat Category:** ${report.threatCategory}`,
    `- **Scanned At:** ${report.scannedAt}`,
    `- **Analysis Duration:** ${report.durationMs} ms`,
    ``,
    `## Detection Summary`,
    report.summaryExplanation,
    ``,
    `## Triggered Signals (${report.signals.length})`,
  ];

  if (report.signals.length === 0) {
    lines.push(`No suspicious or malicious patterns matched.`);
  } else {
    for (const s of report.signals) {
      lines.push(`- **[${s.severity.toUpperCase()} · +${s.points}] ${s.title}** (${s.category}): ${s.detail}${s.evidence ? ` — Evidence: \`${s.evidence}\`` : ''}`);
    }
  }

  if (report.domainInfo) {
    lines.push(
      ``,
      `## Domain & DNS Reputation`,
      `- Registrable Domain: ${report.domainInfo.registrableDomain}`,
      `- TLD: .${report.domainInfo.tld}`,
      `- DNS Status: ${report.domainInfo.dnsStatus}`,
      `- Resolved IPs: ${report.domainInfo.resolvedIps.join(', ') || 'None'}`,
      `- MX / SPF / DMARC: ${report.domainInfo.hasMxRecords ? 'MX' : 'No MX'} / ${report.domainInfo.hasSpfRecord ? 'SPF' : 'No SPF'} / ${report.domainInfo.hasDmarcRecord ? 'DMARC' : 'No DMARC'}`,
      `- Domain Age: ${report.domainInfo.domainAgeDays !== null ? `${report.domainInfo.domainAgeDays} days` : 'Unavailable'}`
    );
  }

  if (report.sslInfo) {
    lines.push(
      ``,
      `## SSL / HTTPS Inspection`,
      `- Uses HTTPS: ${report.sslInfo.usesHttps ? 'Yes' : 'No'}`,
      `- Certificate Present: ${report.sslInfo.certificatePresent ? 'Yes' : 'No'}`,
      `- Issuer: ${report.sslInfo.issuerOrganization ?? 'N/A'}`,
      `- Subject CN: ${report.sslInfo.subjectCommonName ?? 'N/A'}`,
      `- TLS Protocol: ${report.sslInfo.tlsProtocol ?? 'N/A'}`,
      `- Note: ${report.sslInfo.inspectionNote}`
    );
  }

  lines.push(
    ``,
    `## Recommended Security Actions`,
    ...report.recommendations.map((r) => `- ${r}`),
    ``,
    `## Detection Limitations`,
    ...report.limitations.map((l) => `- ${l}`)
  );

  return lines.join('\n');
}

function downloadTextFile(filename: string, content: string, mime: string) {
  const blob = new Blob([content], { type: mime });
  const url = URL.createObjectURL(blob);
  const a = document.createElement('a');
  a.href = url;
  a.download = filename;
  document.body.appendChild(a);
  a.click();
  document.body.removeChild(a);
  URL.revokeObjectURL(url);
}

export function DetectionReportView({ report, onInspectUrl }: DetectionReportViewProps) {
  const radius = 44;
  const circumference = 2 * Math.PI * radius;
  const strokeDashoffset = circumference - (report.riskScore / 100) * circumference;

  const sortedSignals = [...report.signals].sort((a, b) => b.points - a.points);

  const strokeColor =
    report.classification === 'Malicious'
      ? '#38BDF8'
      : report.classification === 'Suspicious'
        ? '#60A5FA'
        : '#94A3B8';

  return (
    <section
      aria-label="Detection report details"
      className="space-y-6"
    >
      {/* Primary Verdict Header */}
      <div className="aegis-surface-active rounded-2xl p-6 sm:p-8">
        <div className="flex flex-col gap-6 lg:flex-row lg:items-center lg:justify-between">
          <div className="min-w-0 flex-1 space-y-3">
            <div className="flex flex-wrap items-center gap-x-3 gap-y-1 text-xs text-[#94A3B8]">
              <span>{report.kind === 'url' ? 'URL Inspection' : 'Email Inspection'}</span>
              <span aria-hidden="true">·</span>
              <span className="tabular-nums">{formatDateTime(report.scannedAt)}</span>
              <span aria-hidden="true">·</span>
              <span className="font-mono tabular-nums">{report.durationMs} ms</span>
            </div>

            <div className="flex flex-wrap items-center gap-4">
              <ClassificationMark classification={report.classification} size="lg" />
              <span className="text-[#475569]" aria-hidden="true">/</span>
              <h2 className="font-display text-xl font-semibold text-[#F1F5F9] sm:text-2xl">
                {report.threatCategory}
              </h2>
            </div>

            <p className="font-mono text-xs text-[#93C5FD] break-all sm:text-sm">
              {report.target}
            </p>

            <p className="max-w-3xl text-sm leading-relaxed text-[#CBD5E1]">
              {report.summaryExplanation}
            </p>

            <div className="flex flex-wrap items-center gap-3 pt-2">
              <button
                type="button"
                onClick={() =>
                  downloadTextFile(
                    `aegistrace-report-${report.id.slice(0, 8)}.json`,
                    JSON.stringify(report, null, 2),
                    'application/json'
                  )
                }
                className="inline-flex items-center gap-2 rounded-lg border border-[#3B82F6]/35 bg-[#161E2E] px-3.5 py-2 text-xs font-medium text-[#CBD5E1] transition-colors hover:border-[#60A5FA] hover:text-[#F8FAFC] whitespace-nowrap cursor-pointer"
              >
                <Download className="h-3.5 w-3.5 text-[#60A5FA]" aria-hidden="true" />
                Export JSON
              </button>
              <button
                type="button"
                onClick={() =>
                  downloadTextFile(
                    `aegistrace-report-${report.id.slice(0, 8)}.md`,
                    buildMarkdownReport(report),
                    'text/markdown'
                  )
                }
                className="inline-flex items-center gap-2 rounded-lg border border-[#94A3B8]/20 bg-[#121722] px-3.5 py-2 text-xs font-medium text-[#CBD5E1] transition-colors hover:border-[#60A5FA] hover:text-[#F8FAFC] whitespace-nowrap cursor-pointer"
              >
                <Download className="h-3.5 w-3.5 text-[#94A3B8]" aria-hidden="true" />
                Export Markdown
              </button>
            </div>
          </div>

          {/* Radial Blue Risk Percentage Gauge */}
          <div className="flex shrink-0 items-center gap-5 self-start lg:self-center">
            <div className="relative flex h-28 w-28 items-center justify-center">
              <svg className="h-28 w-28 -rotate-90" viewBox="0 0 104 104" aria-hidden="true">
                <circle
                  cx="52"
                  cy="52"
                  r={radius}
                  fill="none"
                  stroke="rgba(148, 163, 184, 0.14)"
                  strokeWidth="7"
                />
                <circle
                  cx="52"
                  cy="52"
                  r={radius}
                  fill="none"
                  stroke={strokeColor}
                  strokeWidth="7"
                  strokeLinecap="round"
                  strokeDasharray={circumference}
                  strokeDashoffset={strokeDashoffset}
                  style={{
                    filter:
                      report.riskScore >= 30
                        ? 'drop-shadow(0 0 8px rgba(56, 189, 248, 0.55))'
                        : 'none',
                    transition: 'stroke-dashoffset 450ms cubic-bezier(0.16, 1, 0.3, 1)',
                  }}
                />
              </svg>
              <div className="absolute inset-0 flex flex-col items-center justify-center text-center">
                <span className="font-mono text-2xl font-semibold text-[#F8FAFC] tabular-nums">
                  {report.riskScore}%
                </span>
                <span className="text-[11px] font-medium text-[#94A3B8]">Risk Score</span>
              </div>
            </div>
          </div>
        </div>
      </div>

      {/* Triggered Detection Signals */}
      <div className="aegis-surface rounded-2xl p-6">
        <div className="mb-4 flex items-center justify-between gap-4 border-b border-[#94A3B8]/12 pb-3">
          <div className="flex items-center gap-2.5">
            <Shield className="h-4 w-4 text-[#60A5FA]" aria-hidden="true" />
            <h3 className="font-display text-base font-semibold text-[#F1F5F9]">
              Detection Signals &amp; Pattern Matches
            </h3>
          </div>
          <span className="font-mono text-xs text-[#94A3B8] tabular-nums">
            {sortedSignals.length} finding{sortedSignals.length === 1 ? '' : 's'}
          </span>
        </div>

        {sortedSignals.length === 0 ? (
          <div className="py-6 text-sm text-[#94A3B8]">
            No suspicious lexical, impersonation, transport, or content patterns were triggered during this scan.
          </div>
        ) : (
          <div className="divide-y divide-[#94A3B8]/10">
            {sortedSignals.map((sig) => (
              <div
                key={sig.id}
                className="flex flex-col gap-2 py-3.5 first:pt-1 last:pb-1 sm:flex-row sm:items-start sm:justify-between"
              >
                <div className="space-y-1">
                  <div className="flex flex-wrap items-center gap-x-2.5 gap-y-1">
                    <span className="text-sm font-medium text-[#E2E8F0]">{sig.title}</span>
                    <span className="text-xs text-[#64748B]" aria-hidden="true">·</span>
                    <span className="text-xs text-[#60A5FA]">{sig.category}</span>
                  </div>
                  <p className="text-xs leading-relaxed text-[#94A3B8]">{sig.detail}</p>
                  {sig.evidence && (
                    <p className="font-mono text-[11px] text-[#7DD3FC] break-all">
                      Evidence: {sig.evidence}
                    </p>
                  )}
                </div>
                <div className="flex items-center gap-3 shrink-0 sm:text-right">
                  <span className="text-xs font-medium capitalize text-[#94A3B8]">
                    {sig.severity}
                  </span>
                  <span className="font-mono text-xs font-semibold text-[#60A5FA] tabular-nums">
                    +{sig.points} pts
                  </span>
                </div>
              </div>
            ))}
          </div>
        )}
      </div>

      {/* Domain & SSL Telemetry (for URL scans) */}
      {report.kind === 'url' && (report.domainInfo || report.sslInfo || report.urlMetrics) && (
        <div className="grid grid-cols-1 gap-6 lg:grid-cols-2">
          {report.domainInfo && (
            <div className="aegis-surface rounded-2xl p-6">
              <div className="mb-4 flex items-center gap-2.5 border-b border-[#94A3B8]/12 pb-3">
                <Globe className="h-4 w-4 text-[#60A5FA]" aria-hidden="true" />
                <h3 className="font-display text-base font-semibold text-[#F1F5F9]">
                  Domain &amp; DNS Reputation
                </h3>
              </div>
              <dl className="grid grid-cols-2 gap-x-4 gap-y-3 text-xs">
                <div>
                  <dt className="text-[#64748B]">Registrable Domain</dt>
                  <dd className="mt-0.5 font-mono text-[#E2E8F0] break-all">
                    {report.domainInfo.registrableDomain}
                  </dd>
                </div>
                <div>
                  <dt className="text-[#64748B]">Top-Level Domain</dt>
                  <dd className="mt-0.5 font-mono text-[#E2E8F0]">.{report.domainInfo.tld}</dd>
                </div>
                <div>
                  <dt className="text-[#64748B]">DNS Resolution</dt>
                  <dd className="mt-0.5 font-mono text-[#CBD5E1]">
                    {report.domainInfo.dnsStatus === 'resolved'
                      ? report.domainInfo.resolvedIps.slice(0, 2).join(', ')
                      : report.domainInfo.dnsStatus}
                  </dd>
                </div>
                <div>
                  <dt className="text-[#64748B]">Domain Age (RDAP)</dt>
                  <dd className="mt-0.5 font-mono text-[#E2E8F0] tabular-nums">
                    {report.domainInfo.domainAgeDays !== null
                      ? `${report.domainInfo.domainAgeDays.toLocaleString()} days`
                      : 'Not disclosed'}
                  </dd>
                </div>
                <div>
                  <dt className="text-[#64748B]">Mail Auth (MX / SPF / DMARC)</dt>
                  <dd className="mt-0.5 font-mono text-[#CBD5E1]">
                    {report.domainInfo.hasMxRecords ? 'MX' : 'No MX'} ·{' '}
                    {report.domainInfo.hasSpfRecord ? 'SPF' : 'No SPF'} ·{' '}
                    {report.domainInfo.hasDmarcRecord ? 'DMARC' : 'No DMARC'}
                  </dd>
                </div>
                <div>
                  <dt className="text-[#64748B]">Registrar</dt>
                  <dd className="mt-0.5 text-[#CBD5E1] truncate">
                    {report.domainInfo.registrar ?? 'Unavailable'}
                  </dd>
                </div>
                {report.urlMetrics && (
                  <>
                    <div>
                      <dt className="text-[#64748B]">URL Length / Subdomains</dt>
                      <dd className="mt-0.5 font-mono text-[#CBD5E1] tabular-nums">
                        {report.urlMetrics.urlLength} chars · {report.urlMetrics.subdomainCount} sub
                      </dd>
                    </div>
                    <div>
                      <dt className="text-[#64748B]">Label Entropy</dt>
                      <dd className="mt-0.5 font-mono text-[#CBD5E1] tabular-nums">
                        {report.urlMetrics.domainEntropy} bits
                      </dd>
                    </div>
                  </>
                )}
              </dl>
            </div>
          )}

          {report.sslInfo && (
            <div className="aegis-surface rounded-2xl p-6">
              <div className="mb-4 flex items-center gap-2.5 border-b border-[#94A3B8]/12 pb-3">
                <Lock className="h-4 w-4 text-[#60A5FA]" aria-hidden="true" />
                <h3 className="font-display text-base font-semibold text-[#F1F5F9]">
                  SSL / HTTPS Security Inspection
                </h3>
              </div>
              <dl className="grid grid-cols-2 gap-x-4 gap-y-3 text-xs">
                <div>
                  <dt className="text-[#64748B]">Transport Protocol</dt>
                  <dd className="mt-0.5 font-mono text-[#E2E8F0]">
                    {report.sslInfo.usesHttps
                      ? `HTTPS (${report.sslInfo.tlsProtocol ?? 'TLS'})`
                      : 'HTTP (Unencrypted)'}
                  </dd>
                </div>
                <div>
                  <dt className="text-[#64748B]">Certificate Chain</dt>
                  <dd className="mt-0.5 font-mono text-[#CBD5E1]">
                    {!report.sslInfo.usesHttps
                      ? 'None'
                      : report.sslInfo.trustedBySystem
                        ? 'Trusted CA'
                        : report.sslInfo.certificatePresent
                          ? 'Untrusted / Warning'
                          : 'Unavailable'}
                  </dd>
                </div>
                <div>
                  <dt className="text-[#64748B]">Issuer Organization</dt>
                  <dd className="mt-0.5 text-[#CBD5E1] truncate">
                    {report.sslInfo.issuerOrganization ?? 'N/A'}
                  </dd>
                </div>
                <div>
                  <dt className="text-[#64748B]">Subject Common Name</dt>
                  <dd className="mt-0.5 font-mono text-[#CBD5E1] truncate">
                    {report.sslInfo.subjectCommonName ?? 'N/A'}
                  </dd>
                </div>
                <div>
                  <dt className="text-[#64748B]">Hostname Match</dt>
                  <dd className="mt-0.5 font-mono text-[#CBD5E1]">
                    {report.sslInfo.hostnameMatch === null
                      ? 'N/A'
                      : report.sslInfo.hostnameMatch
                        ? 'Matched'
                        : 'Mismatch'}
                  </dd>
                </div>
                <div>
                  <dt className="text-[#64748B]">Certificate Validity</dt>
                  <dd className="mt-0.5 font-mono text-[#CBD5E1] tabular-nums">
                    {report.sslInfo.daysRemaining !== null
                      ? `${report.sslInfo.daysRemaining} days remaining`
                      : 'N/A'}
                  </dd>
                </div>
              </dl>
              <p className="mt-4 border-t border-[#94A3B8]/12 pt-3 text-xs leading-relaxed text-[#94A3B8]">
                {report.sslInfo.inspectionNote}
              </p>
              {report.httpInfo && (
                <p className="mt-2 text-xs text-[#64748B]">
                  HTTP Probe: {report.httpInfo.note}
                  {report.httpInfo.pageTitle ? ` Title: "${report.httpInfo.pageTitle}"` : ''}
                </p>
              )}
            </div>
          )}
        </div>
      )}

      {/* Email Metadata & Extracted Links */}
      {report.kind === 'email' && report.emailInfo && (
        <div className="grid grid-cols-1 gap-6 lg:grid-cols-2">
          <div className="aegis-surface rounded-2xl p-6">
            <div className="mb-4 flex items-center gap-2.5 border-b border-[#94A3B8]/12 pb-3">
              <Mail className="h-4 w-4 text-[#60A5FA]" aria-hidden="true" />
              <h3 className="font-display text-base font-semibold text-[#F1F5F9]">
                Header &amp; Authentication Telemetry
              </h3>
            </div>
            <dl className="grid grid-cols-2 gap-x-4 gap-y-3 text-xs">
              <div className="col-span-2">
                <dt className="text-[#64748B]">From Address</dt>
                <dd className="mt-0.5 font-mono text-[#E2E8F0] break-all">
                  {report.emailInfo.senderDisplayName
                    ? `${report.emailInfo.senderDisplayName} <${report.emailInfo.senderAddress}>`
                    : report.emailInfo.senderAddress ?? 'Not specified in input'}
                </dd>
              </div>
              <div>
                <dt className="text-[#64748B]">Reply-To</dt>
                <dd className="mt-0.5 font-mono text-[#CBD5E1] break-all">
                  {report.emailInfo.replyToAddress ?? 'Not present'}
                </dd>
              </div>
              <div>
                <dt className="text-[#64748B]">Return-Path</dt>
                <dd className="mt-0.5 font-mono text-[#CBD5E1] break-all">
                  {report.emailInfo.returnPathAddress ?? 'Not present'}
                </dd>
              </div>
              <div>
                <dt className="text-[#64748B]">SPF / DKIM / DMARC</dt>
                <dd className="mt-0.5 font-mono text-[#CBD5E1]">
                  {report.emailInfo.spfStatus} · {report.emailInfo.dkimStatus} ·{' '}
                  {report.emailInfo.dmarcStatus}
                </dd>
              </div>
              <div>
                <dt className="text-[#64748B]">Manipulation Cues</dt>
                <dd className="mt-0.5 font-mono text-[#CBD5E1] tabular-nums">
                  {report.emailInfo.urgencyCueCount} urgency ·{' '}
                  {report.emailInfo.credentialRequestCueCount} credential
                </dd>
              </div>
            </dl>
          </div>

          <div className="aegis-surface rounded-2xl p-6">
            <div className="mb-4 flex items-center justify-between border-b border-[#94A3B8]/12 pb-3">
              <div className="flex items-center gap-2.5">
                <ExternalLink className="h-4 w-4 text-[#60A5FA]" aria-hidden="true" />
                <h3 className="font-display text-base font-semibold text-[#F1F5F9]">
                  Extracted URLs ({report.emailInfo.extractedUrls.length})
                </h3>
              </div>
            </div>

            {report.emailInfo.extractedUrls.length === 0 ? (
              <p className="text-xs text-[#94A3B8]">
                No HTTP/HTTPS links were found in the email body.
              </p>
            ) : (
              <div className="divide-y divide-[#94A3B8]/10">
                {report.emailInfo.extractedUrls.map((item, idx) => (
                  <div
                    key={`${item.url}-${idx}`}
                    className="flex flex-col gap-2 py-2.5 first:pt-0 last:pb-0 sm:flex-row sm:items-center sm:justify-between"
                  >
                    <div className="min-w-0 flex-1 space-y-0.5">
                      <p className="font-mono text-xs text-[#93C5FD] truncate" title={item.url}>
                        {item.url}
                      </p>
                      <div className="flex items-center gap-2 text-[11px] text-[#94A3B8]">
                        <ClassificationMark classification={item.classification} size="sm" />
                        <span aria-hidden="true">·</span>
                        <span className="font-mono tabular-nums">{item.riskScore}% risk</span>
                        {item.mismatchDetected && (
                          <>
                            <span aria-hidden="true">·</span>
                            <span className="text-[#38BDF8]">Anchor mismatch</span>
                          </>
                        )}
                      </div>
                    </div>
                    {onInspectUrl && (
                      <button
                        type="button"
                        onClick={() => onInspectUrl(item.url)}
                        className="inline-flex items-center gap-1.5 rounded-lg border border-[#3B82F6]/30 bg-[#141C2B] px-2.5 py-1.5 text-[11px] font-medium text-[#60A5FA] hover:border-[#60A5FA] hover:text-[#F8FAFC] whitespace-nowrap shrink-0 cursor-pointer"
                      >
                        <Search className="h-3 w-3" aria-hidden="true" />
                        Deep Scan
                      </button>
                    )}
                  </div>
                ))}
              </div>
            )}
          </div>
        </div>
      )}

      {/* Recommended Actions & Detection Limitations */}
      <div className="grid grid-cols-1 gap-6 lg:grid-cols-2">
        <div className="aegis-surface rounded-2xl p-6">
          <div className="mb-3 flex items-center gap-2.5 border-b border-[#94A3B8]/12 pb-3">
            <CheckCircle2 className="h-4 w-4 text-[#60A5FA]" aria-hidden="true" />
            <h3 className="font-display text-base font-semibold text-[#F1F5F9]">
              Recommended Security Actions
            </h3>
          </div>
          <ul className="space-y-2.5 text-xs leading-relaxed text-[#CBD5E1]">
            {report.recommendations.map((rec, i) => (
              <li key={i} className="flex items-start gap-2.5">
                <span className="mt-1.5 h-1.5 w-1.5 shrink-0 rounded-full bg-[#3B82F6]" aria-hidden="true" />
                <span>{rec}</span>
              </li>
            ))}
          </ul>
        </div>

        <div className="aegis-surface rounded-2xl p-6">
          <div className="mb-3 flex items-center gap-2.5 border-b border-[#94A3B8]/12 pb-3">
            <Info className="h-4 w-4 text-[#94A3B8]" aria-hidden="true" />
            <h3 className="font-display text-base font-semibold text-[#F1F5F9]">
              Detection Limitations &amp; Scope
            </h3>
          </div>
          <ul className="space-y-2.5 text-xs leading-relaxed text-[#94A3B8]">
            {report.limitations.map((lim, i) => (
              <li key={i} className="flex items-start gap-2.5">
                <span className="mt-1.5 h-1.5 w-1.5 shrink-0 rounded-full bg-[#64748B]" aria-hidden="true" />
                <span>{lim}</span>
              </li>
            ))}
          </ul>
        </div>
      </div>
    </section>
  );
}

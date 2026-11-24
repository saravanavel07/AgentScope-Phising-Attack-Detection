import { useState } from 'react';
import { ArrowRight, FileText, Mail, Upload } from 'lucide-react';
import type { ScanReport } from '../types/scanner';
import { DetectionReportView } from './DetectionReportView';

interface EmailAnalyzerViewProps {
  onScanStateChange: (scanning: boolean) => void;
  onScanComplete: (report: ScanReport) => void;
  onDeepInspectUrl: (url: string) => void;
}

const SAMPLE_PHISHING_EMAIL = `From: "PayPal Security Center" <alerts@billing-support-notice.xyz>
Reply-To: verify-desk@account-recovery-team.top
Return-Path: <bounce@account-recovery-team.top>
Subject: Urgent Action Required: Your account has been suspended
Authentication-Results: mx.example.net; spf=fail; dkim=fail; dmarc=fail

Dear Customer,

We detected unauthorized login activity on your PayPal account. Your account has been temporarily suspended and will be permanently closed within 24 hours unless you verify your password and billing details.

Confirm your identity immediately at:
<a href="http://paypa1-secure-verify.xyz/login?session=8912a">https://www.paypal.com/myaccount/security</a>

Failure to respond may result in account termination.

Regards,
PayPal Security Department`;

const SAMPLE_SAFE_EMAIL = `From: "GitHub" <noreply@github.com>
Reply-To: noreply@github.com
Return-Path: <noreply@github.com>
Subject: [GitHub] A new SSH key was added to your account
Authentication-Results: mx.example.net; spf=pass; dkim=pass; dmarc=pass

Hello,

The following SSH key was added to your account:
Key fingerprint: SHA256:exampleFingerprintValue

If you recognize this change, no further action is needed. You can review your security settings at https://github.com/settings/keys

Thanks,
The GitHub Team`;

export function EmailAnalyzerView({
  onScanStateChange,
  onScanComplete,
  onDeepInspectUrl,
}: EmailAnalyzerViewProps) {
  const [sender, setSender] = useState('');
  const [subject, setSubject] = useState('');
  const [rawContent, setRawContent] = useState('');
  const [isScanning, setIsScanning] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [latestReport, setLatestReport] = useState<ScanReport | null>(null);

  const runEmailAnalysis = async (payload: { rawContent: string; sender?: string; subject?: string }) => {
    if (!payload.rawContent.trim()) {
      setError('Paste email headers/body or upload an .eml file to analyze.');
      return;
    }

    setError(null);
    setIsScanning(true);
    onScanStateChange(true);

    try {
      const res = await fetch('/api/scan/email', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(payload),
      });
      const data = (await res.json()) as { report?: ScanReport; error?: string };
      if (!res.ok || !data.report) {
        throw new Error(data.error || 'Email analysis failed.');
      }
      setLatestReport(data.report);
      onScanComplete(data.report);
    } catch (err) {
      setError(err instanceof Error ? err.message : 'Unable to analyze email content.');
    } finally {
      setIsScanning(false);
      onScanStateChange(false);
    }
  };

  const handleSubmit = (e: React.FormEvent) => {
    e.preventDefault();
    void runEmailAnalysis({ rawContent, sender, subject });
  };

  const handleFileUpload = (e: React.ChangeEvent<HTMLInputElement>) => {
    const file = e.target.files?.[0];
    if (!file) return;
    if (file.size > 120_000) {
      setError('File exceeds 120 KB limit for text/EML header inspection.');
      return;
    }
    const reader = new FileReader();
    reader.onload = () => {
      const text = typeof reader.result === 'string' ? reader.result : '';
      setRawContent(text);
      setError(null);
    };
    reader.readAsText(file);
  };

  return (
    <div className="space-y-8">
      <div className="space-y-2">
        <h1 className="font-display text-2xl font-bold tracking-tight text-[#F8FAFC] sm:text-3xl aegis-heading-glow">
          Email Phishing &amp; Header Analyzer
        </h1>
        <p className="max-w-2xl text-sm leading-relaxed text-[#94A3B8]">
          Evaluate raw email headers, SPF/DKIM/DMARC alignment, display-name spoofing, urgency manipulation cues, and embedded hyperlinks.
        </p>
      </div>

      <form
        onSubmit={handleSubmit}
        className={`rounded-2xl p-5 sm:p-6 transition-all duration-200 ${
          isScanning ? 'aegis-surface-active aegis-pulse-glow' : 'aegis-surface'
        }`}
      >
        <div className="grid grid-cols-1 gap-4 sm:grid-cols-2 mb-4">
          <div>
            <label htmlFor="email-sender" className="block text-xs font-medium text-[#CBD5E1] mb-1.5">
              Sender Header (Optional if included below)
            </label>
            <input
              id="email-sender"
              type="text"
              value={sender}
              onChange={(e) => setSender(e.target.value)}
              placeholder='e.g. "Support" <help@example.com>'
              disabled={isScanning}
              className="w-full rounded-xl border border-[#94A3B8]/18 bg-[#0B0E14] px-3.5 py-2.5 font-mono text-xs text-[#F1F5F9] placeholder-[#475569] focus:border-[#3B82F6] focus:outline-none focus:ring-2 focus:ring-[#3B82F6]/35"
            />
          </div>
          <div>
            <label htmlFor="email-subject" className="block text-xs font-medium text-[#CBD5E1] mb-1.5">
              Subject Line (Optional if included below)
            </label>
            <input
              id="email-subject"
              type="text"
              value={subject}
              onChange={(e) => setSubject(e.target.value)}
              placeholder="e.g. Action required: verify account"
              disabled={isScanning}
              className="w-full rounded-xl border border-[#94A3B8]/18 bg-[#0B0E14] px-3.5 py-2.5 text-xs text-[#F1F5F9] placeholder-[#475569] focus:border-[#3B82F6] focus:outline-none focus:ring-2 focus:ring-[#3B82F6]/35"
            />
          </div>
        </div>

        <div className="mb-2 flex flex-wrap items-center justify-between gap-2">
          <label htmlFor="email-raw-body" className="text-xs font-medium text-[#CBD5E1]">
            Raw Email Headers &amp; Message Content
          </label>
          <label className="inline-flex items-center gap-1.5 rounded-lg border border-[#94A3B8]/20 bg-[#121722] px-3 py-1.5 text-xs font-medium text-[#CBD5E1] hover:border-[#3B82F6]/50 hover:text-[#60A5FA] cursor-pointer">
            <Upload className="h-3.5 w-3.5" aria-hidden="true" />
            <span>Load .eml / .txt</span>
            <input
              type="file"
              accept=".eml,.txt,.msg,text/plain,message/rfc822"
              onChange={handleFileUpload}
              className="sr-only"
            />
          </label>
        </div>

        <textarea
          id="email-raw-body"
          rows={9}
          value={rawContent}
          onChange={(e) => setRawContent(e.target.value)}
          disabled={isScanning}
          placeholder="Paste full email headers (From, Reply-To, Authentication-Results) and message body or HTML links..."
          className="w-full rounded-xl border border-[#94A3B8]/18 bg-[#0B0E14] p-4 font-mono text-xs leading-relaxed text-[#E2E8F0] placeholder-[#475569] focus:border-[#3B82F6] focus:outline-none focus:ring-2 focus:ring-[#3B82F6]/35"
        />

        <div className="mt-4 flex flex-col gap-4 border-t border-[#94A3B8]/10 pt-4 sm:flex-row sm:items-center sm:justify-between">
          <div className="flex flex-wrap items-center gap-x-4 gap-y-2 text-xs">
            <span className="text-[#64748B]">Load sample input:</span>
            <button
              type="button"
              disabled={isScanning}
              onClick={() => {
                setSender('');
                setSubject('');
                setRawContent(SAMPLE_PHISHING_EMAIL);
              }}
              className="font-medium text-[#60A5FA] hover:text-[#93C5FD] hover:underline underline-offset-4 cursor-pointer"
            >
              Phishing Spoof Sample
            </button>
            <button
              type="button"
              disabled={isScanning}
              onClick={() => {
                setSender('');
                setSubject('');
                setRawContent(SAMPLE_SAFE_EMAIL);
              }}
              className="font-medium text-[#94A3B8] hover:text-[#E2E8F0] hover:underline underline-offset-4 cursor-pointer"
            >
              Legitimate Notice Sample
            </button>
          </div>

          <button
            type="submit"
            disabled={isScanning}
            className="aegis-btn-primary inline-flex min-h-[44px] items-center justify-center gap-2 rounded-xl px-6 py-2.5 text-sm font-semibold text-[#F8FAFC] whitespace-nowrap shrink-0 cursor-pointer disabled:opacity-60"
          >
            <Mail className="h-4 w-4" aria-hidden="true" />
            <span>{isScanning ? 'Analyzing Email...' : 'Analyze Email'}</span>
            <ArrowRight className="h-4 w-4" aria-hidden="true" />
          </button>
        </div>

        {isScanning && (
          <div className="mt-4 space-y-2 border-t border-[#3B82F6]/25 pt-4">
            <div className="relative h-1.5 w-full overflow-hidden rounded-full bg-[#171E2C]">
              <div className="aegis-scan-beam h-full w-1/2 rounded-full bg-gradient-to-r from-transparent via-[#38BDF8] to-transparent" />
            </div>
            <p className="text-xs text-[#93C5FD]">
              Parsing MIME headers, verifying authentication cues, and inspecting embedded links...
            </p>
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

      {!latestReport && !isScanning && (
        <div className="aegis-surface rounded-xl p-5 flex items-start gap-3">
          <FileText className="mt-0.5 h-4 w-4 shrink-0 text-[#60A5FA]" aria-hidden="true" />
          <div className="space-y-1">
            <h2 className="text-sm font-semibold text-[#E2E8F0]">Privacy &amp; Header Guidance</h2>
            <p className="text-xs leading-relaxed text-[#94A3B8]">
              Submitted email text is processed solely to extract sender domains, authentication headers (SPF/DKIM/DMARC), manipulation cues, and embedded URLs. Avoid pasting confidential personal secrets not needed for threat triage.
            </p>
          </div>
        </div>
      )}

      {latestReport && (
        <DetectionReportView report={latestReport} onInspectUrl={onDeepInspectUrl} />
      )}
    </div>
  );
}

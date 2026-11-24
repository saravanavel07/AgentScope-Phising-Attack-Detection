import crypto from 'node:crypto';
import { analyzeUrl, buildRecommendations } from './urlAnalyzer.ts';
import type {
  DetectionSignal,
  EmailAnalysisInfo,
  ScanReport,
  ThreatClassification,
} from '../../src/types/scanner.ts';

export interface EmailScanInput {
  rawContent: string;
  sender?: string;
  subject?: string;
}

const URGENCY_PATTERNS: Array<{ label: string; regex: RegExp }> = [
  { label: 'Immediate deadline pressure', regex: /\b(within\s+24\s+hours?|immediately|urgent\s+action|act\s+now|expires?\s+today|final\s+notice)\b/i },
  { label: 'Account suspension threat', regex: /\b(account\s+(has\s+been\s+)?(suspended|locked|disabled|restricted|terminated)|permanently\s+closed)\b/i },
  { label: 'Unauthorized activity alarm', regex: /\b(unauthorized\s+(login|access|transaction|sign-?in)|unusual\s+activity|security\s+alert)\b/i },
  { label: 'Legal or financial penalty', regex: /\b(legal\s+action|warrant|fine\s+will\s+be\s+assessed|irs|tax\s+refund|overdue\s+invoice)\b/i },
];

const CREDENTIAL_HARVEST_PATTERNS: Array<{ label: string; regex: RegExp }> = [
  { label: 'Credential verification prompt', regex: /\b(verify\s+your\s+(account|identity|password|credentials)|confirm\s+your\s+(password|pin|ssn)|re-?enter\s+your\s+password)\b/i },
  { label: 'Financial / card / crypto solicitation', regex: /\b(wire\s+transfer|gift\s+card|seed\s+phrase|recovery\s+phrase|update\s+(your\s+)?(billing|payment|card)\s+details?)\b/i },
  { label: 'MFA / OTP interception cue', regex: /\b(provide\s+(the\s+)?(otp|one-time\s+code|verification\s+code)|disable\s+2fa)\b/i },
];

const RISKY_ATTACHMENT_REGEX = /\b[\w.-]+\.(exe|scr|bat|cmd|vbs|js|jse|iso|img|html|htm|hta|xlsm|docm|zip|rar)\b/gi;

const FREE_WEBMAIL_DOMAINS = new Set([
  'gmail.com', 'yahoo.com', 'outlook.com', 'hotmail.com', 'aol.com', 'proton.me', 'protonmail.com', 'gmx.com', 'yandex.com',
]);

const BRAND_NAMES_FOR_DISPLAY_SPOOF = [
  'paypal', 'microsoft', 'apple', 'amazon', 'google', 'chase', 'bank of america',
  'wells fargo', 'dhl', 'fedex', 'usps', 'netflix', 'coinbase', 'docusign', 'okta', 'irs',
];

function extractHeaderValue(rawHeaders: string, name: string): string | null {
  const unfolded = rawHeaders.replace(/\r?\n[ \t]+/g, ' ');
  const regex = new RegExp(`^${name}:\\s*(.+)$`, 'im');
  const match = unfolded.match(regex);
  return match?.[1]?.trim() ?? null;
}

function parseEmailAddressAndDisplay(headerVal: string | null): { displayName: string | null; address: string | null; domain: string | null } {
  if (!headerVal) return { displayName: null, address: null, domain: null };
  const angleMatch = headerVal.match(/^(?:"?([^"<]*?)"?\s*)?<([^>\s]+@[^>\s]+)>/);
  if (angleMatch) {
    const displayName = angleMatch[1]?.trim() || null;
    const address = angleMatch[2].trim().toLowerCase();
    const domain = address.split('@')[1] ?? null;
    return { displayName, address, domain };
  }
  const plainMatch = headerVal.match(/([a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,})/);
  if (plainMatch) {
    const address = plainMatch[1].toLowerCase();
    const domain = address.split('@')[1] ?? null;
    return { displayName: null, address, domain };
  }
  return { displayName: null, address: null, domain: null };
}

function extractAuthStatus(authResults: string | null, mechanism: 'spf' | 'dkim' | 'dmarc'): 'pass' | 'fail' | 'softfail' | 'neutral' | 'none' | 'not_present' {
  if (!authResults) return 'not_present';
  const regex = new RegExp(`${mechanism}\\s*=\\s*(pass|fail|softfail|neutral|none)`, 'i');
  const match = authResults.match(regex);
  if (!match) return 'not_present';
  const val = match[1].toLowerCase();
  if (val === 'pass' || val === 'fail' || val === 'softfail' || val === 'neutral' || val === 'none') {
    return val;
  }
  return 'not_present';
}

function extractLinksFromBody(body: string): Array<{ url: string; anchorText: string | null; mismatchDetected: boolean }> {
  const results = new Map<string, { url: string; anchorText: string | null; mismatchDetected: boolean }>();

  // 1. HTML <a href="...">anchor</a>
  const anchorRegex = /<a\b[^>]*href\s*=\s*["'](https?:\/\/[^"'\s<>]+)["'][^>]*>([\s\S]*?)<\/a>/gi;
  for (const m of body.matchAll(anchorRegex)) {
    const url = m[1].trim();
    const anchorRaw = m[2].replace(/<[^>]+>/g, '').replace(/\s+/g, ' ').trim();
    let mismatchDetected = false;
    if (/^https?:\/\//i.test(anchorRaw)) {
      try {
        const hrefHost = new URL(url).hostname.toLowerCase();
        const textHost = new URL(anchorRaw).hostname.toLowerCase();
        if (hrefHost !== textHost) {
          mismatchDetected = true;
        }
      } catch {
        // ignore unparseable anchor text URL
      }
    }
    results.set(url, { url, anchorText: anchorRaw || null, mismatchDetected });
  }

  // 2. Markdown [text](url)
  const mdRegex = /\[([^\]]+)\]\((https?:\/\/[^\s)]+)\)/gi;
  for (const m of body.matchAll(mdRegex)) {
    const anchorRaw = m[1].trim();
    const url = m[2].trim();
    let mismatchDetected = false;
    if (/^https?:\/\//i.test(anchorRaw)) {
      try {
        const hrefHost = new URL(url).hostname.toLowerCase();
        const textHost = new URL(anchorRaw).hostname.toLowerCase();
        if (hrefHost !== textHost) mismatchDetected = true;
      } catch {
        // ignore
      }
    }
    if (!results.has(url)) {
      results.set(url, { url, anchorText: anchorRaw, mismatchDetected });
    }
  }

  // 3. Plain text URLs
  const plainUrlRegex = /https?:\/\/[^\s<>"')\]}]+/gi;
  for (const m of body.matchAll(plainUrlRegex)) {
    const url = m[0].replace(/[.,;:!?]+$/, '');
    if (!results.has(url)) {
      results.set(url, { url, anchorText: null, mismatchDetected: false });
    }
  }

  return Array.from(results.values()).slice(0, 8);
}

export async function analyzeEmail(input: EmailScanInput): Promise<ScanReport> {
  const startedAt = Date.now();
  const raw = input.rawContent?.trim() ?? '';

  if (!raw || raw.length < 12) {
    throw new Error('Please paste email headers or message content (minimum 12 characters) to analyze.');
  }

  // Split headers and body if blank line separator exists with header-like lines at top
  const splitMatch = raw.match(/^([\s\S]*?)\r?\n\r?\n([\s\S]*)$/);
  const hasHeaderBlock = splitMatch ? /^(from|to|subject|return-path|received|authentication-results):/im.test(splitMatch[1]) : false;
  const rawHeaders = hasHeaderBlock && splitMatch ? splitMatch[1] : raw;
  const body = hasHeaderBlock && splitMatch ? splitMatch[2] : raw;

  const fromHeader = extractHeaderValue(rawHeaders, 'From') ?? (input.sender?.trim() || null);
  const replyToHeader = extractHeaderValue(rawHeaders, 'Reply-To');
  const returnPathHeader = extractHeaderValue(rawHeaders, 'Return-Path');
  const subjectHeader = extractHeaderValue(rawHeaders, 'Subject') ?? (input.subject?.trim() || null);
  const authResultsHeader = extractHeaderValue(rawHeaders, 'Authentication-Results');

  const senderParsed = parseEmailAddressAndDisplay(fromHeader);
  const replyParsed = parseEmailAddressAndDisplay(replyToHeader);
  const returnParsed = parseEmailAddressAndDisplay(returnPathHeader);

  const spfStatus = extractAuthStatus(authResultsHeader, 'spf');
  const rawDkim = extractAuthStatus(authResultsHeader, 'dkim');
  const rawDmarc = extractAuthStatus(authResultsHeader, 'dmarc');
  const dkimStatus: 'pass' | 'fail' | 'none' | 'not_present' =
    rawDkim === 'pass' || rawDkim === 'fail' || rawDkim === 'none' ? rawDkim : 'not_present';
  const dmarcStatus: 'pass' | 'fail' | 'none' | 'not_present' =
    rawDmarc === 'pass' || rawDmarc === 'fail' || rawDmarc === 'none' ? rawDmarc : 'not_present';

  const signals: DetectionSignal[] = [];

  // Header & Authentication signals
  if (spfStatus === 'fail' || spfStatus === 'softfail') {
    signals.push({
      id: 'email-spf-fail',
      category: 'Email Headers',
      title: `SPF authentication ${spfStatus}`,
      detail: 'The sending server IP is not authorized by the sender domain’s SPF policy.',
      severity: spfStatus === 'fail' ? 'high' : 'medium',
      points: spfStatus === 'fail' ? 24 : 15,
      evidence: `spf=${spfStatus}`,
    });
  }

  if (dkimStatus === 'fail') {
    signals.push({
      id: 'email-dkim-fail',
      category: 'Email Headers',
      title: 'DKIM cryptographic signature failed',
      detail: 'Message integrity or sender domain signing could not be verified.',
      severity: 'high',
      points: 22,
      evidence: 'dkim=fail',
    });
  }

  if (dmarcStatus === 'fail') {
    signals.push({
      id: 'email-dmarc-fail',
      category: 'Email Headers',
      title: 'DMARC alignment failed',
      detail: 'Neither SPF nor DKIM aligned with the visible From header domain.',
      severity: 'critical',
      points: 28,
      evidence: 'dmarc=fail',
    });
  }

  if (
    senderParsed.domain &&
    replyParsed.domain &&
    senderParsed.domain !== replyParsed.domain
  ) {
    signals.push({
      id: 'email-replyto-mismatch',
      category: 'Email Headers',
      title: 'From and Reply-To domain mismatch',
      detail: `Visible sender uses "${senderParsed.domain}", whereas replies route to "${replyParsed.domain}".`,
      severity: 'high',
      points: 22,
      evidence: `${senderParsed.domain} -> ${replyParsed.domain}`,
    });
  }

  if (
    senderParsed.domain &&
    returnParsed.domain &&
    senderParsed.domain !== returnParsed.domain
  ) {
    signals.push({
      id: 'email-returnpath-mismatch',
      category: 'Email Headers',
      title: 'From and Return-Path domain mismatch',
      detail: `Envelope bounce address (${returnParsed.domain}) differs from visible From domain (${senderParsed.domain}).`,
      severity: 'medium',
      points: 14,
      evidence: `${senderParsed.domain} / ${returnParsed.domain}`,
    });
  }

  // Display name spoofing (e.g. "PayPal Security <random123@gmail.com>")
  if (senderParsed.displayName && senderParsed.domain) {
    const lowerDisplay = senderParsed.displayName.toLowerCase();
    for (const brand of BRAND_NAMES_FOR_DISPLAY_SPOOF) {
      const compactBrand = brand.replace(/\s+/g, '');
      if (
        lowerDisplay.includes(brand) &&
        !senderParsed.domain.includes(compactBrand)
      ) {
        signals.push({
          id: `email-display-spoof-${compactBrand}`,
          category: 'Brand Impersonation',
          title: `Display name impersonates "${brand}" from unrelated domain`,
          detail: `Sender display name references "${brand}", but the email address domain is "${senderParsed.domain}"${FREE_WEBMAIL_DOMAINS.has(senderParsed.domain) ? ' (free webmail)' : ''}.`,
          severity: 'critical',
          points: 32,
          evidence: `${senderParsed.displayName} <${senderParsed.address}>`,
        });
        break;
      }
    }
  }

  // Content analysis: urgency & credential harvesting
  const combinedText = `${subjectHeader ?? ''}\n${body}`;
  let urgencyCueCount = 0;
  for (const pat of URGENCY_PATTERNS) {
    const m = combinedText.match(pat.regex);
    if (m) {
      urgencyCueCount++;
      signals.push({
        id: `email-urgency-${urgencyCueCount}`,
        category: 'Email Content',
        title: pat.label,
        detail: 'Message applies artificial urgency or fear to rush the recipient past verification checks.',
        severity: 'medium',
        points: 11,
        evidence: m[0],
      });
    }
  }

  let credentialRequestCueCount = 0;
  for (const pat of CREDENTIAL_HARVEST_PATTERNS) {
    const m = combinedText.match(pat.regex);
    if (m) {
      credentialRequestCueCount++;
      signals.push({
        id: `email-cred-${credentialRequestCueCount}`,
        category: 'Email Content',
        title: pat.label,
        detail: 'Message solicits sensitive authentication, financial, or personal verification information.',
        severity: 'high',
        points: 20,
        evidence: m[0],
      });
    }
  }

  // Risky attachment mentions
  const attachmentMatches = Array.from(combinedText.matchAll(RISKY_ATTACHMENT_REGEX)).map((m) => m[0]);
  const attachmentWarnings = Array.from(new Set(attachmentMatches));
  if (attachmentWarnings.length > 0) {
    signals.push({
      id: 'email-risky-attachments',
      category: 'Email Content',
      title: 'High-risk attachment filename pattern referenced',
      detail: `Email references executable, macro-enabled, archive, or HTML-smuggling file types (${attachmentWarnings.join(', ')}).`,
      severity: 'high',
      points: 20,
      evidence: attachmentWarnings.join(', '),
    });
  }

  // Extract and inspect embedded URLs (skip deep HTTP body fetch to keep email scan snappy & safe)
  const rawLinks = extractLinksFromBody(body);
  const extractedUrls: EmailAnalysisInfo['extractedUrls'] = [];

  const analyzedLinks = await Promise.all(
    rawLinks.map(async (link) => {
      try {
        const subReport = await analyzeUrl(link.url, { skipHttpProbe: true });
        return { link, subReport };
      } catch {
        return null;
      }
    })
  );

  let maxLinkRisk = 0;
  for (const item of analyzedLinks) {
    if (!item) continue;
    const { link, subReport } = item;
    const effectiveRisk = link.mismatchDetected
      ? Math.min(100, subReport.riskScore + 30)
      : subReport.riskScore;

    if (effectiveRisk > maxLinkRisk) maxLinkRisk = effectiveRisk;

    const linkClassification: ThreatClassification =
      effectiveRisk >= 60 ? 'Malicious' : effectiveRisk >= 30 ? 'Suspicious' : 'Safe';

    extractedUrls.push({
      url: link.url,
      anchorText: link.anchorText,
      mismatchDetected: link.mismatchDetected,
      riskScore: effectiveRisk,
      classification: linkClassification,
    });

    if (link.mismatchDetected) {
      signals.push({
        id: `email-link-mismatch-${extractedUrls.length}`,
        category: 'Email Content',
        title: 'Deceptive hyperlink anchor mismatch',
        detail: `Visible link text displays "${link.anchorText}" while the actual destination points to "${link.url}".`,
        severity: 'critical',
        points: 35,
        evidence: `${link.anchorText} -> ${link.url}`,
      });
    } else if (subReport.classification !== 'Safe') {
      signals.push({
        id: `email-risky-link-${extractedUrls.length}`,
        category: 'URL Structure',
        title: `Embedded link flagged as ${subReport.classification} (${subReport.riskScore}%)`,
        detail: subReport.summaryExplanation,
        severity: subReport.classification === 'Malicious' ? 'high' : 'medium',
        points: subReport.classification === 'Malicious' ? 28 : 15,
        evidence: link.url,
      });
    }
  }

  const rawPoints = signals.reduce((sum, s) => sum + s.points, 0);
  const riskScore = Math.min(100, Math.max(0, Math.max(rawPoints, maxLinkRisk)));

  let classification: ThreatClassification = 'Safe';
  if (riskScore >= 60) classification = 'Malicious';
  else if (riskScore >= 30) classification = 'Suspicious';

  let threatCategory = 'No Significant Email Threat Indicators';
  if (signals.some((s) => s.category === 'Brand Impersonation')) {
    threatCategory = 'Sender Impersonation / Business Email Spoofing';
  } else if (signals.some((s) => s.id.startsWith('email-link-mismatch'))) {
    threatCategory = 'Deceptive Hyperlink Phishing';
  } else if (credentialRequestCueCount > 0) {
    threatCategory = 'Credential & Financial Harvesting Attempt';
  } else if (classification === 'Suspicious') {
    threatCategory = 'Unverified Sender or Social Engineering Indicators';
  } else if (classification === 'Malicious') {
    threatCategory = 'Multi-Vector Email Phishing';
  }

  const emailInfo: EmailAnalysisInfo = {
    senderAddress: senderParsed.address,
    senderDisplayName: senderParsed.displayName,
    senderDomain: senderParsed.domain,
    replyToAddress: replyParsed.address,
    returnPathAddress: returnParsed.address,
    subject: subjectHeader,
    spfStatus,
    dkimStatus,
    dmarcStatus,
    extractedUrls,
    urgencyCueCount,
    credentialRequestCueCount,
    attachmentWarnings,
  };

  const targetLabel = subjectHeader
    ? `Email: ${subjectHeader.slice(0, 64)}`
    : senderParsed.address
      ? `Email from ${senderParsed.address}`
      : 'Email Content Inspection';

  const summaryExplanation =
    classification === 'Safe'
      ? `Email inspection scored ${riskScore}% risk across header alignment, social-engineering cues, and ${extractedUrls.length} extracted URL(s).`
      : `Email is classified as ${classification} (${riskScore}% risk) with ${signals.length} triggered indicator(s) across ${Array.from(new Set(signals.map((s) => s.category))).join(', ')}.`;

  const recommendations = buildRecommendations(classification, 'email', signals);
  const limitations = [
    'When raw Authentication-Results headers are omitted, SPF/DKIM/DMARC verification cannot be confirmed from body text alone.',
    'Text-only paste without MIME attachments cannot inspect binary attachment payloads or QR codes inside images.',
    'Well-crafted spear-phishing from a genuinely compromised partner mailbox may pass SPF/DKIM/DMARC.',
  ];

  return {
    id: crypto.randomUUID(),
    kind: 'email',
    target: targetLabel,
    scannedAt: new Date().toISOString(),
    durationMs: Date.now() - startedAt,
    classification,
    riskScore,
    threatCategory,
    summaryExplanation,
    signals,
    recommendations,
    limitations,
    emailInfo,
  };
}

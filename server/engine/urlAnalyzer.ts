import crypto from 'node:crypto';
import dns from 'node:dns/promises';
import net from 'node:net';
import tls from 'node:tls';
import { validateOutboundHost } from '../security/ssrf.ts';
import type {
  DetectionSignal,
  DomainReputationInfo,
  HttpInspectionInfo,
  ScanReport,
  SslCertificateInfo,
  ThreatClassification,
  UrlStructureMetrics,
} from '../../src/types/scanner.ts';

const SUSPICIOUS_TLDS = new Set([
  'zip', 'mov', 'xyz', 'top', 'click', 'tk', 'ml', 'ga', 'cf', 'gq',
  'work', 'support', 'icu', 'buzz', 'rest', 'cam', 'cfd', 'sbs', 'quest',
  'bond', 'monster', 'loan', 'download', 'stream', 'party', 'review',
]);

const URL_SHORTENERS = new Set([
  'bit.ly', 'tinyurl.com', 't.co', 'ow.ly', 'is.gd', 'buff.ly', 'rb.gy',
  'cutt.ly', 'shorturl.at', 'tiny.cc', 'rebrand.ly', 'lnkd.in', 'goo.gl',
]);

const PROTECTED_BRANDS: Array<{ brand: string; officialDomains: string[] }> = [
  { brand: 'paypal', officialDomains: ['paypal.com', 'paypal.me'] },
  { brand: 'microsoft', officialDomains: ['microsoft.com', 'live.com', 'office.com', 'outlook.com', 'microsoftonline.com'] },
  { brand: 'google', officialDomains: ['google.com', 'accounts.google.com', 'gmail.com', 'youtube.com'] },
  { brand: 'apple', officialDomains: ['apple.com', 'icloud.com'] },
  { brand: 'amazon', officialDomains: ['amazon.com', 'amazon.co.uk', 'amazon.de', 'aws.amazon.com'] },
  { brand: 'netflix', officialDomains: ['netflix.com'] },
  { brand: 'chase', officialDomains: ['chase.com', 'jpmorganchase.com'] },
  { brand: 'bankofamerica', officialDomains: ['bankofamerica.com'] },
  { brand: 'wellsfargo', officialDomains: ['wellsfargo.com'] },
  { brand: 'citibank', officialDomains: ['citi.com', 'citibank.com'] },
  { brand: 'dhl', officialDomains: ['dhl.com'] },
  { brand: 'fedex', officialDomains: ['fedex.com'] },
  { brand: 'usps', officialDomains: ['usps.com'] },
  { brand: 'coinbase', officialDomains: ['coinbase.com'] },
  { brand: 'binance', officialDomains: ['binance.com', 'binance.us'] },
  { brand: 'github', officialDomains: ['github.com', 'github.io'] },
  { brand: 'dropbox', officialDomains: ['dropbox.com'] },
  { brand: 'linkedin', officialDomains: ['linkedin.com'] },
  { brand: 'instagram', officialDomains: ['instagram.com'] },
  { brand: 'facebook', officialDomains: ['facebook.com', 'fb.com'] },
  { brand: 'adobe', officialDomains: ['adobe.com'] },
  { brand: 'docusign', officialDomains: ['docusign.com', 'docusign.net'] },
  { brand: 'okta', officialDomains: ['okta.com'] },
  { brand: 'stripe', officialDomains: ['stripe.com'] },
  { brand: 'cloudflare', officialDomains: ['cloudflare.com'] },
];

const PHISHING_KEYWORDS = [
  'login', 'signin', 'sign-in', 'verify', 'verification', 'secure', 'security',
  'update', 'confirm', 'account', 'suspended', 'locked', 'unlock', 'billing',
  'invoice', 'wallet', 'credential', 'password', 'recover', 'reset', 'mfa',
  'otp', 'authenticate', 'webscr', 'dispatch', 'kyc', 'claim',
];

const MULTI_PART_PUBLIC_SUFFIXES = new Set([
  'co.uk', 'org.uk', 'ac.uk', 'gov.uk', 'com.au', 'net.au', 'org.au',
  'co.jp', 'co.in', 'net.in', 'org.in', 'com.br', 'com.sg', 'co.nz',
]);

function extractRegistrableDomain(hostname: string): { registrableDomain: string; tld: string; subdomainCount: number } {
  const clean = hostname.toLowerCase().replace(/\.$/, '');
  if (net.isIP(clean)) {
    return { registrableDomain: clean, tld: 'ip', subdomainCount: 0 };
  }
  const labels = clean.split('.').filter(Boolean);
  if (labels.length <= 2) {
    return {
      registrableDomain: clean,
      tld: labels[labels.length - 1] ?? '',
      subdomainCount: 0,
    };
  }
  const lastTwo = `${labels[labels.length - 2]}.${labels[labels.length - 1]}`;
  if (MULTI_PART_PUBLIC_SUFFIXES.has(lastTwo) && labels.length >= 3) {
    return {
      registrableDomain: labels.slice(-3).join('.'),
      tld: lastTwo,
      subdomainCount: labels.length - 3,
    };
  }
  return {
    registrableDomain: labels.slice(-2).join('.'),
    tld: labels[labels.length - 1] ?? '',
    subdomainCount: labels.length - 2,
  };
}

function shannonEntropy(input: string): number {
  if (!input) return 0;
  const counts = new Map<string, number>();
  for (const ch of input) {
    counts.set(ch, (counts.get(ch) ?? 0) + 1);
  }
  let entropy = 0;
  for (const count of counts.values()) {
    const p = count / input.length;
    entropy -= p * Math.log2(p);
  }
  return Number(entropy.toFixed(2));
}

function normalizeHomoglyphs(input: string): string {
  return input
    .toLowerCase()
    .replace(/0/g, 'o')
    .replace(/1/g, 'l')
    .replace(/3/g, 'e')
    .replace(/4/g, 'a')
    .replace(/5/g, 's')
    .replace(/7/g, 't')
    .replace(/8/g, 'b')
    .replace(/rn/g, 'm')
    .replace(/vv/g, 'w');
}

function levenshtein(a: string, b: string): number {
  const m = a.length;
  const n = b.length;
  const dp: number[][] = Array.from({ length: m + 1 }, () => Array(n + 1).fill(0));
  for (let i = 0; i <= m; i++) dp[i][0] = i;
  for (let j = 0; j <= n; j++) dp[0][j] = j;
  for (let i = 1; i <= m; i++) {
    for (let j = 1; j <= n; j++) {
      const cost = a[i - 1] === b[j - 1] ? 0 : 1;
      dp[i][j] = Math.min(
        dp[i - 1][j] + 1,
        dp[i][j - 1] + 1,
        dp[i - 1][j - 1] + cost
      );
    }
  }
  return dp[m][n];
}

function detectBrandImpersonation(hostname: string, registrableDomain: string, fullPath: string): DetectionSignal[] {
  const signals: DetectionSignal[] = [];
  const lowerHost = hostname.toLowerCase();
  const sld = registrableDomain.split('.')[0] ?? '';
  const normalizedSld = normalizeHomoglyphs(sld);
  const normalizedHost = normalizeHomoglyphs(lowerHost);
  const lowerPath = fullPath.toLowerCase();

  for (const entry of PROTECTED_BRANDS) {
    const isOfficial = entry.officialDomains.some(
      (official) => registrableDomain === official || registrableDomain.endsWith(`.${official}`)
    );
    if (isOfficial) continue;

    // 1. Direct brand inclusion inside non-official hostname (e.g. paypal-login-verify.xyz or login.paypal.evil.com)
    if (lowerHost.includes(entry.brand) || normalizedHost.includes(entry.brand)) {
      const inSubdomainOnly = !sld.includes(entry.brand) && !normalizedSld.includes(entry.brand);
      signals.push({
        id: `brand-host-${entry.brand}`,
        category: 'Brand Impersonation',
        title: `Possible ${entry.brand} brand impersonation in hostname`,
        detail: inSubdomainOnly
          ? `The brand keyword "${entry.brand}" appears in a subdomain while the actual registrable domain is "${registrableDomain}".`
          : `The non-official domain "${registrableDomain}" embeds or mimics the "${entry.brand}" brand name.`,
        severity: 'critical',
        points: 34,
        evidence: hostname,
      });
      break;
    }

    // 2. Typosquatting edit-distance check on SLD
    const distRaw = levenshtein(sld, entry.brand);
    const distNorm = levenshtein(normalizedSld, entry.brand);
    const minDist = Math.min(distRaw, distNorm);

    if (entry.brand.length >= 5 && minDist > 0 && minDist <= 1) {
      signals.push({
        id: `typosquat-${entry.brand}`,
        category: 'Brand Impersonation',
        title: `Typosquatting similarity to "${entry.brand}"`,
        detail: `The domain label "${sld}" differs from "${entry.brand}" by ${minDist} character/homoglyph substitution.`,
        severity: 'high',
        points: 30,
        evidence: `${registrableDomain} ~ ${entry.brand}`,
      });
      break;
    }

    // 3. Brand keyword in URL path on an unrelated domain alongside login/verify paths
    if (lowerPath.includes(`/${entry.brand}`) || lowerPath.includes(`${entry.brand}-login`)) {
      signals.push({
        id: `brand-path-${entry.brand}`,
        category: 'Brand Impersonation',
        title: `Brand reference "${entry.brand}" in third-party URL path`,
        detail: `The path references "${entry.brand}" on an unaffiliated domain (${registrableDomain}).`,
        severity: 'medium',
        points: 18,
        evidence: fullPath.slice(0, 100),
      });
      break;
    }
  }

  return signals;
}

async function inspectDnsRecords(registrableDomain: string, resolvedIps: string[], dnsAllowed: boolean): Promise<DomainReputationInfo> {
  const { tld } = extractRegistrableDomain(registrableDomain);
  const isIp = net.isIP(registrableDomain) !== 0;

  const base: DomainReputationInfo = {
    hostname: registrableDomain,
    registrableDomain,
    tld,
    isIpLiteral: isIp,
    resolvedIps,
    hasMxRecords: false,
    hasSpfRecord: false,
    hasDmarcRecord: false,
    rdapRegisteredAt: null,
    domainAgeDays: null,
    registrar: null,
    dnsStatus: dnsAllowed ? 'resolved' : resolvedIps.length > 0 ? 'blocked_private' : 'unresolved',
  };

  if (isIp || !dnsAllowed) {
    return base;
  }

  const [mxRes, txtRes, dmarcRes, rdapRes] = await Promise.allSettled([
    Promise.race([
      dns.resolveMx(registrableDomain),
      new Promise<never>((_, rej) => setTimeout(() => rej(new Error('timeout')), 2500)),
    ]),
    Promise.race([
      dns.resolveTxt(registrableDomain),
      new Promise<never>((_, rej) => setTimeout(() => rej(new Error('timeout')), 2500)),
    ]),
    Promise.race([
      dns.resolveTxt(`_dmarc.${registrableDomain}`),
      new Promise<never>((_, rej) => setTimeout(() => rej(new Error('timeout')), 2500)),
    ]),
    fetchRdapInfo(registrableDomain),
  ]);

  if (mxRes.status === 'fulfilled' && mxRes.value.length > 0) {
    base.hasMxRecords = true;
  }

  if (txtRes.status === 'fulfilled') {
    const flattened = txtRes.value.map((chunks) => chunks.join(''));
    base.hasSpfRecord = flattened.some((txt) => txt.toLowerCase().includes('v=spf1'));
  }

  if (dmarcRes.status === 'fulfilled') {
    const flattened = dmarcRes.value.map((chunks) => chunks.join(''));
    base.hasDmarcRecord = flattened.some((txt) => txt.toLowerCase().includes('v=dmarc1'));
  }

  if (rdapRes.status === 'fulfilled' && rdapRes.value) {
    base.rdapRegisteredAt = rdapRes.value.registeredAt;
    base.domainAgeDays = rdapRes.value.ageDays;
    base.registrar = rdapRes.value.registrar;
  }

  return base;
}

async function fetchRdapInfo(
  registrableDomain: string
): Promise<{ registeredAt: string | null; ageDays: number | null; registrar: string | null } | null> {
  const controller = new AbortController();
  const timer = setTimeout(() => controller.abort(), 3000);
  try {
    const res = await fetch(`https://rdap.org/domain/${encodeURIComponent(registrableDomain)}`, {
      signal: controller.signal,
      headers: { Accept: 'application/rdap+json, application/json' },
    });
    if (!res.ok) return null;
    const data = (await res.json()) as {
      events?: Array<{ eventAction?: string; eventDate?: string }>;
      entities?: Array<{ roles?: string[]; vcardArray?: unknown[] }>;
    };

    const regEvent = data.events?.find((e) => e.eventAction === 'registration');
    const registeredAt = regEvent?.eventDate ?? null;
    let ageDays: number | null = null;
    if (registeredAt) {
      const ts = Date.parse(registeredAt);
      if (!Number.isNaN(ts)) {
        ageDays = Math.max(0, Math.floor((Date.now() - ts) / 86_400_000));
      }
    }

    let registrar: string | null = null;
    const registrarEntity = data.entities?.find((e) => e.roles?.includes('registrar'));
    if (registrarEntity && Array.isArray(registrarEntity.vcardArray)) {
      const fields = registrarEntity.vcardArray[1];
      if (Array.isArray(fields)) {
        const fnField = fields.find((f) => Array.isArray(f) && f[0] === 'fn');
        if (Array.isArray(fnField) && typeof fnField[3] === 'string') {
          registrar = fnField[3];
        }
      }
    }

    return { registeredAt, ageDays, registrar };
  } catch {
    return null;
  } finally {
    clearTimeout(timer);
  }
}

async function inspectSslCertificate(
  hostname: string,
  port: number,
  usesHttps: boolean,
  allowedToConnect: boolean
): Promise<SslCertificateInfo> {
  if (!usesHttps) {
    return {
      usesHttps: false,
      certificatePresent: false,
      trustedBySystem: null,
      subjectCommonName: null,
      issuerOrganization: null,
      validFrom: null,
      validTo: null,
      daysRemaining: null,
      tlsProtocol: null,
      hostnameMatch: null,
      inspectionNote: 'Target uses unencrypted HTTP. Traffic and credentials can be intercepted in transit.',
    };
  }

  if (!allowedToConnect) {
    return {
      usesHttps: true,
      certificatePresent: false,
      trustedBySystem: null,
      subjectCommonName: null,
      issuerOrganization: null,
      validFrom: null,
      validTo: null,
      daysRemaining: null,
      tlsProtocol: null,
      hostnameMatch: null,
      inspectionNote: 'TLS handshake skipped because target did not pass public DNS/IP validation.',
    };
  }

  return new Promise((resolve) => {
    let settled = false;
    const finish = (info: SslCertificateInfo) => {
      if (!settled) {
        settled = true;
        resolve(info);
      }
    };

    const socket = tls.connect(
      {
        host: hostname,
        port,
        servername: net.isIP(hostname) ? undefined : hostname,
        rejectUnauthorized: false,
        timeout: 3500,
      },
      () => {
        try {
          const cert = socket.getPeerCertificate(false);
          const tlsProtocol = socket.getProtocol() ?? null;
          const authorized = socket.authorized;
          const authError = socket.authorizationError;

          if (!cert || Object.keys(cert).length === 0) {
            socket.end();
            finish({
              usesHttps: true,
              certificatePresent: false,
              trustedBySystem: false,
              subjectCommonName: null,
              issuerOrganization: null,
              validFrom: null,
              validTo: null,
              daysRemaining: null,
              tlsProtocol,
              hostnameMatch: false,
              inspectionNote: 'Server completed TCP connection without presenting an X.509 certificate.',
            });
            return;
          }

          const validFrom = cert.valid_from ?? null;
          const validTo = cert.valid_to ?? null;
          let daysRemaining: number | null = null;
          if (validTo) {
            const expMs = Date.parse(validTo);
            if (!Number.isNaN(expMs)) {
              daysRemaining = Math.floor((expMs - Date.now()) / 86_400_000);
            }
          }

          const certIdentityErr = tls.checkServerIdentity(hostname, cert);
          const hostnameMatch = !certIdentityErr;

          const toSingleString = (val: string | string[] | undefined): string | null =>
            Array.isArray(val) ? (val[0] ?? null) : (val ?? null);

          socket.end();
          finish({
            usesHttps: true,
            certificatePresent: true,
            trustedBySystem: authorized,
            subjectCommonName: toSingleString(cert.subject?.CN),
            issuerOrganization: toSingleString(cert.issuer?.O) ?? toSingleString(cert.issuer?.CN),
            validFrom,
            validTo,
            daysRemaining,
            tlsProtocol,
            hostnameMatch,
            inspectionNote: authorized
              ? 'Valid TLS certificate chain verified. Note: HTTPS only encrypts transport; phishing sites frequently use free Domain-Validated certificates.'
              : `TLS certificate verification warning: ${String(authError || 'Untrusted or mismatched certificate')}.`,
          });
        } catch {
          socket.destroy();
          finish({
            usesHttps: true,
            certificatePresent: false,
            trustedBySystem: false,
            subjectCommonName: null,
            issuerOrganization: null,
            validFrom: null,
            validTo: null,
            daysRemaining: null,
            tlsProtocol: null,
            hostnameMatch: null,
            inspectionNote: 'Unable to parse peer TLS certificate.',
          });
        }
      }
    );

    socket.setTimeout(3500, () => {
      socket.destroy();
      finish({
        usesHttps: true,
        certificatePresent: false,
        trustedBySystem: null,
        subjectCommonName: null,
        issuerOrganization: null,
        validFrom: null,
        validTo: null,
        daysRemaining: null,
        tlsProtocol: null,
        hostnameMatch: null,
        inspectionNote: 'TLS handshake timed out after 3.5 seconds.',
      });
    });

    socket.on('error', (err) => {
      socket.destroy();
      finish({
        usesHttps: true,
        certificatePresent: false,
        trustedBySystem: false,
        subjectCommonName: null,
        issuerOrganization: null,
        validFrom: null,
        validTo: null,
        daysRemaining: null,
        tlsProtocol: null,
        hostnameMatch: null,
        inspectionNote: `TLS connection failed: ${err.message}`,
      });
    });
  });
}

async function inspectHttpBehavior(initialUrl: URL, allowedToConnect: boolean): Promise<HttpInspectionInfo> {
  if (!allowedToConnect) {
    return {
      fetched: false,
      statusCode: null,
      redirectChain: [],
      crossDomainRedirect: false,
      hasPasswordForm: false,
      externalFormAction: false,
      pageTitle: null,
      note: 'HTTP probe skipped due to unresolved or restricted destination.',
    };
  }

  const redirectChain: string[] = [];
  let currentUrl = initialUrl;
  let crossDomainRedirect = false;
  const initialRegDomain = extractRegistrableDomain(initialUrl.hostname).registrableDomain;

  try {
    let finalResponse: Response | null = null;

    for (let hop = 0; hop < 3; hop++) {
      const controller = new AbortController();
      const timer = setTimeout(() => controller.abort(), 3500);
      try {
        const res = await fetch(currentUrl.toString(), {
          method: 'GET',
          redirect: 'manual',
          signal: controller.signal,
          headers: {
            'User-Agent': 'AegisTrace-SecurityScanner/1.0',
            Accept: 'text/html,application/xhtml+xml;q=0.9,*/*;q=0.5',
          },
        });

        if (res.status >= 300 && res.status < 400) {
          const loc = res.headers.get('location');
          if (!loc) {
            finalResponse = res;
            break;
          }
          const nextUrl = new URL(loc, currentUrl);
          if (nextUrl.protocol !== 'http:' && nextUrl.protocol !== 'https:') {
            break;
          }
          const safety = await validateOutboundHost(nextUrl.hostname);
          if (!safety.allowed) {
            return {
              fetched: false,
              statusCode: res.status,
              redirectChain: [...redirectChain, nextUrl.toString()],
              crossDomainRedirect: true,
              hasPasswordForm: false,
              externalFormAction: false,
              pageTitle: null,
              note: 'Redirect pointed to a private or unresolvable host and was halted.',
            };
          }
          const nextRegDomain = extractRegistrableDomain(nextUrl.hostname).registrableDomain;
          if (nextRegDomain !== initialRegDomain) {
            crossDomainRedirect = true;
          }
          redirectChain.push(nextUrl.toString());
          currentUrl = nextUrl;
          continue;
        }

        finalResponse = res;
        break;
      } finally {
        clearTimeout(timer);
      }
    }

    if (!finalResponse) {
      return {
        fetched: false,
        statusCode: null,
        redirectChain,
        crossDomainRedirect,
        hasPasswordForm: false,
        externalFormAction: false,
        pageTitle: null,
        note: 'Exceeded maximum safe redirect hops or aborted unsafe redirect.',
      };
    }

    const contentType = finalResponse.headers.get('content-type') ?? '';
    let hasPasswordForm = false;
    let externalFormAction = false;
    let pageTitle: string | null = null;

    if (contentType.includes('text/html') || contentType.includes('application/xhtml')) {
      const reader = finalResponse.body?.getReader();
      let html = '';
      if (reader) {
        const decoder = new TextDecoder();
        let totalBytes = 0;
        while (totalBytes < 128 * 1024) {
          const { done, value } = await reader.read();
          if (done || !value) break;
          totalBytes += value.byteLength;
          html += decoder.decode(value, { stream: true });
        }
        await reader.cancel().catch(() => {});
      }

      const titleMatch = html.match(/<title[^>]*>([\s\S]*?)<\/title>/i);
      if (titleMatch?.[1]) {
        pageTitle = titleMatch[1].replace(/\s+/g, ' ').trim().slice(0, 140);
      }

      hasPasswordForm = /<input[^>]+type\s*=\s*["']?password["']?/i.test(html);
      const formMatches = html.matchAll(/<form[^>]+action\s*=\s*["']([^"']+)["']/gi);
      const finalReg = extractRegistrableDomain(currentUrl.hostname).registrableDomain;
      for (const m of formMatches) {
        const actionRaw = m[1];
        if (actionRaw && /^https?:\/\//i.test(actionRaw)) {
          try {
            const actionUrl = new URL(actionRaw);
            const actionReg = extractRegistrableDomain(actionUrl.hostname).registrableDomain;
            if (actionReg !== finalReg) {
              externalFormAction = true;
            }
          } catch {
            // ignore malformed action
          }
        }
      }
    } else {
      await finalResponse.body?.cancel().catch(() => {});
    }

    return {
      fetched: true,
      statusCode: finalResponse.status,
      redirectChain,
      crossDomainRedirect,
      hasPasswordForm,
      externalFormAction,
      pageTitle,
      note: `HTTP ${finalResponse.status} inspected safely (${redirectChain.length} redirect${redirectChain.length === 1 ? '' : 's'}).`,
    };
  } catch (err) {
    return {
      fetched: false,
      statusCode: null,
      redirectChain,
      crossDomainRedirect,
      hasPasswordForm: false,
      externalFormAction: false,
      pageTitle: null,
      note: `HTTP probe did not complete: ${err instanceof Error ? err.message : 'network error'}.`,
    };
  }
}

export async function analyzeUrl(rawInput: string, options?: { skipHttpProbe?: boolean }): Promise<ScanReport> {
  const startedAt = Date.now();
  const trimmed = rawInput.trim();

  if (!trimmed) {
    throw new Error('Please enter a URL to scan.');
  }

  const lowerTrimmed = trimmed.toLowerCase();
  if (
    lowerTrimmed.startsWith('javascript:') ||
    lowerTrimmed.startsWith('data:') ||
    lowerTrimmed.startsWith('vbscript:') ||
    lowerTrimmed.startsWith('file:')
  ) {
    throw new Error('Unsupported or potentially unsafe URI scheme. Only http:// and https:// URLs can be inspected.');
  }

  const candidate = /^https?:\/\//i.test(trimmed) ? trimmed : `https://${trimmed}`;
  let parsed: URL;
  try {
    parsed = new URL(candidate);
  } catch {
    throw new Error('Invalid URL format. Example: https://example.com/path');
  }

  if (parsed.protocol !== 'http:' && parsed.protocol !== 'https:') {
    throw new Error('Only HTTP and HTTPS protocols are supported.');
  }

  const hostname = parsed.hostname.toLowerCase();
  const { registrableDomain, tld, subdomainCount } = extractRegistrableDomain(hostname);
  const isIpLiteral = net.isIP(hostname.replace(/^\[|\]$/g, '')) !== 0;
  const usesPunycode = hostname.split('.').some((label) => label.startsWith('xn--'));
  const hasNonAsciiHost = /[^\x20-\x7e]/.test(trimmed.split('/')[2] ?? '');
  const usesUrlShortener = URL_SHORTENERS.has(registrableDomain);
  const hasAtSymbol = parsed.username.length > 0 || parsed.password.length > 0 || trimmed.includes('@');
  const portNum = parsed.port ? Number(parsed.port) : null;
  const nonStandardPort = portNum && portNum !== 80 && portNum !== 443 ? portNum : null;
  const pathSegments = parsed.pathname.split('/').filter(Boolean);
  const domainEntropy = shannonEntropy(registrableDomain.split('.')[0] ?? hostname);

  const urlMetrics: UrlStructureMetrics = {
    normalizedUrl: parsed.toString(),
    protocol: parsed.protocol.replace(':', '').toUpperCase(),
    urlLength: parsed.toString().length,
    subdomainCount,
    pathDepth: pathSegments.length,
    queryParamCount: Array.from(parsed.searchParams.keys()).length,
    domainEntropy,
    usesPunycode,
    usesUrlShortener,
    hasAtSymbol,
    nonStandardPort,
  };

  const signals: DetectionSignal[] = [];

  // 1. URL Structure checks
  if (isIpLiteral) {
    signals.push({
      id: 'url-ip-literal',
      category: 'URL Structure',
      title: 'Direct IP address used instead of domain name',
      detail: 'Phishing infrastructure frequently hosts deceptive login pages on raw IP addresses to evade domain-level reputation filters.',
      severity: 'high',
      points: 30,
      evidence: hostname,
    });
  }

  if (hasAtSymbol) {
    signals.push({
      id: 'url-at-symbol',
      category: 'URL Structure',
      title: 'Embedded "@" credential-obfuscation syntax',
      detail: 'Browsers treat text before "@" as userinfo and route to the host after "@", disguising the true destination.',
      severity: 'critical',
      points: 35,
      evidence: parsed.username ? `${parsed.username}@${hostname}` : '@',
    });
  }

  if (usesPunycode || hasNonAsciiHost) {
    signals.push({
      id: 'url-punycode',
      category: 'URL Structure',
      title: 'Internationalized / Punycode domain (IDN homograph risk)',
      detail: 'Domain contains xn-- punycode labels or non-ASCII characters, a technique used in homograph spoofing attacks.',
      severity: 'high',
      points: 26,
      evidence: hostname,
    });
  }

  if (subdomainCount >= 3) {
    signals.push({
      id: 'url-deep-subdomains',
      category: 'URL Structure',
      title: 'Excessive subdomain nesting',
      detail: `URL uses ${subdomainCount} subdomain levels, often used to push legitimate-looking words to the left of the address bar.`,
      severity: 'medium',
      points: 16,
      evidence: hostname,
    });
  }

  if (parsed.toString().length > 100) {
    signals.push({
      id: 'url-long',
      category: 'URL Structure',
      title: 'Unusually long URL string',
      detail: `Length is ${parsed.toString().length} characters; extended query tokens or paths can obscure destination hostnames.`,
      severity: 'low',
      points: 10,
      evidence: `${parsed.toString().length} chars`,
    });
  }

  if (nonStandardPort !== null) {
    signals.push({
      id: 'url-nonstd-port',
      category: 'URL Structure',
      title: `Non-standard HTTP port (${nonStandardPort})`,
      detail: 'Legitimate consumer web portals rarely expose login interfaces on non-standard TCP ports.',
      severity: 'medium',
      points: 15,
      evidence: `Port ${nonStandardPort}`,
    });
  }

  if (usesUrlShortener) {
    signals.push({
      id: 'url-shortener',
      category: 'URL Structure',
      title: 'URL shortener conceals final destination',
      detail: `Domain "${registrableDomain}" is a link-shortening service that masks the true landing hostname until resolved.`,
      severity: 'medium',
      points: 18,
      evidence: registrableDomain,
    });
  }

  if (domainEntropy >= 3.85 && (registrableDomain.split('.')[0]?.length ?? 0) >= 10) {
    signals.push({
      id: 'url-high-entropy',
      category: 'URL Structure',
      title: 'High-entropy / algorithmically generated domain label',
      detail: `Domain label exhibits Shannon entropy of ${domainEntropy}, consistent with DGA or disposable phishing domains.`,
      severity: 'medium',
      points: 16,
      evidence: `Entropy ${domainEntropy}`,
    });
  }

  if (SUSPICIOUS_TLDS.has(tld)) {
    signals.push({
      id: 'domain-risky-tld',
      category: 'Domain & DNS',
      title: `Elevated-abuse top-level domain (.${tld})`,
      detail: `The .${tld} TLD experiences disproportionately high phishing and disposable campaign registration rates.`,
      severity: 'medium',
      points: 18,
      evidence: `.${tld}`,
    });
  }

  // Phishing keywords in host or path
  const hostAndPath = `${hostname}${parsed.pathname}${parsed.search}`.toLowerCase();
  const matchedKeywords = PHISHING_KEYWORDS.filter((kw) => hostAndPath.includes(kw));
  if (matchedKeywords.length >= 2) {
    signals.push({
      id: 'url-keyword-cluster',
      category: 'URL Structure',
      title: 'Credential & urgency keyword clustering',
      detail: `URL combines multiple sensitive action keywords (${matchedKeywords.slice(0, 5).join(', ')}).`,
      severity: matchedKeywords.length >= 3 ? 'high' : 'medium',
      points: matchedKeywords.length >= 3 ? 22 : 14,
      evidence: matchedKeywords.slice(0, 5).join(', '),
    });
  }

  // 2. Brand Impersonation checks
  const brandSignals = detectBrandImpersonation(hostname, registrableDomain, `${parsed.pathname}${parsed.search}`);
  signals.push(...brandSignals);

  // 3. SSRF-safe host validation + DNS/RDAP + TLS + HTTP inspection
  const outboundSafety = await validateOutboundHost(hostname);
  const [domainInfo, sslInfo, httpInfo] = await Promise.all([
    inspectDnsRecords(registrableDomain, outboundSafety.resolvedIps, outboundSafety.allowed),
    inspectSslCertificate(
      hostname,
      portNum ?? 443,
      parsed.protocol === 'https:',
      outboundSafety.allowed
    ),
    options?.skipHttpProbe
      ? Promise.resolve<HttpInspectionInfo>({
          fetched: false,
          statusCode: null,
          redirectChain: [],
          crossDomainRedirect: false,
          hasPasswordForm: false,
          externalFormAction: false,
          pageTitle: null,
          note: 'HTTP probe skipped for secondary link inspection.',
        })
      : inspectHttpBehavior(parsed, outboundSafety.allowed),
  ]);

  // Domain & DNS Signals
  if (!outboundSafety.allowed) {
    signals.push({
      id: 'dns-unresolved-or-blocked',
      category: 'Domain & DNS',
      title: outboundSafety.resolvedIps.length > 0 ? 'Target resolves to restricted network space' : 'Domain fails live DNS resolution',
      detail: outboundSafety.reason ?? 'Domain could not be resolved on public DNS.',
      severity: 'medium',
      points: outboundSafety.resolvedIps.length > 0 ? 22 : 12,
      evidence: hostname,
    });
  } else {
    if (domainInfo.domainAgeDays !== null) {
      if (domainInfo.domainAgeDays < 30) {
        signals.push({
          id: 'domain-very-young',
          category: 'Domain & DNS',
          title: 'Newly registered domain (< 30 days old)',
          detail: `RDAP records indicate this domain was created ${domainInfo.domainAgeDays} day(s) ago, a strong indicator of fresh phishing infrastructure.`,
          severity: 'high',
          points: 28,
          evidence: `${domainInfo.domainAgeDays} days`,
        });
      } else if (domainInfo.domainAgeDays < 90) {
        signals.push({
          id: 'domain-young',
          category: 'Domain & DNS',
          title: 'Recently registered domain (< 90 days old)',
          detail: `RDAP registration age is ${domainInfo.domainAgeDays} days; exercise caution with credential entry.`,
          severity: 'medium',
          points: 14,
          evidence: `${domainInfo.domainAgeDays} days`,
        });
      }
    }

    if (!domainInfo.isIpLiteral && !domainInfo.hasSpfRecord && !domainInfo.hasDmarcRecord && !domainInfo.hasMxRecords) {
      signals.push({
        id: 'dns-minimal-posture',
        category: 'Domain & DNS',
        title: 'Minimal DNS mail & authentication posture',
        detail: 'Domain publishes no MX, SPF, or DMARC records, typical of single-purpose throwaway landing domains.',
        severity: 'low',
        points: 8,
        evidence: 'No MX/SPF/DMARC',
      });
    }
  }

  // SSL & HTTPS Signals
  if (!sslInfo.usesHttps) {
    signals.push({
      id: 'ssl-no-https',
      category: 'SSL & HTTPS',
      title: 'Unencrypted HTTP transport',
      detail: 'Connection lacks TLS encryption; credentials or session tokens submitted here are exposed in plaintext.',
      severity: 'medium',
      points: 20,
      evidence: 'HTTP',
    });
  } else if (outboundSafety.allowed) {
    if (!sslInfo.certificatePresent) {
      signals.push({
        id: 'ssl-missing-cert',
        category: 'SSL & HTTPS',
        title: 'HTTPS handshake failed or certificate absent',
        detail: sslInfo.inspectionNote,
        severity: 'medium',
        points: 16,
        evidence: 'No TLS cert',
      });
    } else {
      if (sslInfo.hostnameMatch === false) {
        signals.push({
          id: 'ssl-hostname-mismatch',
          category: 'SSL & HTTPS',
          title: 'TLS certificate hostname mismatch',
          detail: `Certificate Common Name (${sslInfo.subjectCommonName ?? 'unknown'}) does not match requested hostname "${hostname}".`,
          severity: 'high',
          points: 25,
          evidence: sslInfo.subjectCommonName ?? hostname,
        });
      }
      if (sslInfo.trustedBySystem === false) {
        signals.push({
          id: 'ssl-untrusted',
          category: 'SSL & HTTPS',
          title: 'Untrusted or self-signed TLS certificate',
          detail: sslInfo.inspectionNote,
          severity: 'high',
          points: 22,
          evidence: sslInfo.issuerOrganization ?? 'Self-signed / Untrusted',
        });
      }
      if (sslInfo.daysRemaining !== null && sslInfo.daysRemaining < 0) {
        signals.push({
          id: 'ssl-expired',
          category: 'SSL & HTTPS',
          title: 'Expired SSL/TLS certificate',
          detail: `Certificate expired ${Math.abs(sslInfo.daysRemaining)} day(s) ago.`,
          severity: 'high',
          points: 20,
          evidence: sslInfo.validTo ?? 'Expired',
        });
      }
    }
  }

  // HTTP Behavior Signals
  if (httpInfo.crossDomainRedirect) {
    signals.push({
      id: 'http-cross-redirect',
      category: 'HTTP Behavior',
      title: 'Cross-domain redirect chain detected',
      detail: 'Initial URL redirects visitors onto a different registrable domain, often used to evade URL scanners.',
      severity: 'medium',
      points: 16,
      evidence: httpInfo.redirectChain[httpInfo.redirectChain.length - 1],
    });
  }

  if (httpInfo.externalFormAction) {
    signals.push({
      id: 'http-external-form',
      category: 'HTTP Behavior',
      title: 'HTML form posts data to an external domain',
      detail: 'A form on this page submits user input to a third-party domain, a classic credential-exfiltration pattern.',
      severity: 'critical',
      points: 30,
      evidence: 'External <form action>',
    });
  }

  if (httpInfo.hasPasswordForm && signals.some((s) => s.severity === 'high' || s.severity === 'critical')) {
    signals.push({
      id: 'http-password-on-risky-host',
      category: 'HTTP Behavior',
      title: 'Password input field on flagged domain',
      detail: 'The page renders a password field while exhibiting high-risk phishing or impersonation indicators.',
      severity: 'high',
      points: 18,
      evidence: '<input type="password">',
    });
  }

  // Calculate calibrated risk score
  const rawPoints = signals.reduce((sum, s) => sum + s.points, 0);
  const riskScore = Math.min(100, Math.max(0, rawPoints));

  let classification: ThreatClassification = 'Safe';
  if (riskScore >= 60) classification = 'Malicious';
  else if (riskScore >= 30) classification = 'Suspicious';

  let threatCategory = 'No Significant Threat Indicators';
  if (signals.some((s) => s.category === 'Brand Impersonation')) {
    threatCategory = 'Brand Impersonation / Credential Harvesting';
  } else if (signals.some((s) => s.id === 'url-at-symbol' || s.id === 'url-punycode' || s.id === 'url-ip-literal')) {
    threatCategory = 'Obfuscated / Deceptive URL Infrastructure';
  } else if (signals.some((s) => s.id === 'http-external-form')) {
    threatCategory = 'Credential Exfiltration Form';
  } else if (classification === 'Suspicious') {
    threatCategory = 'Anomalous Domain or Transport Indicators';
  } else if (classification === 'Malicious') {
    threatCategory = 'High-Risk Phishing Indicator Cluster';
  }

  const summaryExplanation = buildUrlSummary(classification, riskScore, registrableDomain, signals, sslInfo);
  const recommendations = buildRecommendations(classification, 'url', signals, sslInfo);
  const limitations = [
    'HTTPS presence or a valid TLS certificate only confirms encrypted transport—not site legitimacy; phishing campaigns regularly use automated Domain-Validated certificates.',
    'Newly launched zero-day phishing pages on compromised legitimate domains may not trigger static lexical rules.',
    'Dynamic client-side JavaScript redirects or CAPTCHA-gated phishing kits cannot be fully executed in a non-browser HTTP probe.',
  ];

  return {
    id: crypto.randomUUID(),
    kind: 'url',
    target: parsed.toString(),
    scannedAt: new Date().toISOString(),
    durationMs: Date.now() - startedAt,
    classification,
    riskScore,
    threatCategory,
    summaryExplanation,
    signals,
    recommendations,
    limitations,
    urlMetrics,
    domainInfo,
    sslInfo,
    httpInfo,
  };
}

function buildUrlSummary(
  classification: ThreatClassification,
  riskScore: number,
  registrableDomain: string,
  signals: DetectionSignal[],
  sslInfo: SslCertificateInfo
): string {
  if (classification === 'Safe') {
    const tlsNote = sslInfo.usesHttps && sslInfo.trustedBySystem
      ? 'TLS certificate validation succeeded'
      : sslInfo.usesHttps
        ? 'HTTPS is enabled'
        : 'no HTTPS transport was observed';
    return `Analysis of ${registrableDomain} produced a low risk score (${riskScore}%) with ${signals.length} minor/informational observation(s) and ${tlsNote}. Always verify context before entering sensitive credentials.`;
  }
  const topTitles = signals
    .slice()
    .sort((a, b) => b.points - a.points)
    .slice(0, 2)
    .map((s) => s.title.toLowerCase());
  return `Target ${registrableDomain} is classified as ${classification} (${riskScore}% risk) primarily due to ${topTitles.join(' and ')}.`;
}

export function buildRecommendations(
  classification: ThreatClassification,
  kind: 'url' | 'email',
  signals: DetectionSignal[],
  sslInfo?: SslCertificateInfo
): string[] {
  const recs: string[] = [];

  if (classification === 'Malicious') {
    recs.push('Do not open, click, or submit any credentials, MFA codes, or payment details on this target.');
    recs.push(kind === 'email'
      ? 'Quarantine or delete the message and report the sender domain to your security operations team.'
      : 'Block the hostname and registrable domain in your DNS resolver, web proxy, and endpoint security policy.');
  } else if (classification === 'Suspicious') {
    recs.push('Treat this target with caution and verify authenticity through an independent, known-good channel before interacting.');
    if (kind === 'url') {
      recs.push('Navigate manually by typing the official organization domain rather than following the inspected link.');
    }
  } else {
    recs.push('No high-risk phishing patterns were detected, though you should still confirm the expected brand domain before signing in.');
  }

  if (sslInfo && !sslInfo.usesHttps) {
    recs.push('Avoid transmitting passwords or personal information over unencrypted HTTP connections.');
  }
  if (signals.some((s) => s.category === 'Brand Impersonation')) {
    recs.push('Compare the registrable domain character-by-character against the official vendor domain to catch homoglyphs.');
  }
  if (signals.some((s) => s.category === 'Email Headers')) {
    recs.push('Verify SPF, DKIM, and DMARC alignment in full mail headers before trusting sender identity.');
  }

  return recs;
}

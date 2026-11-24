export type ThreatClassification = 'Safe' | 'Suspicious' | 'Malicious';

export type ScanKind = 'url' | 'email';

export type SignalSeverity = 'info' | 'low' | 'medium' | 'high' | 'critical';

export type SignalCategory =
  | 'URL Structure'
  | 'Domain & DNS'
  | 'SSL & HTTPS'
  | 'Brand Impersonation'
  | 'HTTP Behavior'
  | 'Email Headers'
  | 'Email Content';

export interface DetectionSignal {
  id: string;
  category: SignalCategory;
  title: string;
  detail: string;
  severity: SignalSeverity;
  points: number;
  evidence?: string;
}

export interface DomainReputationInfo {
  hostname: string;
  registrableDomain: string;
  tld: string;
  isIpLiteral: boolean;
  resolvedIps: string[];
  hasMxRecords: boolean;
  hasSpfRecord: boolean;
  hasDmarcRecord: boolean;
  rdapRegisteredAt: string | null;
  domainAgeDays: number | null;
  registrar: string | null;
  dnsStatus: 'resolved' | 'unresolved' | 'blocked_private' | 'skipped';
}

export interface SslCertificateInfo {
  usesHttps: boolean;
  certificatePresent: boolean;
  trustedBySystem: boolean | null;
  subjectCommonName: string | null;
  issuerOrganization: string | null;
  validFrom: string | null;
  validTo: string | null;
  daysRemaining: number | null;
  tlsProtocol: string | null;
  hostnameMatch: boolean | null;
  inspectionNote: string;
}

export interface UrlStructureMetrics {
  normalizedUrl: string;
  protocol: string;
  urlLength: number;
  subdomainCount: number;
  pathDepth: number;
  queryParamCount: number;
  domainEntropy: number;
  usesPunycode: boolean;
  usesUrlShortener: boolean;
  hasAtSymbol: boolean;
  nonStandardPort: number | null;
}

export interface HttpInspectionInfo {
  fetched: boolean;
  statusCode: number | null;
  redirectChain: string[];
  crossDomainRedirect: boolean;
  hasPasswordForm: boolean;
  externalFormAction: boolean;
  pageTitle: string | null;
  note: string;
}

export interface EmailAnalysisInfo {
  senderAddress: string | null;
  senderDisplayName: string | null;
  senderDomain: string | null;
  replyToAddress: string | null;
  returnPathAddress: string | null;
  subject: string | null;
  spfStatus: 'pass' | 'fail' | 'softfail' | 'neutral' | 'none' | 'not_present';
  dkimStatus: 'pass' | 'fail' | 'none' | 'not_present';
  dmarcStatus: 'pass' | 'fail' | 'none' | 'not_present';
  extractedUrls: Array<{
    url: string;
    anchorText: string | null;
    mismatchDetected: boolean;
    riskScore: number;
    classification: ThreatClassification;
  }>;
  urgencyCueCount: number;
  credentialRequestCueCount: number;
  attachmentWarnings: string[];
}

export interface ScanReport {
  id: string;
  kind: ScanKind;
  target: string;
  scannedAt: string;
  durationMs: number;
  classification: ThreatClassification;
  riskScore: number;
  threatCategory: string;
  summaryExplanation: string;
  signals: DetectionSignal[];
  recommendations: string[];
  limitations: string[];
  urlMetrics?: UrlStructureMetrics;
  domainInfo?: DomainReputationInfo;
  sslInfo?: SslCertificateInfo;
  httpInfo?: HttpInspectionInfo;
  emailInfo?: EmailAnalysisInfo;
}

export interface DashboardStats {
  totalScans: number;
  safeCount: number;
  suspiciousCount: number;
  maliciousCount: number;
  urlScanCount: number;
  emailScanCount: number;
  averageRiskScore: number;
  riskHistogram: Array<{
    bucket: string;
    count: number;
  }>;
  vectorBreakdown: Array<{
    category: SignalCategory;
    hits: number;
  }>;
  recentReports: ScanReport[];
}

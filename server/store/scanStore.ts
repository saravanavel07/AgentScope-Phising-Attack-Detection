import fs from 'node:fs/promises';
import path from 'node:path';
import type { DashboardStats, ScanReport, SignalCategory } from '../../src/types/scanner.ts';

const DATA_DIR = path.resolve(process.cwd(), '.data');
const STORE_FILE = path.join(DATA_DIR, 'scans.json');
const MAX_STORED_REPORTS = 200;

let writeQueue: Promise<void> = Promise.resolve();

async function ensureStoreFile(): Promise<void> {
  await fs.mkdir(DATA_DIR, { recursive: true });
  try {
    await fs.access(STORE_FILE);
  } catch {
    await fs.writeFile(STORE_FILE, '[]', 'utf8');
  }
}

export async function readAllReports(): Promise<ScanReport[]> {
  try {
    await ensureStoreFile();
    const raw = await fs.readFile(STORE_FILE, 'utf8');
    const parsed = JSON.parse(raw);
    if (!Array.isArray(parsed)) return [];
    return parsed as ScanReport[];
  } catch {
    return [];
  }
}

export async function saveScanReport(report: ScanReport): Promise<void> {
  writeQueue = writeQueue.then(async () => {
    const existing = await readAllReports();
    const updated = [report, ...existing.filter((r) => r.id !== report.id)].slice(
      0,
      MAX_STORED_REPORTS
    );
    await ensureStoreFile();
    const tmpFile = `${STORE_FILE}.tmp`;
    await fs.writeFile(tmpFile, JSON.stringify(updated, null, 2), 'utf8');
    await fs.rename(tmpFile, STORE_FILE);
  });
  return writeQueue;
}

export async function deleteScanReport(id: string): Promise<boolean> {
  let deleted = false;
  writeQueue = writeQueue.then(async () => {
    const existing = await readAllReports();
    const filtered = existing.filter((r) => r.id !== id);
    if (filtered.length !== existing.length) {
      deleted = true;
      await ensureStoreFile();
      const tmpFile = `${STORE_FILE}.tmp`;
      await fs.writeFile(tmpFile, JSON.stringify(filtered, null, 2), 'utf8');
      await fs.rename(tmpFile, STORE_FILE);
    }
  });
  await writeQueue;
  return deleted;
}

export async function clearAllReports(): Promise<void> {
  writeQueue = writeQueue.then(async () => {
    await ensureStoreFile();
    const tmpFile = `${STORE_FILE}.tmp`;
    await fs.writeFile(tmpFile, '[]', 'utf8');
    await fs.rename(tmpFile, STORE_FILE);
  });
  return writeQueue;
}

export async function computeDashboardStats(): Promise<DashboardStats> {
  const reports = await readAllReports();
  const totalScans = reports.length;
  let safeCount = 0;
  let suspiciousCount = 0;
  let maliciousCount = 0;
  let urlScanCount = 0;
  let emailScanCount = 0;
  let totalScore = 0;

  const buckets = [
    { bucket: '0–19', count: 0 },
    { bucket: '20–39', count: 0 },
    { bucket: '40–59', count: 0 },
    { bucket: '60–79', count: 0 },
    { bucket: '80–100', count: 0 },
  ];

  const categoryMap = new Map<SignalCategory, number>([
    ['URL Structure', 0],
    ['Domain & DNS', 0],
    ['SSL & HTTPS', 0],
    ['Brand Impersonation', 0],
    ['HTTP Behavior', 0],
    ['Email Headers', 0],
    ['Email Content', 0],
  ]);

  for (const r of reports) {
    if (r.classification === 'Safe') safeCount++;
    else if (r.classification === 'Suspicious') suspiciousCount++;
    else if (r.classification === 'Malicious') maliciousCount++;

    if (r.kind === 'url') urlScanCount++;
    else emailScanCount++;

    totalScore += r.riskScore;

    if (r.riskScore < 20) buckets[0].count++;
    else if (r.riskScore < 40) buckets[1].count++;
    else if (r.riskScore < 60) buckets[2].count++;
    else if (r.riskScore < 80) buckets[3].count++;
    else buckets[4].count++;

    const seenCatsInReport = new Set<SignalCategory>();
    for (const sig of r.signals) {
      if (sig.points > 0 && !seenCatsInReport.has(sig.category)) {
        seenCatsInReport.add(sig.category);
        categoryMap.set(sig.category, (categoryMap.get(sig.category) ?? 0) + 1);
      }
    }
  }

  return {
    totalScans,
    safeCount,
    suspiciousCount,
    maliciousCount,
    urlScanCount,
    emailScanCount,
    averageRiskScore: totalScans > 0 ? Math.round(totalScore / totalScans) : 0,
    riskHistogram: buckets,
    vectorBreakdown: Array.from(categoryMap.entries()).map(([category, hits]) => ({
      category,
      hits,
    })),
    recentReports: reports.slice(0, 12),
  };
}

import { useCallback, useEffect, useState } from 'react';
import { AnimatePresence, motion } from 'motion/react';
import { DashboardOverview } from './components/DashboardOverview';
import { EmailAnalyzerView } from './components/EmailAnalyzerView';
import { ParticleField } from './components/ParticleField';
import { ReportsArchiveView } from './components/ReportsArchiveView';
import { TopNav, type AppView } from './components/TopNav';
import { UrlScannerView } from './components/UrlScannerView';
import type { DashboardStats, ScanReport } from './types/scanner';

export default function App() {
  const [activeView, setActiveView] = useState<AppView>('overview');
  const [isScanning, setIsScanning] = useState(false);
  const [stats, setStats] = useState<DashboardStats | null>(null);
  const [reports, setReports] = useState<ScanReport[]>([]);
  const [loadingData, setLoadingData] = useState(true);
  const [selectedReport, setSelectedReport] = useState<ScanReport | null>(null);
  const [pendingUrlScan, setPendingUrlScan] = useState<string | undefined>(undefined);

  const fetchTelemetry = useCallback(async () => {
    try {
      const [statsRes, reportsRes] = await Promise.all([
        fetch('/api/stats'),
        fetch('/api/reports'),
      ]);
      if (statsRes.ok) {
        const s = (await statsRes.json()) as DashboardStats;
        setStats(s);
      }
      if (reportsRes.ok) {
        const r = (await reportsRes.json()) as { reports: ScanReport[] };
        setReports(r.reports ?? []);
      }
    } catch {
      // Keep existing state on transient network error
    } finally {
      setLoadingData(false);
    }
  }, []);

  useEffect(() => {
    void fetchTelemetry();
  }, [fetchTelemetry]);

  const handleScanComplete = useCallback(
    (report: ScanReport) => {
      setSelectedReport(report);
      void fetchTelemetry();
    },
    [fetchTelemetry]
  );

  const handleLaunchUrlScan = (url: string) => {
    setPendingUrlScan(url);
    setActiveView('url');
  };

  const handleSelectReport = (report: ScanReport | null) => {
    setSelectedReport(report);
    setActiveView('reports');
  };

  const handleDeleteReport = async (id: string) => {
    try {
      const res = await fetch(`/api/reports/${encodeURIComponent(id)}`, { method: 'DELETE' });
      if (res.ok) {
        if (selectedReport?.id === id) {
          setSelectedReport(null);
        }
        await fetchTelemetry();
      }
    } catch {
      // ignore
    }
  };

  const handleClearAll = async () => {
    try {
      const res = await fetch('/api/reports', { method: 'DELETE' });
      if (res.ok) {
        setSelectedReport(null);
        await fetchTelemetry();
      }
    } catch {
      // ignore
    }
  };

  return (
    <div className="relative min-h-screen bg-[#090B10] text-[#E2E8F0]">
      <ParticleField isScanning={isScanning} />

      <div className="relative z-10 flex min-h-screen flex-col">
        <TopNav
          activeView={activeView}
          onNavigate={(view) => {
            if (view !== 'url') setPendingUrlScan(undefined);
            setActiveView(view);
          }}
          onQuickNewScan={() => {
            setPendingUrlScan(undefined);
            setActiveView('url');
          }}
        />

        <main className="mx-auto w-full max-w-[1360px] flex-1 px-4 py-8 sm:px-6 lg:px-8">
          <AnimatePresence mode="wait">
            <motion.div
              key={activeView}
              initial={{ opacity: 0, y: 8 }}
              animate={{ opacity: 1, y: 0 }}
              exit={{ opacity: 0, y: -6 }}
              transition={{ duration: 0.18, ease: [0.16, 1, 0.3, 1] }}
            >
              {activeView === 'overview' && (
                <DashboardOverview
                  stats={stats}
                  loading={loadingData}
                  onQuickScanUrl={handleLaunchUrlScan}
                  onOpenEmailAnalyzer={() => setActiveView('email')}
                  onSelectReport={handleSelectReport}
                />
              )}

              {activeView === 'url' && (
                <UrlScannerView
                  initialUrl={pendingUrlScan}
                  onScanStateChange={setIsScanning}
                  onScanComplete={handleScanComplete}
                />
              )}

              {activeView === 'email' && (
                <EmailAnalyzerView
                  onScanStateChange={setIsScanning}
                  onScanComplete={handleScanComplete}
                  onDeepInspectUrl={handleLaunchUrlScan}
                />
              )}

              {activeView === 'reports' && (
                <ReportsArchiveView
                  reports={reports}
                  selectedReport={selectedReport}
                  onSelectReport={setSelectedReport}
                  onDeleteReport={handleDeleteReport}
                  onClearAll={handleClearAll}
                  onInspectUrl={handleLaunchUrlScan}
                />
              )}
            </motion.div>
          </AnimatePresence>
        </main>

        <footer className="border-t border-[#94A3B8]/10 bg-[#090B10]/70 py-5 backdrop-blur-md">
          <div className="mx-auto flex max-w-[1360px] flex-col items-start justify-between gap-2 px-4 text-xs text-[#64748B] sm:flex-row sm:items-center sm:px-6 lg:px-8">
            <span>AegisTrace Phishing Attack Detector</span>
            <span>Heuristic, DNS, RDAP, and TLS inspection · HTTPS alone does not guarantee safety</span>
          </div>
        </footer>
      </div>
    </div>
  );
}

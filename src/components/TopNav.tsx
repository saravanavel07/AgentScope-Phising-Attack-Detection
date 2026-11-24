import { useState } from 'react';
import { Menu, X } from 'lucide-react';

export type AppView = 'overview' | 'url' | 'email' | 'reports';

interface TopNavProps {
  activeView: AppView;
  onNavigate: (view: AppView) => void;
  onQuickNewScan: () => void;
}

const NAV_ITEMS: Array<{ id: AppView; label: string }> = [
  { id: 'overview', label: 'Overview' },
  { id: 'url', label: 'URL Scanner' },
  { id: 'email', label: 'Email Analyzer' },
  { id: 'reports', label: 'Threat Reports' },
];

export function TopNav({ activeView, onNavigate, onQuickNewScan }: TopNavProps) {
  const [mobileOpen, setMobileOpen] = useState(false);

  const handleSelect = (view: AppView) => {
    onNavigate(view);
    setMobileOpen(false);
  };

  return (
    <header className="sticky top-0 z-30 border-b border-[#94A3B8]/12 bg-[#090B10]/85 backdrop-blur-xl">
      <div className="mx-auto flex max-w-[1360px] items-center justify-between gap-8 px-4 py-3.5 sm:px-6 lg:px-8">
        {/* Zone 1: Single text element wordmark */}
        <a
          href="#overview"
          onClick={(e) => {
            e.preventDefault();
            handleSelect('overview');
          }}
          className="font-display text-xl font-bold tracking-tight text-[#F1F5F9] whitespace-nowrap shrink-0 aegis-heading-glow focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-[#3B82F6] rounded-md px-1"
        >
          AegisTrace
        </a>

        {/* Zone 2: 4 clean single-line navigation links */}
        <nav aria-label="Primary navigation" className="hidden md:flex items-center gap-7">
          {NAV_ITEMS.map((item) => {
            const isActive = activeView === item.id;
            return (
              <button
                key={item.id}
                type="button"
                onClick={() => handleSelect(item.id)}
                className={`relative py-1.5 text-sm font-medium whitespace-nowrap shrink-0 transition-colors duration-150 focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-[#3B82F6] rounded-sm ${
                  isActive
                    ? 'text-[#60A5FA]'
                    : 'text-[#94A3B8] hover:text-[#E2E8F0]'
                }`}
              >
                {item.label}
                {isActive && (
                  <span
                    aria-hidden="true"
                    className="absolute inset-x-0 -bottom-[15px] h-[2px] bg-gradient-to-r from-[#2563EB] via-[#60A5FA] to-[#38BDF8] shadow-[0_0_12px_rgba(56,189,248,0.85)]"
                  />
                )}
              </button>
            );
          })}
        </nav>

        {/* Zone 3: 1 primary CTA button + mobile menu trigger */}
        <div className="flex items-center gap-3 shrink-0">
          <button
            type="button"
            onClick={onQuickNewScan}
            className="aegis-btn-primary rounded-lg px-4 py-2 text-xs font-semibold text-[#F8FAFC] whitespace-nowrap shrink-0 cursor-pointer focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-[#38BDF8]"
          >
            New Scan
          </button>

          <button
            type="button"
            aria-label={mobileOpen ? 'Close navigation menu' : 'Open navigation menu'}
            aria-expanded={mobileOpen}
            onClick={() => setMobileOpen((prev) => !prev)}
            className="flex h-10 w-10 items-center justify-center rounded-lg border border-[#94A3B8]/18 bg-[#121722] text-[#CBD5E1] hover:border-[#3B82F6]/50 hover:text-[#60A5FA] md:hidden"
          >
            {mobileOpen ? <X className="h-5 w-5" /> : <Menu className="h-5 w-5" />}
          </button>
        </div>
      </div>

      {/* Mobile navigation drawer */}
      {mobileOpen && (
        <nav
          aria-label="Mobile navigation"
          className="border-t border-[#94A3B8]/12 bg-[#0D1119]/95 px-4 py-3 md:hidden"
        >
          <div className="flex flex-col gap-1">
            {NAV_ITEMS.map((item) => {
              const isActive = activeView === item.id;
              return (
                <button
                  key={item.id}
                  type="button"
                  onClick={() => handleSelect(item.id)}
                  className={`flex min-h-[44px] items-center justify-between rounded-lg px-3 text-left text-sm font-medium transition-colors ${
                    isActive
                      ? 'bg-[#2563EB]/18 text-[#60A5FA]'
                      : 'text-[#94A3B8] hover:bg-[#171E2C] hover:text-[#E2E8F0]'
                  }`}
                >
                  <span>{item.label}</span>
                  {isActive && <span className="text-xs text-[#38BDF8]">Active</span>}
                </button>
              );
            })}
          </div>
        </nav>
      )}
    </header>
  );
}

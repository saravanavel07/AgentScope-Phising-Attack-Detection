import { AlertTriangle, ShieldAlert, ShieldCheck } from 'lucide-react';
import type { ThreatClassification } from '../types/scanner';

interface ClassificationMarkProps {
  classification: ThreatClassification;
  size?: 'sm' | 'md' | 'lg';
}

export function ClassificationMark({ classification, size = 'md' }: ClassificationMarkProps) {
  const iconClass = size === 'lg' ? 'h-5 w-5' : size === 'sm' ? 'h-3.5 w-3.5' : 'h-4 w-4';
  const textClass =
    size === 'lg'
      ? 'text-base font-semibold tracking-tight'
      : size === 'sm'
        ? 'text-xs font-medium'
        : 'text-sm font-semibold';

  if (classification === 'Safe') {
    return (
      <span className={`inline-flex items-center gap-1.5 text-[#CBD5E1] whitespace-nowrap shrink-0 ${textClass}`}>
        <ShieldCheck className={`${iconClass} text-[#93C5FD]`} aria-hidden="true" />
        <span>Safe</span>
      </span>
    );
  }

  if (classification === 'Suspicious') {
    return (
      <span className={`inline-flex items-center gap-1.5 text-[#93C5FD] whitespace-nowrap shrink-0 ${textClass}`}>
        <AlertTriangle className={`${iconClass} text-[#60A5FA]`} aria-hidden="true" />
        <span>Suspicious</span>
      </span>
    );
  }

  return (
    <span className={`inline-flex items-center gap-1.5 text-[#38BDF8] whitespace-nowrap shrink-0 ${textClass}`}>
      <ShieldAlert className={`${iconClass} text-[#38BDF8] drop-shadow-[0_0_8px_rgba(56,189,248,0.65)]`} aria-hidden="true" />
      <span>Malicious</span>
    </span>
  );
}

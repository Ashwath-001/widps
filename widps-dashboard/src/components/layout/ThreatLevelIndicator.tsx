import type { ThreatLevel } from '../../types';

const LEVEL_CONFIG: Record<ThreatLevel, { color: string; bg: string; label: string }> = {
  LOW: { color: '#22C55E', bg: 'bg-[var(--color-accent-green)]/10', label: 'LOW' },
  MEDIUM: { color: '#FACC15', bg: 'bg-[var(--color-accent-warning)]/10', label: 'MEDIUM' },
  HIGH: { color: '#FB923C', bg: 'bg-orange-500/10', label: 'HIGH' },
  CRITICAL: { color: '#EF4444', bg: 'bg-[var(--color-accent-danger)]/10', label: 'CRITICAL' },
};

interface ThreatLevelIndicatorProps {
  level: ThreatLevel;
}

export default function ThreatLevelIndicator({ level }: ThreatLevelIndicatorProps) {
  const cfg = LEVEL_CONFIG[level];
  return (
    <div className={`flex items-center gap-2 pl-2.5 pr-3 py-1.5 rounded-full border ${cfg.bg}`} style={{ borderColor: `${cfg.color}40` }}>
      <span className="relative flex items-center justify-center w-2.5 h-2.5">
        <span className="absolute inline-flex w-full h-full rounded-full pulse-ring" style={{ backgroundColor: cfg.color }} />
        <span className="relative inline-flex w-2 h-2 rounded-full" style={{ backgroundColor: cfg.color }} />
      </span>
      <span className="text-xs font-semibold tracking-wide" style={{ color: cfg.color }}>
        THREAT LEVEL: {cfg.label}
      </span>
    </div>
  );
}

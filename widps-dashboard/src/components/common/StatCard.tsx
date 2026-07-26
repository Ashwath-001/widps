import type { LucideIcon } from 'lucide-react';
import Card from './Card';
import AnimatedNumber from './AnimatedNumber';

interface StatCardProps {
  icon: LucideIcon;
  label: string;
  value: number;
  suffix?: string;
  decimals?: number;
  tone?: 'default' | 'green' | 'blue' | 'warning' | 'danger';
  subtext?: string;
  delay?: number;
}

const TONE_COLORS: Record<string, string> = {
  default: 'text-[var(--color-text)]',
  green: 'text-[var(--color-accent-green)]',
  blue: 'text-[var(--color-accent-blue)]',
  warning: 'text-[var(--color-accent-warning)]',
  danger: 'text-[var(--color-accent-danger)]',
};

const ICON_BG: Record<string, string> = {
  default: 'bg-[var(--color-border-soft)] text-[var(--color-text-secondary)]',
  green: 'bg-[var(--color-accent-green)]/10 text-[var(--color-accent-green)]',
  blue: 'bg-[var(--color-accent-blue)]/10 text-[var(--color-accent-blue)]',
  warning: 'bg-[var(--color-accent-warning)]/10 text-[var(--color-accent-warning)]',
  danger: 'bg-[var(--color-accent-danger)]/10 text-[var(--color-accent-danger)]',
};

export default function StatCard({
  icon: Icon,
  label,
  value,
  suffix = '',
  decimals = 0,
  tone = 'default',
  subtext,
  delay = 0,
}: StatCardProps) {
  return (
    <Card delay={delay} className="p-5">
      <div className="flex items-start justify-between">
        <div>
          <p className="text-xs font-medium text-[var(--color-text-secondary)] uppercase tracking-wide">{label}</p>
          <p className={`mt-2 text-2xl font-semibold ${TONE_COLORS[tone]}`}>
            <AnimatedNumber value={value} decimals={decimals} suffix={suffix} />
          </p>
          {subtext && <p className="mt-1 text-xs text-[var(--color-text-muted)]">{subtext}</p>}
        </div>
        <div className={`w-9 h-9 rounded-lg flex items-center justify-center shrink-0 ${ICON_BG[tone]}`}>
          <Icon size={18} strokeWidth={2} />
        </div>
      </div>
    </Card>
  );
}

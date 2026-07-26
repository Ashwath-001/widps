interface StatusBadgeProps {
  status: string;
}

const STYLES: Record<string, string> = {
  Normal: 'bg-[var(--color-accent-green)]/10 text-[var(--color-accent-green)] border-[var(--color-accent-green)]/30',
  Suspicious: 'bg-[var(--color-accent-warning)]/10 text-[var(--color-accent-warning)] border-[var(--color-accent-warning)]/30',
  Malicious: 'bg-[var(--color-accent-danger)]/10 text-[var(--color-accent-danger)] border-[var(--color-accent-danger)]/30',
  Low: 'bg-[var(--color-accent-green)]/10 text-[var(--color-accent-green)] border-[var(--color-accent-green)]/30',
  Medium: 'bg-[var(--color-accent-warning)]/10 text-[var(--color-accent-warning)] border-[var(--color-accent-warning)]/30',
  High: 'bg-orange-500/10 text-orange-400 border-orange-500/30',
  Critical: 'bg-[var(--color-accent-danger)]/10 text-[var(--color-accent-danger)] border-[var(--color-accent-danger)]/30',
  Active: 'bg-[var(--color-accent-danger)]/10 text-[var(--color-accent-danger)] border-[var(--color-accent-danger)]/30',
  Investigating: 'bg-[var(--color-accent-warning)]/10 text-[var(--color-accent-warning)] border-[var(--color-accent-warning)]/30',
  Mitigated: 'bg-[var(--color-accent-green)]/10 text-[var(--color-accent-green)] border-[var(--color-accent-green)]/30',
  Ignored: 'bg-[var(--color-border-soft)] text-[var(--color-text-muted)] border-[var(--color-border)]',
};

export default function StatusBadge({ status }: StatusBadgeProps) {
  const style = STYLES[status] ?? 'bg-[var(--color-border-soft)] text-[var(--color-text-muted)] border-[var(--color-border)]';
  return (
    <span className={`inline-flex items-center gap-1.5 px-2.5 py-1 rounded-full border text-xs font-medium ${style}`}>
      <span className="w-1.5 h-1.5 rounded-full bg-current" />
      {status}
    </span>
  );
}

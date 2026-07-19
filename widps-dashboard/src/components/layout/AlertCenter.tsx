import { AnimatePresence, motion } from 'framer-motion';
import { X, BellOff } from 'lucide-react';
import type { AlertItem, Severity } from '../../types';

const SEVERITY_DOT: Record<Severity, string> = {
  Low: 'bg-[var(--color-accent-green)]',
  Medium: 'bg-[var(--color-accent-warning)]',
  High: 'bg-orange-400',
  Critical: 'bg-[var(--color-accent-danger)]',
};

interface AlertCenterProps {
  open: boolean;
  onClose: () => void;
  alerts: AlertItem[];
  onMarkRead: (id: string) => void;
  onMarkAllRead: () => void;
}

export default function AlertCenter({ open, onClose, alerts, onMarkRead, onMarkAllRead }: AlertCenterProps) {
  const grouped: Record<Severity, AlertItem[]> = { Critical: [], High: [], Medium: [], Low: [] };
  alerts.forEach((a) => grouped[a.severity].push(a));

  return (
    <AnimatePresence>
      {open && (
        <>
          <motion.div
            initial={{ opacity: 0 }}
            animate={{ opacity: 1 }}
            exit={{ opacity: 0 }}
            className="fixed inset-0 bg-black/50 backdrop-blur-sm z-40"
            onClick={onClose}
          />
          <motion.div
            initial={{ x: '100%' }}
            animate={{ x: 0 }}
            exit={{ x: '100%' }}
            transition={{ duration: 0.28, ease: 'easeOut' }}
            className="fixed right-0 top-0 h-full w-full max-w-sm bg-[var(--color-bg-elevated)] border-l border-[var(--color-border)] z-50 flex flex-col"
          >
            <div className="h-16 flex items-center justify-between px-5 border-b border-[var(--color-border)] shrink-0">
              <h2 className="text-sm font-semibold">Alert Center</h2>
              <div className="flex items-center gap-3">
                <button onClick={onMarkAllRead} className="text-xs text-[var(--color-accent-blue)] hover:underline">
                  Mark all read
                </button>
                <button onClick={onClose} className="w-8 h-8 rounded-lg flex items-center justify-center text-[var(--color-text-secondary)] hover:bg-white/5">
                  <X size={16} />
                </button>
              </div>
            </div>

            <div className="flex-1 overflow-y-auto px-5 py-4 space-y-6">
              {(['Critical', 'High', 'Medium', 'Low'] as Severity[]).map((sev) =>
                grouped[sev].length > 0 ? (
                  <div key={sev}>
                    <p className="text-xs font-semibold text-[var(--color-text-muted)] uppercase tracking-wide mb-2">
                      {sev} Severity
                    </p>
                    <div className="space-y-2">
                      {grouped[sev].map((a) => (
                        <button
                          key={a.id}
                          onClick={() => onMarkRead(a.id)}
                          className={`w-full text-left p-3 rounded-lg border transition-colors ${
                            a.read
                              ? 'border-[var(--color-border-soft)] bg-transparent opacity-60'
                              : 'border-[var(--color-border)] bg-[var(--color-card)]'
                          }`}
                        >
                          <div className="flex items-center gap-2">
                            <span className={`w-1.5 h-1.5 rounded-full ${SEVERITY_DOT[a.severity]}`} />
                            <p className="text-sm font-medium">{a.title}</p>
                          </div>
                          <p className="text-xs text-[var(--color-text-secondary)] mt-1 leading-snug">{a.detail}</p>
                          <p className="data-mono text-[10px] text-[var(--color-text-muted)] mt-1.5">{a.time}</p>
                        </button>
                      ))}
                    </div>
                  </div>
                ) : null
              )}

              {alerts.length === 0 && (
                <div className="flex flex-col items-center justify-center text-center py-16 text-[var(--color-text-muted)]">
                  <BellOff size={28} className="mb-3 opacity-60" />
                  <p className="text-sm">No alerts to show.</p>
                </div>
              )}
            </div>
          </motion.div>
        </>
      )}
    </AnimatePresence>
  );
}

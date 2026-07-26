import { AnimatePresence, motion } from 'framer-motion';
import { Radio, ShieldAlert, Wifi, BrainCircuit, Activity } from 'lucide-react';
import type { LiveFeedItem } from '../../types';

const TONE_CONFIG: Record<LiveFeedItem['tone'], { dot: string; bg: string; icon: typeof ShieldAlert }> = {
  danger: { dot: 'bg-[var(--color-accent-danger)]', bg: 'bg-red-500/5', icon: ShieldAlert },
  warning: { dot: 'bg-[var(--color-accent-warning)]', bg: 'bg-yellow-500/5', icon: ShieldAlert },
  info: { dot: 'bg-[var(--color-accent-blue)]', bg: 'bg-blue-500/5', icon: Wifi },
  success: { dot: 'bg-[var(--color-accent-green)]', bg: 'bg-green-500/5', icon: Activity },
};

function getIcon(message: string, tone: LiveFeedItem['tone']) {
  if (message.startsWith('AI:')) return BrainCircuit;
  if (message.startsWith('Capturing')) return Radio;
  return TONE_CONFIG[tone].icon;
}

interface LiveAttackFeedProps {
  items: LiveFeedItem[];
}

export default function LiveAttackFeed({ items }: LiveAttackFeedProps) {
  return (
    <aside className="hidden xl:flex flex-col w-[300px] shrink-0 border-l border-[var(--color-border)] bg-[var(--color-bg-elevated)] h-screen sticky top-0">
      <div className="h-16 flex items-center justify-between px-4 border-b border-[var(--color-border)] shrink-0">
        <div className="flex items-center gap-2">
          <span className="relative flex items-center justify-center">
            <Radio size={15} className="text-[var(--color-accent-blue)]" />
            {items.some((i) => i.tone === 'danger') && (
              <span className="absolute -top-0.5 -right-0.5 w-2 h-2 rounded-full bg-[var(--color-accent-danger)] animate-pulse" />
            )}
          </span>
          <h2 className="text-sm font-semibold">Live Feed</h2>
        </div>
        <span className="text-[10px] text-[var(--color-text-muted)] data-mono">{items.length} events</span>
      </div>

      <div className="flex-1 overflow-y-auto px-3 py-3 space-y-1.5">
        {items.length === 0 && (
          <div className="text-center py-12">
            <Radio size={24} className="mx-auto text-[var(--color-text-muted)] opacity-40 mb-2" />
            <p className="text-xs text-[var(--color-text-muted)]">Waiting for events...</p>
            <p className="text-[10px] text-[var(--color-text-muted)] mt-1">Alerts and ML predictions will appear here in real-time</p>
          </div>
        )}
        <AnimatePresence initial={false}>
          {items.map((item) => {
            const config = TONE_CONFIG[item.tone];
            const Icon = getIcon(item.message, item.tone);
            return (
              <motion.div
                key={item.id}
                initial={{ opacity: 0, x: 20, height: 0 }}
                animate={{ opacity: 1, x: 0, height: 'auto' }}
                exit={{ opacity: 0, x: 20, height: 0 }}
                transition={{ duration: 0.2 }}
                className={`rounded-lg px-3 py-2.5 ${config.bg} border border-transparent hover:border-[var(--color-border-soft)] transition-colors`}
              >
                <div className="flex items-start gap-2.5">
                  <div className="mt-0.5 shrink-0">
                    <Icon size={13} className={item.tone === 'danger' ? 'text-[var(--color-accent-danger)]' : item.tone === 'warning' ? 'text-[var(--color-accent-warning)]' : item.tone === 'success' ? 'text-[var(--color-accent-green)]' : 'text-[var(--color-accent-blue)]'} />
                  </div>
                  <div className="flex-1 min-w-0">
                    <p className="text-[12px] text-[var(--color-text)] leading-snug break-words">{item.message}</p>
                    <p className="data-mono text-[10px] text-[var(--color-text-muted)] mt-1">{item.time}</p>
                  </div>
                  <span className={`w-1.5 h-1.5 rounded-full shrink-0 mt-1.5 ${config.dot}`} />
                </div>
              </motion.div>
            );
          })}
        </AnimatePresence>
      </div>
    </aside>
  );
}

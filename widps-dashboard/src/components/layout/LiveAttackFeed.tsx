import { AnimatePresence, motion } from 'framer-motion';
import { Radio } from 'lucide-react';
import type { LiveFeedItem } from '../../types';

const TONE_DOT: Record<LiveFeedItem['tone'], string> = {
  info: 'bg-[var(--color-accent-blue)]',
  warning: 'bg-[var(--color-accent-warning)]',
  danger: 'bg-[var(--color-accent-danger)]',
  success: 'bg-[var(--color-accent-green)]',
};

interface LiveAttackFeedProps {
  items: LiveFeedItem[];
}

export default function LiveAttackFeed({ items }: LiveAttackFeedProps) {
  return (
    <aside className="hidden xl:flex flex-col w-[300px] shrink-0 border-l border-[var(--color-border)] bg-[var(--color-bg-elevated)] h-screen sticky top-0">
      <div className="h-16 flex items-center gap-2 px-4 border-b border-[var(--color-border)] shrink-0">
        <Radio size={15} className="text-[var(--color-accent-blue)]" />
        <h2 className="text-sm font-semibold">Live Attack Feed</h2>
      </div>
      <div className="flex-1 overflow-y-auto px-4 py-4 space-y-3">
        <AnimatePresence initial={false}>
          {items.map((item) => (
            <motion.div
              key={item.id}
              initial={{ opacity: 0, x: 24 }}
              animate={{ opacity: 1, x: 0 }}
              exit={{ opacity: 0, x: 24 }}
              transition={{ duration: 0.25 }}
              className="flex gap-3"
            >
              <div className="flex flex-col items-center pt-1.5">
                <span className={`w-2 h-2 rounded-full ${TONE_DOT[item.tone]}`} />
                <span className="w-px flex-1 bg-[var(--color-border)] mt-1" />
              </div>
              <div className="pb-1">
                <p className="data-mono text-[11px] text-[var(--color-text-muted)]">{item.time}</p>
                <p className="text-sm text-[var(--color-text)] leading-snug mt-0.5">{item.message}</p>
              </div>
            </motion.div>
          ))}
        </AnimatePresence>
      </div>
    </aside>
  );
}

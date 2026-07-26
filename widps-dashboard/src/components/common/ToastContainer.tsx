import { AnimatePresence, motion } from 'framer-motion';
import { CheckCircle, XCircle, Info, AlertTriangle, X } from 'lucide-react';
import type { Toast, ToastType } from '../../hooks/useToast';

const ICONS: Record<ToastType, typeof Info> = {
  success: CheckCircle,
  error: XCircle,
  info: Info,
  warning: AlertTriangle,
};

const COLORS: Record<ToastType, string> = {
  success: 'text-[var(--color-accent-green)] border-[var(--color-accent-green)]/30',
  error: 'text-[var(--color-accent-danger)] border-[var(--color-accent-danger)]/30',
  info: 'text-[var(--color-accent-blue)] border-[var(--color-accent-blue)]/30',
  warning: 'text-[var(--color-accent-warning)] border-[var(--color-accent-warning)]/30',
};

interface ToastContainerProps {
  toasts: Toast[];
  onDismiss: (id: string) => void;
}

export default function ToastContainer({ toasts, onDismiss }: ToastContainerProps) {
  return (
    <div className="fixed bottom-6 right-6 z-50 flex flex-col gap-3 w-[360px]" data-hide-print>
      <AnimatePresence>
        {toasts.map((toast) => {
          const Icon = ICONS[toast.type];
          return (
            <motion.div
              key={toast.id}
              initial={{ opacity: 0, y: 20, scale: 0.95 }}
              animate={{ opacity: 1, y: 0, scale: 1 }}
              exit={{ opacity: 0, y: 10, scale: 0.95 }}
              transition={{ duration: 0.2 }}
              className={`flex items-start gap-3 px-5 py-4 rounded-xl border bg-[var(--color-bg-elevated)] shadow-xl ${COLORS[toast.type]}`}
            >
              <Icon size={20} className="shrink-0 mt-0.5" />
              <p className="text-sm font-medium text-[var(--color-text)] flex-1 leading-snug">{toast.message}</p>
              <button
                onClick={() => onDismiss(toast.id)}
                className="shrink-0 text-[var(--color-text-muted)] hover:text-[var(--color-text)] transition-colors"
              >
                <X size={16} />
              </button>
            </motion.div>
          );
        })}
      </AnimatePresence>
    </div>
  );
}

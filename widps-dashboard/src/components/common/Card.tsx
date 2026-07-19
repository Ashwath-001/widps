import { motion } from 'framer-motion';
import type { ReactNode } from 'react';

interface CardProps {
  children: ReactNode;
  className?: string;
  delay?: number;
  hover?: boolean;
}

/**
 * Base surface used across the dashboard. Fades/slides in on mount so page
 * transitions feel deliberate rather than an instant content dump.
 */
export default function Card({ children, className = '', delay = 0, hover = true }: CardProps) {
  return (
    <motion.div
      initial={{ opacity: 0, y: 12 }}
      animate={{ opacity: 1, y: 0 }}
      transition={{ duration: 0.35, delay, ease: 'easeOut' }}
      className={`bg-[var(--color-card)] border border-[var(--color-border)] rounded-xl ${
        hover ? 'transition-colors duration-200 hover:border-[var(--color-border-soft)] hover:bg-[var(--color-card-hover)]' : ''
      } ${className}`}
    >
      {children}
    </motion.div>
  );
}

import { motion } from 'framer-motion';
import type { ReactNode } from 'react';

interface CardProps {
  children: ReactNode;
  className?: string;
  delay?: number;
  hover?: boolean;
}

/**
 * Base surface used across the dashboard. Lightweight fade-in on mount.
 * Kept minimal for performance on ARM (Raspberry Pi 5).
 */
export default function Card({ children, className = '', delay = 0, hover = true }: CardProps) {
  return (
    <motion.div
      initial={{ opacity: 0 }}
      animate={{ opacity: 1 }}
      transition={{ duration: 0.15, delay: Math.min(delay, 0.1) }}
      className={`bg-[var(--color-card)] border border-[var(--color-border)] rounded-xl ${
        hover ? 'transition-colors duration-200 hover:border-[var(--color-border-soft)] hover:bg-[var(--color-card-hover)]' : ''
      } ${className}`}
    >
      {children}
    </motion.div>
  );
}

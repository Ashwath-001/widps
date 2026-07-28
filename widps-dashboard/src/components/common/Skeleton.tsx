interface SkeletonProps {
  className?: string;
  count?: number;
}

export default function Skeleton({ className = '', count = 1 }: SkeletonProps) {
  return (
    <>
      {Array.from({ length: count }, (_, i) => (
        <div
          key={i}
          className={`animate-pulse rounded bg-[var(--color-border-soft)] ${className}`}
        />
      ))}
    </>
  );
}

export function SkeletonCard({ delay = 0 }: { delay?: number }) {
  return (
    <div
      className="p-5 rounded-xl border border-[var(--color-border-soft)] bg-[var(--color-card)]"
      style={{ animationDelay: `${delay}s` }}
    >
      <Skeleton className="h-3 w-24 mb-3" />
      <Skeleton className="h-7 w-16 mb-2" />
      <Skeleton className="h-2.5 w-32" />
    </div>
  );
}

export function SkeletonTable({ rows = 5 }: { rows?: number }) {
  return (
    <div className="space-y-2 p-4">
      <Skeleton className="h-8 w-full" />
      {Array.from({ length: rows }, (_, i) => (
        <Skeleton key={i} className="h-12 w-full" />
      ))}
    </div>
  );
}

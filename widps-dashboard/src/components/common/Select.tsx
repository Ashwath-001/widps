import { useState, useRef, useEffect } from 'react';
import { ChevronDown } from 'lucide-react';

interface SelectOption {
  value: string;
  label: string;
}

interface SelectProps {
  value: string;
  onChange: (value: string) => void;
  options: SelectOption[];
  placeholder?: string;
  className?: string;
}

export default function Select({ value, onChange, options, placeholder, className = '' }: SelectProps) {
  const [open, setOpen] = useState(false);
  const ref = useRef<HTMLDivElement>(null);

  const selected = options.find(o => o.value === value);

  useEffect(() => {
    function handleClickOutside(e: MouseEvent) {
      if (ref.current && !ref.current.contains(e.target as Node)) {
        setOpen(false);
      }
    }
    if (open) {
      document.addEventListener('mousedown', handleClickOutside);
      return () => document.removeEventListener('mousedown', handleClickOutside);
    }
  }, [open]);

  return (
    <div ref={ref} className={`relative inline-block ${className}`}>
      <button
        type="button"
        onClick={() => setOpen(!open)}
        className="flex items-center justify-between gap-2 h-[30px] px-2.5 rounded-lg text-xs bg-[var(--color-card)] border border-[var(--color-border)] text-[var(--color-text)] hover:border-[var(--color-accent-blue)] transition-colors min-w-[90px]"
      >
        <span className={`truncate ${selected ? '' : 'text-[var(--color-text-muted)]'}`}>
          {selected?.label || placeholder || 'Select...'}
        </span>
        <ChevronDown size={11} className={`text-[var(--color-text-muted)] shrink-0 transition-transform ${open ? 'rotate-180' : ''}`} />
      </button>

      {open && (
        <div className="absolute left-0 z-50 mt-1 min-w-full w-max max-w-[200px] rounded-lg border border-[var(--color-border)] bg-[var(--color-bg-elevated)] shadow-xl overflow-hidden">
          <div className="max-h-52 overflow-y-auto py-1">
            {options.map((opt) => (
              <button
                key={opt.value}
                type="button"
                onClick={() => { onChange(opt.value); setOpen(false); }}
                className={`w-full text-left px-3 py-1.5 text-xs transition-colors ${
                  opt.value === value
                    ? 'bg-[var(--color-accent-blue)]/10 text-[var(--color-accent-blue)] font-medium'
                    : 'text-[var(--color-text-secondary)] hover:bg-[var(--color-card)] hover:text-[var(--color-text)]'
                }`}
              >
                {opt.label}
              </button>
            ))}
          </div>
        </div>
      )}
    </div>
  );
}

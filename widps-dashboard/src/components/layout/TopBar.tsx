import { useEffect, useState } from 'react';
import { Bell, Search, Settings, Moon, Menu } from 'lucide-react';
import ThreatLevelIndicator from './ThreatLevelIndicator';
import type { ThreatLevel } from '../../types';

interface TopBarProps {
  threatLevel: ThreatLevel;
  unreadAlerts: number;
  onOpenAlerts: () => void;
  onOpenSettings: () => void;
  onToggleSidebar: () => void;
}

export default function TopBar({ threatLevel, unreadAlerts, onOpenAlerts, onOpenSettings, onToggleSidebar }: TopBarProps) {
  const [now, setNow] = useState(new Date());

  useEffect(() => {
    const id = setInterval(() => setNow(new Date()), 1000);
    return () => clearInterval(id);
  }, []);

  return (
    <header className="h-16 shrink-0 border-b border-[var(--color-border)] bg-[var(--color-bg-elevated)]/80 backdrop-blur px-6 flex items-center justify-between gap-4 sticky top-0 z-20">
      <div className="flex items-center gap-4 min-w-0">
        <button
          onClick={onToggleSidebar}
          className="lg:hidden w-9 h-9 rounded-lg flex items-center justify-center text-[var(--color-text-secondary)] hover:bg-white/5 hover:text-[var(--color-text)] transition-colors"
          aria-label="Toggle menu"
        >
          <Menu size={18} />
        </button>
        <h1 className="text-base font-semibold whitespace-nowrap hidden sm:block">WIDPS AI Dashboard</h1>
        <h1 className="text-base font-semibold whitespace-nowrap sm:hidden">WIDPS</h1>
        <div className="hidden md:flex items-center gap-2 px-3 py-1.5 rounded-lg bg-[var(--color-card)] border border-[var(--color-border)] w-72 max-w-full">
          <Search size={14} className="text-[var(--color-text-muted)] shrink-0" />
          <input
            type="text"
            placeholder="Search SSID, BSSID, MAC..."
            className="bg-transparent text-sm outline-none w-full placeholder:text-[var(--color-text-muted)]"
          />
        </div>
      </div>

      <div className="flex items-center gap-3 shrink-0">
        <ThreatLevelIndicator level={threatLevel} />

        <span className="hidden lg:block data-mono text-sm text-[var(--color-text-secondary)] tabular-nums">
          {now.toLocaleTimeString('en-GB')}
        </span>

        <button
          onClick={onOpenAlerts}
          className="relative w-9 h-9 rounded-lg flex items-center justify-center text-[var(--color-text-secondary)] hover:bg-white/5 hover:text-[var(--color-text)] transition-colors focus-visible:outline focus-visible:outline-2 focus-visible:outline-[var(--color-accent-blue)]"
          aria-label="Notifications"
        >
          <Bell size={17} />
          {unreadAlerts > 0 && (
            <span className="absolute top-1 right-1 min-w-[15px] h-[15px] px-[3px] rounded-full bg-[var(--color-accent-danger)] text-[9px] font-bold flex items-center justify-center">
              {unreadAlerts}
            </span>
          )}
        </button>

        <button
          onClick={onOpenSettings}
          className="w-9 h-9 rounded-lg flex items-center justify-center text-[var(--color-text-secondary)] hover:bg-white/5 hover:text-[var(--color-text)] transition-colors focus-visible:outline focus-visible:outline-2 focus-visible:outline-[var(--color-accent-blue)]"
          aria-label="Settings"
        >
          <Settings size={17} />
        </button>

        <button
          className="w-9 h-9 rounded-lg flex items-center justify-center text-[var(--color-text-secondary)] hover:bg-white/5 hover:text-[var(--color-text)] transition-colors focus-visible:outline focus-visible:outline-2 focus-visible:outline-[var(--color-accent-blue)]"
          aria-label="Toggle dark mode"
        >
          <Moon size={17} />
        </button>
      </div>
    </header>
  );
}

import { useEffect, useState } from 'react';
import { Bell, Settings, Moon, Sun, Menu } from 'lucide-react';
import ThreatLevelIndicator from './ThreatLevelIndicator';
import type { ThreatLevel } from '../../types';

interface TopBarProps {
  threatLevel: ThreatLevel;
  unreadAlerts: number;
  onOpenAlerts: () => void;
  onOpenSettings: () => void;
  onToggleSidebar: () => void;
  theme: 'dark' | 'light';
  onToggleTheme: () => void;
}

export default function TopBar({ threatLevel, unreadAlerts, onOpenAlerts, onOpenSettings, onToggleSidebar, theme, onToggleTheme }: TopBarProps) {
  const [now, setNow] = useState(new Date());

  useEffect(() => {
    const id = setInterval(() => setNow(new Date()), 1000);
    return () => clearInterval(id);
  }, []);

  return (
    <header className="h-14 sm:h-16 shrink-0 border-b border-[var(--color-border)] bg-[var(--color-bg-elevated)]/80 backdrop-blur px-3 sm:px-6 flex items-center justify-between gap-2 sm:gap-4 sticky top-0 z-20">
      {/* Left: hamburger + title */}
      <div className="flex items-center gap-2 sm:gap-4 min-w-0">
        <button
          onClick={onToggleSidebar}
          className="lg:hidden w-9 h-9 rounded-lg flex items-center justify-center text-[var(--color-text-secondary)] hover:bg-white/5 hover:text-[var(--color-text)] transition-colors shrink-0"
          aria-label="Toggle menu"
        >
          <Menu size={18} />
        </button>
        <h1 className="text-sm sm:text-base font-semibold whitespace-nowrap shrink-0">WIDPS</h1>
      </div>

      {/* Center: threat level (hidden on very small screens, shown from sm+) */}
      <div className="hidden xs:flex sm:flex items-center justify-center flex-1 min-w-0">
        <ThreatLevelIndicator level={threatLevel} />
      </div>

      {/* Right: action buttons */}
      <div className="flex items-center gap-1 sm:gap-2 shrink-0">
        {/* Threat on very small screens - compact version */}
        <div className="sm:hidden">
          <ThreatLevelIndicator level={threatLevel} compact />
        </div>

        <span className="hidden lg:block data-mono text-xs text-[var(--color-text-secondary)] tabular-nums">
          {now.toLocaleTimeString('en-GB')}
        </span>

        <button
          onClick={onOpenAlerts}
          className="relative w-8 h-8 sm:w-9 sm:h-9 rounded-lg flex items-center justify-center text-[var(--color-text-secondary)] hover:bg-white/5 hover:text-[var(--color-text)] transition-colors"
          aria-label="Notifications"
        >
          <Bell size={16} />
          {unreadAlerts > 0 && (
            <span className="absolute top-0.5 right-0.5 min-w-[14px] h-[14px] px-[2px] rounded-full bg-[var(--color-accent-danger)] text-[8px] font-bold flex items-center justify-center text-white">
              {unreadAlerts > 99 ? '99+' : unreadAlerts}
            </span>
          )}
        </button>

        <button
          onClick={onOpenSettings}
          className="hidden sm:flex w-9 h-9 rounded-lg items-center justify-center text-[var(--color-text-secondary)] hover:bg-white/5 hover:text-[var(--color-text)] transition-colors"
          aria-label="Settings"
        >
          <Settings size={17} />
        </button>

        <button
          onClick={onToggleTheme}
          className="w-8 h-8 sm:w-9 sm:h-9 rounded-lg flex items-center justify-center text-[var(--color-text-secondary)] hover:bg-white/5 hover:text-[var(--color-text)] transition-colors"
          aria-label="Toggle theme"
        >
          {theme === 'dark' ? <Sun size={16} /> : <Moon size={16} />}
        </button>
      </div>
    </header>
  );
}

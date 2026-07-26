import {
  LayoutDashboard,
  Wifi,
  Activity,
  BrainCircuit,
  ShieldAlert,
  ScrollText,
  BarChart3,
  Share2,
  FileBarChart,
  Settings,
  Radar,
  ChevronsLeft,
  ChevronsRight,
} from 'lucide-react';
import type { LucideIcon } from 'lucide-react';
import type { PageKey } from '../../App';

interface NavItem {
  key: PageKey;
  label: string;
  icon: LucideIcon;
}

const NAV_ITEMS: NavItem[] = [
  { key: 'overview', label: 'Dashboard', icon: LayoutDashboard },
  { key: 'network', label: 'Network', icon: Wifi },
  { key: 'traffic', label: 'Traffic', icon: Activity },
  { key: 'ai', label: 'AI Detection', icon: BrainCircuit },
  { key: 'threats', label: 'Threats', icon: ShieldAlert },
  { key: 'log', label: 'Event Log', icon: ScrollText },
  { key: 'stats', label: 'Statistics', icon: BarChart3 },
  { key: 'topology', label: 'Topology', icon: Share2 },
  { key: 'reports', label: 'Reports', icon: FileBarChart },
  { key: 'settings', label: 'Settings', icon: Settings },
];

interface SidebarProps {
  active: PageKey;
  onNavigate: (key: PageKey) => void;
  collapsed: boolean;
  onToggleCollapsed: () => void;
}

export default function Sidebar({ active, onNavigate, collapsed, onToggleCollapsed }: SidebarProps) {
  return (
    <aside
      className={`h-screen sticky top-0 flex flex-col border-r border-[var(--color-border)] bg-[var(--color-bg-elevated)] transition-[width] duration-300 ease-out ${
        collapsed ? 'w-[72px]' : 'w-[240px]'
      }`}
    >
      <div className="h-16 flex items-center gap-2.5 px-4 border-b border-[var(--color-border)] shrink-0">
        <div className="w-8 h-8 rounded-lg bg-[var(--color-accent-blue)]/15 flex items-center justify-center shrink-0">
          <Radar size={18} className="text-[var(--color-accent-blue)]" />
        </div>
        {!collapsed && (
          <div className="min-w-0">
            <p className="text-sm font-bold leading-tight truncate">WIDPS</p>
            <p className="text-[10px] text-[var(--color-text-muted)] leading-tight">Threat Intelligence</p>
          </div>
        )}
      </div>

      <nav className="flex-1 py-3 px-2 space-y-1 overflow-y-auto">
        {NAV_ITEMS.map((item) => {
          const isActive = active === item.key;
          const Icon = item.icon;
          return (
            <button
              key={item.key}
              onClick={() => onNavigate(item.key)}
              title={collapsed ? item.label : undefined}
              className={`group relative w-full flex items-center gap-3 px-3 py-2.5 rounded-lg text-sm font-medium transition-colors duration-150 focus-visible:outline focus-visible:outline-2 focus-visible:outline-[var(--color-accent-blue)] ${
                isActive
                  ? 'bg-[var(--color-accent-blue)]/12 text-[var(--color-accent-blue)]'
                  : 'text-[var(--color-text-secondary)] hover:bg-white/5 hover:text-[var(--color-text)]'
              }`}
            >
              {isActive && (
                <span className="absolute left-0 top-1.5 bottom-1.5 w-0.5 rounded-full bg-[var(--color-accent-blue)]" />
              )}
              <Icon size={18} strokeWidth={2} className="shrink-0" />
              {!collapsed && (
                <div className="flex items-center justify-between flex-1 min-w-0">
                  <span className="truncate">{item.label}</span>
                  {item.key === 'ai' && (
                    <span className="text-[9px] font-semibold uppercase px-1.5 py-0.5 rounded bg-blue-500/10 text-blue-400 border border-blue-500/20">
                      Soon
                    </span>
                  )}
                </div>
              )}
            </button>
          );
        })}
      </nav>

      <button
        onClick={onToggleCollapsed}
        className="h-12 flex items-center justify-center gap-2 border-t border-[var(--color-border)] text-[var(--color-text-muted)] hover:text-[var(--color-text)] hover:bg-white/5 transition-colors text-xs shrink-0"
      >
        {collapsed ? <ChevronsRight size={16} /> : <><ChevronsLeft size={16} /> Collapse</>}
      </button>
    </aside>
  );
}

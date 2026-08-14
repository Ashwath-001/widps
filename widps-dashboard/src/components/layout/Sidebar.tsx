import { useState } from 'react';
import { ChevronsLeft, ChevronsRight, ChevronDown } from 'lucide-react';
import { NAV_GROUPS, type PageKey } from '../../config/navigation';

interface SidebarProps {
  active: PageKey;
  onNavigate: (key: PageKey) => void;
  collapsed: boolean;
  onToggleCollapsed: () => void;
}

export default function Sidebar({ active, onNavigate, collapsed, onToggleCollapsed }: SidebarProps) {
  // Track which groups are expanded (all open by default)
  const [openGroups, setOpenGroups] = useState<Set<string>>(() => new Set(NAV_GROUPS.map(g => g.id)));

  const toggleGroup = (id: string) => {
    setOpenGroups((prev) => {
      const next = new Set(prev);
      if (next.has(id)) next.delete(id);
      else next.add(id);
      return next;
    });
  };

  return (
    <aside
      className={`h-screen sticky top-0 flex flex-col border-r border-[var(--color-border)] bg-[var(--color-bg-elevated)] transition-[width] duration-300 ease-out ${
        collapsed ? 'w-[72px] lg:w-[72px]' : 'w-[260px] sm:w-[220px]'
      }`}
    >
      {/* Logo */}
      <div className="h-14 sm:h-16 flex items-center gap-2.5 px-4 border-b border-[var(--color-border)] shrink-0">
        <div className="w-8 h-8 rounded-lg bg-[var(--color-accent-blue)]/10 flex items-center justify-center shrink-0 overflow-hidden">
          <img src="/favicon.svg" alt="WIDPS" className="w-6 h-6" />
        </div>
        {!collapsed && (
          <div className="min-w-0">
            <p className="text-sm font-bold leading-tight truncate">WIDPS</p>
            <p className="text-[10px] text-[var(--color-text-muted)] leading-tight">Wireless IDS</p>
          </div>
        )}
      </div>

      {/* Navigation */}
      <nav className="flex-1 py-2 px-2 overflow-y-auto overscroll-contain">
        {NAV_GROUPS.map((group) => {
          const isOpen = openGroups.has(group.id);

          return (
            <div key={group.id} className="mb-1">
              {/* Group header (clickable to collapse, hidden when sidebar collapsed) */}
              {!collapsed && (
                <button
                  onClick={() => toggleGroup(group.id)}
                  className="w-full flex items-center justify-between px-2 py-1.5 text-[10px] uppercase font-semibold tracking-wider text-[var(--color-text-muted)] hover:text-[var(--color-text-secondary)] transition-colors"
                >
                  <span>{group.label}</span>
                  <ChevronDown size={10} className={`transition-transform ${isOpen ? '' : '-rotate-90'}`} />
                </button>
              )}

              {/* Group items */}
              {(isOpen || collapsed) && (
                <div className="space-y-0.5">
                  {group.items.map((item) => {
                    const isActive = active === item.key;
                    const Icon = item.icon;
                    return (
                      <button
                        key={item.key}
                        onClick={() => onNavigate(item.key)}
                        title={collapsed ? item.label : undefined}
                        className={`group relative w-full flex items-center gap-2.5 px-2.5 py-[7px] rounded-lg text-[13px] font-medium transition-colors duration-150 ${
                          isActive
                            ? 'bg-[var(--color-accent-blue)]/12 text-[var(--color-accent-blue)]'
                            : 'text-[var(--color-text-secondary)] hover:bg-white/5 hover:text-[var(--color-text)]'
                        }`}
                      >
                        {isActive && (
                          <span className="absolute left-0 top-1.5 bottom-1.5 w-0.5 rounded-full bg-[var(--color-accent-blue)]" />
                        )}
                        <Icon size={15} strokeWidth={2} className="shrink-0" />
                        {!collapsed && <span className="truncate">{item.label}</span>}
                      </button>
                    );
                  })}
                </div>
              )}
            </div>
          );
        })}
      </nav>

      {/* Collapse toggle (desktop only) */}
      <button
        onClick={onToggleCollapsed}
        className="hidden lg:flex h-10 items-center justify-center gap-2 border-t border-[var(--color-border)] text-[var(--color-text-muted)] hover:text-[var(--color-text)] hover:bg-white/5 transition-colors text-xs shrink-0"
      >
        {collapsed ? <ChevronsRight size={16} /> : <><ChevronsLeft size={16} /> Collapse</>}
      </button>
    </aside>
  );
}

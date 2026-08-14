import React, { useState } from 'react';
import { AnimatePresence, motion } from 'framer-motion';
import Sidebar from './components/layout/Sidebar';
import TopBar from './components/layout/TopBar';
import LiveAttackFeed from './components/layout/LiveAttackFeed';
import AlertCenter from './components/layout/AlertCenter';
import ErrorBoundary from './components/common/ErrorBoundary';
import Overview from './pages/Overview';
import LiveNetwork from './pages/LiveNetwork';
import LiveTraffic from './pages/LiveTraffic';
import AIDetection from './pages/AIDetection';
import ThreatMap from './pages/ThreatMap';
import EventLog from './pages/EventLog';
import Statistics from './pages/Statistics';
import DeviceTopology from './pages/DeviceTopology';
import Reports from './pages/Reports';
import SettingsPage from './pages/SettingsPage';
import Honeypot from './pages/Honeypot';
import ShapExplainability from './pages/ShapExplainability';
import ThreatScoring from './pages/ThreatScoring';
import SecurityAudit from './pages/SecurityAudit';
import SystemLogs from './pages/SystemLogs';
import ThreatIntel from './pages/ThreatIntel';
import { useLiveFeed, useLiveAlerts } from './hooks/useMockLiveData';
import { useHashRoute } from './hooks/useHashRoute';
import { useTheme } from './hooks/useTheme';
import type { PageKey } from './config/navigation';
import type { ThreatLevel } from './types';

export type { PageKey } from './config/navigation';

const PAGES: Record<PageKey, () => React.ReactElement> = {
  overview: Overview,
  network: LiveNetwork,
  traffic: LiveTraffic,
  ai: AIDetection,
  shap: ShapExplainability,
  scoring: ThreatScoring,
  threats: ThreatMap,
  intel: ThreatIntel,
  honeypot: Honeypot,
  log: EventLog,
  stats: Statistics,
  topology: DeviceTopology,
  logs: SystemLogs,
  audit: SecurityAudit,
  reports: Reports,
  settings: SettingsPage,
};

export default function App() {
  const [page, navigate] = useHashRoute();
  const [theme, toggleTheme] = useTheme();
  const [collapsed, setCollapsed] = useState(false);
  const [sidebarOpen, setSidebarOpen] = useState(false);
  const [alertsOpen, setAlertsOpen] = useState(false);

  const liveAlerts = useLiveAlerts();
  const [readIds, setReadIds] = useState<Set<string>>(() => {
    try {
      const saved = localStorage.getItem('widps_read_alerts');
      return saved ? new Set(JSON.parse(saved)) : new Set();
    } catch {
      return new Set();
    }
  });
  const alerts = liveAlerts.map((a) => ({ ...a, read: readIds.has(a.id) }));

  const markRead = (id: string) => {
    setReadIds((prev) => {
      const next = new Set(prev).add(id);
      localStorage.setItem('widps_read_alerts', JSON.stringify([...next].slice(-500)));
      return next;
    });
  };

  const markAllRead = () => {
    const allIds = new Set(liveAlerts.map((a) => a.id));
    setReadIds(allIds);
    localStorage.setItem('widps_read_alerts', JSON.stringify([...allIds].slice(-500)));
  };

  const liveFeed = useLiveFeed();
  const unread = alerts.filter((a) => !a.read).length;
  const hasCriticalUnread = alerts.some((a) => !a.read && a.severity === 'Critical');
  const threatLevel: ThreatLevel = hasCriticalUnread ? 'CRITICAL' : unread > 0 ? 'MEDIUM' : 'LOW';

  const ActivePage = PAGES[page];

  const handleNavigate = (key: PageKey) => {
    navigate(key);
    setSidebarOpen(false);
  };

  return (
    <div className="flex min-h-screen bg-[var(--color-bg)] ops-grid-bg">
      {sidebarOpen && (
        <div className="fixed inset-0 bg-black/50 z-30 lg:hidden" onClick={() => setSidebarOpen(false)} />
      )}

      <div className={`fixed lg:relative z-40 lg:z-0 transition-transform duration-300 lg:translate-x-0 ${
        sidebarOpen ? 'translate-x-0' : '-translate-x-full lg:translate-x-0'
      }`} data-hide-print>
        <Sidebar active={page} onNavigate={handleNavigate} collapsed={collapsed} onToggleCollapsed={() => setCollapsed((c) => !c)} />
      </div>

      <div className="flex-1 flex flex-col min-w-0">
        <TopBar
          threatLevel={threatLevel}
          unreadAlerts={unread}
          onOpenAlerts={() => setAlertsOpen(true)}
          onOpenSettings={() => handleNavigate('settings')}
          onToggleSidebar={() => setSidebarOpen((o) => !o)}
          theme={theme}
          onToggleTheme={toggleTheme}
        />

        <main className="flex-1 p-4 sm:p-6 lg:p-8 pb-20 max-w-[1600px] w-full mx-auto">
          <AnimatePresence mode="popLayout">
            <motion.div
              key={page}
              initial={{ opacity: 0 }}
              animate={{ opacity: 1 }}
              exit={{ opacity: 0 }}
              transition={{ duration: 0.12 }}
            >
              <ErrorBoundary>
                <ActivePage />
              </ErrorBoundary>
            </motion.div>
          </AnimatePresence>
        </main>
      </div>

      <div data-hide-print>
        <LiveAttackFeed items={liveFeed} />
      </div>

      <AlertCenter
        open={alertsOpen}
        onClose={() => setAlertsOpen(false)}
        alerts={alerts}
        onMarkRead={markRead}
        onMarkAllRead={markAllRead}
      />
    </div>
  );
}

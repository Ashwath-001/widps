import React, { useState } from 'react';
import { AnimatePresence, motion } from 'framer-motion';
import Sidebar from './components/layout/Sidebar';
import TopBar from './components/layout/TopBar';
import LiveAttackFeed from './components/layout/LiveAttackFeed';
import AlertCenter from './components/layout/AlertCenter';
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
import { useLiveFeed, useLiveAlerts } from './hooks/useMockLiveData';
import type { ThreatLevel } from './types';

export type PageKey =
  | 'overview'
  | 'network'
  | 'traffic'
  | 'ai'
  | 'threats'
  | 'log'
  | 'stats'
  | 'topology'
  | 'reports'
  | 'settings';

const PAGES: Record<PageKey, () => React.ReactElement> = {
  overview: Overview,
  network: LiveNetwork,
  traffic: LiveTraffic,
  ai: AIDetection,
  threats: ThreatMap,
  log: EventLog,
  stats: Statistics,
  topology: DeviceTopology,
  reports: Reports,
  settings: SettingsPage,
};

export default function App() {
  const [page, setPage] = useState<PageKey>('overview');
  const [collapsed, setCollapsed] = useState(false);
  const [alertsOpen, setAlertsOpen] = useState(false);

  // Alerts come from the Rust backend's /api/alerts endpoint (polled every
  // 2s). "Read" state is tracked client-side only, keyed by alert id, since
  // the backend doesn't know about read/unread — see useLiveAlerts in
  // hooks/useMockLiveData.ts for the polling logic.
  const liveAlerts = useLiveAlerts();
  const [readIds, setReadIds] = useState<Set<string>>(new Set());
  const alerts = liveAlerts.map((a) => ({ ...a, read: readIds.has(a.id) }));

  const liveFeed = useLiveFeed();
  const unread = alerts.filter((a) => !a.read).length;
  const hasCriticalUnread = alerts.some((a) => !a.read && a.severity === 'Critical');
  const threatLevel: ThreatLevel = hasCriticalUnread ? 'CRITICAL' : unread > 0 ? 'MEDIUM' : 'LOW';

  const ActivePage = PAGES[page];

  return (
    <div className="flex min-h-screen bg-[var(--color-bg)] ops-grid-bg">
      <Sidebar active={page} onNavigate={setPage} collapsed={collapsed} onToggleCollapsed={() => setCollapsed((c) => !c)} />

      <div className="flex-1 flex flex-col min-w-0">
        <TopBar
          threatLevel={threatLevel}
          unreadAlerts={unread}
          onOpenAlerts={() => setAlertsOpen(true)}
          onOpenSettings={() => setPage('settings')}
        />

        <main className="flex-1 p-6 lg:p-8 max-w-[1600px] w-full mx-auto">
          <AnimatePresence mode="wait">
            <motion.div
              key={page}
              initial={{ opacity: 0, y: 8 }}
              animate={{ opacity: 1, y: 0 }}
              exit={{ opacity: 0, y: -8 }}
              transition={{ duration: 0.2 }}
            >
              <ActivePage />
            </motion.div>
          </AnimatePresence>
        </main>
      </div>

      <LiveAttackFeed items={liveFeed} />

      <AlertCenter
        open={alertsOpen}
        onClose={() => setAlertsOpen(false)}
        alerts={alerts}
        onMarkRead={(id) => setReadIds((prev) => new Set(prev).add(id))}
        onMarkAllRead={() => setReadIds(new Set(liveAlerts.map((a) => a.id)))}
      />
    </div>
  );
}
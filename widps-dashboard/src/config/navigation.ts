/**
 * WIDPS Navigation Config — Single Source of Truth
 * ==================================================
 * Add a page here and it automatically appears in:
 *   - Sidebar (grouped with collapsible sections)
 *   - Hash route (obfuscated URL)
 *   - App router (lazy-loaded page component)
 *
 * To add a new page:
 *   1. Create the page component in src/pages/
 *   2. Add an entry here with the correct group
 *   That's it. No other files to touch.
 */

import {
  LayoutDashboard,
  Wifi,
  Activity,
  BrainCircuit,
  Layers,
  Gauge,
  ShieldAlert,
  Shield,
  Bug,
  ScrollText,
  BarChart3,
  Share2,
  Terminal,
  Lock,
  FileBarChart,
  Settings,
} from 'lucide-react';
import type { LucideIcon } from 'lucide-react';

export type PageKey =
  | 'overview'
  | 'network'
  | 'traffic'
  | 'ai'
  | 'shap'
  | 'scoring'
  | 'threats'
  | 'intel'
  | 'honeypot'
  | 'log'
  | 'stats'
  | 'topology'
  | 'logs'
  | 'audit'
  | 'reports'
  | 'settings';

export interface NavItem {
  key: PageKey;
  label: string;
  icon: LucideIcon;
}

export interface NavGroup {
  id: string;
  label: string;
  items: NavItem[];
}

export const NAV_GROUPS: NavGroup[] = [
  {
    id: 'monitor',
    label: 'Monitoring',
    items: [
      { key: 'overview', label: 'Dashboard', icon: LayoutDashboard },
      { key: 'network', label: 'Network', icon: Wifi },
      { key: 'traffic', label: 'Traffic', icon: Activity },
    ],
  },
  {
    id: 'detection',
    label: 'Detection & AI',
    items: [
      { key: 'ai', label: 'AI Engine', icon: BrainCircuit },
      { key: 'shap', label: 'Explainability', icon: Layers },
      { key: 'scoring', label: 'Threat Scores', icon: Gauge },
    ],
  },
  {
    id: 'response',
    label: 'Threat Response',
    items: [
      { key: 'threats', label: 'Threat Map', icon: ShieldAlert },
      { key: 'intel', label: 'Threat Intel', icon: Shield },
      { key: 'honeypot', label: 'Honeypot', icon: Bug },
    ],
  },
  {
    id: 'analysis',
    label: 'Analysis',
    items: [
      { key: 'log', label: 'Event Log', icon: ScrollText },
      { key: 'stats', label: 'Statistics', icon: BarChart3 },
      { key: 'topology', label: 'Topology', icon: Share2 },
    ],
  },
  {
    id: 'system',
    label: 'System',
    items: [
      { key: 'logs', label: 'System Logs', icon: Terminal },
      { key: 'audit', label: 'Security', icon: Lock },
      { key: 'reports', label: 'Reports', icon: FileBarChart },
      { key: 'settings', label: 'Settings', icon: Settings },
    ],
  },
];

// Flat list of all page keys (derived from groups)
export const ALL_PAGE_KEYS: PageKey[] = NAV_GROUPS.flatMap(g => g.items.map(i => i.key));

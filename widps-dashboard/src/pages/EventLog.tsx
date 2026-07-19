import { useMemo, useState } from 'react';
import { Search, Download, ScrollText } from 'lucide-react';
import Card from '../components/common/Card';
import StatusBadge from '../components/common/StatusBadge';
import { useLiveAlerts } from '../hooks/useMockLiveData';
import type { LogEntry } from '../types';

function exportToCsv(logs: LogEntry[]) {
  const headers = ['Time', 'Attack', 'Severity', 'Prediction', 'Confidence', 'Action Taken', 'Status'];
  const rows = logs.map((e) => [e.time, e.attack, e.severity, e.prediction, `${e.confidencePct}%`, e.actionTaken, e.status]);
  const csv = [headers, ...rows].map((r) => r.map((c) => `"${c}"`).join(',')).join('\n');
  const blob = new Blob([csv], { type: 'text/csv;charset=utf-8;' });
  const url = URL.createObjectURL(blob);
  const a = document.createElement('a');
  a.href = url;
  a.download = `widps_event_log_${new Date().toISOString().slice(0, 10)}.csv`;
  a.click();
  URL.revokeObjectURL(url);
}

export default function EventLog() {
  const alerts = useLiveAlerts();
  const [query, setQuery] = useState('');

  const logs: LogEntry[] = useMemo(() => {
    return alerts.map((a, i) => ({
      id: a.id || `log-${i}`,
      time: a.time,
      attack: a.title,
      severity: a.severity,
      prediction: a.detail || a.title,
      confidencePct: a.severity === 'Critical' ? 96 : a.severity === 'High' ? 88 : 72,
      actionTaken: a.severity === 'Critical' ? 'Alert raised' : 'Logged & Flagged',
      status: 'Active',
    }));
  }, [alerts]);

  const filtered = useMemo(() => {
    const q = query.trim().toLowerCase();
    if (!q) return logs;
    return logs.filter(
      (e) =>
        e.attack.toLowerCase().includes(q) ||
        e.prediction.toLowerCase().includes(q) ||
        e.status.toLowerCase().includes(q)
    );
  }, [query, logs]);

  return (
    <div className="space-y-6">
      <div className="flex items-center justify-between flex-wrap gap-3">
        <div>
          <h1 className="text-xl font-semibold">Event Log ({logs.length})</h1>
          <p className="text-sm text-[var(--color-text-secondary)] mt-1">Real-time detection and security alert log.</p>
        </div>
        <div className="flex items-center gap-2">
          <div className="flex items-center gap-2 px-3 py-2 rounded-lg bg-[var(--color-card)] border border-[var(--color-border)] w-64">
            <Search size={14} className="text-[var(--color-text-muted)] shrink-0" />
            <input
              value={query}
              onChange={(e) => setQuery(e.target.value)}
              placeholder="Search event logs..."
              className="bg-transparent text-sm outline-none w-full placeholder:text-[var(--color-text-muted)]"
            />
          </div>
          <button
            onClick={() => exportToCsv(logs)}
            disabled={logs.length === 0}
            className="flex items-center gap-2 px-3 py-2 rounded-lg bg-[var(--color-accent-blue)] text-white text-sm font-medium hover:bg-[var(--color-accent-blue-soft)] transition-colors disabled:opacity-50"
          >
            <Download size={14} />
            Export CSV
          </button>
        </div>
      </div>

      {logs.length === 0 ? (
        <Card className="p-12 text-center" hover={false}>
          <ScrollText size={36} className="mx-auto text-[var(--color-text-muted)] mb-3 opacity-50" />
          <h3 className="text-base font-semibold">No Logged Events Yet</h3>
          <p className="text-xs text-[var(--color-text-muted)] max-w-md mx-auto mt-1 leading-relaxed">
            The detection engine is monitoring frames. When attack anomalies (such as Rogue APs or Deauth floods) are detected, log records will appear here.
          </p>
        </Card>
      ) : (
        <Card className="overflow-x-auto" hover={false} delay={0.05}>
          <table className="w-full text-sm min-w-[820px]">
            <thead>
              <tr className="border-b border-[var(--color-border)] text-left text-xs text-[var(--color-text-secondary)] uppercase tracking-wide">
                <th className="px-4 py-3 font-medium">Time</th>
                <th className="px-4 py-3 font-medium">Attack Event</th>
                <th className="px-4 py-3 font-medium">Severity</th>
                <th className="px-4 py-3 font-medium">Detail / Payload</th>
                <th className="px-4 py-3 font-medium">Confidence</th>
                <th className="px-4 py-3 font-medium">Action Taken</th>
                <th className="px-4 py-3 font-medium">Status</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-[var(--color-border-soft)]">
              {filtered.map((e) => (
                <tr key={e.id} className="hover:bg-white/[0.03] transition-colors">
                  <td className="px-4 py-3 data-mono text-xs text-[var(--color-text-secondary)] whitespace-nowrap">{e.time}</td>
                  <td className="px-4 py-3 font-medium text-[var(--color-text)] whitespace-nowrap">{e.attack}</td>
                  <td className="px-4 py-3">
                    <StatusBadge status={e.severity} />
                  </td>
                  <td className="px-4 py-3 text-xs text-[var(--color-text-secondary)] max-w-xs truncate">{e.prediction}</td>
                  <td className="px-4 py-3 data-mono text-xs">{e.confidencePct}%</td>
                  <td className="px-4 py-3 text-xs text-[var(--color-text-secondary)] whitespace-nowrap">{e.actionTaken}</td>
                  <td className="px-4 py-3">
                    <StatusBadge status={e.status} />
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </Card>
      )}
    </div>
  );
}

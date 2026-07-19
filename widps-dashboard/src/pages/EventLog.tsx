import { useMemo, useState } from 'react';
import { Search, Download } from 'lucide-react';
import Card from '../components/common/Card';
import StatusBadge from '../components/common/StatusBadge';
import { eventLog } from '../data/mockData';

function exportToCsv() {
  const headers = ['Time', 'Attack', 'Severity', 'Prediction', 'Confidence', 'Action Taken', 'Status'];
  const rows = eventLog.map((e) => [e.time, e.attack, e.severity, e.prediction, `${e.confidencePct}%`, e.actionTaken, e.status]);
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
  const [query, setQuery] = useState('');

  const filtered = useMemo(() => {
    const q = query.trim().toLowerCase();
    if (!q) return eventLog;
    return eventLog.filter(
      (e) => e.attack.toLowerCase().includes(q) || e.prediction.toLowerCase().includes(q) || e.status.toLowerCase().includes(q)
    );
  }, [query]);

  return (
    <div className="space-y-6">
      <div className="flex items-center justify-between flex-wrap gap-3">
        <div>
          <h1 className="text-xl font-semibold">Event Log</h1>
          <p className="text-sm text-[var(--color-text-secondary)] mt-1">Full detection history for this session.</p>
        </div>
        <div className="flex items-center gap-2">
          <div className="flex items-center gap-2 px-3 py-2 rounded-lg bg-[var(--color-card)] border border-[var(--color-border)] w-64">
            <Search size={14} className="text-[var(--color-text-muted)] shrink-0" />
            <input
              value={query}
              onChange={(e) => setQuery(e.target.value)}
              placeholder="Search events..."
              className="bg-transparent text-sm outline-none w-full placeholder:text-[var(--color-text-muted)]"
            />
          </div>
          <button
            onClick={exportToCsv}
            className="flex items-center gap-2 px-3 py-2 rounded-lg bg-[var(--color-accent-blue)] text-white text-sm font-medium hover:bg-[var(--color-accent-blue-soft)] transition-colors"
          >
            <Download size={14} />
            Export CSV
          </button>
        </div>
      </div>

      <Card className="overflow-x-auto" hover={false} delay={0.05}>
        <table className="w-full text-sm min-w-[820px]">
          <thead>
            <tr className="border-b border-[var(--color-border)] text-left text-xs text-[var(--color-text-secondary)] uppercase tracking-wide">
              <th className="px-4 py-3 font-medium">Time</th>
              <th className="px-4 py-3 font-medium">Attack</th>
              <th className="px-4 py-3 font-medium">Severity</th>
              <th className="px-4 py-3 font-medium">Prediction</th>
              <th className="px-4 py-3 font-medium">Confidence</th>
              <th className="px-4 py-3 font-medium">Action Taken</th>
              <th className="px-4 py-3 font-medium">Status</th>
            </tr>
          </thead>
          <tbody>
            {filtered.map((e) => (
              <tr key={e.id} className="border-b border-[var(--color-border-soft)] last:border-0 hover:bg-white/[0.03] transition-colors">
                <td className="px-4 py-3 data-mono text-[var(--color-text-secondary)]">{e.time}</td>
                <td className="px-4 py-3 font-medium">{e.attack}</td>
                <td className="px-4 py-3">
                  <StatusBadge status={e.severity} />
                </td>
                <td className="px-4 py-3 text-[var(--color-text-secondary)]">{e.prediction}</td>
                <td className="px-4 py-3 data-mono">{e.confidencePct}%</td>
                <td className="px-4 py-3 text-[var(--color-text-secondary)]">{e.actionTaken}</td>
                <td className="px-4 py-3">
                  <StatusBadge status={e.status} />
                </td>
              </tr>
            ))}
            {filtered.length === 0 && (
              <tr>
                <td colSpan={7} className="px-4 py-10 text-center text-[var(--color-text-muted)] text-sm">
                  No events match "{query}".
                </td>
              </tr>
            )}
          </tbody>
        </table>
      </Card>
    </div>
  );
}

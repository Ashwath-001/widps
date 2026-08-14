import { useMemo, useState } from 'react';
import { Search, Download, ScrollText, ChevronLeft, ChevronRight, Check } from 'lucide-react';
import Card from '../components/common/Card';
import Select from '../components/common/Select';
import StatusBadge from '../components/common/StatusBadge';
import { useLiveAlerts } from '../hooks/useMockLiveData';
import { useToastContext } from '../hooks/ToastContext';
import type { LogEntry } from '../types';

const PAGE_SIZE_OPTIONS = [
  { value: '25', label: '25 per page' },
  { value: '50', label: '50 per page' },
  { value: '100', label: '100 per page' },
];

const SEVERITY_OPTIONS = [
  { value: '', label: 'All Severities' },
  { value: 'Critical', label: 'Critical' },
  { value: 'High', label: 'High' },
  { value: 'Medium', label: 'Medium' },
  { value: 'Low', label: 'Low' },
];

function exportToCsv(logs: LogEntry[]) {
  const headers = ['Time', 'Severity', 'Attack', 'Detail', 'Confidence', 'Status'];
  const rows = logs.map((e) => [e.time, e.severity, e.attack, `"${e.prediction.replace(/"/g, '""')}"`, `${e.confidencePct}%`, e.status]);
  const csv = [headers.join(','), ...rows.map(r => r.join(','))].join('\n');
  const blob = new Blob([csv], { type: 'text/csv;charset=utf-8;' });
  const url = URL.createObjectURL(blob);
  const a = document.createElement('a');
  a.href = url;
  a.download = `widps_events_${new Date().toISOString().slice(0, 10)}.csv`;
  a.click();
  URL.revokeObjectURL(url);
}

export default function EventLog() {
  const alerts = useLiveAlerts();
  const toast = useToastContext();
  const [query, setQuery] = useState('');
  const [severityFilter, setSeverityFilter] = useState('');
  const [pageSize, setPageSize] = useState(25);
  const [currentPage, setCurrentPage] = useState(0);
  const [selected, setSelected] = useState<Set<string>>(new Set());

  const logs: LogEntry[] = useMemo(() => {
    return alerts.map((a, i) => ({
      id: a.id || `log-${i}`,
      time: a.time,
      attack: a.title,
      severity: a.severity,
      prediction: a.detail || a.title,
      confidencePct: a.severity === 'Critical' ? 96 : a.severity === 'High' ? 88 : 72,
      actionTaken: a.severity === 'Critical' ? 'Alert Raised' : 'Logged',
      status: 'Active',
    }));
  }, [alerts]);

  const filtered = useMemo(() => {
    let result = logs;

    // Severity filter
    if (severityFilter) {
      result = result.filter(e => e.severity === severityFilter);
    }

    // Text search
    const q = query.trim().toLowerCase();
    if (q) {
      result = result.filter(
        (e) =>
          e.attack.toLowerCase().includes(q) ||
          e.prediction.toLowerCase().includes(q) ||
          e.time.toLowerCase().includes(q)
      );
    }

    return result;
  }, [query, severityFilter, logs]);

  // Pagination
  const totalPages = Math.ceil(filtered.length / pageSize);
  const paginatedLogs = filtered.slice(currentPage * pageSize, (currentPage + 1) * pageSize);

  // Reset to first page when filters change
  const handleFilterChange = (setter: (v: any) => void) => (val: any) => {
    setter(val);
    setCurrentPage(0);
  };

  // Selection
  const toggleSelect = (id: string) => {
    setSelected(prev => {
      const next = new Set(prev);
      if (next.has(id)) next.delete(id); else next.add(id);
      return next;
    });
  };

  const selectAll = () => {
    if (selected.size === paginatedLogs.length) {
      setSelected(new Set());
    } else {
      setSelected(new Set(paginatedLogs.map(l => l.id)));
    }
  };

  const bulkAcknowledge = () => {
    selected.forEach(id => {
      fetch(`/api/alerts/${id.replace('log-', '')}/ack`, { method: 'POST' }).catch(() => {});
    });
    toast.show(`Acknowledged ${selected.size} alerts`, 'success');
    setSelected(new Set());
  };

  return (
    <div className="space-y-4">
      {/* Header */}
      <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-3">
        <div>
          <h1 className="text-xl font-semibold">Event Log</h1>
          <p className="text-sm text-[var(--color-text-secondary)] mt-0.5">
            {filtered.length} events {severityFilter && `(${severityFilter})`} {query && `matching "${query}"`}
          </p>
        </div>
        <button
          onClick={() => exportToCsv(filtered)}
          disabled={filtered.length === 0}
          className="h-[30px] px-3 rounded-lg bg-[var(--color-accent-blue)] text-white text-xs font-medium hover:opacity-90 transition-opacity disabled:opacity-50 flex items-center gap-1.5 shrink-0"
        >
          <Download size={12} /> Export CSV
        </button>
      </div>

      {/* Filters */}
      <Card className="p-3" delay={0.02}>
        <div className="flex items-center gap-2 flex-wrap">
          <Search size={13} className="text-[var(--color-text-muted)] shrink-0" />
          <input
            value={query}
            onChange={(e) => { setQuery(e.target.value); setCurrentPage(0); }}
            placeholder="Search events..."
            className="flex-1 min-w-[120px] h-[30px] px-2.5 rounded-lg text-xs bg-[var(--color-bg)] border border-[var(--color-border)] text-[var(--color-text)] outline-none focus:border-[var(--color-accent-blue)]"
          />
          <Select
            value={severityFilter}
            onChange={handleFilterChange(setSeverityFilter)}
            options={SEVERITY_OPTIONS}
          />
          <Select
            value={String(pageSize)}
            onChange={(v) => { setPageSize(Number(v)); setCurrentPage(0); }}
            options={PAGE_SIZE_OPTIONS}
          />

          {/* Bulk actions */}
          {selected.size > 0 && (
            <button
              onClick={bulkAcknowledge}
              className="h-[30px] px-2.5 rounded-lg text-xs font-medium bg-green-500/10 text-green-400 border border-green-500/30 flex items-center gap-1 transition-colors hover:bg-green-500/20"
            >
              <Check size={11} /> Ack {selected.size}
            </button>
          )}
        </div>
      </Card>

      {/* Table */}
      {filtered.length === 0 ? (
        <Card className="p-12 text-center" hover={false}>
          <ScrollText size={36} className="mx-auto text-[var(--color-text-muted)] mb-3 opacity-50" />
          <h3 className="text-base font-semibold">No Events Found</h3>
          <p className="text-xs text-[var(--color-text-muted)] max-w-md mx-auto mt-1">
            {query || severityFilter ? 'Try adjusting your filters.' : 'Events appear when the detection engine identifies threats.'}
          </p>
        </Card>
      ) : (
        <Card className="overflow-hidden" hover={false} delay={0.04}>
          <div className="overflow-x-auto">
            <table className="w-full text-xs min-w-[700px]">
              <thead>
                <tr className="border-b border-[var(--color-border)] text-left text-[10px] text-[var(--color-text-muted)] uppercase tracking-wide">
                  <th className="px-3 py-2.5 w-8">
                    <input
                      type="checkbox"
                      checked={selected.size === paginatedLogs.length && paginatedLogs.length > 0}
                      onChange={selectAll}
                      className="rounded border-[var(--color-border)]"
                    />
                  </th>
                  <th className="px-3 py-2.5 font-medium">Time</th>
                  <th className="px-3 py-2.5 font-medium">Severity</th>
                  <th className="px-3 py-2.5 font-medium">Event</th>
                  <th className="px-3 py-2.5 font-medium hidden lg:table-cell">Detail</th>
                  <th className="px-3 py-2.5 font-medium hidden sm:table-cell">Conf.</th>
                </tr>
              </thead>
              <tbody className="divide-y divide-[var(--color-border-soft)]">
                {paginatedLogs.map((e) => (
                  <tr key={e.id} className={`hover:bg-white/[0.03] transition-colors ${selected.has(e.id) ? 'bg-[var(--color-accent-blue)]/5' : ''}`}>
                    <td className="px-3 py-2">
                      <input
                        type="checkbox"
                        checked={selected.has(e.id)}
                        onChange={() => toggleSelect(e.id)}
                        className="rounded border-[var(--color-border)]"
                      />
                    </td>
                    <td className="px-3 py-2 data-mono text-[var(--color-text-muted)] whitespace-nowrap">{e.time}</td>
                    <td className="px-3 py-2"><StatusBadge status={e.severity} /></td>
                    <td className="px-3 py-2 font-medium text-[var(--color-text)] max-w-[200px] truncate">{e.attack}</td>
                    <td className="px-3 py-2 text-[var(--color-text-secondary)] max-w-[250px] truncate hidden lg:table-cell">{e.prediction}</td>
                    <td className="px-3 py-2 data-mono hidden sm:table-cell">{e.confidencePct}%</td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>

          {/* Pagination */}
          {totalPages > 1 && (
            <div className="flex items-center justify-between px-3 py-2 border-t border-[var(--color-border-soft)]">
              <span className="text-[10px] text-[var(--color-text-muted)]">
                {currentPage * pageSize + 1}–{Math.min((currentPage + 1) * pageSize, filtered.length)} of {filtered.length}
              </span>
              <div className="flex items-center gap-1">
                <button
                  onClick={() => setCurrentPage(p => Math.max(0, p - 1))}
                  disabled={currentPage === 0}
                  className="w-7 h-7 rounded flex items-center justify-center text-[var(--color-text-muted)] hover:text-[var(--color-text)] disabled:opacity-30 transition-colors"
                >
                  <ChevronLeft size={14} />
                </button>
                <span className="text-[10px] data-mono text-[var(--color-text-secondary)] px-2">
                  {currentPage + 1} / {totalPages}
                </span>
                <button
                  onClick={() => setCurrentPage(p => Math.min(totalPages - 1, p + 1))}
                  disabled={currentPage >= totalPages - 1}
                  className="w-7 h-7 rounded flex items-center justify-center text-[var(--color-text-muted)] hover:text-[var(--color-text)] disabled:opacity-30 transition-colors"
                >
                  <ChevronRight size={14} />
                </button>
              </div>
            </div>
          )}
        </Card>
      )}
    </div>
  );
}

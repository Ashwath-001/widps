import { useState, useEffect, useCallback } from 'react';
import { Terminal, Filter, RefreshCw, Download } from 'lucide-react';
import Card from '../components/common/Card';
import Select from '../components/common/Select';

interface LogEntry {
  '@timestamp': string;
  level: string;
  service: string;
  message: string;
  fields?: Record<string, unknown>;
  duration_ms?: number;
  host?: string;
  pid?: number;
}

const LEVEL_COLORS: Record<string, string> = {
  TRACE: 'text-gray-500',
  DEBUG: 'text-blue-400',
  INFO: 'text-green-400',
  WARN: 'text-yellow-400',
  ERROR: 'text-red-400',
  FATAL: 'text-red-600 font-bold',
};

const LEVEL_BG: Record<string, string> = {
  TRACE: 'bg-gray-500/10 border-gray-500/20',
  DEBUG: 'bg-blue-500/10 border-blue-500/20',
  INFO: 'bg-green-500/10 border-green-500/20',
  WARN: 'bg-yellow-500/10 border-yellow-500/20',
  ERROR: 'bg-red-500/10 border-red-500/20',
  FATAL: 'bg-red-700/20 border-red-700/30',
};

async function fetchLogs(level?: string, service?: string, limit = 100): Promise<LogEntry[]> {
  const host = typeof window !== 'undefined' && window.location.hostname || 'localhost';
  const candidates = [`http://${host}:8787`, 'http://localhost:8787'];

  const params = new URLSearchParams();
  if (level) params.set('level', level);
  if (service) params.set('service', service);
  params.set('limit', String(limit));

  for (const base of candidates) {
    try {
      const res = await fetch(`${base}/api/logs?${params}`);
      if (res.ok) return res.json();
    } catch { /* next */ }
  }
  return [];
}

async function fetchServices(): Promise<string[]> {
  const host = typeof window !== 'undefined' && window.location.hostname || 'localhost';
  const candidates = [`http://${host}:8787`, 'http://localhost:8787'];
  for (const base of candidates) {
    try {
      const res = await fetch(`${base}/api/logs/services`);
      if (res.ok) return res.json();
    } catch { /* next */ }
  }
  return [];
}

export default function SystemLogs() {
  const [logs, setLogs] = useState<LogEntry[]>([]);
  const [services, setServices] = useState<string[]>([]);
  const [levelFilter, setLevelFilter] = useState<string>('');
  const [serviceFilter, setServiceFilter] = useState<string>('');
  const [limit, setLimit] = useState(100);
  const [loading, setLoading] = useState(false);
  const [autoRefresh, setAutoRefresh] = useState(true);
  const [expanded, setExpanded] = useState<number | null>(null);

  const refresh = useCallback(async () => {
    setLoading(true);
    const [logsData, svcData] = await Promise.all([
      fetchLogs(levelFilter || undefined, serviceFilter || undefined, limit),
      fetchServices(),
    ]);
    setLogs(logsData);
    if (svcData.length > 0) setServices(svcData);
    setLoading(false);
  }, [levelFilter, serviceFilter, limit]);

  useEffect(() => {
    refresh();
  }, [refresh]);

  useEffect(() => {
    if (!autoRefresh) return;
    const id = setInterval(refresh, 3000);
    return () => clearInterval(id);
  }, [autoRefresh, refresh]);

  const exportLogs = () => {
    const content = logs.map(l => JSON.stringify(l)).join('\n');
    const blob = new Blob([content], { type: 'application/x-ndjson' });
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = `widps-logs-${new Date().toISOString().slice(0, 10)}.jsonl`;
    a.click();
    URL.revokeObjectURL(url);
  };

  return (
    <div className="space-y-4">
      <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-3">
        <div>
          <h1 className="text-xl font-semibold flex items-center gap-2">
            <Terminal size={20} className="text-[var(--color-accent-green)]" />
            System Logs
          </h1>
          <p className="text-sm text-[var(--color-text-secondary)] mt-1">
            Structured JSON logs from all WIDPS services (ECS-compatible).
          </p>
        </div>
        <div className="flex items-center gap-2 shrink-0">
          <button
            onClick={() => setAutoRefresh(!autoRefresh)}
            className={`h-[30px] px-3 rounded-lg text-xs font-medium border transition-colors ${
              autoRefresh
                ? 'bg-green-500/10 text-green-400 border-green-500/30'
                : 'bg-[var(--color-card)] text-[var(--color-text-muted)] border-[var(--color-border)]'
            }`}
          >
            {autoRefresh ? 'Live' : 'Paused'}
          </button>
          <button
            onClick={refresh}
            disabled={loading}
            className="h-[30px] w-[30px] rounded-lg border border-[var(--color-border)] flex items-center justify-center text-[var(--color-text-muted)] hover:text-[var(--color-text)] transition-colors"
          >
            <RefreshCw size={13} className={loading ? 'animate-spin' : ''} />
          </button>
          <button
            onClick={exportLogs}
            className="h-[30px] w-[30px] rounded-lg border border-[var(--color-border)] flex items-center justify-center text-[var(--color-text-muted)] hover:text-[var(--color-text)] transition-colors"
          >
            <Download size={13} />
          </button>
        </div>
      </div>

      <Card className="p-3" delay={0.02}>
        <div className="flex items-center gap-2 flex-wrap">
          <Filter size={13} className="text-[var(--color-text-muted)] shrink-0" />

          <Select
            value={levelFilter}
            onChange={setLevelFilter}
            options={[
              { value: '', label: 'All Levels' },
              { value: 'TRACE', label: 'TRACE' },
              { value: 'DEBUG', label: 'DEBUG' },
              { value: 'INFO', label: 'INFO' },
              { value: 'WARN', label: 'WARN' },
              { value: 'ERROR', label: 'ERROR' },
              { value: 'FATAL', label: 'FATAL' },
            ]}
          />

          <Select
            value={serviceFilter}
            onChange={setServiceFilter}
            options={[
              { value: '', label: 'All Services' },
              ...services.map((svc) => ({ value: svc, label: svc })),
            ]}
          />

          <Select
            value={String(limit)}
            onChange={(v) => setLimit(Number(v))}
            options={[
              { value: '50', label: '50 lines' },
              { value: '100', label: '100 lines' },
              { value: '250', label: '250 lines' },
              { value: '500', label: '500 lines' },
            ]}
          />

          <span className="text-[10px] text-[var(--color-text-muted)] ml-auto hidden sm:inline">
            {logs.length} entries
          </span>
        </div>
      </Card>

      {/* Log entries */}
      <Card className="p-0 overflow-hidden" delay={0.04}>
        <div className="max-h-[calc(100vh-280px)] overflow-y-auto overflow-x-auto">
          {logs.length > 0 ? (
            <div className="divide-y divide-[var(--color-border-soft)]">
              {logs.map((entry, i) => {
                const ts = entry['@timestamp'] || '';
                const timeOnly = ts.includes('T') ? ts.split('T')[1]?.slice(0, 12) : ts;
                const levelCls = LEVEL_COLORS[entry.level] || 'text-[var(--color-text)]';
                const bgCls = LEVEL_BG[entry.level] || '';
                const hasFields = entry.fields && Object.keys(entry.fields).length > 0;
                const isExpanded = expanded === i;

                return (
                  <div
                    key={i}
                    className={`px-3 py-2 hover:bg-[var(--color-bg)] transition-colors cursor-pointer ${
                      entry.level === 'ERROR' || entry.level === 'FATAL' ? 'bg-red-500/5' : ''
                    }`}
                    onClick={() => setExpanded(isExpanded ? null : i)}
                  >
                    <div className="flex items-center gap-2 text-[11px] font-mono min-w-0">
                      <span className="text-[var(--color-text-muted)] shrink-0 w-20 sm:w-24">
                        {timeOnly}
                      </span>
                      <span className={`px-1.5 py-0.5 rounded border text-[9px] font-bold shrink-0 w-11 text-center ${bgCls} ${levelCls}`}>
                        {entry.level}
                      </span>
                      <span className="text-[var(--color-accent-blue)] shrink-0 w-16 sm:w-24 truncate">
                        {entry.service}
                      </span>
                      <span className="text-[var(--color-text-secondary)] truncate flex-1 min-w-0">
                        {entry.message}
                      </span>
                      {entry.duration_ms !== undefined && (
                        <span className="text-[var(--color-accent-warning)] shrink-0 text-[10px]">
                          {entry.duration_ms.toFixed(1)}ms
                        </span>
                      )}
                    </div>

                    {/* Expanded fields */}
                    {isExpanded && hasFields && (
                      <div className="mt-2 ml-24 sm:ml-28 p-2 rounded bg-[var(--color-bg)] border border-[var(--color-border-soft)] text-[10px] font-mono">
                        {Object.entries(entry.fields!).map(([k, v]) => (
                          <div key={k} className="flex gap-2">
                            <span className="text-[var(--color-accent-blue)]">{k}:</span>
                            <span className="text-[var(--color-text-secondary)]">{JSON.stringify(v)}</span>
                          </div>
                        ))}
                      </div>
                    )}
                  </div>
                );
              })}
            </div>
          ) : (
            <div className="p-8 text-center">
              <Terminal size={32} className="mx-auto text-[var(--color-text-muted)] mb-2" />
              <p className="text-sm text-[var(--color-text-secondary)]">No log entries</p>
              <p className="text-xs text-[var(--color-text-muted)] mt-1">
                Logs appear when the backend starts capturing frames.
              </p>
            </div>
          )}
        </div>
      </Card>
    </div>
  );
}

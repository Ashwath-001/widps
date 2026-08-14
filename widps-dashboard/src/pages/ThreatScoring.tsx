import { useState, useEffect } from 'react';
import { Shield, Clock, Link2 } from 'lucide-react';
import Card from '../components/common/Card';

interface Evidence {
  source: string;
  weight: number;
  description: string;
  timestamp: string;
}

interface ThreatProfile {
  bssid: string;
  ssid: string | null;
  score: number;
  cvss_severity: string;
  cvss_score: number;
  evidence: Evidence[];
  first_seen: string;
  last_updated: string;
  alert_count: number;
  verdict: string;
  correlation_active: boolean;
  distinct_sources: string[];
  attack_vector: string;
}

async function fetchThreats(): Promise<ThreatProfile[]> {
  try {
    const res = await fetch('/api/threats');
    if (res.ok) return res.json();
  } catch { /* fallback */ }
  const host = typeof window !== 'undefined' && window.location.hostname || 'localhost';
  const candidates = [`http://${host}:8787`, 'http://localhost:8787'];
  for (const base of candidates) {
    try {
      const res = await fetch(`${base}/api/threats`);
      if (res.ok) return res.json();
    } catch { /* next */ }
  }
  return [];
}

function severityColor(severity: string): string {
  switch (severity) {
    case 'CRITICAL': return 'text-red-400 bg-red-500/10 border-red-500/30';
    case 'HIGH': return 'text-orange-400 bg-orange-500/10 border-orange-500/30';
    case 'MEDIUM': return 'text-yellow-400 bg-yellow-500/10 border-yellow-500/30';
    case 'LOW': return 'text-blue-400 bg-blue-500/10 border-blue-500/30';
    default: return 'text-gray-400 bg-gray-500/10 border-gray-500/30';
  }
}

export default function ThreatScoring() {
  const [threats, setThreats] = useState<ThreatProfile[]>([]);
  const [expanded, setExpanded] = useState<string | null>(null);
  const [cvssFilter, setCvssFilter] = useState('');

  useEffect(() => {
    let cancelled = false;
    const poll = async () => {
      const data = await fetchThreats();
      if (!cancelled) setThreats(data.sort((a, b) => b.score - a.score));
      if (!cancelled) setTimeout(poll, 3000);
    };
    poll();
    return () => { cancelled = true; };
  }, []);

  let filtered = threats;
  if (cvssFilter) {
    filtered = threats.filter(t => t.cvss_severity === cvssFilter);
  }

  const critical = threats.filter(t => t.cvss_severity === 'CRITICAL').length;
  const high = threats.filter(t => t.cvss_severity === 'HIGH').length;
  const correlated = threats.filter(t => t.correlation_active).length;

  return (
    <div className="space-y-6">
      <div>
        <h1 className="text-xl font-semibold flex items-center gap-2">
          <Shield size={20} className="text-[var(--color-accent-danger)]" />
          Composite Threat Scoring
        </h1>
        <p className="text-sm text-[var(--color-text-secondary)] mt-1">
          Multi-factor evidence accumulation with CVSS-inspired severity mapping and temporal decay.
        </p>
      </div>

      {/* Summary stats */}
      <div className="grid grid-cols-2 sm:grid-cols-5 gap-3">
        <Card className="p-3 text-center" delay={0.02}>
          <p className="text-2xl font-bold data-mono">{threats.length}</p>
          <p className="text-[10px] text-[var(--color-text-muted)] uppercase mt-1">Active Profiles</p>
        </Card>
        <Card className="p-3 text-center" delay={0.04}>
          <p className="text-2xl font-bold data-mono text-red-400">{critical}</p>
          <p className="text-[10px] text-[var(--color-text-muted)] uppercase mt-1">Critical</p>
        </Card>
        <Card className="p-3 text-center" delay={0.06}>
          <p className="text-2xl font-bold data-mono text-orange-400">{high}</p>
          <p className="text-[10px] text-[var(--color-text-muted)] uppercase mt-1">High</p>
        </Card>
        <Card className="p-3 text-center" delay={0.08}>
          <p className="text-2xl font-bold data-mono text-[var(--color-accent-blue)]">{correlated}</p>
          <p className="text-[10px] text-[var(--color-text-muted)] uppercase mt-1">Correlated</p>
        </Card>
        <Card className="p-3 text-center" delay={0.10}>
          <p className="text-2xl font-bold data-mono">
            {threats.length > 0 ? (threats.reduce((s, t) => s + t.score, 0) / threats.length).toFixed(0) : '0'}
          </p>
          <p className="text-[10px] text-[var(--color-text-muted)] uppercase mt-1">Avg Score</p>
        </Card>
      </div>

      {/* Filter */}
      <div className="flex items-center gap-2 flex-wrap">
        <span className="text-[10px] text-[var(--color-text-muted)]">Filter:</span>
        {['', 'CRITICAL', 'HIGH', 'MEDIUM', 'LOW'].map(level => (
          <button
            key={level}
            onClick={() => setCvssFilter(level)}
            className={`h-[26px] px-2 rounded text-[10px] font-medium border transition-colors ${
              cvssFilter === level
                ? 'bg-[var(--color-accent-blue)]/10 text-[var(--color-accent-blue)] border-[var(--color-accent-blue)]/30'
                : 'border-[var(--color-border)] text-[var(--color-text-muted)] hover:text-[var(--color-text)]'
            }`}
          >
            {level || 'All'}
          </button>
        ))}
        <span className="text-[10px] text-[var(--color-text-muted)] ml-auto">{filtered.length} profiles</span>
      </div>

      {/* Threat profiles */}
      {filtered.length > 0 ? (
        <div className="space-y-3">
          {filtered.map((t) => (
            <Card key={t.bssid} className="p-0 overflow-hidden" delay={0.12}>
              {/* Header row */}
              <div className="p-4 cursor-pointer hover:bg-[var(--color-bg)] transition-colors"
                onClick={() => setExpanded(expanded === t.bssid ? null : t.bssid)}
              >
                <div className="flex flex-col sm:flex-row items-start sm:items-center gap-4">
                  {/* Score gauge */}
                  <div className="relative w-14 h-14 shrink-0">
                    <svg className="w-14 h-14 -rotate-90" viewBox="0 0 56 56">
                      <circle cx="28" cy="28" r="24" fill="none" stroke="var(--color-border)" strokeWidth="4" />
                      <circle
                        cx="28" cy="28" r="24" fill="none"
                        stroke={t.score >= 85 ? '#EF4444' : t.score >= 60 ? '#F97316' : t.score >= 30 ? '#EAB308' : '#3B82F6'}
                        strokeWidth="4"
                        strokeDasharray={`${(t.score / 100) * 151} 151`}
                        strokeLinecap="round"
                      />
                    </svg>
                    <span className="absolute inset-0 flex items-center justify-center text-xs font-bold data-mono">
                      {t.score.toFixed(0)}
                    </span>
                  </div>

                  {/* Info */}
                  <div className="flex-1 min-w-0">
                    <div className="flex items-center gap-2 flex-wrap">
                      <p className="text-sm font-medium truncate">{t.ssid || '<Unknown>'}</p>
                      {t.correlation_active && (
                        <span className="px-1.5 py-0.5 rounded text-[9px] font-medium bg-purple-500/10 text-purple-400 border border-purple-500/30 flex items-center gap-0.5">
                          <Link2 size={8} /> CORRELATED
                        </span>
                      )}
                    </div>
                    <p className="text-xs data-mono text-[var(--color-accent-blue)]">{t.bssid}</p>
                    <p className="text-[10px] text-[var(--color-text-muted)] mt-0.5">
                      Vector: {t.attack_vector} • Alerts: {t.alert_count} • Since: {t.first_seen}
                    </p>
                  </div>

                  {/* CVSS badge */}
                  <div className="sm:text-right shrink-0">
                    <span className={`px-2 py-1 rounded text-[10px] font-bold border ${severityColor(t.cvss_severity)}`}>
                      CVSS {t.cvss_score.toFixed(1)} - {t.cvss_severity}
                    </span>
                    <p className="text-[10px] text-[var(--color-text-muted)] mt-1">{t.verdict}</p>
                  </div>
                </div>

                {/* Source tags */}
                {t.distinct_sources.length > 0 && (
                  <div className="flex gap-1 mt-2 flex-wrap">
                    {t.distinct_sources.map((src, i) => (
                      <span key={i} className="px-1.5 py-0.5 rounded text-[9px] bg-[var(--color-bg)] border border-[var(--color-border-soft)] text-[var(--color-text-muted)]">
                        {src}
                      </span>
                    ))}
                  </div>
                )}
              </div>

              {/* Expanded evidence timeline */}
              {expanded === t.bssid && (
                <div className="border-t border-[var(--color-border-soft)] p-4 bg-[var(--color-bg)]">
                  <h4 className="text-xs font-semibold mb-3 flex items-center gap-1">
                    <Clock size={12} /> Evidence Timeline ({t.evidence.length} entries)
                  </h4>
                  <div className="space-y-2 max-h-64 overflow-y-auto">
                    {t.evidence.map((ev, i) => (
                      <div key={i} className="flex flex-wrap sm:flex-nowrap items-start gap-2 sm:gap-3 text-[11px]">
                        <span className="text-[var(--color-text-muted)] data-mono shrink-0 w-14">{ev.timestamp}</span>
                        <span className="px-1.5 py-0.5 rounded bg-[var(--color-card)] text-[10px] font-medium shrink-0">
                          {ev.source}
                        </span>
                        <span className="flex-1 text-[var(--color-text-secondary)] min-w-0 break-words">{ev.description}</span>
                        <span className="text-[var(--color-accent-warning)] data-mono shrink-0">
                          +{ev.weight.toFixed(0)}
                        </span>
                      </div>
                    ))}
                  </div>
                </div>
              )}
            </Card>
          ))}
        </div>
      ) : (
        <Card className="p-8 text-center" delay={0.12}>
          <Shield size={40} className="mx-auto text-[var(--color-text-muted)] mb-3" />
          <p className="text-sm text-[var(--color-text-secondary)]">No active threat profiles</p>
          <p className="text-xs text-[var(--color-text-muted)] mt-1">
            Profiles are created when detectors or ML identify suspicious BSSIDs. Scores decay over time.
          </p>
        </Card>
      )}
    </div>
  );
}

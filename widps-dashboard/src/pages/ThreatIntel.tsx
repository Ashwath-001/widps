import { useState, useEffect } from 'react';
import { Shield, Eye, Ban, RotateCcw, Download, Search } from 'lucide-react';
import Card from '../components/common/Card';
import Select from '../components/common/Select';
import { useToastContext } from '../hooks/ToastContext';

interface DeviceEnrichment {
  vendor: string;
  is_attack_hardware: boolean;
  attack_hardware_type: string | null;
  is_locally_administered: boolean;
  ssid_suspicion_reasons: string[];
  similar_to_known_ssids: [string, number][];
  first_seen: string;
  days_on_network: number;
  total_observations: number;
  consistency_score: number;
}

interface ReputationEvent {
  timestamp: string;
  delta: number;
  reason: string;
  source: string;
}

interface DeviceIntel {
  mac: string;
  ssid: string | null;
  reputation_score: number;
  reputation_level: string;
  enrichment: DeviceEnrichment;
  ioc_matches: string[];
  admin_action: { action: string; timestamp: string; reason: string | null } | null;
  last_updated: string;
  history: ReputationEvent[];
}

interface IntelStats {
  total_devices: number;
  trusted: number;
  known: number;
  unknown: number;
  watchlist: number;
  threat: number;
  ioc_hits: number;
}

interface IntelData {
  stats: IntelStats;
  devices: DeviceIntel[];
}

async function fetchIntel(): Promise<IntelData | null> {
  try {
    const res = await fetch('/api/intel');
    if (res.ok) return res.json();
  } catch {}
  return null;
}

function levelColor(level: string): string {
  switch (level) {
    case 'TRUSTED': return 'text-green-400 bg-green-500/10 border-green-500/30';
    case 'KNOWN': return 'text-blue-400 bg-blue-500/10 border-blue-500/30';
    case 'UNKNOWN': return 'text-gray-400 bg-gray-500/10 border-gray-500/30';
    case 'WATCHLIST': return 'text-yellow-400 bg-yellow-500/10 border-yellow-500/30';
    case 'THREAT': return 'text-red-400 bg-red-500/10 border-red-500/30';
    default: return 'text-gray-400 bg-gray-500/10 border-gray-500/30';
  }
}

function repBar(score: number): { width: string; color: string } {
  const normalized = (score + 100) / 200; // -100..+100 → 0..1
  const width = `${Math.max(2, normalized * 100)}%`;
  const color = score > 50 ? '#22C55E' : score > 20 ? '#3B82F6' : score >= -20 ? '#6B7280' : score >= -50 ? '#EAB308' : '#EF4444';
  return { width, color };
}

export default function ThreatIntel() {
  const [data, setData] = useState<IntelData | null>(null);
  const [levelFilter, setLevelFilter] = useState('');
  const [expanded, setExpanded] = useState<string | null>(null);
  const [search, setSearch] = useState('');
  const toast = useToastContext();

  useEffect(() => {
    let cancelled = false;
    const poll = async () => {
      const d = await fetchIntel();
      if (!cancelled && d) setData(d);
      if (!cancelled) setTimeout(poll, 5000);
    };
    poll();
    return () => { cancelled = true; };
  }, []);

  const adminAction = (mac: string, action: string) => {
    const reason = prompt(`Reason for ${action}ing ${mac}:`);
    if (reason === null) return;

    fetch(`/api/intel/${mac.replace(/:/g, '-')}/${action}`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ reason }),
    })
      .then((r) => { if (r.ok) toast.show(`${mac} ${action}ed`, 'success'); })
      .catch(() => toast.show('Action failed', 'error'));
  };

  const exportFeed = () => {
    window.open('/api/intel/feed', '_blank');
    toast.show('STIX feed exported', 'success');
  };

  const stats = data?.stats;
  let devices = data?.devices || [];

  // Apply filters
  if (levelFilter) {
    devices = devices.filter(d => d.reputation_level === levelFilter);
  }
  if (search) {
    const q = search.toLowerCase();
    devices = devices.filter(d =>
      d.mac.toLowerCase().includes(q) ||
      (d.ssid && d.ssid.toLowerCase().includes(q)) ||
      d.enrichment.vendor.toLowerCase().includes(q)
    );
  }

  // Sort by reputation (most dangerous first)
  devices.sort((a, b) => a.reputation_score - b.reputation_score);

  return (
    <div className="space-y-4">
      <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-3">
        <div>
          <h1 className="text-xl font-semibold flex items-center gap-2">
            <Shield size={20} className="text-[var(--color-accent-blue)]" />
            Threat Intelligence
          </h1>
          <p className="text-sm text-[var(--color-text-secondary)] mt-1">
            Device reputation scoring, IoC matching, and policy enforcement.
          </p>
        </div>
        <button onClick={exportFeed} className="h-[30px] px-3 rounded-lg text-xs font-medium border border-[var(--color-border)] text-[var(--color-text-muted)] hover:text-[var(--color-text)] flex items-center gap-1.5 shrink-0 transition-colors">
          <Download size={12} /> STIX Export
        </button>
      </div>

      {/* Stats */}
      {stats && (
        <div className="grid grid-cols-3 sm:grid-cols-7 gap-2">
          <Card className="p-2.5 text-center" delay={0.02}>
            <p className="text-lg font-bold data-mono">{stats.total_devices}</p>
            <p className="text-[9px] text-[var(--color-text-muted)] uppercase">Total</p>
          </Card>
          <Card className="p-2.5 text-center" delay={0.03}>
            <p className="text-lg font-bold data-mono text-green-400">{stats.trusted}</p>
            <p className="text-[9px] text-[var(--color-text-muted)] uppercase">Trusted</p>
          </Card>
          <Card className="p-2.5 text-center" delay={0.04}>
            <p className="text-lg font-bold data-mono text-blue-400">{stats.known}</p>
            <p className="text-[9px] text-[var(--color-text-muted)] uppercase">Known</p>
          </Card>
          <Card className="p-2.5 text-center" delay={0.05}>
            <p className="text-lg font-bold data-mono">{stats.unknown}</p>
            <p className="text-[9px] text-[var(--color-text-muted)] uppercase">Unknown</p>
          </Card>
          <Card className="p-2.5 text-center" delay={0.06}>
            <p className="text-lg font-bold data-mono text-yellow-400">{stats.watchlist}</p>
            <p className="text-[9px] text-[var(--color-text-muted)] uppercase">Watch</p>
          </Card>
          <Card className="p-2.5 text-center" delay={0.07}>
            <p className="text-lg font-bold data-mono text-red-400">{stats.threat}</p>
            <p className="text-[9px] text-[var(--color-text-muted)] uppercase">Threat</p>
          </Card>
          <Card className="p-2.5 text-center" delay={0.08}>
            <p className="text-lg font-bold data-mono text-[var(--color-accent-warning)]">{stats.ioc_hits}</p>
            <p className="text-[9px] text-[var(--color-text-muted)] uppercase">IoC Hits</p>
          </Card>
        </div>
      )}

      {/* Filters */}
      <Card className="p-3" delay={0.10}>
        <div className="flex items-center gap-2 flex-wrap">
          <Search size={13} className="text-[var(--color-text-muted)] shrink-0" />
          <input
            type="text"
            value={search}
            onChange={(e) => setSearch(e.target.value)}
            placeholder="Search MAC, SSID, vendor..."
            className="flex-1 min-w-[140px] h-[30px] px-2.5 rounded-lg text-xs bg-[var(--color-bg)] border border-[var(--color-border)] text-[var(--color-text)] outline-none focus:border-[var(--color-accent-blue)]"
          />
          <Select
            value={levelFilter}
            onChange={setLevelFilter}
            options={[
              { value: '', label: 'All Levels' },
              { value: 'TRUSTED', label: 'Trusted' },
              { value: 'KNOWN', label: 'Known' },
              { value: 'UNKNOWN', label: 'Unknown' },
              { value: 'WATCHLIST', label: 'Watchlist' },
              { value: 'THREAT', label: 'Threat' },
            ]}
          />
          <span className="text-[10px] text-[var(--color-text-muted)] ml-auto hidden sm:inline">
            {devices.length} devices
          </span>
        </div>
      </Card>

      {/* Device list */}
      <div className="space-y-2">
        {devices.slice(0, 50).map((d) => {
          const bar = repBar(d.reputation_score);
          const isExpanded = expanded === d.mac;

          return (
            <Card key={d.mac} className="p-0 overflow-hidden" delay={0.12}>
              <div
                className="p-3 cursor-pointer hover:bg-[var(--color-bg)] transition-colors"
                onClick={() => setExpanded(isExpanded ? null : d.mac)}
              >
                <div className="flex flex-col sm:flex-row sm:items-center gap-2 sm:gap-4">
                  {/* Reputation bar + score */}
                  <div className="flex items-center gap-2 min-w-0 flex-1">
                    <div className="w-16 h-2 rounded-full bg-[var(--color-border)] overflow-hidden shrink-0">
                      <div className="h-full rounded-full" style={{ width: bar.width, backgroundColor: bar.color }} />
                    </div>
                    <span className="text-xs data-mono w-8 shrink-0" style={{ color: bar.color }}>
                      {d.reputation_score > 0 ? '+' : ''}{d.reputation_score}
                    </span>
                    <span className={`px-1.5 py-0.5 rounded text-[9px] font-bold border shrink-0 ${levelColor(d.reputation_level)}`}>
                      {d.reputation_level}
                    </span>
                  </div>

                  {/* Device info */}
                  <div className="flex-1 min-w-0">
                    <p className="text-xs font-mono truncate">{d.mac}</p>
                    <p className="text-[10px] text-[var(--color-text-muted)] truncate">
                      {d.ssid || '-'} • {d.enrichment.vendor || 'Unknown vendor'} • {d.enrichment.total_observations} obs
                    </p>
                  </div>

                  {/* IoC indicators */}
                  <div className="flex items-center gap-1 shrink-0 flex-wrap">
                    {d.enrichment.is_attack_hardware && (
                      <span className="px-1.5 py-0.5 rounded text-[8px] font-bold bg-red-500/20 text-red-400 border border-red-500/30">HW</span>
                    )}
                    {d.enrichment.is_locally_administered && (
                      <span className="px-1.5 py-0.5 rounded text-[8px] font-bold bg-yellow-500/20 text-yellow-400 border border-yellow-500/30">RND</span>
                    )}
                    {d.ioc_matches.length > 0 && (
                      <span className="px-1.5 py-0.5 rounded text-[8px] font-bold bg-orange-500/20 text-orange-400 border border-orange-500/30">
                        {d.ioc_matches.length} IoC
                      </span>
                    )}
                  </div>
                </div>
              </div>

              {/* Expanded detail */}
              {isExpanded && (
                <div className="border-t border-[var(--color-border-soft)] p-3 bg-[var(--color-bg)] space-y-3">
                  {/* Enrichment */}
                  <div className="grid grid-cols-2 sm:grid-cols-4 gap-2 text-[10px]">
                    <div>
                      <span className="text-[var(--color-text-muted)]">Vendor</span>
                      <p className="font-medium">{d.enrichment.vendor || 'Unknown'}</p>
                    </div>
                    <div>
                      <span className="text-[var(--color-text-muted)]">First Seen</span>
                      <p className="font-medium">{d.enrichment.first_seen}</p>
                    </div>
                    <div>
                      <span className="text-[var(--color-text-muted)]">Days Active</span>
                      <p className="font-medium">{d.enrichment.days_on_network.toFixed(1)}</p>
                    </div>
                    <div>
                      <span className="text-[var(--color-text-muted)]">Consistency</span>
                      <p className="font-medium">{(d.enrichment.consistency_score * 100).toFixed(0)}%</p>
                    </div>
                  </div>

                  {/* IoC matches */}
                  {d.ioc_matches.length > 0 && (
                    <div>
                      <p className="text-[10px] text-[var(--color-text-muted)] uppercase mb-1">IoC Matches</p>
                      <div className="space-y-0.5">
                        {d.ioc_matches.map((ioc, i) => (
                          <p key={i} className="text-[10px] text-[var(--color-accent-warning)] pl-2 border-l-2 border-yellow-500/30">{ioc}</p>
                        ))}
                      </div>
                    </div>
                  )}

                  {/* Reputation history */}
                  {d.history.length > 0 && (
                    <div>
                      <p className="text-[10px] text-[var(--color-text-muted)] uppercase mb-1">Reputation History</p>
                      <div className="space-y-0.5 max-h-32 overflow-y-auto">
                        {d.history.slice(-10).map((ev, i) => (
                          <div key={i} className="flex items-center gap-2 text-[10px]">
                            <span className="text-[var(--color-text-muted)] w-12 shrink-0">{ev.timestamp}</span>
                            <span className={`w-8 shrink-0 font-mono text-right ${ev.delta > 0 ? 'text-green-400' : 'text-red-400'}`}>
                              {ev.delta > 0 ? '+' : ''}{ev.delta}
                            </span>
                            <span className="px-1 py-0.5 rounded bg-[var(--color-card)] text-[8px] shrink-0">{ev.source}</span>
                            <span className="text-[var(--color-text-secondary)] truncate">{ev.reason}</span>
                          </div>
                        ))}
                      </div>
                    </div>
                  )}

                  {/* Admin actions */}
                  <div className="flex items-center gap-2 pt-2 border-t border-[var(--color-border-soft)] flex-wrap">
                    <button
                      onClick={(e) => { e.stopPropagation(); adminAction(d.mac, 'whitelist'); }}
                      className="h-[26px] px-2.5 rounded text-[10px] font-medium border border-green-500/30 text-green-400 hover:bg-green-500/10 flex items-center gap-1 transition-colors"
                    >
                      <Eye size={10} /> Trust
                    </button>
                    <button
                      onClick={(e) => { e.stopPropagation(); adminAction(d.mac, 'blacklist'); }}
                      className="h-[26px] px-2.5 rounded text-[10px] font-medium border border-red-500/30 text-red-400 hover:bg-red-500/10 flex items-center gap-1 transition-colors"
                    >
                      <Ban size={10} /> Blacklist
                    </button>
                    <button
                      onClick={(e) => { e.stopPropagation(); adminAction(d.mac, 'reset'); }}
                      className="h-[26px] px-2.5 rounded text-[10px] font-medium border border-[var(--color-border)] text-[var(--color-text-muted)] hover:bg-[var(--color-card)] flex items-center gap-1 transition-colors"
                    >
                      <RotateCcw size={10} /> Reset
                    </button>
                    {d.admin_action && (
                      <span className="text-[9px] text-[var(--color-text-muted)] ml-auto">
                        Last action: {d.admin_action.action} ({d.admin_action.timestamp})
                      </span>
                    )}
                  </div>
                </div>
              )}
            </Card>
          );
        })}

        {devices.length === 0 && (
          <Card className="p-8 text-center" delay={0.12}>
            <Shield size={36} className="mx-auto text-[var(--color-text-muted)] mb-2" />
            <p className="text-sm text-[var(--color-text-secondary)]">No devices in intelligence database</p>
            <p className="text-xs text-[var(--color-text-muted)] mt-1">
              Devices appear as the sensor captures wireless frames.
            </p>
          </Card>
        )}
      </div>
    </div>
  );
}

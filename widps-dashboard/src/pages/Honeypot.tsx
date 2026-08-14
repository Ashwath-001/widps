import { useState, useEffect } from 'react';
import { Bug, Wifi, ShieldAlert, Activity, Radio, Link2 } from 'lucide-react';
import Card from '../components/common/Card';

interface HoneypotStats {
  total_connections: number;
  confirmed_attackers: number;
  dynamic_ssid_catches: number;
  active_dynamic_ssids: number;
  tracked_unserved_ssids: number;
  correlated_rogue_operators: number;
  correlated_deauth_sources: number;
}

interface Correlation {
  mac_address: string;
  confirmation_type: string;
  confidence_weight: number;
  evidence_chain: string[];
  timestamp: string;
  related_bssid: string | null;
}

interface HoneypotConnection {
  mac_address: string;
  ip_address: string;
  hostname: string | null;
  connected_ssid: string;
  timestamp: string;
  is_dynamic_ssid: boolean;
  correlation: Correlation | null;
  dns_queries: string[];
}

type PendingDynamic = [string, number];

interface HoneypotData {
  stats: HoneypotStats | null;
  connections: HoneypotConnection[];
  pending_dynamic_ssids: PendingDynamic[];
}

async function fetchHoneypot(): Promise<HoneypotData | null> {
  const host = typeof window !== 'undefined' && window.location.hostname || 'localhost';
  const candidates = [`http://${host}:8787`, 'http://localhost:8787'];
  for (const base of candidates) {
    try {
      const res = await fetch(`${base}/api/honeypot/status`);
      if (res.ok) return res.json();
    } catch { /* next */ }
  }
  return null;
}

export default function Honeypot() {
  const [data, setData] = useState<HoneypotData | null>(null);

  useEffect(() => {
    let cancelled = false;
    const poll = async () => {
      const d = await fetchHoneypot();
      if (!cancelled && d) setData(d);
      if (!cancelled) setTimeout(poll, 5000);
    };
    poll();
    return () => { cancelled = true; };
  }, []);

  const stats = data?.stats;
  const connections = data?.connections || [];
  const pending = data?.pending_dynamic_ssids || [];
  const confirmed = connections.filter(c => c.correlation !== null);
  const uncorrelated = connections.filter(c => c.correlation === null);

  return (
    <div className="space-y-6">
      <div>
        <h1 className="text-xl font-semibold flex items-center gap-2">
          <Bug size={20} className="text-[var(--color-accent-warning)]" />
          Honeypot Deception System
        </h1>
        <p className="text-sm text-[var(--color-text-secondary)] mt-1">
          Dynamic false-positive elimination via attacker confirmation traps.
        </p>
      </div>

      {/* Stats Grid */}
      <div className="grid grid-cols-2 sm:grid-cols-4 lg:grid-cols-7 gap-3">
        <Card className="p-3 text-center" delay={0.02}>
          <p className="text-2xl font-bold data-mono">{stats?.total_connections ?? 0}</p>
          <p className="text-[10px] text-[var(--color-text-muted)] uppercase mt-1">Total Connections</p>
        </Card>
        <Card className="p-3 text-center" delay={0.04}>
          <p className="text-2xl font-bold data-mono text-[var(--color-accent-danger)]">{stats?.confirmed_attackers ?? 0}</p>
          <p className="text-[10px] text-[var(--color-text-muted)] uppercase mt-1">Confirmed Attackers</p>
        </Card>
        <Card className="p-3 text-center" delay={0.06}>
          <p className="text-2xl font-bold data-mono text-[var(--color-accent-warning)]">{stats?.dynamic_ssid_catches ?? 0}</p>
          <p className="text-[10px] text-[var(--color-text-muted)] uppercase mt-1">Dynamic Catches</p>
        </Card>
        <Card className="p-3 text-center" delay={0.08}>
          <p className="text-2xl font-bold data-mono">{stats?.active_dynamic_ssids ?? 0}</p>
          <p className="text-[10px] text-[var(--color-text-muted)] uppercase mt-1">Active Traps</p>
        </Card>
        <Card className="p-3 text-center" delay={0.10}>
          <p className="text-2xl font-bold data-mono">{stats?.tracked_unserved_ssids ?? 0}</p>
          <p className="text-[10px] text-[var(--color-text-muted)] uppercase mt-1">Tracked Probes</p>
        </Card>
        <Card className="p-3 text-center" delay={0.12}>
          <p className="text-2xl font-bold data-mono">{stats?.correlated_rogue_operators ?? 0}</p>
          <p className="text-[10px] text-[var(--color-text-muted)] uppercase mt-1">Rogue Suspects</p>
        </Card>
        <Card className="p-3 text-center" delay={0.14}>
          <p className="text-2xl font-bold data-mono">{stats?.correlated_deauth_sources ?? 0}</p>
          <p className="text-[10px] text-[var(--color-text-muted)] uppercase mt-1">Deauth Sources</p>
        </Card>
      </div>

      {/* How It Works */}
      <Card className="p-5" delay={0.16}>
        <h3 className="text-sm font-semibold mb-3 flex items-center gap-2">
          <Link2 size={14} className="text-[var(--color-accent-blue)]" />
          Correlation Logic
        </h3>
        <div className="grid grid-cols-1 md:grid-cols-3 gap-4 text-xs">
          <div className="p-3 rounded-lg bg-[var(--color-bg)] border border-[var(--color-border-soft)]">
            <p className="font-semibold text-[var(--color-accent-danger)]">Rogue AP Operator</p>
            <p className="text-[var(--color-text-muted)] mt-1">
              Device flagged as running a suspected Evil Twin ALSO connects to our honeypot.
              Legitimate APs never seek open WiFi. Confidence: 80%
            </p>
          </div>
          <div className="p-3 rounded-lg bg-[var(--color-bg)] border border-[var(--color-border-soft)]">
            <p className="font-semibold text-[var(--color-accent-warning)]">Deauth Attacker</p>
            <p className="text-[var(--color-text-muted)] mt-1">
              Device detected sending deauth floods ALSO probes/connects to honeypot.
              Correlates DoS with active reconnaissance. Confidence: 75%
            </p>
          </div>
          <div className="p-3 rounded-lg bg-[var(--color-bg)] border border-[var(--color-border-soft)]">
            <p className="font-semibold text-[var(--color-accent-blue)]">Dynamic SSID Trap</p>
            <p className="text-[var(--color-text-muted)] mt-1">
              Device connects to an SSID that didn't exist until we deployed it as a trap.
              Proves active network seeking behavior. Confidence: 50%
            </p>
          </div>
        </div>
      </Card>

      {/* Confirmed Attackers */}
      {confirmed.length > 0 && (
        <Card className="p-5" delay={0.18}>
          <h3 className="text-sm font-semibold mb-3 flex items-center gap-2">
            <ShieldAlert size={14} className="text-[var(--color-accent-danger)]" />
            Confirmed Attackers ({confirmed.length})
          </h3>
          <div className="space-y-3">
            {confirmed.map((c, i) => (
              <div key={i} className="p-4 rounded-lg border border-red-500/20 bg-red-500/5">
                <div className="flex flex-col sm:flex-row items-start sm:items-center justify-between gap-2 mb-2">
                  <div className="min-w-0">
                    <p className="text-sm font-mono font-medium break-all">{c.mac_address}</p>
                    <p className="text-xs text-[var(--color-text-muted)]">
                      {c.hostname || 'No hostname'} • {c.ip_address} • SSID: {c.connected_ssid}
                    </p>
                  </div>
                  <div className="sm:text-right shrink-0">
                    <span className="px-2 py-0.5 rounded text-[10px] font-medium bg-red-500/20 text-red-400 border border-red-500/30">
                      {c.correlation?.confirmation_type}
                    </span>
                    <p className="text-xs data-mono mt-1 text-[var(--color-accent-danger)]">
                      {c.correlation?.confidence_weight.toFixed(0)}/100
                    </p>
                  </div>
                </div>
                {c.correlation && (
                  <div className="mt-2 pl-3 border-l-2 border-red-500/30 space-y-1">
                    {c.correlation.evidence_chain.map((ev, j) => (
                      <p key={j} className="text-[11px] text-[var(--color-text-muted)]">
                        {j + 1}. {ev}
                      </p>
                    ))}
                  </div>
                )}
                {c.dns_queries.length > 0 && (
                  <div className="mt-2 flex flex-wrap gap-1">
                    {c.dns_queries.slice(0, 8).map((q, j) => (
                      <span key={j} className="px-1.5 py-0.5 text-[10px] rounded bg-[var(--color-card)] text-[var(--color-text-muted)]">
                        {q}
                      </span>
                    ))}
                    {c.dns_queries.length > 8 && (
                      <span className="px-1.5 py-0.5 text-[10px] rounded bg-[var(--color-card)] text-[var(--color-text-muted)]">
                        +{c.dns_queries.length - 8} more
                      </span>
                    )}
                  </div>
                )}
              </div>
            ))}
          </div>
        </Card>
      )}

      {/* Uncorrelated Connections */}
      {uncorrelated.length > 0 && (
        <Card className="p-5" delay={0.20}>
          <h3 className="text-sm font-semibold mb-3 flex items-center gap-2">
            <Activity size={14} className="text-[var(--color-text-secondary)]" />
            Uncorrelated Connections ({uncorrelated.length})
          </h3>
          <p className="text-xs text-[var(--color-text-muted)] mb-3">
            Devices that connected to honeypot but have no prior IDS correlation. Monitoring for further activity.
          </p>
          <div className="overflow-x-auto">
            <table className="w-full text-xs">
              <thead>
                <tr className="text-[var(--color-text-muted)] border-b border-[var(--color-border-soft)]">
                  <th className="pb-2 text-left">MAC</th>
                  <th className="pb-2 text-left">IP</th>
                  <th className="pb-2 text-left">Hostname</th>
                  <th className="pb-2 text-left">SSID</th>
                  <th className="pb-2 text-left">Dynamic?</th>
                  <th className="pb-2 text-left">Time</th>
                </tr>
              </thead>
              <tbody className="divide-y divide-[var(--color-border-soft)]">
                {uncorrelated.map((c, i) => (
                  <tr key={i} className="text-[var(--color-text-secondary)]">
                    <td className="py-2 font-mono">{c.mac_address}</td>
                    <td className="py-2">{c.ip_address}</td>
                    <td className="py-2">{c.hostname || '-'}</td>
                    <td className="py-2">{c.connected_ssid}</td>
                    <td className="py-2">{c.is_dynamic_ssid ? '✓ Trap' : '-'}</td>
                    <td className="py-2">{c.timestamp}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        </Card>
      )}

      {/* Pending Dynamic SSID Deployments */}
      {pending.length > 0 && (
        <Card className="p-5" delay={0.22}>
          <h3 className="text-sm font-semibold mb-3 flex items-center gap-2">
            <Radio size={14} className="text-[var(--color-accent-green)]" />
            Dynamic SSID Candidates ({pending.length})
          </h3>
          <p className="text-xs text-[var(--color-text-muted)] mb-3">
            SSIDs detected via probe requests that no AP currently serves. Candidates for trap deployment.
          </p>
          <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-3 gap-2">
            {pending.map(([ssid, count], i) => (
              <div key={i} className="p-3 rounded-lg bg-[var(--color-bg)] border border-[var(--color-border-soft)] flex items-center justify-between">
                <div>
                  <p className="text-sm font-medium">"{ssid}"</p>
                  <p className="text-[10px] text-[var(--color-text-muted)]">{count} devices probing</p>
                </div>
                <Wifi size={14} className="text-[var(--color-accent-green)]" />
              </div>
            ))}
          </div>
        </Card>
      )}

      {/* Empty state */}
      {!stats && (
        <Card className="p-6" delay={0.16}>
          <div className="text-center mb-4">
            <Bug size={36} className="mx-auto text-[var(--color-text-muted)] mb-2" />
            <p className="text-sm font-medium">Honeypot Deception System</p>
            <p className="text-xs text-[var(--color-text-muted)] mt-1">
              Not currently active. The system needs a second WiFi adapter in AP mode.
            </p>
          </div>
          <div className="grid grid-cols-1 sm:grid-cols-2 gap-3 text-xs">
            <div className="p-3 rounded-lg bg-[var(--color-bg)] border border-[var(--color-border-soft)]">
              <p className="font-semibold text-[var(--color-text)]">How to Start</p>
              <code className="block mt-1 text-[10px] text-[var(--color-accent-blue)] font-mono">sudo bash honeypot/setup.sh</code>
              <p className="text-[var(--color-text-muted)] mt-1">Requires: second USB WiFi adapter (AP-capable)</p>
            </div>
            <div className="p-3 rounded-lg bg-[var(--color-bg)] border border-[var(--color-border-soft)]">
              <p className="font-semibold text-[var(--color-text)]">What It Does</p>
              <p className="text-[var(--color-text-muted)] mt-1">
                Creates fake WiFi networks. When a device flagged by the IDS connects to one, it confirms the device is malicious (eliminates false positives).
              </p>
            </div>
            <div className="p-3 rounded-lg bg-[var(--color-bg)] border border-[var(--color-border-soft)]">
              <p className="font-semibold text-[var(--color-text)]">SSIDs Deployed</p>
              <p className="text-[var(--color-text-muted)] mt-1">FreeWiFi, eduroam_guest, HP-Print-Setup, DIRECT-wifi + dynamically generated</p>
            </div>
            <div className="p-3 rounded-lg bg-[var(--color-bg)] border border-[var(--color-border-soft)]">
              <p className="font-semibold text-[var(--color-text)]">Intelligence Gathered</p>
              <p className="text-[var(--color-text-muted)] mt-1">DNS queries, DHCP fingerprints, connection duration, credential submissions, tool signatures</p>
            </div>
          </div>
        </Card>
      )}
    </div>
  );
}

import { useMemo, useState, useEffect } from 'react';
import { X, Router, Smartphone, ShieldQuestion, Skull, Share2 } from 'lucide-react';
import Card from '../components/common/Card';
import { useScannedNetworks } from '../hooks/useMockLiveData';
import type { NodeKind, TopologyNode, TopologyLink } from '../types';

interface ClientData {
  mac: string;
  probed_ssids: string[];
  associated_bssid: string | null;
  deauth_count: number;
}

const NODE_STYLE: Record<NodeKind, { fill: string; stroke: string; icon: typeof Router }> = {
  ap: { fill: '#3B82F6', stroke: '#1D4ED8', icon: Router },
  client: { fill: '#22C55E', stroke: '#16A34A', icon: Smartphone },
  suspicious: { fill: '#FACC15', stroke: '#CA8A04', icon: ShieldQuestion },
  attacker: { fill: '#EF4444', stroke: '#B91C1C', icon: Skull },
};

async function fetchClients(): Promise<ClientData[]> {
  try {
    const res = await fetch('/api/clients');
    if (res.ok) return res.json();
  } catch { /* fallback */ }
  const host = window.location.hostname || 'localhost';
  try {
    const res = await fetch(`http://${host}:8787/api/clients`);
    if (res.ok) return res.json();
  } catch {}
  return [];
}

export default function DeviceTopology() {
  const networks = useScannedNetworks();
  const [clients, setClients] = useState<ClientData[]>([]);
  const [selected, setSelected] = useState<TopologyNode | null>(null);

  useEffect(() => {
    let cancelled = false;
    const poll = async () => {
      const data = await fetchClients();
      if (!cancelled) setClients(data);
      if (!cancelled) setTimeout(poll, 5000);
    };
    poll();
    return () => { cancelled = true; };
  }, []);

  const { nodes, links } = useMemo(() => {
    const nodeList: TopologyNode[] = [];
    const linkList: TopologyLink[] = [];
    const width = 740;
    const height = 420;
    const centerX = width / 2;
    const centerY = height / 2;

    const apCount = networks.length;
    const apRadius = Math.min(160, Math.max(80, apCount * 20));

    networks.forEach((ap, i) => {
      const angle = (i / Math.max(1, apCount)) * Math.PI * 2 - Math.PI / 2;
      const x = Math.round(centerX + Math.cos(angle) * apRadius);
      const y = Math.round(centerY + Math.sin(angle) * (apRadius * 0.7));

      nodeList.push({
        id: ap.id || `ap-${i}`,
        label: ap.ssid || '<Hidden>',
        kind: ap.status === 'Malicious' ? 'attacker' : ap.status === 'Suspicious' ? 'suspicious' : 'ap',
        mac: ap.bssid,
        x,
        y,
      });
    });

    const clientRadius = apRadius + 80;
    let clientIndex = 0;
    const totalClients = clients.length;

    clients.forEach((client) => {
      const angle = (clientIndex / Math.max(1, totalClients)) * Math.PI * 2;
      const x = Math.round(centerX + Math.cos(angle) * clientRadius);
      const y = Math.round(centerY + Math.sin(angle) * (clientRadius * 0.65));

      const kind: NodeKind = client.deauth_count > 3 ? 'attacker' : client.deauth_count > 0 ? 'suspicious' : 'client';

      nodeList.push({
        id: `client-${client.mac}`,
        label: client.mac.substring(0, 8) + '...',
        kind,
        mac: client.mac,
        x,
        y,
      });

      if (client.associated_bssid) {
        const apNode = nodeList.find((n) => n.mac === client.associated_bssid);
        if (apNode) {
          linkList.push({
            source: apNode.id,
            target: `client-${client.mac}`,
            suspicious: client.deauth_count > 0,
          });
        }
      }

      clientIndex++;
    });

    return { nodes: nodeList, links: linkList };
  }, [networks, clients]);

  return (
    <div className="space-y-6">
      <div>
        <h1 className="text-xl font-semibold">Device Topology ({nodes.length})</h1>
        <p className="text-sm text-[var(--color-text-secondary)] mt-1">
          {networks.length} access points + {clients.length} client devices on scanned channels.
        </p>
      </div>

      <div className="flex items-center gap-5 flex-wrap text-xs text-[var(--color-text-secondary)]">
        {(Object.keys(NODE_STYLE) as NodeKind[]).map((kind) => (
          <div key={kind} className="flex items-center gap-1.5">
            <span className="w-2.5 h-2.5 rounded-full" style={{ backgroundColor: NODE_STYLE[kind].fill }} />
            <span className="capitalize">{kind === 'ap' ? 'Access Point' : kind === 'client' ? 'Client' : kind}</span>
          </div>
        ))}
      </div>

      {nodes.length === 0 ? (
        <Card className="p-12 text-center" hover={false}>
          <Share2 size={36} className="mx-auto text-[var(--color-text-muted)] mb-3 opacity-50" />
          <h3 className="text-base font-semibold">No Devices Detected</h3>
          <p className="text-xs text-[var(--color-text-muted)] max-w-md mx-auto mt-1 leading-relaxed">
            As wireless networks and client devices are scanned, the topology will build in real-time.
          </p>
        </Card>
      ) : (
        <Card className="p-4" delay={0.05} hover={false}>
          <svg viewBox="0 0 800 480" className="w-full h-[480px] ops-grid-bg rounded-lg">
            {links.map((link, i) => {
              const source = nodes.find((n) => n.id === link.source);
              const target = nodes.find((n) => n.id === link.target);
              if (!source || !target) return null;
              return (
                <line
                  key={i}
                  x1={source.x}
                  y1={source.y}
                  x2={target.x}
                  y2={target.y}
                  stroke={link.suspicious ? 'var(--color-accent-danger)' : 'var(--color-border)'}
                  strokeWidth={link.suspicious ? 2 : 1}
                  strokeDasharray={link.suspicious ? '5 4' : undefined}
                  opacity={0.6}
                />
              );
            })}

            {nodes.map((node) => {
              const style = NODE_STYLE[node.kind];
              const Icon = style.icon;
              const isAp = node.kind === 'ap' || node.kind === 'suspicious' || node.kind === 'attacker';
              const radius = isAp ? 22 : 16;
              return (
                <g
                  key={node.id}
                  transform={`translate(${node.x}, ${node.y})`}
                  className="cursor-pointer"
                  onClick={() => setSelected(node)}
                >
                  <circle r={radius} fill={style.fill} fillOpacity={0.15} stroke={style.stroke} strokeWidth={1.5} />
                  <foreignObject x={-8} y={-8} width={16} height={16}>
                    <Icon size={16} color={style.fill} strokeWidth={2} />
                  </foreignObject>
                  <text
                    y={radius + 14}
                    textAnchor="middle"
                    fill="var(--color-text-secondary)"
                    fontSize={10}
                    fontFamily="Inter, sans-serif"
                  >
                    {node.label}
                  </text>
                </g>
              );
            })}
          </svg>
        </Card>
      )}

      {selected && (
        <div className="fixed inset-0 bg-black/60 backdrop-blur-sm z-30 flex items-center justify-center px-4" onClick={() => setSelected(null)}>
          <div onClick={(e) => e.stopPropagation()} className="w-full max-w-sm bg-[var(--color-bg-elevated)] border border-[var(--color-border)] rounded-xl p-6">
            <div className="flex items-start justify-between mb-4">
              <div>
                <p className="text-xs text-[var(--color-text-muted)] uppercase tracking-wide capitalize">{selected.kind}</p>
                <h2 className="text-lg font-semibold mt-1">{selected.label}</h2>
              </div>
              <button onClick={() => setSelected(null)} className="w-8 h-8 rounded-lg flex items-center justify-center text-[var(--color-text-secondary)] hover:bg-white/5">
                <X size={16} />
              </button>
            </div>
            <div className="space-y-2 text-sm">
              <div className="flex justify-between py-2 border-b border-[var(--color-border-soft)]">
                <span className="text-[var(--color-text-secondary)]">MAC Address</span>
                <span className="data-mono text-[var(--color-accent-blue)]">{selected.mac}</span>
              </div>
              <div className="flex justify-between py-2 border-b border-[var(--color-border-soft)]">
                <span className="text-[var(--color-text-secondary)]">Type</span>
                <span className="capitalize">{selected.kind}</span>
              </div>
              {clients.find((c) => c.mac === selected.mac) && (
                <>
                  <div className="flex justify-between py-2 border-b border-[var(--color-border-soft)]">
                    <span className="text-[var(--color-text-secondary)]">Associated AP</span>
                    <span className="data-mono text-xs">{clients.find((c) => c.mac === selected.mac)?.associated_bssid || 'None'}</span>
                  </div>
                  <div className="flex justify-between py-2">
                    <span className="text-[var(--color-text-secondary)]">Deauth Count</span>
                    <span className={clients.find((c) => c.mac === selected.mac)!.deauth_count > 0 ? 'text-[var(--color-accent-danger)]' : ''}>
                      {clients.find((c) => c.mac === selected.mac)?.deauth_count}
                    </span>
                  </div>
                </>
              )}
            </div>
          </div>
        </div>
      )}
    </div>
  );
}

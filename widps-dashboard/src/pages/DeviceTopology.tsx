import { useMemo, useState } from 'react';
import { X, Router, Smartphone, ShieldQuestion, Skull, Share2 } from 'lucide-react';
import Card from '../components/common/Card';
import { useScannedNetworks } from '../hooks/useMockLiveData';
import type { NodeKind, TopologyNode } from '../types';

const NODE_STYLE: Record<NodeKind, { fill: string; stroke: string; icon: typeof Router }> = {
  ap: { fill: '#3B82F6', stroke: '#1D4ED8', icon: Router },
  client: { fill: '#22C55E', stroke: '#16A34A', icon: Smartphone },
  suspicious: { fill: '#FACC15', stroke: '#CA8A04', icon: ShieldQuestion },
  attacker: { fill: '#EF4444', stroke: '#B91C1C', icon: Skull },
};

export default function DeviceTopology() {
  const networks = useScannedNetworks();
  const [selected, setSelected] = useState<TopologyNode | null>(null);

  const nodes: TopologyNode[] = useMemo(() => {
    const list: TopologyNode[] = [];
    const width = 740;
    const height = 360;

    networks.forEach((ap, i) => {
      const count = networks.length;
      const angle = (i / Math.max(1, count)) * Math.PI * 2 - Math.PI / 2;
      const radius = count > 1 ? 140 : 0;
      const x = Math.round(width / 2 + Math.cos(angle) * radius);
      const y = Math.round(height / 2 + Math.sin(angle) * (radius * 0.7));

      list.push({
        id: ap.id || `ap-${i}`,
        label: ap.ssid || '<Hidden SSID>',
        kind: ap.status === 'Malicious' ? 'attacker' : ap.status === 'Suspicious' ? 'suspicious' : 'ap',
        mac: ap.bssid,
        x,
        y,
      });
    });

    return list;
  }, [networks]);

  const links = useMemo(() => {
    if (nodes.length <= 1) return [];
    const center = nodes[0];
    return nodes.slice(1).map((n) => ({
      source: center.id,
      target: n.id,
      suspicious: n.kind === 'attacker' || n.kind === 'suspicious',
    }));
  }, [nodes]);

  return (
    <div className="space-y-6">
      <div>
        <h1 className="text-xl font-semibold">Device Topology ({nodes.length})</h1>
        <p className="text-sm text-[var(--color-text-secondary)] mt-1">
          Spatial graph of collected wireless access points scanned on wlan1mon.
        </p>
      </div>

      <div className="flex items-center gap-5 flex-wrap text-xs text-[var(--color-text-secondary)]">
        {(Object.keys(NODE_STYLE) as NodeKind[]).map((kind) => (
          <div key={kind} className="flex items-center gap-1.5">
            <span className="w-2.5 h-2.5 rounded-full" style={{ backgroundColor: NODE_STYLE[kind].fill }} />
            <span className="capitalize">{kind === 'ap' ? 'Access Point' : kind}</span>
          </div>
        ))}
      </div>

      {nodes.length === 0 ? (
        <Card className="p-12 text-center" hover={false}>
          <Share2 size={36} className="mx-auto text-[var(--color-text-muted)] mb-3 opacity-50" />
          <h3 className="text-base font-semibold">No Scanned Nodes Collected</h3>
          <p className="text-xs text-[var(--color-text-muted)] max-w-md mx-auto mt-1 leading-relaxed">
            As wireless access points and stations are scanned, device topology nodes will automatically render in real-time.
          </p>
        </Card>
      ) : (
        <Card className="p-4" delay={0.05} hover={false}>
          <svg viewBox="0 0 800 420" className="w-full h-[420px] ops-grid-bg rounded-lg">
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
                  stroke={link.suspicious ? '#EF4444' : 'var(--color-border)'}
                  strokeWidth={link.suspicious ? 2 : 1.5}
                  strokeDasharray={link.suspicious ? '5 4' : undefined}
                />
              );
            })}

            {nodes.map((node) => {
              const style = NODE_STYLE[node.kind];
              const Icon = style.icon;
              return (
                <g
                  key={node.id}
                  transform={`translate(${node.x}, ${node.y})`}
                  className="cursor-pointer"
                  onClick={() => setSelected(node)}
                >
                  <circle r={24} fill={style.fill} fillOpacity={0.15} stroke={style.stroke} strokeWidth={1.5} />
                  <foreignObject x={-10} y={-10} width={20} height={20}>
                    <Icon size={20} color={style.fill} strokeWidth={2} />
                  </foreignObject>
                  <text
                    y={38}
                    textAnchor="middle"
                    fill="var(--color-text-secondary)"
                    fontSize={11}
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
            <div className="flex items-center justify-between py-2 border-b border-[var(--color-border-soft)] text-sm">
              <span className="text-[var(--color-text-secondary)]">BSSID MAC</span>
              <span className="data-mono text-[var(--color-accent-blue)]">{selected.mac}</span>
            </div>
            <div className="flex items-center justify-between py-2 text-sm">
              <span className="text-[var(--color-text-secondary)]">Category</span>
              <span className="capitalize">{selected.kind}</span>
            </div>
          </div>
        </div>
      )}
    </div>
  );
}

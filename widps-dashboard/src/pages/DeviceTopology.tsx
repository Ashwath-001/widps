import { useState } from 'react';
import { X, Router, Smartphone, ShieldQuestion, Skull } from 'lucide-react';
import Card from '../components/common/Card';
import { topologyNodes, topologyLinks } from '../data/mockData';
import type { NodeKind, TopologyNode } from '../types';

const NODE_STYLE: Record<NodeKind, { fill: string; stroke: string; icon: typeof Router }> = {
  ap: { fill: '#3B82F6', stroke: '#1D4ED8', icon: Router },
  client: { fill: '#22C55E', stroke: '#16A34A', icon: Smartphone },
  suspicious: { fill: '#FACC15', stroke: '#CA8A04', icon: ShieldQuestion },
  attacker: { fill: '#EF4444', stroke: '#B91C1C', icon: Skull },
};

export default function DeviceTopology() {
  const [selected, setSelected] = useState<TopologyNode | null>(null);

  return (
    <div className="space-y-6">
      <div>
        <h1 className="text-xl font-semibold">Device Topology</h1>
        <p className="text-sm text-[var(--color-text-secondary)] mt-1">
          Relationships between the access point, its clients, and flagged devices.
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

      <Card className="p-4" delay={0.05} hover={false}>
        <svg viewBox="0 0 800 420" className="w-full h-[420px] ops-grid-bg rounded-lg">
          {topologyLinks.map((link, i) => {
            const source = topologyNodes.find((n) => n.id === link.source)!;
            const target = topologyNodes.find((n) => n.id === link.target)!;
            return (
              <line
                key={i}
                x1={source.x}
                y1={source.y}
                x2={target.x}
                y2={target.y}
                stroke={link.suspicious ? '#EF4444' : '#1e293b'}
                strokeWidth={link.suspicious ? 2 : 1.5}
                strokeDasharray={link.suspicious ? '5 4' : undefined}
              />
            );
          })}

          {topologyNodes.map((node) => {
            const style = NODE_STYLE[node.kind];
            const Icon = style.icon;
            return (
              <g
                key={node.id}
                transform={`translate(${node.x}, ${node.y})`}
                className="cursor-pointer"
                onClick={() => setSelected(node)}
              >
                <circle r={26} fill={style.fill} fillOpacity={0.15} stroke={style.stroke} strokeWidth={1.5} />
                <foreignObject x={-11} y={-11} width={22} height={22}>
                  <Icon size={22} color={style.fill} strokeWidth={2} />
                </foreignObject>
                <text
                  y={44}
                  textAnchor="middle"
                  fill="#94A3B8"
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

      {selected && (
        <div className="fixed inset-0 bg-black/50 backdrop-blur-sm z-30 flex items-center justify-center px-4" onClick={() => setSelected(null)}>
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
              <span className="text-[var(--color-text-secondary)]">MAC Address</span>
              <span className="data-mono">{selected.mac}</span>
            </div>
            <div className="flex items-center justify-between py-2 text-sm">
              <span className="text-[var(--color-text-secondary)]">Role</span>
              <span className="capitalize">{selected.kind}</span>
            </div>
          </div>
        </div>
      )}
    </div>
  );
}

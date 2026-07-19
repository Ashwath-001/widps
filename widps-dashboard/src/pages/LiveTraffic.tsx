import {
  ResponsiveContainer,
  LineChart,
  Line,
  AreaChart,
  Area,
  BarChart,
  Bar,
  Cell,
  XAxis,
  YAxis,
  CartesianGrid,
  Tooltip,
} from 'recharts';
import Card from '../components/common/Card';
import { useTrafficHistory } from '../hooks/useMockLiveData';
import { channelUtilization, signalDistribution } from '../data/mockData';

const AXIS_STYLE = { fontSize: 11, fill: '#64748B' };

const tooltipStyle = {
  contentStyle: {
    background: '#111827',
    border: '1px solid #1e293b',
    borderRadius: 8,
    fontSize: 12,
  },
  labelStyle: { color: '#94A3B8' },
};

interface MiniChartProps {
  title: string;
  color: string;
  dataKey: string;
  data: any[];
  delay?: number;
  kind?: 'line' | 'area';
}

function MiniChart({ title, color, dataKey, data, delay = 0, kind = 'line' }: MiniChartProps) {
  return (
    <Card className="p-4" delay={delay}>
      <div className="flex items-center justify-between mb-2">
        <h3 className="text-xs font-semibold text-[var(--color-text-secondary)] uppercase tracking-wide">{title}</h3>
        <span className="data-mono text-sm font-semibold" style={{ color }}>
          {data[data.length - 1]?.[dataKey] ?? 0}
        </span>
      </div>
      <ResponsiveContainer width="100%" height={110}>
        {kind === 'area' ? (
          <AreaChart data={data}>
            <defs>
              <linearGradient id={`grad-${dataKey}`} x1="0" y1="0" x2="0" y2="1">
                <stop offset="5%" stopColor={color} stopOpacity={0.35} />
                <stop offset="95%" stopColor={color} stopOpacity={0} />
              </linearGradient>
            </defs>
            <XAxis dataKey="t" hide />
            <YAxis hide />
            <Tooltip {...tooltipStyle} />
            <Area type="monotone" dataKey={dataKey} stroke={color} fill={`url(#grad-${dataKey})`} strokeWidth={2} isAnimationActive={false} />
          </AreaChart>
        ) : (
          <LineChart data={data}>
            <XAxis dataKey="t" hide />
            <YAxis hide />
            <Tooltip {...tooltipStyle} />
            <Line type="monotone" dataKey={dataKey} stroke={color} strokeWidth={2} dot={false} isAnimationActive={false} />
          </LineChart>
        )}
      </ResponsiveContainer>
    </Card>
  );
}

export default function LiveTraffic() {
  const traffic = useTrafficHistory();

  return (
    <div className="space-y-6">
      <div>
        <h1 className="text-xl font-semibold">Live Traffic</h1>
        <p className="text-sm text-[var(--color-text-secondary)] mt-1">Frame-level throughput, updated every second.</p>
      </div>

      <div className="grid grid-cols-1 sm:grid-cols-2 xl:grid-cols-3 gap-4">
        <MiniChart title="Beacon Frames / sec" color="#3B82F6" dataKey="beacon" data={traffic} delay={0.02} />
        <MiniChart title="Probe Requests / sec" color="#22C55E" dataKey="probeRequest" data={traffic} delay={0.05} />
        <MiniChart title="Authentication Frames / sec" color="#FACC15" dataKey="auth" data={traffic} delay={0.08} />
        <MiniChart title="Association Frames / sec" color="#A78BFA" dataKey="assoc" data={traffic} delay={0.11} />
        <MiniChart title="Disassociation Frames / sec" color="#FB923C" dataKey="disassoc" data={traffic} delay={0.14} />
        <MiniChart title="Deauthentication Frames / sec" color="#EF4444" dataKey="deauth" data={traffic} delay={0.17} kind="area" />
      </div>

      <div className="grid grid-cols-1 xl:grid-cols-3 gap-4">
        <Card className="p-5 xl:col-span-2" delay={0.2}>
          <h3 className="text-sm font-semibold mb-4">Packet Rate</h3>
          <ResponsiveContainer width="100%" height={220}>
            <AreaChart data={traffic}>
              <defs>
                <linearGradient id="grad-packetRate" x1="0" y1="0" x2="0" y2="1">
                  <stop offset="5%" stopColor="#3B82F6" stopOpacity={0.4} />
                  <stop offset="95%" stopColor="#3B82F6" stopOpacity={0} />
                </linearGradient>
              </defs>
              <CartesianGrid stroke="#1e293b" strokeDasharray="3 3" vertical={false} />
              <XAxis dataKey="t" tick={AXIS_STYLE} tickLine={false} axisLine={{ stroke: '#1e293b' }} minTickGap={40} />
              <YAxis tick={AXIS_STYLE} tickLine={false} axisLine={false} />
              <Tooltip {...tooltipStyle} />
              <Area type="monotone" dataKey="packetRate" stroke="#3B82F6" fill="url(#grad-packetRate)" strokeWidth={2} isAnimationActive={false} />
            </AreaChart>
          </ResponsiveContainer>
        </Card>

        <Card className="p-5" delay={0.23}>
          <h3 className="text-sm font-semibold mb-4">Channel Utilization</h3>
          <ResponsiveContainer width="100%" height={220}>
            <BarChart data={channelUtilization}>
              <CartesianGrid stroke="#1e293b" strokeDasharray="3 3" vertical={false} />
              <XAxis dataKey="channel" tick={AXIS_STYLE} tickLine={false} axisLine={{ stroke: '#1e293b' }} />
              <YAxis tick={AXIS_STYLE} tickLine={false} axisLine={false} />
              <Tooltip {...tooltipStyle} />
              <Bar dataKey="utilizationPct" radius={[4, 4, 0, 0]}>
                {channelUtilization.map((entry) => (
                  <Cell key={entry.channel} fill={entry.utilizationPct > 60 ? '#EF4444' : '#3B82F6'} />
                ))}
              </Bar>
            </BarChart>
          </ResponsiveContainer>
        </Card>
      </div>

      <Card className="p-5" delay={0.26}>
        <h3 className="text-sm font-semibold mb-4">Signal Strength Distribution</h3>
        <ResponsiveContainer width="100%" height={200}>
          <BarChart data={signalDistribution}>
            <CartesianGrid stroke="#1e293b" strokeDasharray="3 3" vertical={false} />
            <XAxis dataKey="range" tick={AXIS_STYLE} tickLine={false} axisLine={{ stroke: '#1e293b' }} />
            <YAxis tick={AXIS_STYLE} tickLine={false} axisLine={false} />
            <Tooltip {...tooltipStyle} />
            <Bar dataKey="count" fill="#22C55E" radius={[4, 4, 0, 0]} />
          </BarChart>
        </ResponsiveContainer>
      </Card>
    </div>
  );
}

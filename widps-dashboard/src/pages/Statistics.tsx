import { useMemo } from 'react';
import {
  ResponsiveContainer,
  PieChart,
  Pie,
  Cell,
  Legend,
  BarChart,
  Bar,
  XAxis,
  YAxis,
  CartesianGrid,
  Tooltip,
} from 'recharts';
import Card from '../components/common/Card';
import { useLiveAlerts, useScannedNetworks } from '../hooks/useMockLiveData';

const AXIS_STYLE = { fontSize: 11, fill: '#64748B' };
const tooltipStyle = {
  contentStyle: { background: '#111827', border: '1px solid #1e293b', borderRadius: 8, fontSize: 12 },
  labelStyle: { color: '#94A3B8' },
};

const COLOR_PALETTE = ['#EF4444', '#FACC15', '#3B82F6', '#22C55E', '#A78BFA', '#FB923C'];

export default function Statistics() {
  const alerts = useLiveAlerts();
  const networks = useScannedNetworks();

  const attackDistribution = useMemo(() => {
    const counts: Record<string, number> = {};
    alerts.forEach((a) => {
      counts[a.title] = (counts[a.title] || 0) + 1;
    });

    const entries = Object.entries(counts).map(([name, value], i) => ({
      name,
      value,
      color: COLOR_PALETTE[i % COLOR_PALETTE.length],
    }));

    if (entries.length === 0) {
      return [{ name: 'No Alerts Logged', value: 1, color: '#334155' }];
    }
    return entries;
  }, [alerts]);

  const channelStats = useMemo(() => {
    const channelCounts: Record<number, number> = {};
    networks.forEach((ap) => {
      channelCounts[ap.channel] = (channelCounts[ap.channel] || 0) + 1;
    });

    return [1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 36, 44, 149].map((ch) => ({
      channel: `Ch ${ch}`,
      count: channelCounts[ch] || 0,
    })).filter((c) => c.count > 0 || c.channel === 'Ch 1' || c.channel === 'Ch 6' || c.channel === 'Ch 11');
  }, [networks]);

  return (
    <div className="space-y-6">
      <div>
        <h1 className="text-xl font-semibold">Statistics & Analytics</h1>
        <p className="text-sm text-[var(--color-text-secondary)] mt-1">Real-time aggregate detection metrics from scanned channels.</p>
      </div>

      <div className="grid grid-cols-1 lg:grid-cols-2 gap-4">
        <Card className="p-5" delay={0.03}>
          <h3 className="text-sm font-semibold mb-4">Detected Attack Distribution ({alerts.length})</h3>
          <ResponsiveContainer width="100%" height={260}>
            <PieChart>
              <Pie
                data={attackDistribution}
                dataKey="value"
                nameKey="name"
                innerRadius={60}
                outerRadius={95}
                paddingAngle={3}
                isAnimationActive
              >
                {attackDistribution.map((entry) => (
                  <Cell key={entry.name} fill={entry.color} stroke="var(--color-card)" strokeWidth={2} />
                ))}
              </Pie>
              <Tooltip {...tooltipStyle} />
              <Legend
                verticalAlign="bottom"
                height={36}
                formatter={(value) => <span className="text-xs text-[var(--color-text-secondary)]">{value}</span>}
              />
            </PieChart>
          </ResponsiveContainer>
        </Card>

        <Card className="p-5" delay={0.06}>
          <h3 className="text-sm font-semibold mb-4">Scanned Channel Network Distribution</h3>
          <ResponsiveContainer width="100%" height={260}>
            <BarChart data={channelStats}>
              <CartesianGrid stroke="#1e293b" strokeDasharray="3 3" vertical={false} />
              <XAxis dataKey="channel" tick={AXIS_STYLE} tickLine={false} axisLine={{ stroke: '#1e293b' }} />
              <YAxis tick={AXIS_STYLE} tickLine={false} axisLine={false} />
              <Tooltip {...tooltipStyle} />
              <Bar dataKey="count" fill="#3B82F6" radius={[4, 4, 0, 0]} />
            </BarChart>
          </ResponsiveContainer>
        </Card>
      </div>
    </div>
  );
}

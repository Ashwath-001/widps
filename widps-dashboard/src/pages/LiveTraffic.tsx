import { useMemo } from 'react';
import {
  ResponsiveContainer,
  BarChart,
  Bar,
  LineChart,
  Line,
  Cell,
  XAxis,
  YAxis,
  CartesianGrid,
  Tooltip,
  Legend,
} from 'recharts';
import Card from '../components/common/Card';
import { useScannedNetworks, useSystemStatus, useTrafficHistory } from '../hooks/useMockLiveData';

const AXIS_STYLE = { fontSize: 11, fill: 'var(--color-text-muted)' };

const tooltipStyle = {
  contentStyle: {
    background: 'var(--color-card)',
    border: '1px solid var(--color-border)',
    borderRadius: 8,
    fontSize: 12,
  },
  labelStyle: { color: 'var(--color-text-secondary)' },
};

export default function LiveTraffic() {
  const networks = useScannedNetworks();
  const status = useSystemStatus();
  const traffic = useTrafficHistory();

  const channelUtilization = useMemo(() => {
    const chCounts: Record<number, number> = {};
    networks.forEach((ap) => {
      chCounts[ap.channel] = (chCounts[ap.channel] || 0) + 1;
    });

    return [1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11].map((ch) => ({
      channel: `Ch ${ch}`,
      count: chCounts[ch] || 0,
    }));
  }, [networks]);

  const signalDistribution = useMemo(() => {
    let strong = 0;
    let good = 0;
    let fair = 0;
    let weak = 0;

    networks.forEach((ap) => {
      if (ap.rssi >= -50) strong++;
      else if (ap.rssi >= -65) good++;
      else if (ap.rssi >= -80) fair++;
      else weak++;
    });

    return [
      { range: 'Strong (-30 to -50)', count: strong },
      { range: 'Good (-51 to -65)', count: good },
      { range: 'Fair (-66 to -80)', count: fair },
      { range: 'Weak (< -80)', count: weak },
    ];
  }, [networks]);

  const latestPps = traffic.length > 0 ? traffic[traffic.length - 1].packetRate : 0;

  return (
    <div className="space-y-6">
      <div>
        <h1 className="text-xl font-semibold">Live Traffic Telemetry</h1>
        <p className="text-sm text-[var(--color-text-secondary)] mt-1">
          Real-time frame capture rates and wireless spectrum analysis from {status.interfaceName || 'wlan1mon'}.
        </p>
      </div>

      <div className="grid grid-cols-2 sm:grid-cols-4 gap-4">
        <Card className="p-4" delay={0.02}>
          <p className="text-xs text-[var(--color-text-muted)] font-medium uppercase tracking-wide">Packets/sec</p>
          <p className="text-2xl font-bold mt-1 text-[var(--color-accent-blue)] data-mono">{latestPps}</p>
        </Card>
        <Card className="p-4" delay={0.04}>
          <p className="text-xs text-[var(--color-text-muted)] font-medium uppercase tracking-wide">Collected APs</p>
          <p className="text-2xl font-bold mt-1 text-[var(--color-text)] data-mono">{networks.length}</p>
        </Card>
        <Card className="p-4" delay={0.06}>
          <p className="text-xs text-[var(--color-text-muted)] font-medium uppercase tracking-wide">Channel</p>
          <p className="text-2xl font-bold mt-1 text-[var(--color-accent-green)] data-mono">{status.currentChannel || 1}</p>
        </Card>
        <Card className="p-4" delay={0.08}>
          <p className="text-xs text-[var(--color-text-muted)] font-medium uppercase tracking-wide">Engine</p>
          <p className="text-sm font-semibold mt-1 text-[var(--color-accent-green)]">{status.detectionEngineStatus || 'Running'}</p>
        </Card>
      </div>

      <Card className="p-5" delay={0.10}>
        <h3 className="text-sm font-semibold mb-4">Frame Type Rate (1s resolution, last 60s)</h3>
        <ResponsiveContainer width="100%" height={280}>
          <LineChart data={traffic}>
            <CartesianGrid stroke="var(--color-border)" strokeDasharray="3 3" vertical={false} />
            <XAxis dataKey="t" tick={AXIS_STYLE} tickLine={false} axisLine={{ stroke: 'var(--color-border)' }} interval="preserveStartEnd" />
            <YAxis tick={AXIS_STYLE} tickLine={false} axisLine={false} />
            <Tooltip {...tooltipStyle} />
            <Legend verticalAlign="top" height={30} wrapperStyle={{ fontSize: 11 }} />
            <Line type="monotone" dataKey="beacon" stroke="#3B82F6" strokeWidth={2} dot={false} name="Beacon" />
            <Line type="monotone" dataKey="probeRequest" stroke="#22C55E" strokeWidth={1.5} dot={false} name="Probe Req" />
            <Line type="monotone" dataKey="deauth" stroke="#EF4444" strokeWidth={2} dot={false} name="Deauth" />
            <Line type="monotone" dataKey="auth" stroke="#FACC15" strokeWidth={1.5} dot={false} name="Auth" />
            <Line type="monotone" dataKey="packetRate" stroke="#A78BFA" strokeWidth={1} dot={false} name="Total PPS" strokeDasharray="4 2" />
          </LineChart>
        </ResponsiveContainer>
      </Card>

      <div className="grid grid-cols-1 xl:grid-cols-2 gap-4">
        <Card className="p-5" delay={0.14}>
          <h3 className="text-sm font-semibold mb-4">Channel Density (APs per Channel)</h3>
          <ResponsiveContainer width="100%" height={220}>
            <BarChart data={channelUtilization}>
              <CartesianGrid stroke="var(--color-border)" strokeDasharray="3 3" vertical={false} />
              <XAxis dataKey="channel" tick={AXIS_STYLE} tickLine={false} axisLine={{ stroke: 'var(--color-border)' }} />
              <YAxis tick={AXIS_STYLE} tickLine={false} axisLine={false} />
              <Tooltip {...tooltipStyle} />
              <Bar dataKey="count" fill="#3B82F6" radius={[4, 4, 0, 0]} />
            </BarChart>
          </ResponsiveContainer>
        </Card>

        <Card className="p-5" delay={0.18}>
          <h3 className="text-sm font-semibold mb-4">Signal Strength Distribution</h3>
          <ResponsiveContainer width="100%" height={220}>
            <BarChart data={signalDistribution}>
              <CartesianGrid stroke="var(--color-border)" strokeDasharray="3 3" vertical={false} />
              <XAxis dataKey="range" tick={AXIS_STYLE} tickLine={false} axisLine={{ stroke: 'var(--color-border)' }} />
              <YAxis tick={AXIS_STYLE} tickLine={false} axisLine={false} />
              <Tooltip {...tooltipStyle} />
              <Bar dataKey="count" fill="#22C55E" radius={[4, 4, 0, 0]}>
                {signalDistribution.map((_, index) => (
                  <Cell key={index} fill={index === 0 ? '#22C55E' : index === 1 ? '#3B82F6' : index === 2 ? '#FACC15' : '#EF4444'} />
                ))}
              </Bar>
            </BarChart>
          </ResponsiveContainer>
        </Card>
      </div>
    </div>
  );
}

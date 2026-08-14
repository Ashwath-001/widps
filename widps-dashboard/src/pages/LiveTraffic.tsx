import { useMemo, useState } from 'react';
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

const TIME_RANGES = [
  { label: '30s', seconds: 30 },
  { label: '1m', seconds: 60 },
  { label: '5m', seconds: 300 },
];

export default function LiveTraffic() {
  const networks = useScannedNetworks();
  const status = useSystemStatus();
  const traffic = useTrafficHistory();
  const [timeRange, setTimeRange] = useState(60);

  const visibleTraffic = useMemo(() => {
    // Show only the last N seconds of data
    return traffic.slice(-timeRange);
  }, [traffic, timeRange]);

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
      { range: 'Strong', count: strong },
      { range: 'Good', count: good },
      { range: 'Fair', count: fair },
      { range: 'Weak', count: weak },
    ];
  }, [networks]);

  const latestPps = traffic.length > 0 ? traffic[traffic.length - 1].packetRate : 0;

  return (
    <div className="space-y-5">
      <div>
        <h1 className="text-xl font-semibold">Live Traffic</h1>
        <p className="text-sm text-[var(--color-text-secondary)] mt-1">
          Frame capture rates and spectrum analysis from {status.interfaceName || 'wlan1mon'}.
        </p>
      </div>

      <div className="grid grid-cols-2 sm:grid-cols-4 gap-3">
        <Card className="p-3" delay={0.02}>
          <p className="text-[10px] text-[var(--color-text-muted)] uppercase">Packets/sec</p>
          <p className="text-xl font-bold mt-0.5 text-[var(--color-accent-blue)] data-mono">{latestPps}</p>
        </Card>
        <Card className="p-3" delay={0.03}>
          <p className="text-[10px] text-[var(--color-text-muted)] uppercase">Networks</p>
          <p className="text-xl font-bold mt-0.5 data-mono">{networks.length}</p>
        </Card>
        <Card className="p-3" delay={0.04}>
          <p className="text-[10px] text-[var(--color-text-muted)] uppercase">Channel</p>
          <p className="text-xl font-bold mt-0.5 text-[var(--color-accent-green)] data-mono">{status.currentChannel || 1}</p>
        </Card>
        <Card className="p-3" delay={0.05}>
          <p className="text-[10px] text-[var(--color-text-muted)] uppercase">Engine</p>
          <p className="text-sm font-semibold mt-1 text-[var(--color-accent-green)]">{status.detectionEngineStatus || 'Running'}</p>
        </Card>
      </div>

      {/* Frame Rate Chart with Time Range */}
      <Card className="p-5" delay={0.08}>
        <div className="flex items-center justify-between mb-4 flex-wrap gap-2">
          <h3 className="text-sm font-semibold">Frame Rate (1s resolution)</h3>
          <div className="flex items-center gap-1">
            {TIME_RANGES.map((r) => (
              <button
                key={r.seconds}
                onClick={() => setTimeRange(r.seconds)}
                className={`h-[26px] px-2.5 rounded text-[10px] font-medium border transition-colors ${
                  timeRange === r.seconds
                    ? 'bg-[var(--color-accent-blue)]/10 text-[var(--color-accent-blue)] border-[var(--color-accent-blue)]/30'
                    : 'border-[var(--color-border)] text-[var(--color-text-muted)] hover:text-[var(--color-text)]'
                }`}
              >
                {r.label}
              </button>
            ))}
          </div>
        </div>
        {visibleTraffic.length > 0 ? (
          <ResponsiveContainer width="100%" height={260}>
            <LineChart data={visibleTraffic}>
              <CartesianGrid stroke="var(--color-border)" strokeDasharray="3 3" vertical={false} />
              <XAxis dataKey="t" tick={AXIS_STYLE} tickLine={false} axisLine={{ stroke: 'var(--color-border)' }} interval="preserveStartEnd" />
              <YAxis tick={AXIS_STYLE} tickLine={false} axisLine={false} />
              <Tooltip {...tooltipStyle} />
              <Legend verticalAlign="top" height={28} wrapperStyle={{ fontSize: 10 }} />
              <Line type="monotone" dataKey="beacon" stroke="#3B82F6" strokeWidth={2} dot={false} name="Beacon" />
              <Line type="monotone" dataKey="probeRequest" stroke="#22C55E" strokeWidth={1.5} dot={false} name="Probe" />
              <Line type="monotone" dataKey="deauth" stroke="#EF4444" strokeWidth={2} dot={false} name="Deauth" />
              <Line type="monotone" dataKey="auth" stroke="#FACC15" strokeWidth={1.5} dot={false} name="Auth" />
              <Line type="monotone" dataKey="packetRate" stroke="#A78BFA" strokeWidth={1} dot={false} name="Total" strokeDasharray="4 2" />
            </LineChart>
          </ResponsiveContainer>
        ) : (
          <div className="h-[260px] flex items-center justify-center text-xs text-[var(--color-text-muted)]">
            Waiting for traffic data from backend...
          </div>
        )}
      </Card>

      <div className="grid grid-cols-1 xl:grid-cols-2 gap-4">
        <Card className="p-5" delay={0.12}>
          <h3 className="text-sm font-semibold mb-4">Channel Density</h3>
          {networks.length > 0 ? (
            <ResponsiveContainer width="100%" height={200}>
              <BarChart data={channelUtilization}>
                <CartesianGrid stroke="var(--color-border)" strokeDasharray="3 3" vertical={false} />
                <XAxis dataKey="channel" tick={AXIS_STYLE} tickLine={false} axisLine={{ stroke: 'var(--color-border)' }} />
                <YAxis tick={AXIS_STYLE} tickLine={false} axisLine={false} />
                <Tooltip {...tooltipStyle} />
                <Bar dataKey="count" fill="#3B82F6" radius={[4, 4, 0, 0]} />
              </BarChart>
            </ResponsiveContainer>
          ) : (
            <div className="h-[200px] flex items-center justify-center text-xs text-[var(--color-text-muted)]">
              No networks scanned yet
            </div>
          )}
        </Card>

        <Card className="p-5" delay={0.14}>
          <h3 className="text-sm font-semibold mb-4">Signal Distribution</h3>
          {networks.length > 0 ? (
            <ResponsiveContainer width="100%" height={200}>
              <BarChart data={signalDistribution}>
                <CartesianGrid stroke="var(--color-border)" strokeDasharray="3 3" vertical={false} />
                <XAxis dataKey="range" tick={AXIS_STYLE} tickLine={false} axisLine={{ stroke: 'var(--color-border)' }} />
                <YAxis tick={AXIS_STYLE} tickLine={false} axisLine={false} />
                <Tooltip {...tooltipStyle} />
                <Bar dataKey="count" radius={[4, 4, 0, 0]}>
                  {signalDistribution.map((_, i) => (
                    <Cell key={i} fill={i === 0 ? '#22C55E' : i === 1 ? '#3B82F6' : i === 2 ? '#FACC15' : '#EF4444'} />
                  ))}
                </Bar>
              </BarChart>
            </ResponsiveContainer>
          ) : (
            <div className="h-[200px] flex items-center justify-center text-xs text-[var(--color-text-muted)]">
              No networks scanned yet
            </div>
          )}
        </Card>
      </div>
    </div>
  );
}

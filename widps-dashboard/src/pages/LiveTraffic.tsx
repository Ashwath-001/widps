import { useMemo } from 'react';
import {
  ResponsiveContainer,
  BarChart,
  Bar,
  Cell,
  XAxis,
  YAxis,
  CartesianGrid,
  Tooltip,
} from 'recharts';
import Card from '../components/common/Card';
import { useScannedNetworks, useSystemStatus } from '../hooks/useMockLiveData';

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

export default function LiveTraffic() {
  const networks = useScannedNetworks();
  const status = useSystemStatus();

  // Channel Utilization computed from real collected access points
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

  // Signal Strength Distribution computed from real RSSI of collected access points
  const signalDistribution = useMemo(() => {
    let strong = 0; // -30 to -50
    let good = 0;   // -51 to -65
    let fair = 0;   // -66 to -80
    let weak = 0;   // < -80

    networks.forEach((ap) => {
      if (ap.rssi >= -50) strong++;
      else if (ap.rssi >= -65) good++;
      else if (ap.rssi >= -80) fair++;
      else weak++;
    });

    return [
      { range: 'Strong (-30 to -50 dBm)', count: strong },
      { range: 'Good (-51 to -65 dBm)', count: good },
      { range: 'Fair (-66 to -80 dBm)', count: fair },
      { range: 'Weak (< -80 dBm)', count: weak },
    ];
  }, [networks]);

  return (
    <div className="space-y-6">
      <div>
        <h1 className="text-xl font-semibold">Live Traffic Telemetry</h1>
        <p className="text-sm text-[var(--color-text-secondary)] mt-1">Real-time interface telemetry and wireless spectrum analysis from wlan1mon.</p>
      </div>

      <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-4 gap-4">
        <Card className="p-4" delay={0.02}>
          <p className="text-xs text-[var(--color-text-muted)] font-medium uppercase tracking-wide">Collected Access Points</p>
          <p className="text-2xl font-bold mt-1 text-[var(--color-accent-blue)] data-mono">{networks.length}</p>
        </Card>
        <Card className="p-4" delay={0.04}>
          <p className="text-xs text-[var(--color-text-muted)] font-medium uppercase tracking-wide">Active Interface</p>
          <p className="text-sm font-semibold mt-1 text-[var(--color-text)] data-mono">{status.interfaceName || 'wlan1mon'}</p>
        </Card>
        <Card className="p-4" delay={0.06}>
          <p className="text-xs text-[var(--color-text-muted)] font-medium uppercase tracking-wide">Current Hopper Channel</p>
          <p className="text-2xl font-bold mt-1 text-[var(--color-accent-green)] data-mono">Ch {status.currentChannel || 1}</p>
        </Card>
        <Card className="p-4" delay={0.08}>
          <p className="text-xs text-[var(--color-text-muted)] font-medium uppercase tracking-wide">Detection Engine</p>
          <p className="text-sm font-semibold mt-1 text-[var(--color-accent-green)]">{status.detectionEngineStatus || 'Running'}</p>
        </Card>
      </div>

      <div className="grid grid-cols-1 xl:grid-cols-2 gap-4">
        <Card className="p-5" delay={0.12}>
          <h3 className="text-sm font-semibold mb-4">Channel Density (Collected APs per Channel)</h3>
          <ResponsiveContainer width="100%" height={250}>
            <BarChart data={channelUtilization}>
              <CartesianGrid stroke="#1e293b" strokeDasharray="3 3" vertical={false} />
              <XAxis dataKey="channel" tick={AXIS_STYLE} tickLine={false} axisLine={{ stroke: '#1e293b' }} />
              <YAxis tick={AXIS_STYLE} tickLine={false} axisLine={false} />
              <Tooltip {...tooltipStyle} />
              <Bar dataKey="count" fill="#3B82F6" radius={[4, 4, 0, 0]} />
            </BarChart>
          </ResponsiveContainer>
        </Card>

        <Card className="p-5" delay={0.16}>
          <h3 className="text-sm font-semibold mb-4">Signal Strength Distribution (Real RSSI)</h3>
          <ResponsiveContainer width="100%" height={250}>
            <BarChart data={signalDistribution}>
              <CartesianGrid stroke="#1e293b" strokeDasharray="3 3" vertical={false} />
              <XAxis dataKey="range" tick={AXIS_STYLE} tickLine={false} axisLine={{ stroke: '#1e293b' }} />
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

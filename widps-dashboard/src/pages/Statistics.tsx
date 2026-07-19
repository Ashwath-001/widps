import {
  ResponsiveContainer,
  PieChart,
  Pie,
  Cell,
  Legend,
  LineChart,
  Line,
  BarChart,
  Bar,
  RadarChart,
  PolarGrid,
  PolarAngleAxis,
  PolarRadiusAxis,
  Radar,
  XAxis,
  YAxis,
  CartesianGrid,
  Tooltip,
} from 'recharts';
import Card from '../components/common/Card';
import { attackDistribution, generateThreatsOverTime, topChannels, frameTypeRadar } from '../data/mockData';

const AXIS_STYLE = { fontSize: 11, fill: '#64748B' };
const tooltipStyle = {
  contentStyle: { background: '#111827', border: '1px solid #1e293b', borderRadius: 8, fontSize: 12 },
  labelStyle: { color: '#94A3B8' },
};

const threatsOverTime = generateThreatsOverTime();

export default function Statistics() {
  return (
    <div className="space-y-6">
      <div>
        <h1 className="text-xl font-semibold">Statistics</h1>
        <p className="text-sm text-[var(--color-text-secondary)] mt-1">Aggregate detection trends for this session.</p>
      </div>

      <div className="grid grid-cols-1 lg:grid-cols-2 gap-4">
        <Card className="p-5" delay={0.03}>
          <h3 className="text-sm font-semibold mb-4">Attack Distribution</h3>
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
          <h3 className="text-sm font-semibold mb-4">Threats Over Time</h3>
          <ResponsiveContainer width="100%" height={260}>
            <LineChart data={threatsOverTime}>
              <CartesianGrid stroke="#1e293b" strokeDasharray="3 3" vertical={false} />
              <XAxis dataKey="t" tick={AXIS_STYLE} tickLine={false} axisLine={{ stroke: '#1e293b' }} interval={3} />
              <YAxis tick={AXIS_STYLE} tickLine={false} axisLine={false} />
              <Tooltip {...tooltipStyle} />
              <Line type="monotone" dataKey="count" stroke="#EF4444" strokeWidth={2} dot={false} />
            </LineChart>
          </ResponsiveContainer>
        </Card>

        <Card className="p-5" delay={0.09}>
          <h3 className="text-sm font-semibold mb-4">Top Channels by Attack Count</h3>
          <ResponsiveContainer width="100%" height={260}>
            <BarChart data={topChannels} layout="vertical">
              <CartesianGrid stroke="#1e293b" strokeDasharray="3 3" horizontal={false} />
              <XAxis type="number" tick={AXIS_STYLE} tickLine={false} axisLine={{ stroke: '#1e293b' }} />
              <YAxis dataKey="channel" type="category" tick={AXIS_STYLE} tickLine={false} axisLine={false} width={50} />
              <Tooltip {...tooltipStyle} />
              <Bar dataKey="attackCount" fill="#3B82F6" radius={[0, 4, 4, 0]} />
            </BarChart>
          </ResponsiveContainer>
        </Card>

        <Card className="p-5" delay={0.12}>
          <h3 className="text-sm font-semibold mb-4">Frame Type Distribution</h3>
          <ResponsiveContainer width="100%" height={260}>
            <RadarChart data={frameTypeRadar}>
              <PolarGrid stroke="#1e293b" />
              <PolarAngleAxis dataKey="frameType" tick={AXIS_STYLE} />
              <PolarRadiusAxis tick={false} axisLine={false} domain={[0, 100]} />
              <Radar dataKey="value" stroke="#3B82F6" fill="#3B82F6" fillOpacity={0.3} />
              <Tooltip {...tooltipStyle} />
            </RadarChart>
          </ResponsiveContainer>
        </Card>
      </div>
    </div>
  );
}

import React from 'react';
import {
  AreaChart,
  Area,
  XAxis,
  YAxis,
  Tooltip,
  ResponsiveContainer,
  PieChart,
  Pie,
  Cell,
  Legend
} from 'recharts';
import { TrendingUp, PieChart as PieIcon } from 'lucide-react';

export function Charts({ metricsHistory, logs }) {
  // Protocol Distribution calculation from buffered logs
  const protocolCounts = logs.reduce((acc, log) => {
    const proto = log.protocol ? log.protocol.toUpperCase() : 'OTHER';
    acc[proto] = (acc[proto] || 0) + 1;
    return acc;
  }, {});

  const pieData = Object.keys(protocolCounts).map((proto) => ({
    name: proto,
    value: protocolCounts[proto],
  }));

  const COLORS = ['#00f0ff', '#3b82f6', '#8b5cf6', '#10b981', '#f59e0b', '#ef4444'];

  return (
    <div className="charts-grid">
      <div className="card-panel">
        <div className="panel-header">
          <div className="panel-title">
            <TrendingUp size={18} style={{ color: '#00f0ff' }} />
            <span>Ingestion Throughput Trend (Logs / sec)</span>
          </div>
        </div>

        <div className="chart-container">
          <ResponsiveContainer width="100%" height="100%">
            <AreaChart data={metricsHistory} margin={{ top: 10, right: 20, left: -20, bottom: 0 }}>
              <defs>
                <linearGradient id="colorLps" x1="0" y1="0" x2="0" y2="1">
                  <stop offset="5%" stopColor="#00f0ff" stopOpacity={0.4} />
                  <stop offset="95%" stopColor="#00f0ff" stopOpacity={0.0} />
                </linearGradient>
              </defs>
              <XAxis dataKey="time" stroke="#6b7280" fontSize={11} />
              <YAxis stroke="#6b7280" fontSize={11} />
              <Tooltip
                contentStyle={{
                  backgroundColor: '#111827',
                  borderColor: 'rgba(0, 240, 255, 0.3)',
                  borderRadius: '8px',
                  color: '#ffffff',
                  fontSize: '0.85rem',
                }}
                itemStyle={{ color: '#00f0ff', fontWeight: 600 }}
                labelStyle={{ color: '#ffffff', fontWeight: 600 }}
              />
              <Area
                type="monotone"
                dataKey="throughput_lps"
                name="Logs / sec"
                stroke="#00f0ff"
                strokeWidth={2}
                fillOpacity={1}
                fill="url(#colorLps)"
              />
            </AreaChart>
          </ResponsiveContainer>
        </div>
      </div>

      <div className="card-panel">
        <div className="panel-header">
          <div className="panel-title">
            <PieIcon size={18} style={{ color: '#8b5cf6' }} />
            <span>Protocol Distribution</span>
          </div>
        </div>

        <div className="chart-container">
          <ResponsiveContainer width="100%" height="100%">
            <PieChart>
              <Pie
                data={pieData}
                cx="50%"
                cy="50%"
                innerRadius={50}
                outerRadius={75}
                paddingAngle={4}
                dataKey="value"
              >
                {pieData.map((entry, index) => (
                  <Cell key={`cell-${index}`} fill={COLORS[index % COLORS.length]} />
                ))}
              </Pie>
              <Tooltip
                contentStyle={{
                  backgroundColor: '#111827',
                  borderColor: 'rgba(139, 92, 246, 0.3)',
                  borderRadius: '8px',
                  color: '#ffffff',
                  fontSize: '0.85rem',
                  boxShadow: '0 10px 25px -5px rgba(0, 0, 0, 0.5)'
                }}
                itemStyle={{ color: '#ffffff', fontWeight: 600 }}
                labelStyle={{ color: '#8b5cf6', fontWeight: 600 }}
              />
              <Legend
                verticalAlign="bottom"
                height={36}
                formatter={(value) => <span style={{ color: '#9ca3af', fontSize: '0.75rem' }}>{value}</span>}
              />
            </PieChart>
          </ResponsiveContainer>
        </div>
      </div>
    </div>
  );
}

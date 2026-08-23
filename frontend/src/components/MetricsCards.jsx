import React from 'react';
import { Activity, AlertTriangle, Wifi, Database } from 'lucide-react';

export function MetricsCards({ metrics, totalLogs }) {
  return (
    <div className="metrics-grid">
      <div className="metric-card">
        <div className="metric-info">
          <span className="metric-label">Ingestion Throughput</span>
          <span className="metric-value">{metrics.throughput_lps || 0} <small style={{ fontSize: '0.9rem', color: '#9ca3af' }}>logs/s</small></span>
          <span className="metric-sub">Real-Time Ingestion Rate</span>
        </div>
        <div className="metric-icon-box cyan">
          <Activity size={24} />
        </div>
      </div>

      <div className="metric-card">
        <div className="metric-info">
          <span className="metric-label">Active Threats</span>
          <span className="metric-value" style={{ color: metrics.active_alerts_count > 0 ? '#ef4444' : '#10b981' }}>
            {metrics.active_alerts_count || 0}
          </span>
          <span className="metric-sub">Requires SOC Review</span>
        </div>
        <div className="metric-icon-box red">
          <AlertTriangle size={24} />
        </div>
      </div>

      <div className="metric-card">
        <div className="metric-info">
          <span className="metric-label">Network Bandwidth</span>
          <span className="metric-value">{metrics.bandwidth_kbps || 0} <small style={{ fontSize: '0.9rem', color: '#9ca3af' }}>KB/s</small></span>
          <span className="metric-sub">Payload Volume</span>
        </div>
        <div className="metric-icon-box blue">
          <Wifi size={24} />
        </div>
      </div>

      <div className="metric-card">
        <div className="metric-info">
          <span className="metric-label">Buffer Capacity</span>
          <span className="metric-value">{totalLogs} <small style={{ fontSize: '0.9rem', color: '#9ca3af' }}>buffered</small></span>
          <span className="metric-sub">Active UI Memory Window</span>
        </div>
        <div className="metric-icon-box purple">
          <Database size={24} />
        </div>
      </div>
    </div>
  );
}

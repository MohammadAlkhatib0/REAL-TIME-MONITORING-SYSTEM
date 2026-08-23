import React from 'react';
import { ShieldAlert, CheckCircle, Flame } from 'lucide-react';

export function AlertFeed({ alerts, acknowledgeAlert }) {
  return (
    <div className="card-panel">
      <div className="panel-header">
        <div className="panel-title">
          <Flame size={18} style={{ color: '#ef4444' }} />
          <span>Real-Time Threat Alerts ({alerts.length})</span>
        </div>
      </div>

      <div className="alert-feed-list">
        {alerts.length === 0 ? (
          <div style={{ textAlign: 'center', padding: '2rem 1rem', color: '#6b7280', fontSize: '0.85rem' }}>
            <CheckCircle size={32} style={{ color: '#10b981', marginBottom: '0.5rem' }} />
            <p>No active security threats detected.</p>
          </div>
        ) : (
          alerts.map((alert) => {
            const isAck = alert.status === 'ACKNOWLEDGED';
            const formattedTime = alert.timestamp ? new Date(alert.timestamp).toLocaleTimeString() : '';
            return (
              <div key={alert.id || Math.random()} className={`alert-item ${alert.severity}`}>
                <div className="alert-item-header">
                  <span className={`alert-rule-badge ${alert.severity}`}>
                    {alert.rule_name}
                  </span>
                  <span className="alert-time">{formattedTime}</span>
                </div>

                <div className="alert-desc">{alert.description}</div>

                <div className="alert-footer">
                  <span>SRC: {alert.source_ip}</span>
                  {isAck ? (
                    <span style={{ color: '#10b981', display: 'flex', alignItems: 'center', gap: '0.2rem' }}>
                      <CheckCircle size={12} /> Acknowledged
                    </span>
                  ) : (
                    <button className="ack-btn" onClick={() => acknowledgeAlert(alert.id)}>
                      Acknowledge
                    </button>
                  )}
                </div>
              </div>
            );
          })
        )}
      </div>
    </div>
  );
}

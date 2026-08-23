import React, { useState } from 'react';
import { Terminal, Search, Filter } from 'lucide-react';

export function LogTable({ logs }) {
  const [searchTerm, setSearchTerm] = useState('');
  const [protocolFilter, setProtocolFilter] = useState('ALL');
  const [actionFilter, setActionFilter] = useState('ALL');

  const filteredLogs = logs.filter((log) => {
    const matchesSearch =
      searchTerm === '' ||
      log.source_ip.includes(searchTerm) ||
      log.destination_ip.includes(searchTerm) ||
      (log.message && log.message.toLowerCase().includes(searchTerm.toLowerCase()));

    const matchesProtocol =
      protocolFilter === 'ALL' || log.protocol.toUpperCase() === protocolFilter;

    const matchesAction =
      actionFilter === 'ALL' || log.action.toUpperCase() === actionFilter;

    return matchesSearch && matchesProtocol && matchesAction;
  });

  return (
    <div className="card-panel">
      <div className="panel-header">
        <div className="panel-title">
          <Terminal size={18} style={{ color: '#00f0ff' }} />
          <span>Live Network Log Stream</span>
          <span style={{ fontSize: '0.75rem', color: '#6b7280', fontWeight: '400' }}>
            ({filteredLogs.length} / {logs.length} shown)
          </span>
        </div>

        <div className="log-filters">
          <div style={{ position: 'relative', display: 'flex', alignItems: 'center' }}>
            <Search size={14} style={{ position: 'absolute', left: '10px', color: '#6b7280' }} />
            <input
              type="text"
              className="filter-input"
              placeholder="Search IP or Payload..."
              value={searchTerm}
              onChange={(e) => setSearchTerm(e.target.value)}
              style={{ paddingLeft: '2rem' }}
            />
          </div>

          <select
            className="filter-select"
            value={protocolFilter}
            onChange={(e) => setProtocolFilter(e.target.value)}
          >
            <option value="ALL">All Protocols</option>
            <option value="TCP">TCP</option>
            <option value="UDP">UDP</option>
            <option value="HTTP">HTTP</option>
            <option value="HTTPS">HTTPS</option>
          </select>

          <select
            className="filter-select"
            value={actionFilter}
            onChange={(e) => setActionFilter(e.target.value)}
          >
            <option value="ALL">All Actions</option>
            <option value="ALLOW">ALLOW</option>
            <option value="BLOCK">BLOCK</option>
          </select>
        </div>
      </div>

      <div className="table-wrapper">
        <table className="log-table">
          <thead>
            <tr>
              <th>Timestamp</th>
              <th>Source IP:Port</th>
              <th>Dest IP:Port</th>
              <th>Protocol</th>
              <th>Action</th>
              <th>Bytes</th>
              <th>Message Payload</th>
            </tr>
          </thead>
          <tbody>
            {filteredLogs.length === 0 ? (
              <tr>
                <td colSpan="7" style={{ textAlign: 'center', padding: '2rem', color: '#6b7280' }}>
                  No log records matching current filter criteria.
                </td>
              </tr>
            ) : (
              filteredLogs.map((log) => {
                const formattedTime = log.timestamp
                  ? new Date(log.timestamp).toLocaleTimeString()
                  : '';
                return (
                  <tr key={log.id || Math.random()}>
                    <td style={{ color: '#9ca3af' }}>{formattedTime}</td>
                    <td>
                      <span style={{ color: '#00f0ff' }}>{log.source_ip}</span>
                      <span style={{ color: '#6b7280' }}>:{log.source_port}</span>
                    </td>
                    <td>
                      <span>{log.destination_ip}</span>
                      <span style={{ color: '#6b7280' }}>:{log.destination_port}</span>
                    </td>
                    <td>
                      <span className="tag-protocol">{log.protocol}</span>
                    </td>
                    <td>
                      <span className={`tag-action ${log.action}`}>{log.action}</span>
                    </td>
                    <td style={{ color: '#9ca3af' }}>{log.bytes_transferred} B</td>
                    <td style={{ maxWidth: '350px', overflow: 'hidden', textOverflow: 'ellipsis' }}>
                      {log.message}
                    </td>
                  </tr>
                );
              })
            )}
          </tbody>
        </table>
      </div>
    </div>
  );
}

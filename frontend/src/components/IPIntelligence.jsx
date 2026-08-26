import React, { useState, useEffect } from 'react';
import { Shield, ShieldAlert, ShieldCheck, Lock, Unlock, Plus, Search, AlertTriangle, Eye, RefreshCw, X } from 'lucide-react';

const API_BASE = '/api';

export function IPIntelligence() {
  const [blacklist, setBlacklist] = useState([]);
  const [loading, setLoading] = useState(true);
  const [searchQuery, setSearchQuery] = useState('');
  
  // Form State for blocking IP
  const [newIp, setNewIp] = useState('');
  const [newDangerLevel, setNewDangerLevel] = useState('HIGH');
  const [newReason, setNewReason] = useState('');
  const [submitting, setSubmitting] = useState(false);
  const [message, setMessage] = useState(null);

  // Inspector State
  const [inspectIp, setInspectIp] = useState('');
  const [inspectData, setInspectData] = useState(null);
  const [inspectLoading, setInspectLoading] = useState(false);

  // Fetch Blacklist on mount & refresh
  const fetchBlacklist = async () => {
    try {
      setLoading(true);
      const res = await fetch(`${API_BASE}/ip/blacklist`);
      if (res.ok) {
        const data = await res.json();
        setBlacklist(data);
      }
    } catch (err) {
      console.error("Failed to fetch IP blacklist:", err);
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    fetchBlacklist();
  }, []);

  // Handle Block IP Submit
  const handleBlockIp = async (e) => {
    e.preventDefault();
    if (!newIp.trim()) return;

    setSubmitting(true);
    setMessage(null);

    try {
      const res = await fetch(`${API_BASE}/ip/blacklist`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          ip_address: newIp.trim(),
          danger_level: newDangerLevel,
          reason: newReason.trim() || 'Manual Administrative Block'
        })
      });

      if (res.ok) {
        const data = await res.json();
        setMessage({ type: 'success', text: `IP ${newIp} blocked successfully (${newDangerLevel} Danger Level)` });
        setNewIp('');
        setNewReason('');
        fetchBlacklist();
      } else {
        const errData = await res.json();
        setMessage({ type: 'error', text: errData.detail || 'Failed to block IP' });
      }
    } catch (err) {
      setMessage({ type: 'error', text: 'Connection error. Could not block IP.' });
    } finally {
      setSubmitting(false);
    }
  };

  // Handle Unblock IP
  const handleUnblockIp = async (ipAddress) => {
    try {
      const res = await fetch(`${API_BASE}/ip/unblacklist`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ ip_address: ipAddress })
      });

      if (res.ok) {
        setMessage({ type: 'success', text: `IP ${ipAddress} unblocked successfully!` });
        setBlacklist(prev => prev.filter(item => item.ip_address !== ipAddress));
      } else {
        setMessage({ type: 'error', text: 'Failed to unblock IP' });
      }
    } catch (err) {
      setMessage({ type: 'error', text: 'Connection error. Could not unblock IP.' });
    }
  };

  // Inspect IP
  const handleInspectIp = async (ipAddress) => {
    setInspectIp(ipAddress);
    setInspectLoading(true);
    try {
      const res = await fetch(`${API_BASE}/ip/${ipAddress}/info`);
      if (res.ok) {
        const data = await res.json();
        setInspectData(data);
      }
    } catch (err) {
      console.error("Failed to inspect IP:", err);
    } finally {
      setInspectLoading(false);
    }
  };

  // Filter Blacklist
  const filteredList = blacklist.filter(item =>
    item.ip_address.toLowerCase().includes(searchQuery.toLowerCase()) ||
    (item.reason && item.reason.toLowerCase().includes(searchQuery.toLowerCase())) ||
    (item.danger_level && item.danger_level.toLowerCase().includes(searchQuery.toLowerCase()))
  );

  // Danger Level Badge Styling
  const getDangerBadge = (level) => {
    const lvl = (level || 'HIGH').toUpperCase();
    if (lvl === 'CRITICAL') {
      return <span className="badge badge-critical"><AlertTriangle size={12} /> CRITICAL</span>;
    } else if (lvl === 'HIGH') {
      return <span className="badge badge-high"><ShieldAlert size={12} /> HIGH</span>;
    } else if (lvl === 'MEDIUM') {
      return <span className="badge badge-medium"><Shield size={12} /> MEDIUM</span>;
    } else {
      return <span className="badge badge-low"><ShieldCheck size={12} /> LOW</span>;
    }
  };

  // Metric counts
  const criticalCount = blacklist.filter(i => (i.danger_level || '').toUpperCase() === 'CRITICAL').length;
  const highCount = blacklist.filter(i => (i.danger_level || '').toUpperCase() === 'HIGH').length;
  const mediumLowCount = blacklist.filter(i => ['MEDIUM', 'LOW'].includes((i.danger_level || '').toUpperCase())).length;

  return (
    <div className="ip-intelligence-container" style={{ padding: '1.5rem', display: 'flex', flexDirection: 'column', gap: '1.5rem' }}>
      
      {/* Page Header */}
      <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
        <div>
          <h2 style={{ fontSize: '1.4rem', fontWeight: 'bold', display: 'flex', alignItems: 'center', gap: '0.5rem', color: '#f8fafc' }}>
            <Lock size={22} color="#ef4444" /> IP Intelligence & Blacklist Management
          </h2>
          <p style={{ color: '#94a3b8', fontSize: '0.9rem', marginTop: '0.2rem' }}>
            Enforce firewall blocking policies based on IP danger levels and inspect real-time threat intelligence.
          </p>
        </div>
        <button onClick={fetchBlacklist} className="btn-secondary" style={{ display: 'flex', alignItems: 'center', gap: '0.4rem', padding: '0.5rem 1rem', background: '#1e293b', border: '1px solid #334155', borderRadius: '6px', color: '#e2e8f0', cursor: 'pointer' }}>
          <RefreshCw size={14} /> Refresh List
        </button>
      </div>

      {/* Alert Banner */}
      {message && (
        <div style={{
          padding: '0.75rem 1rem',
          borderRadius: '8px',
          background: message.type === 'success' ? 'rgba(34, 197, 94, 0.15)' : 'rgba(239, 68, 68, 0.15)',
          border: `1px solid ${message.type === 'success' ? '#22c55e' : '#ef4444'}`,
          color: message.type === 'success' ? '#4ade80' : '#f87171',
          display: 'flex',
          justify: 'space-between',
          alignItems: 'center'
        }}>
          <span>{message.text}</span>
          <button onClick={() => setMessage(null)} style={{ background: 'none', border: 'none', color: 'inherit', cursor: 'pointer' }}>
            <X size={16} />
          </button>
        </div>
      )}

      {/* Summary Cards */}
      <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(220px, 1fr))', gap: '1rem' }}>
        <div className="card-panel" style={{ background: '#0f172a', border: '1px solid #1e293b', borderRadius: '10px', padding: '1rem' }}>
          <span style={{ color: '#94a3b8', fontSize: '0.85rem' }}>Total Blacklisted IPs</span>
          <div style={{ fontSize: '1.8rem', fontWeight: 'bold', color: '#ef4444', marginTop: '0.3rem' }}>{blacklist.length}</div>
        </div>

        <div className="card-panel" style={{ background: '#0f172a', border: '1px solid #1e293b', borderRadius: '10px', padding: '1rem' }}>
          <span style={{ color: '#94a3b8', fontSize: '0.85rem' }}>Critical Danger Level</span>
          <div style={{ fontSize: '1.8rem', fontWeight: 'bold', color: '#f43f5e', marginTop: '0.3rem' }}>{criticalCount}</div>
        </div>

        <div className="card-panel" style={{ background: '#0f172a', border: '1px solid #1e293b', borderRadius: '10px', padding: '1rem' }}>
          <span style={{ color: '#94a3b8', fontSize: '0.85rem' }}>High Danger Level</span>
          <div style={{ fontSize: '1.8rem', fontWeight: 'bold', color: '#f97316', marginTop: '0.3rem' }}>{highCount}</div>
        </div>

        <div className="card-panel" style={{ background: '#0f172a', border: '1px solid #1e293b', borderRadius: '10px', padding: '1rem' }}>
          <span style={{ color: '#94a3b8', fontSize: '0.85rem' }}>Medium / Low Danger</span>
          <div style={{ fontSize: '1.8rem', fontWeight: 'bold', color: '#eab308', marginTop: '0.3rem' }}>{mediumLowCount}</div>
        </div>
      </div>

      {/* Block IP Form */}
      <div style={{ background: '#0f172a', border: '1px solid #1e293b', borderRadius: '10px', padding: '1.25rem' }}>
        <h3 style={{ fontSize: '1.1rem', fontWeight: '600', color: '#f8fafc', marginBottom: '1rem', display: 'flex', alignItems: 'center', gap: '0.5rem' }}>
          <Plus size={18} color="#3b82f6" /> Add IP to Blacklist (Block IP)
        </h3>
        
        <form onSubmit={handleBlockIp} style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(200px, 1fr))', gap: '1rem', alignItems: 'end' }}>
          <div>
            <label style={{ display: 'block', fontSize: '0.85rem', color: '#94a3b8', marginBottom: '0.4rem' }}>IP Address</label>
            <input
              type="text"
              placeholder="e.g. 198.51.100.250"
              value={newIp}
              onChange={(e) => setNewIp(e.target.value)}
              style={{ width: '100%', padding: '0.6rem 0.8rem', background: '#1e293b', border: '1px solid #334155', borderRadius: '6px', color: '#f8fafc' }}
              required
            />
          </div>

          <div>
            <label style={{ display: 'block', fontSize: '0.85rem', color: '#94a3b8', marginBottom: '0.4rem' }}>Danger Level</label>
            <select
              value={newDangerLevel}
              onChange={(e) => setNewDangerLevel(e.target.value)}
              style={{ width: '100%', padding: '0.6rem 0.8rem', background: '#1e293b', border: '1px solid #334155', borderRadius: '6px', color: '#f8fafc' }}
            >
              <option value="CRITICAL">🔴 CRITICAL (Immediate Block & Alert)</option>
              <option value="HIGH">🟧 HIGH (Strict Inspection & Block)</option>
              <option value="MEDIUM">🟨 MEDIUM (Suspicious Activity)</option>
              <option value="LOW">🟦 LOW (Monitored IP)</option>
            </select>
          </div>

          <div>
            <label style={{ display: 'block', fontSize: '0.85rem', color: '#94a3b8', marginBottom: '0.4rem' }}>Reason / Notes</label>
            <input
              type="text"
              placeholder="Reason for blocking..."
              value={newReason}
              onChange={(e) => setNewReason(e.target.value)}
              style={{ width: '100%', padding: '0.6rem 0.8rem', background: '#1e293b', border: '1px solid #334155', borderRadius: '6px', color: '#f8fafc' }}
            />
          </div>

          <button
            type="submit"
            disabled={submitting}
            style={{
              padding: '0.65rem 1.2rem',
              background: '#ef4444',
              border: 'none',
              borderRadius: '6px',
              color: '#ffffff',
              fontWeight: '600',
              cursor: submitting ? 'not-allowed' : 'pointer',
              display: 'flex',
              alignItems: 'center',
              justifyContent: 'center',
              gap: '0.5rem'
            }}
          >
            <Lock size={16} /> {submitting ? 'Blocking...' : 'Block IP'}
          </button>
        </form>
      </div>

      {/* Blacklist Table */}
      <div style={{ background: '#0f172a', border: '1px solid #1e293b', borderRadius: '10px', padding: '1.25rem' }}>
        <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: '1rem', flexWrap: 'wrap', gap: '0.8rem' }}>
          <h3 style={{ fontSize: '1.1rem', fontWeight: '600', color: '#f8fafc', display: 'flex', alignItems: 'center', gap: '0.5rem' }}>
            <ShieldAlert size={18} color="#ef4444" /> Currently Blacklisted IP Addresses ({filteredList.length})
          </h3>

          <div style={{ position: 'relative', minWidth: '240px' }}>
            <Search size={16} color="#94a3b8" style={{ position: 'absolute', left: '0.8rem', top: '50%', transform: 'translateY(-50%)' }} />
            <input
              type="text"
              placeholder="Search IP, reason, danger level..."
              value={searchQuery}
              onChange={(e) => setSearchQuery(e.target.value)}
              style={{ width: '100%', padding: '0.5rem 0.8rem 0.5rem 2.2rem', background: '#1e293b', border: '1px solid #334155', borderRadius: '6px', color: '#f8fafc', fontSize: '0.85rem' }}
            />
          </div>
        </div>

        {loading ? (
          <div style={{ padding: '2rem', textAlign: 'center', color: '#94a3b8' }}>Loading IP Blacklist...</div>
        ) : filteredList.length === 0 ? (
          <div style={{ padding: '2rem', textAlign: 'center', color: '#64748b' }}>No blacklisted IPs found matching search.</div>
        ) : (
          <div style={{ overflowX: 'auto' }}>
            <table style={{ width: '100%', borderCollapse: 'collapse', textAlign: 'left', fontSize: '0.9rem' }}>
              <thead>
                <tr style={{ borderBottom: '1px solid #1e293b', color: '#94a3b8' }}>
                  <th style={{ padding: '0.75rem 1rem' }}>IP Address</th>
                  <th style={{ padding: '0.75rem 1rem' }}>Danger Level</th>
                  <th style={{ padding: '0.75rem 1rem' }}>Threat Hits</th>
                  <th style={{ padding: '0.75rem 1rem' }}>Blocking Reason</th>
                  <th style={{ padding: '0.75rem 1rem' }}>Date Added</th>
                  <th style={{ padding: '0.75rem 1rem', textAlign: 'right' }}>Actions</th>
                </tr>
              </thead>
              <tbody>
                {filteredList.map((item) => (
                  <tr key={item.id || item.ip_address} style={{ borderBottom: '1px solid #1e293b', color: '#e2e8f0' }}>
                    <td style={{ padding: '0.75rem 1rem', fontWeight: 'bold', fontFamily: 'monospace', color: '#f8fafc' }}>
                      {item.ip_address}
                    </td>
                    <td style={{ padding: '0.75rem 1rem' }}>
                      {getDangerBadge(item.danger_level)}
                    </td>
                    <td style={{ padding: '0.75rem 1rem' }}>
                      <span style={{ padding: '0.2rem 0.5rem', background: '#1e293b', borderRadius: '4px', fontWeight: '600', color: item.threat_count > 0 ? '#ef4444' : '#94a3b8' }}>
                        {item.threat_count || 0} hits
                      </span>
                    </td>
                    <td style={{ padding: '0.75rem 1rem', color: '#94a3b8', maxWidth: '280px', overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap' }}>
                      {item.reason || 'Manual Blacklist'}
                    </td>
                    <td style={{ padding: '0.75rem 1rem', color: '#64748b', fontSize: '0.85rem' }}>
                      {item.created_at ? new Date(item.created_at).toLocaleString() : 'N/A'}
                    </td>
                    <td style={{ padding: '0.75rem 1rem', textAlign: 'right' }}>
                      <div style={{ display: 'flex', justifyContent: 'flex-end', gap: '0.5rem' }}>
                        <button
                          onClick={() => handleInspectIp(item.ip_address)}
                          style={{ background: '#1e293b', border: '1px solid #334155', color: '#38bdf8', borderRadius: '4px', padding: '0.35rem 0.6rem', cursor: 'pointer', display: 'flex', alignItems: 'center', gap: '0.3rem', fontSize: '0.8rem' }}
                        >
                          <Eye size={14} /> Inspect
                        </button>
                        <button
                          onClick={() => handleUnblockIp(item.ip_address)}
                          style={{ background: 'rgba(34, 197, 94, 0.15)', border: '1px solid #22c55e', color: '#4ade80', borderRadius: '4px', padding: '0.35rem 0.6rem', cursor: 'pointer', display: 'flex', alignItems: 'center', gap: '0.3rem', fontSize: '0.8rem' }}
                        >
                          <Unlock size={14} /> Unblock
                        </button>
                      </div>
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        )}
      </div>

      {/* IP Inspector Modal */}
      {inspectIp && (
        <div style={{ position: 'fixed', inset: 0, background: 'rgba(0, 0, 0, 0.75)', backdropFilter: 'blur(4px)', display: 'flex', alignItems: 'center', justifyContent: 'center', zIndex: 1000, padding: '1rem' }}>
          <div style={{ background: '#0f172a', border: '1px solid #334155', borderRadius: '12px', padding: '1.5rem', maxWidth: '600px', width: '100%', color: '#f8fafc' }}>
            <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: '1rem', borderBottom: '1px solid #1e293b', paddingBottom: '0.75rem' }}>
              <h3 style={{ fontSize: '1.2rem', fontWeight: 'bold', display: 'flex', alignItems: 'center', gap: '0.5rem' }}>
                <Eye size={20} color="#38bdf8" /> IP Intelligence Telemetry: <span style={{ fontFamily: 'monospace', color: '#38bdf8' }}>{inspectIp}</span>
              </h3>
              <button onClick={() => setInspectIp('')} style={{ background: 'none', border: 'none', color: '#94a3b8', cursor: 'pointer' }}>
                <X size={20} />
              </button>
            </div>

            {inspectLoading ? (
              <div style={{ padding: '2rem', textAlign: 'center', color: '#94a3b8' }}>Fetching IP Telemetry...</div>
            ) : inspectData ? (
              <div style={{ display: 'flex', flexDirection: 'column', gap: '1rem' }}>
                <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: '1rem' }}>
                  <div style={{ background: '#1e293b', padding: '0.8rem', borderRadius: '6px' }}>
                    <span style={{ color: '#94a3b8', fontSize: '0.8rem' }}>Blacklist Status</span>
                    <div style={{ fontWeight: 'bold', marginTop: '0.2rem', color: inspectData.is_blacklisted ? '#ef4444' : '#22c55e' }}>
                      {inspectData.is_blacklisted ? '🔒 BLACKLISTED' : '✅ CLEAN'}
                    </div>
                  </div>
                  <div style={{ background: '#1e293b', padding: '0.8rem', borderRadius: '6px' }}>
                    <span style={{ color: '#94a3b8', fontSize: '0.8rem' }}>Danger Level</span>
                    <div style={{ marginTop: '0.2rem' }}>{getDangerBadge(inspectData.danger_level)}</div>
                  </div>
                  <div style={{ background: '#1e293b', padding: '0.8rem', borderRadius: '6px' }}>
                    <span style={{ color: '#94a3b8', fontSize: '0.8rem' }}>Total Network Logs</span>
                    <div style={{ fontSize: '1.2rem', fontWeight: 'bold' }}>{inspectData.total_logs}</div>
                  </div>
                  <div style={{ background: '#1e293b', padding: '0.8rem', borderRadius: '6px' }}>
                    <span style={{ color: '#94a3b8', fontSize: '0.8rem' }}>Total Threat Alerts</span>
                    <div style={{ fontSize: '1.2rem', fontWeight: 'bold', color: '#ef4444' }}>{inspectData.total_alerts}</div>
                  </div>
                </div>

                {inspectData.recent_alerts && inspectData.recent_alerts.length > 0 && (
                  <div>
                    <h4 style={{ fontSize: '0.95rem', fontWeight: '600', color: '#94a3b8', marginBottom: '0.5rem' }}>Recent Threat Detections</h4>
                    <div style={{ display: 'flex', flexDirection: 'column', gap: '0.4rem', maxHeight: '180px', overflowY: 'auto' }}>
                      {inspectData.recent_alerts.map(a => (
                        <div key={a.id} style={{ background: '#1e293b', padding: '0.6rem 0.8rem', borderRadius: '6px', fontSize: '0.85rem' }}>
                          <div style={{ display: 'flex', justifyContent: 'space-between', fontWeight: '600', color: '#ef4444' }}>
                            <span>{a.rule_name}</span>
                            <span>{a.severity}</span>
                          </div>
                          <div style={{ color: '#cbd5e1', marginTop: '0.2rem' }}>{a.description}</div>
                        </div>
                      ))}
                    </div>
                  </div>
                )}
              </div>
            ) : (
              <div style={{ padding: '1rem', color: '#ef4444' }}>Could not load data for this IP.</div>
            )}
          </div>
        </div>
      )}

    </div>
  );
}

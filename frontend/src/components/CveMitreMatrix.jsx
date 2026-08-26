import React, { useState, useEffect } from 'react';
import { ShieldAlert, Cpu, AlertTriangle, ExternalLink, CheckCircle, Flame, Layers } from 'lucide-react';

const API_BASE = '/api';

export function CveMitreMatrix() {
  const [matrix, setMatrix] = useState([]);
  const [loading, setLoading] = useState(true);

  useEffect(() => {
    fetch(`${API_BASE}/mitre/matrix`)
      .then(res => res.json())
      .then(data => {
        setMatrix(data);
        setLoading(false);
      })
      .catch(err => {
        console.error('Failed to load MITRE matrix:', err);
        setLoading(false);
      });
  }, []);

  const cveDatabase = [
    { cve: 'CVE-2023-34362', name: 'MOVEit Transfer SQLi RCE', cvss: 9.8, ttp: 'T1190', tactic: 'Initial Access', threat: 'SQL Injection' },
    { cve: 'CVE-2021-44228', name: 'Log4Shell Apache RCE', cvss: 10.0, ttp: 'T1059', tactic: 'Execution', threat: 'Command Injection' },
    { cve: 'CVE-2024-3094', name: 'XZ Utils SSH Bypass', cvss: 10.0, ttp: 'T1110', tactic: 'Credential Access', threat: 'Brute Force' },
    { cve: 'CVE-2023-44487', name: 'HTTP/2 Rapid Reset DDoS', cvss: 7.5, ttp: 'T1498', tactic: 'Impact', threat: 'Traffic Anomaly' }
  ];

  return (
    <div style={{ padding: '1.5rem', display: 'flex', flexDirection: 'column', gap: '1.5rem' }}>
      
      {/* Header */}
      <div>
        <h2 style={{ fontSize: '1.4rem', fontWeight: 'bold', display: 'flex', alignItems: 'center', gap: '0.5rem', color: '#f8fafc' }}>
          <Layers size={22} color="#f59e0b" /> MITRE ATT&CK Framework & CVE Vulnerability Intelligence
        </h2>
        <p style={{ color: '#94a3b8', fontSize: '0.9rem', marginTop: '0.2rem' }}>
          Mapping detected network threat vectors directly to MITRE ATT&CK Tactics, Techniques, and NVD CVE Vulnerability Identifiers.
        </p>
      </div>

      {/* CVE Top Vulnerabilities Grid */}
      <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(260px, 1fr))', gap: '1rem' }}>
        {cveDatabase.map(item => (
          <div key={item.cve} style={{ background: '#0f172a', border: '1px solid #1e293b', borderRadius: '10px', padding: '1.25rem' }}>
            <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
              <span style={{ fontWeight: 'bold', color: '#38bdf8', fontSize: '0.9rem' }}>{item.cve}</span>
              <span style={{ padding: '0.25rem 0.5rem', borderRadius: '4px', fontSize: '0.75rem', fontWeight: 'bold', background: item.cvss >= 9.0 ? 'rgba(239, 68, 68, 0.2)' : 'rgba(245, 158, 11, 0.2)', color: item.cvss >= 9.0 ? '#ef4444' : '#f59e0b' }}>
                CVSS {item.cvss}
              </span>
            </div>
            <div style={{ fontSize: '1rem', fontWeight: '600', color: '#f8fafc', marginTop: '0.5rem' }}>{item.name}</div>
            <div style={{ fontSize: '0.8rem', color: '#94a3b8', marginTop: '0.4rem', display: 'flex', gap: '0.8rem' }}>
              <span>MITRE: <strong>{item.ttp}</strong></span>
              <span>Threat: <strong style={{ color: '#ef4444' }}>{item.threat}</strong></span>
            </div>
          </div>
        ))}
      </div>

      {/* MITRE ATT&CK Navigation Matrix Table */}
      <div style={{ background: '#0f172a', border: '1px solid #1e293b', borderRadius: '10px', padding: '1.25rem' }}>
        <h3 style={{ fontSize: '1.1rem', fontWeight: '600', color: '#f8fafc', marginBottom: '1rem', display: 'flex', alignItems: 'center', gap: '0.5rem' }}>
          <ShieldAlert size={18} color="#ef4444" /> Detected Tactics, Techniques & Procedures (TTPs)
        </h3>

        {loading ? (
          <div style={{ padding: '2rem', textAlign: 'center', color: '#94a3b8' }}>Loading MITRE ATT&CK Matrix...</div>
        ) : (
          <div style={{ overflowX: 'auto' }}>
            <table style={{ width: '100%', borderCollapse: 'collapse', textAlign: 'left', fontSize: '0.85rem' }}>
              <thead>
                <tr style={{ borderBottom: '1px solid #334155', color: '#94a3b8' }}>
                  <th style={{ padding: '0.75rem' }}>MITRE TACTIC</th>
                  <th style={{ padding: '0.75rem' }}>TECHNIQUE & ID</th>
                  <th style={{ padding: '0.75rem' }}>DETECTED RULE</th>
                  <th style={{ padding: '0.75rem' }}>SEVERITY</th>
                  <th style={{ padding: '0.75rem' }}>ACTIVE COUNT</th>
                </tr>
              </thead>
              <tbody>
                {matrix.map((row, idx) => (
                  <tr key={idx} style={{ borderBottom: '1px solid #1e293b', color: '#f8fafc' }}>
                    <td style={{ padding: '0.75rem', fontWeight: '600', color: '#38bdf8' }}>{row.tactic}</td>
                    <td style={{ padding: '0.75rem' }}>{row.technique}</td>
                    <td style={{ padding: '0.75rem', color: '#e2e8f0' }}>{row.mapped_rule}</td>
                    <td style={{ padding: '0.75rem' }}>
                      <span style={{ padding: '0.2rem 0.5rem', borderRadius: '4px', fontSize: '0.75rem', fontWeight: 'bold', background: row.severity === 'CRITICAL' ? '#991b1b' : (row.severity === 'HIGH' ? '#c2410c' : '#854d0e'), color: '#ffffff' }}>
                        {row.severity}
                      </span>
                    </td>
                    <td style={{ padding: '0.75rem', fontWeight: 'bold', color: '#f59e0b' }}>{row.detected_count} Hits</td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        )}
      </div>

    </div>
  );
}

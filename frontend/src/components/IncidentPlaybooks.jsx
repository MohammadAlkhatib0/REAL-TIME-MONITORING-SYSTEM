import React, { useState } from 'react';
import { ShieldAlert, FileText, CheckCircle2, Download, ToggleLeft, ToggleRight, ArrowRight, ShieldCheck, AlertOctagon } from 'lucide-react';

const API_BASE = '/api';

export function IncidentPlaybooks() {
  const [playbooks, setPlaybooks] = useState([
    { id: 1, name: 'Auto-Containment (IP Blacklisting)', desc: 'Automatically block IPs when Threat Score exceeds 85.0', active: true, triggerCount: 14 },
    { id: 2, name: 'L7 Rate Limiting Engine', desc: 'Throttle client requests when throughput > 100 req/sec', active: true, triggerCount: 28 },
    { id: 3, name: 'Brute Force Quarantine', desc: 'Lockout source IP after 5 consecutive auth failures', active: true, triggerCount: 9 },
    { id: 4, name: 'SIEM Webhook Integration', desc: 'Stream Critical alerts to Enterprise Splunk / Datadog', active: false, triggerCount: 0 }
  ]);

  const [downloading, setDownloading] = useState(false);

  const togglePlaybook = (id) => {
    setPlaybooks(prev => prev.map(p => p.id === id ? { ...p, active: !p.active } : p));
  };

  const handleExportAuditReport = async () => {
    setDownloading(true);
    try {
      const res = await fetch(`${API_BASE}/threats?limit=50`);
      let data = [];
      if (res.ok) {
        data = await res.json();
      }

      const auditPayload = {
        organization: "ENTERPRISE SOC INCIDENT REPORT",
        generated_at: new Date().toISOString(),
        standard: "SOC 2 Type II / ISO 27001 Compliance Audit",
        total_threats_audited: data.length,
        threat_incidents: data
      };

      const blob = new Blob([JSON.stringify(auditPayload, null, 2)], { type: 'application/json' });
      const url = URL.createObjectURL(blob);
      const a = document.createElement('a');
      a.href = url;
      a.download = `SOC2_Security_Audit_Report_${Date.now()}.json`;
      a.click();
      URL.revokeObjectURL(url);
    } catch (err) {
      console.error("Audit export failed:", err);
    } finally {
      setDownloading(false);
    }
  };

  return (
    <div style={{ padding: '1.5rem', display: 'flex', flexDirection: 'column', gap: '1.5rem' }}>
      
      {/* Header */}
      <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
        <div>
          <h2 style={{ fontSize: '1.4rem', fontWeight: 'bold', display: 'flex', alignItems: 'center', gap: '0.5rem', color: '#f8fafc' }}>
            <FileText size={22} color="#a855f7" /> Incident Response Playbooks & Compliance Audit
          </h2>
          <p style={{ color: '#94a3b8', fontSize: '0.9rem', marginTop: '0.2rem' }}>
            Automated SOC containment playbooks, NIST incident handling workflows, and audit report generation.
          </p>
        </div>

        <button
          onClick={handleExportAuditReport}
          disabled={downloading}
          style={{
            display: 'flex',
            alignItems: 'center',
            gap: '0.5rem',
            padding: '0.6rem 1.2rem',
            background: '#a855f7',
            border: 'none',
            borderRadius: '6px',
            color: '#ffffff',
            fontWeight: '600',
            cursor: downloading ? 'not-allowed' : 'pointer'
          }}
        >
          <Download size={16} /> {downloading ? 'Generating Audit Report...' : 'Export SOC 2 Audit Report (JSON)'}
        </button>
      </div>

      {/* Automated Containment Playbooks */}
      <div style={{ background: '#0f172a', border: '1px solid #1e293b', borderRadius: '10px', padding: '1.25rem' }}>
        <h3 style={{ fontSize: '1.1rem', fontWeight: '600', color: '#f8fafc', marginBottom: '1rem', display: 'flex', alignItems: 'center', gap: '0.5rem' }}>
          <ShieldCheck size={18} color="#22c55e" /> Active Automated Response Playbooks
        </h3>

        <div style={{ display: 'flex', flexDirection: 'column', gap: '1rem' }}>
          {playbooks.map(p => (
            <div key={p.id} style={{ background: '#1e293b', border: '1px solid #334155', borderRadius: '8px', padding: '1rem', display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
              <div>
                <div style={{ display: 'flex', alignItems: 'center', gap: '0.6rem' }}>
                  <span style={{ fontWeight: 'bold', color: '#f8fafc', fontSize: '1rem' }}>{p.name}</span>
                  <span style={{ padding: '0.2rem 0.5rem', background: '#0f172a', borderRadius: '4px', fontSize: '0.75rem', color: '#38bdf8' }}>
                    {p.triggerCount} Executions
                  </span>
                </div>
                <div style={{ fontSize: '0.85rem', color: '#94a3b8', marginTop: '0.3rem' }}>{p.desc}</div>
              </div>

              <button
                onClick={() => togglePlaybook(p.id)}
                style={{ background: 'none', border: 'none', cursor: 'pointer', color: p.active ? '#22c55e' : '#64748b' }}
              >
                {p.active ? <ToggleRight size={32} /> : <ToggleLeft size={32} />}
              </button>
            </div>
          ))}
        </div>
      </div>

      {/* Incident Matrix */}
      <div style={{ background: '#0f172a', border: '1px solid #1e293b', borderRadius: '10px', padding: '1.25rem' }}>
        <h3 style={{ fontSize: '1.1rem', fontWeight: '600', color: '#f8fafc', marginBottom: '0.8rem', display: 'flex', alignItems: 'center', gap: '0.5rem' }}>
          <AlertOctagon size={18} color="#ef4444" /> Enterprise Incident Escalation Matrix (NIST SP 800-61)
        </h3>

        <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(200px, 1fr))', gap: '1rem' }}>
          <div style={{ background: 'rgba(239, 68, 68, 0.1)', border: '1px solid #ef4444', borderRadius: '8px', padding: '1rem' }}>
            <span style={{ color: '#ef4444', fontWeight: 'bold', fontSize: '0.85rem' }}>P1 - CRITICAL INCIDENT</span>
            <div style={{ color: '#f8fafc', fontSize: '0.9rem', marginTop: '0.4rem', fontWeight: '600' }}>SQL Injection / Ransomware C2</div>
            <div style={{ color: '#94a3b8', fontSize: '0.75rem', marginTop: '0.2rem' }}>Auto-quarantine & Page On-Call SOC Director within 5 mins</div>
          </div>

          <div style={{ background: 'rgba(249, 115, 22, 0.1)', border: '1px solid #f97316', borderRadius: '8px', padding: '1rem' }}>
            <span style={{ color: '#f97316', fontWeight: 'bold', fontSize: '0.85rem' }}>P2 - HIGH INCIDENT</span>
            <div style={{ color: '#f8fafc', fontSize: '0.9rem', marginTop: '0.4rem', fontWeight: '600' }}>DDoS / Port Scanning</div>
            <div style={{ color: '#94a3b8', fontSize: '0.75rem', marginTop: '0.2rem' }}>Apply L7 rate limiting & notify Tier 2 Security Analyst</div>
          </div>

          <div style={{ background: 'rgba(234, 179, 8, 0.1)', border: '1px solid #eab308', borderRadius: '8px', padding: '1rem' }}>
            <span style={{ color: '#eab308', fontWeight: 'bold', fontSize: '0.85rem' }}>P3 - MEDIUM INCIDENT</span>
            <div style={{ color: '#f8fafc', fontSize: '0.9rem', marginTop: '0.4rem', fontWeight: '600' }}>Brute Force Logins</div>
            <div style={{ color: '#94a3b8', fontSize: '0.75rem', marginTop: '0.2rem' }}>Enforce 15-minute IP lock & MFA prompt</div>
          </div>
        </div>
      </div>

    </div>
  );
}

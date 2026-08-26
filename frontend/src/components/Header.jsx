import React from 'react';
import { Shield, Play, Pause, LayoutDashboard, Lock, Globe, FileText, Layers } from 'lucide-react';

export function Header({ isConnected, isPaused, togglePause, activeTab, setActiveTab }) {
  return (
    <header className="header-bar">
      <div className="brand-section">
        <div className="brand-logo">
          <Shield size={24} />
        </div>
        <div>
          <div className="brand-title">CYBERSENTINEL</div>
          <div className="brand-subtitle">Real-Time Threat Detection & Log Ingestion Engine</div>
        </div>
      </div>

      {/* Navigation Tabs */}
      <div style={{ display: 'flex', gap: '0.3rem', background: '#0f172a', padding: '0.3rem', borderRadius: '8px', border: '1px solid #1e293b' }}>
        <button
          onClick={() => setActiveTab('dashboard')}
          style={{
            padding: '0.45rem 0.8rem',
            borderRadius: '6px',
            border: 'none',
            background: activeTab === 'dashboard' ? '#3b82f6' : 'transparent',
            color: activeTab === 'dashboard' ? '#ffffff' : '#94a3b8',
            fontWeight: '600',
            cursor: 'pointer',
            display: 'flex',
            alignItems: 'center',
            gap: '0.4rem',
            fontSize: '0.85rem'
          }}
        >
          <LayoutDashboard size={15} /> Dashboard
        </button>

        <button
          onClick={() => setActiveTab('geo-map')}
          style={{
            padding: '0.45rem 0.8rem',
            borderRadius: '6px',
            border: 'none',
            background: activeTab === 'geo-map' ? '#0284c7' : 'transparent',
            color: activeTab === 'geo-map' ? '#ffffff' : '#94a3b8',
            fontWeight: '600',
            cursor: 'pointer',
            display: 'flex',
            alignItems: 'center',
            gap: '0.4rem',
            fontSize: '0.85rem'
          }}
        >
          <Globe size={15} /> Geo-Threats & Simulator
        </button>

        <button
          onClick={() => setActiveTab('ip-intelligence')}
          style={{
            padding: '0.45rem 0.8rem',
            borderRadius: '6px',
            border: 'none',
            background: activeTab === 'ip-intelligence' ? '#ef4444' : 'transparent',
            color: activeTab === 'ip-intelligence' ? '#ffffff' : '#94a3b8',
            fontWeight: '600',
            cursor: 'pointer',
            display: 'flex',
            alignItems: 'center',
            gap: '0.4rem',
            fontSize: '0.85rem'
          }}
        >
          <Lock size={15} /> IP Blacklist
        </button>

        <button
          onClick={() => setActiveTab('playbooks')}
          style={{
            padding: '0.45rem 0.8rem',
            borderRadius: '6px',
            border: 'none',
            background: activeTab === 'playbooks' ? '#a855f7' : 'transparent',
            color: activeTab === 'playbooks' ? '#ffffff' : '#94a3b8',
            fontWeight: '600',
            cursor: 'pointer',
            display: 'flex',
            alignItems: 'center',
            gap: '0.4rem',
            fontSize: '0.85rem'
          }}
        >
          <FileText size={15} /> Playbooks & Audit
        </button>

        <button
          onClick={() => setActiveTab('cve-matrix')}
          style={{
            padding: '0.45rem 0.8rem',
            borderRadius: '6px',
            border: 'none',
            background: activeTab === 'cve-matrix' ? '#f59e0b' : 'transparent',
            color: activeTab === 'cve-matrix' ? '#ffffff' : '#94a3b8',
            fontWeight: '600',
            cursor: 'pointer',
            display: 'flex',
            alignItems: 'center',
            gap: '0.4rem',
            fontSize: '0.85rem'
          }}
        >
          <Layers size={15} /> MITRE & CVE Matrix
        </button>
      </div>

      <div className="status-controls">
        <div className={`pulse-badge ${isConnected ? 'live' : 'disconnected'}`}>
          <span className="pulse-dot"></span>
          {isConnected ? (isPaused ? 'STREAM PAUSED' : 'LIVE STREAM') : 'RECONNECTING'}
        </div>

        <button 
          className={`action-btn ${isPaused ? 'active' : ''}`}
          onClick={togglePause}
          title={isPaused ? 'Resume Stream' : 'Pause Stream'}
        >
          {isPaused ? <Play size={16} /> : <Pause size={16} />}
          <span>{isPaused ? 'Resume' : 'Pause'}</span>
        </button>
      </div>
    </header>
  );
}

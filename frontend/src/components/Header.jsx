import React from 'react';
import { Shield, Play, Pause, LayoutDashboard, Lock } from 'lucide-react';

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
      <div style={{ display: 'flex', gap: '0.5rem', background: '#0f172a', padding: '0.3rem', borderRadius: '8px', border: '1px solid #1e293b' }}>
        <button
          onClick={() => setActiveTab('dashboard')}
          style={{
            padding: '0.5rem 1rem',
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
          <LayoutDashboard size={16} /> Live Dashboard
        </button>

        <button
          onClick={() => setActiveTab('ip-intelligence')}
          style={{
            padding: '0.5rem 1rem',
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
          <Lock size={16} /> IP Intelligence & Blacklist
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

import React from 'react';
import { Shield, Play, Pause, Radio, RefreshCw } from 'lucide-react';

export function Header({ isConnected, isPaused, togglePause, logCount }) {
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

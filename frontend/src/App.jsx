import React, { useState } from 'react';
import { useWebSocket } from './hooks/useWebSocket';
import { Header } from './components/Header';
import { MetricsCards } from './components/MetricsCards';
import { AlertFeed } from './components/AlertFeed';
import { LogTable } from './components/LogTable';
import { Charts } from './components/Charts';
import { IPIntelligence } from './components/IPIntelligence';
import { GeoThreatMap } from './components/GeoThreatMap';
import { IncidentPlaybooks } from './components/IncidentPlaybooks';

export default function App() {
  const [activeTab, setActiveTab] = useState('dashboard');

  const {
    isConnected,
    isPaused,
    togglePause,
    logs,
    alerts,
    metrics,
    metricsHistory,
    acknowledgeAlert,
  } = useWebSocket();

  return (
    <div className="app-container">
      <Header
        isConnected={isConnected}
        isPaused={isPaused}
        togglePause={togglePause}
        logCount={logs.length}
        activeTab={activeTab}
        setActiveTab={setActiveTab}
      />

      {activeTab === 'dashboard' && (
        <>
          <MetricsCards metrics={metrics} totalLogs={logs.length} />
          <Charts metricsHistory={metricsHistory} logs={logs} />
          <div className="dashboard-grid">
            <LogTable logs={logs} />
            <AlertFeed alerts={alerts} acknowledgeAlert={acknowledgeAlert} />
          </div>
        </>
      )}

      {activeTab === 'geo-map' && <GeoThreatMap />}
      {activeTab === 'ip-intelligence' && <IPIntelligence />}
      {activeTab === 'playbooks' && <IncidentPlaybooks />}
    </div>
  );
}

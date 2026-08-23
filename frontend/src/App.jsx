import React from 'react';
import { useWebSocket } from './hooks/useWebSocket';
import { Header } from './components/Header';
import { MetricsCards } from './components/MetricsCards';
import { AlertFeed } from './components/AlertFeed';
import { LogTable } from './components/LogTable';
import { Charts } from './components/Charts';

export default function App() {
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
      />

      <MetricsCards metrics={metrics} totalLogs={logs.length} />

      <Charts metricsHistory={metricsHistory} logs={logs} />

      <div className="dashboard-grid">
        <LogTable logs={logs} />
        <AlertFeed alerts={alerts} acknowledgeAlert={acknowledgeAlert} />
      </div>
    </div>
  );
}

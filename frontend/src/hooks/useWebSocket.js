import { useState, useEffect, useRef, useCallback } from 'react';

const WS_URL = 'ws://127.0.0.1:8000/ws/live-feed';

export function useWebSocket() {
  const [isConnected, setIsConnected] = useState(false);
  const [isPaused, setIsPaused] = useState(false);
  const [logs, setLogs] = useState([]);
  const [alerts, setAlerts] = useState([]);
  const [metrics, setMetrics] = useState({
    throughput_lps: 0.0,
    active_alerts_count: 0,
    bandwidth_kbps: 0.0,
  });
  const [metricsHistory, setMetricsHistory] = useState([]);
  
  const wsRef = useRef(null);
  const isPausedRef = useRef(isPaused);

  useEffect(() => {
    isPausedRef.current = isPaused;
  }, [isPaused]);

  const connect = useCallback(() => {
    const ws = new WebSocket(WS_URL);
    wsRef.current = ws;

    ws.onopen = () => {
      console.log('[WebSocket] Connected to live feed');
      setIsConnected(true);
    };

    ws.onmessage = (event) => {
      try {
        const data = JSON.parse(event.data);
        const { type, payload } = data;

        if (type === 'INITIAL_STATE') {
          setLogs(payload.logs || []);
          setAlerts(payload.alerts || []);
          if (payload.metrics) {
            setMetrics(payload.metrics);
          }
        } else if (type === 'LOG') {
          if (!isPausedRef.current) {
            setLogs((prev) => [payload, ...prev.slice(0, 99)]);
          }
        } else if (type === 'ALERT') {
          setAlerts((prev) => [payload, ...prev.slice(0, 49)]);
          setMetrics((prev) => ({
            ...prev,
            active_alerts_count: prev.active_alerts_count + 1,
          }));
        } else if (type === 'ALERT_UPDATE') {
          setAlerts((prev) =>
            prev.map((a) => (a.id === payload.id ? payload : a))
          );
        } else if (type === 'METRICS') {
          setMetrics(payload);
          setMetricsHistory((prev) => {
            const updated = [...prev, { ...payload, time: new Date().toLocaleTimeString() }];
            return updated.slice(-20); // Keep last 20 snapshot data points
          });
        }
      } catch (err) {
        console.error('[WebSocket] Parsing error:', err);
      }
    };

    ws.onclose = () => {
      console.log('[WebSocket] Disconnected. Reconnecting in 3s...');
      setIsConnected(false);
      setTimeout(() => connect(), 3000);
    };

    ws.onerror = (err) => {
      console.error('[WebSocket] Error:', err);
      ws.close();
    };
  }, []);

  useEffect(() => {
    connect();
    return () => {
      if (wsRef.current) wsRef.current.close();
    };
  }, [connect]);

  const acknowledgeAlert = async (alertId) => {
    try {
      const res = await fetch(`http://127.0.0.1:8000/api/alerts/${alertId}/status?status=ACKNOWLEDGED`, {
        method: 'PUT',
      });
      if (res.ok) {
        setAlerts((prev) =>
          prev.map((a) => (a.id === alertId ? { ...a, status: 'ACKNOWLEDGED' } : a))
        );
      }
    } catch (err) {
      console.error('Error acknowledging alert:', err);
    }
  };

  const togglePause = () => setIsPaused((prev) => !prev);

  return {
    isConnected,
    isPaused,
    togglePause,
    logs,
    alerts,
    metrics,
    metricsHistory,
    acknowledgeAlert,
  };
}

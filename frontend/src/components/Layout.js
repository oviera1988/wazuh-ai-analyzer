import React, { useState, useEffect } from 'react';
import { Link } from 'react-router-dom';
import { syncAlerts, getSyncStatus } from '../utils/api';

export default function Layout({ children }) {
  const [syncStatus, setSyncStatus] = useState(null);
  const [syncing, setSyncing] = useState(false);

  useEffect(() => {
    checkStatus();
    const interval = setInterval(checkStatus, 5000);
    return () => clearInterval(interval);
  }, []);

  async function checkStatus() {
    try {
      const { data } = await getSyncStatus();
      setSyncStatus(data);
      setSyncing(data.status === 'running');
    } catch (_) {}
  }

  async function handleSync() {
    setSyncing(true);
    try {
      await syncAlerts();
    } catch (e) {
      alert('Error iniciando sincronización: ' + e.message);
      setSyncing(false);
    }
  }

  return (
    <div style={{ minHeight: '100vh', display: 'flex', flexDirection: 'column' }}>
      <header style={{
        background: '#0d1117',
        borderBottom: '1px solid #30363d',
        padding: '0 24px',
        height: 56,
        display: 'flex',
        alignItems: 'center',
        justifyContent: 'space-between',
        position: 'sticky',
        top: 0,
        zIndex: 100,
      }}>
        <Link to="/" style={{ textDecoration: 'none', display: 'flex', alignItems: 'center', gap: 10 }}>
          <span style={{ fontSize: 20 }}>🛡️</span>
          <span style={{ fontWeight: 700, color: '#e6edf3', fontSize: 15 }}>Wazuh AI Analyzer</span>
        </Link>

        <div style={{ display: 'flex', alignItems: 'center', gap: 16 }}>
          {syncStatus && (
            <span style={{ fontSize: 12, color: '#8b949e' }}>
              {syncing ? (
                <span style={{ color: '#388bfd' }}>⟳ {syncStatus.message}</span>
              ) : syncStatus.last_sync ? (
                `Última sync: ${new Date(syncStatus.last_sync).toLocaleTimeString()}`
              ) : 'Sin sincronizar'}
            </span>
          )}
          <button
            className="btn btn-primary"
            onClick={handleSync}
            disabled={syncing}
          >
            {syncing ? '⟳ Sincronizando...' : '↓ Sincronizar Alertas'}
          </button>
        </div>
      </header>

      <main style={{ flex: 1, padding: '24px', maxWidth: 1400, margin: '0 auto', width: '100%' }}>
        {children}
      </main>
    </div>
  );
}

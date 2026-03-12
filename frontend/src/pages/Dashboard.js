import React, { useState, useEffect, useCallback } from 'react';
import { BarChart, Bar, XAxis, YAxis, Tooltip, ResponsiveContainer, Cell } from 'recharts';
import { getAlerts, getStats, getAgents } from '../utils/api';
import AlertRow from '../components/AlertRow';

const SEVERITY_ORDER = ['crítico', 'alto', 'medio', 'bajo', 'informativo'];
const SEV_COLORS = {
  'crítico': '#ff4d4f', 'alto': '#ff7a00',
  'medio': '#faad14', 'bajo': '#52c41a', 'informativo': '#1890ff',
};

export default function Dashboard() {
  const [alerts, setAlerts] = useState([]);
  const [stats, setStats] = useState(null);
  const [agents, setAgents] = useState([]);
  const [loading, setLoading] = useState(true);
  const [total, setTotal] = useState(0);
  const [page, setPage] = useState(0);

  // Filtros
  const [filterSeverity, setFilterSeverity] = useState('');
  const [filterAgent, setFilterAgent] = useState('');
  const [sortBy, setSortBy] = useState('ai_priority');

  const PAGE_SIZE = 50;

  const fetchAlerts = useCallback(async () => {
    setLoading(true);
    try {
      const { data } = await getAlerts({
        severity: filterSeverity || undefined,
        agent: filterAgent || undefined,
        sort_by: sortBy,
        limit: PAGE_SIZE,
        offset: page * PAGE_SIZE,
      });
      setAlerts(data.alerts);
      setTotal(data.total);
    } catch (e) {
      console.error(e);
    } finally {
      setLoading(false);
    }
  }, [filterSeverity, filterAgent, sortBy, page]);

  useEffect(() => { fetchAlerts(); }, [fetchAlerts]);

  useEffect(() => {
    getStats().then(({ data }) => setStats(data)).catch(() => {});
    getAgents().then(({ data }) => setAgents(data)).catch(() => {});
  }, []);

  const chartData = stats?.by_severity
    ? SEVERITY_ORDER.map((s) => ({ name: s, count: stats.by_severity[s] || 0 }))
    : [];

  return (
    <div>
      {/* Stats row */}
      {stats && (
        <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(160px, 1fr))', gap: 12, marginBottom: 24 }}>
          <StatCard label="Total Alertas" value={stats.total} color="#388bfd" />
          {SEVERITY_ORDER.map((s) => (
            <StatCard
              key={s}
              label={s.charAt(0).toUpperCase() + s.slice(1)}
              value={stats.by_severity?.[s] || 0}
              color={SEV_COLORS[s]}
            />
          ))}
        </div>
      )}

      <div style={{ display: 'grid', gridTemplateColumns: '1fr 300px', gap: 20 }}>
        {/* Left: Alert list */}
        <div>
          {/* Filters */}
          <div style={{
            display: 'flex', gap: 10, marginBottom: 16, alignItems: 'center', flexWrap: 'wrap',
          }}>
            <select
              value={filterSeverity}
              onChange={(e) => { setFilterSeverity(e.target.value); setPage(0); }}
              style={selectStyle}
            >
              <option value="">Todas las severidades</option>
              {SEVERITY_ORDER.map((s) => (
                <option key={s} value={s}>{s.charAt(0).toUpperCase() + s.slice(1)}</option>
              ))}
            </select>

            <select
              value={filterAgent}
              onChange={(e) => { setFilterAgent(e.target.value); setPage(0); }}
              style={selectStyle}
            >
              <option value="">Todos los agentes</option>
              {agents.map((a) => <option key={a} value={a}>{a}</option>)}
            </select>

            <select
              value={sortBy}
              onChange={(e) => { setSortBy(e.target.value); setPage(0); }}
              style={selectStyle}
            >
              <option value="ai_priority">Ordenar: Prioridad IA</option>
              <option value="timestamp">Ordenar: Más recientes</option>
              <option value="rule_level">Ordenar: Nivel Wazuh</option>
            </select>

            <span style={{ marginLeft: 'auto', color: '#8b949e', fontSize: 12 }}>
              {total} alertas
            </span>
          </div>

          {/* List */}
          {loading ? (
            <div style={{ textAlign: 'center', padding: 40, color: '#8b949e' }}>
              Cargando alertas...
            </div>
          ) : alerts.length === 0 ? (
            <div className="card" style={{ padding: 40, textAlign: 'center', color: '#8b949e' }}>
              <div style={{ fontSize: 40, marginBottom: 12 }}>🔒</div>
              <div style={{ fontWeight: 500, marginBottom: 6 }}>Sin alertas</div>
              <div style={{ fontSize: 12 }}>Presiona "Sincronizar Alertas" para descargar desde Wazuh</div>
            </div>
          ) : (
            <>
              {alerts.map((alert, i) => (
                <AlertRow key={alert.id} alert={alert} rank={page * PAGE_SIZE + i + 1} />
              ))}
              <div style={{ display: 'flex', justifyContent: 'center', gap: 8, marginTop: 16 }}>
                <button className="btn" onClick={() => setPage(p => p - 1)} disabled={page === 0}>
                  ← Anterior
                </button>
                <span style={{ padding: '6px 12px', color: '#8b949e', fontSize: 13 }}>
                  Página {page + 1} / {Math.ceil(total / PAGE_SIZE)}
                </span>
                <button className="btn" onClick={() => setPage(p => p + 1)} disabled={(page + 1) * PAGE_SIZE >= total}>
                  Siguiente →
                </button>
              </div>
            </>
          )}
        </div>

        {/* Right: Charts + top agents */}
        <div>
          <div className="card" style={{ padding: 16, marginBottom: 16 }}>
            <div style={{ fontSize: 12, fontWeight: 600, color: '#8b949e', marginBottom: 12, textTransform: 'uppercase', letterSpacing: 1 }}>
              Alertas por Severidad
            </div>
            <ResponsiveContainer width="100%" height={200}>
              <BarChart data={chartData} margin={{ left: -20 }}>
                <XAxis dataKey="name" tick={{ fill: '#8b949e', fontSize: 11 }} />
                <YAxis tick={{ fill: '#8b949e', fontSize: 11 }} />
                <Tooltip
                  contentStyle={{ background: '#1c2128', border: '1px solid #30363d', borderRadius: 6 }}
                  labelStyle={{ color: '#e6edf3' }}
                />
                <Bar dataKey="count" radius={[3, 3, 0, 0]}>
                  {chartData.map((entry) => (
                    <Cell key={entry.name} fill={SEV_COLORS[entry.name] || '#388bfd'} />
                  ))}
                </Bar>
              </BarChart>
            </ResponsiveContainer>
          </div>

          {stats?.top_agents?.length > 0 && (
            <div className="card" style={{ padding: 16 }}>
              <div style={{ fontSize: 12, fontWeight: 600, color: '#8b949e', marginBottom: 12, textTransform: 'uppercase', letterSpacing: 1 }}>
                Top Agentes
              </div>
              {stats.top_agents.slice(0, 8).map((a) => (
                <div key={a.agent} style={{
                  display: 'flex', justifyContent: 'space-between', alignItems: 'center',
                  padding: '5px 0', borderBottom: '1px solid #30363d',
                }}>
                  <span style={{ fontSize: 12, color: '#e6edf3' }}>📡 {a.agent}</span>
                  <span style={{ fontSize: 12, color: '#388bfd', fontWeight: 600 }}>{a.count}</span>
                </div>
              ))}
            </div>
          )}
        </div>
      </div>
    </div>
  );
}

function StatCard({ label, value, color }) {
  return (
    <div className="card" style={{ padding: '14px 16px' }}>
      <div style={{ fontSize: 24, fontWeight: 700, color }}>{value ?? '—'}</div>
      <div style={{ fontSize: 11, color: '#8b949e', marginTop: 2 }}>{label}</div>
    </div>
  );
}

const selectStyle = {
  background: '#1c2128',
  border: '1px solid #30363d',
  borderRadius: 6,
  color: '#e6edf3',
  padding: '5px 10px',
  fontSize: 12,
  cursor: 'pointer',
};

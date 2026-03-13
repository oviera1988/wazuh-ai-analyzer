import React, { useState, useEffect, useCallback } from 'react';
import {
  BarChart, Bar, XAxis, YAxis, Tooltip, ResponsiveContainer, Cell,
} from 'recharts';
import { getAlerts, getStats, getAgents } from '../utils/api';
import AlertRow from '../components/AlertRow';

const SEVERITY_ORDER = ['crítico', 'alto', 'medio', 'bajo', 'informativo'];
const SEV_COLORS = {
  'crítico': '#ff4d4f', 'alto': '#ff7a00',
  'medio': '#faad14', 'bajo': '#52c41a', 'informativo': '#1890ff',
};
const SEV_BG = {
  'crítico': 'rgba(255,77,79,0.12)', 'alto': 'rgba(255,122,0,0.12)',
  'medio': 'rgba(250,173,20,0.12)', 'bajo': 'rgba(82,196,26,0.12)',
  'informativo': 'rgba(24,144,255,0.12)',
};

export default function Dashboard() {
  const [alerts, setAlerts]     = useState([]);
  const [stats, setStats]       = useState(null);
  const [agents, setAgents]     = useState([]);
  const [loading, setLoading]   = useState(true);
  const [total, setTotal]       = useState(0);
  const [page, setPage]         = useState(0);
  const [filterSeverity, setFilterSeverity] = useState('');
  const [filterAgent, setFilterAgent]       = useState('');
  const [sortBy, setSortBy]                 = useState('ai_priority');
  const PAGE_SIZE = 50;

  const fetchAlerts = useCallback(async () => {
    setLoading(true);
    try {
      const { data } = await getAlerts({
        severity: filterSeverity || undefined,
        agent:    filterAgent    || undefined,
        sort_by:  sortBy,
        limit:    PAGE_SIZE,
        offset:   page * PAGE_SIZE,
      });
      setAlerts(data.alerts);
      setTotal(data.total);
    } catch (e) { console.error(e); }
    finally { setLoading(false); }
  }, [filterSeverity, filterAgent, sortBy, page]);

  useEffect(() => { fetchAlerts(); }, [fetchAlerts]);
  useEffect(() => {
    getStats().then(({ data }) => setStats(data)).catch(() => {});
    getAgents().then(({ data }) => setAgents(data)).catch(() => {});
  }, []);

  const severityChartData = stats?.by_severity
    ? SEVERITY_ORDER.map((s) => ({ name: s, count: stats.by_severity[s] || 0 })).filter(d => d.count > 0)
    : [];

  const ruleChartData = stats?.top_rules
    ? stats.top_rules.slice(0, 8).map((r) => ({
        name: r.description?.length > 32 ? r.description.slice(0, 32) + '…' : (r.description || r.rule_id),
        fullName: r.description || r.rule_id,
        count: r.count,
      }))
    : [];

  const handleSeverityClick = (sev) => { setFilterSeverity(p => p === sev ? '' : sev); setPage(0); };
  const handleAgentClick    = (agent) => { setFilterAgent(p => p === agent ? '' : agent); setPage(0); };
  const clearFilters        = () => { setFilterSeverity(''); setFilterAgent(''); setPage(0); };
  const hasFilters          = filterSeverity || filterAgent;

  return (
    <div>
      {stats && (
        <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(145px, 1fr))', gap: 10, marginBottom: 20 }}>
          <StatCard label="Total" value={stats.total} color="#388bfd" active={!filterSeverity} onClick={clearFilters} subtitle="Ver todas" />
          {SEVERITY_ORDER.map((s) => (
            <StatCard key={s} label={s.charAt(0).toUpperCase() + s.slice(1)}
              value={stats.by_severity?.[s] || 0} color={SEV_COLORS[s]} bg={SEV_BG[s]}
              active={filterSeverity === s} onClick={() => handleSeverityClick(s)}
              subtitle={filterSeverity === s ? 'Filtrando' : 'Click para filtrar'} />
          ))}
        </div>
      )}

      {hasFilters && (
        <div style={{ display: 'flex', gap: 8, marginBottom: 14, alignItems: 'center', flexWrap: 'wrap' }}>
          <span style={{ fontSize: 12, color: '#8b949e' }}>Filtros:</span>
          {filterSeverity && (
            <FilterTag color={SEV_COLORS[filterSeverity]} bg={SEV_BG[filterSeverity]} onClick={() => setFilterSeverity('')}>
              {filterSeverity} x
            </FilterTag>
          )}
          {filterAgent && (
            <FilterTag color="#388bfd" bg="rgba(56,139,253,0.1)" onClick={() => setFilterAgent('')}>
              {filterAgent} x
            </FilterTag>
          )}
          <button onClick={clearFilters} style={{ fontSize: 11, padding: '3px 10px', borderRadius: 20, background: 'transparent', border: '1px solid #30363d', color: '#8b949e', cursor: 'pointer' }}>
            Limpiar todo
          </button>
        </div>
      )}

      <div style={{ display: 'grid', gridTemplateColumns: '1fr 320px', gap: 20 }}>
        <div>
          <div style={{ display: 'flex', gap: 10, marginBottom: 14, alignItems: 'center', flexWrap: 'wrap' }}>
            <select value={filterSeverity} onChange={(e) => { setFilterSeverity(e.target.value); setPage(0); }} style={selectStyle}>
              <option value="">Todas las severidades</option>
              {SEVERITY_ORDER.map((s) => <option key={s} value={s}>{s.charAt(0).toUpperCase() + s.slice(1)}</option>)}
            </select>
            <select value={filterAgent} onChange={(e) => { setFilterAgent(e.target.value); setPage(0); }} style={selectStyle}>
              <option value="">Todos los agentes</option>
              {agents.map((a) => <option key={a} value={a}>{a}</option>)}
            </select>
            <select value={sortBy} onChange={(e) => { setSortBy(e.target.value); setPage(0); }} style={selectStyle}>
              <option value="ai_priority">Prioridad IA</option>
              <option value="timestamp">Mas recientes</option>
              <option value="rule_level">Nivel Wazuh</option>
            </select>
            <span style={{ marginLeft: 'auto', color: '#8b949e', fontSize: 12 }}>{total} alertas</span>
          </div>

          {loading ? (
            <div style={{ textAlign: 'center', padding: 40, color: '#8b949e' }}>Cargando alertas...</div>
          ) : alerts.length === 0 ? (
            <div className="card" style={{ padding: 40, textAlign: 'center', color: '#8b949e' }}>
              <div style={{ fontSize: 36, marginBottom: 10 }}>�Lock</div>
              <div style={{ fontWeight: 500 }}>Sin alertas</div>
              <div style={{ fontSize: 12, marginTop: 6 }}>
                {hasFilters ? 'No hay alertas con los filtros seleccionados.' : 'Presiona Sincronizar para descargar desde Wazuh'}
              </div>
            </div>
          ) : (
            <>
              {alerts.map((alert, i) => <AlertRow key={alert.id} alert={alert} rank={page * PAGE_SIZE + i + 1} />)}
              <div style={{ display: 'flex', justifyContent: 'center', gap: 8, marginTop: 16 }}>
                <button className="btn" onClick={() => setPage(p => p - 1)} disabled={page === 0}>Anterior</button>
                <span style={{ padding: '6px 12px', color: '#8b949e', fontSize: 13 }}>
                  Pagina {page + 1} / {Math.max(1, Math.ceil(total / PAGE_SIZE))}
                </span>
                <button className="btn" onClick={() => setPage(p => p + 1)} disabled={(page + 1) * PAGE_SIZE >= total}>Siguiente</button>
              </div>
            </>
          )}
        </div>

        <div style={{ display: 'flex', flexDirection: 'column', gap: 16 }}>

          <div className="card" style={{ padding: 16 }}>
            <SectionTitle>Por Severidad</SectionTitle>
            <ResponsiveContainer width="100%" height={170}>
              <BarChart data={severityChartData} margin={{ left: -20 }}
                onClick={(e) => e?.activeLabel && handleSeverityClick(e.activeLabel)}>
                <XAxis dataKey="name" tick={{ fill: '#8b949e', fontSize: 10 }} />
                <YAxis tick={{ fill: '#8b949e', fontSize: 10 }} />
                <Tooltip contentStyle={{ background: '#1c2128', border: '1px solid #30363d', borderRadius: 6 }} labelStyle={{ color: '#e6edf3' }} />
                <Bar dataKey="count" radius={[3, 3, 0, 0]} cursor="pointer">
                  {severityChartData.map((entry) => (
                    <Cell key={entry.name} fill={SEV_COLORS[entry.name]} opacity={filterSeverity && filterSeverity !== entry.name ? 0.25 : 1} />
                  ))}
                </Bar>
              </BarChart>
            </ResponsiveContainer>
            <div style={{ fontSize: 10, color: '#656d76', textAlign: 'center', marginTop: 2 }}>Click en barra para filtrar</div>
          </div>

          {ruleChartData.length > 0 && (
            <div className="card" style={{ padding: 16 }}>
              <SectionTitle>Top Tipos de Evento</SectionTitle>
              <ResponsiveContainer width="100%" height={230}>
                <BarChart data={ruleChartData} layout="vertical" margin={{ left: 0, right: 8 }}>
                  <XAxis type="number" tick={{ fill: '#8b949e', fontSize: 10 }} />
                  <YAxis type="category" dataKey="name" tick={{ fill: '#8b949e', fontSize: 9 }} width={115} />
                  <Tooltip
                    contentStyle={{ background: '#1c2128', border: '1px solid #30363d', borderRadius: 6 }}
                    labelStyle={{ color: '#e6edf3' }}
                    formatter={(val, name, props) => [val, props.payload.fullName]}
                  />
                  <Bar dataKey="count" radius={[0, 3, 3, 0]}>
                    {ruleChartData.map((_, i) => (
                      <Cell key={i} fill={"hsl(" + (200 + i * 18) + ", 65%, 55%)"} />
                    ))}
                  </Bar>
                </BarChart>
              </ResponsiveContainer>
            </div>
          )}

          {stats?.top_agents?.length > 0 && (
            <div className="card" style={{ padding: 16 }}>
              <SectionTitle>Top Agentes</SectionTitle>
              {stats.top_agents.slice(0, 8).map((a) => {
                const isActive = filterAgent === a.agent;
                const pct = Math.round((a.count / (stats.top_agents[0]?.count || 1)) * 100);
                return (
                  <div key={a.agent} onClick={() => handleAgentClick(a.agent)} style={{
                    padding: '6px 4px', borderBottom: '1px solid #30363d', cursor: 'pointer',
                    borderRadius: 4, background: isActive ? 'rgba(56,139,253,0.08)' : 'transparent',
                    transition: 'background 0.15s',
                  }}>
                    <div style={{ display: 'flex', justifyContent: 'space-between', marginBottom: 3 }}>
                      <span style={{ fontSize: 12, color: isActive ? '#388bfd' : '#e6edf3' }}>
                        {isActive ? '> ' : ''}{a.agent}
                      </span>
                      <span style={{ fontSize: 12, color: '#388bfd', fontWeight: 600 }}>{a.count}</span>
                    </div>
                    <div style={{ height: 3, background: '#30363d', borderRadius: 2 }}>
                      <div style={{ height: '100%', borderRadius: 2, width: pct + '%', background: isActive ? '#388bfd' : '#388bfd60', transition: 'width 0.4s' }} />
                    </div>
                  </div>
                );
              })}
              <div style={{ fontSize: 10, color: '#656d76', textAlign: 'center', marginTop: 8 }}>Click para filtrar por agente</div>
            </div>
          )}

          {stats?.top_mitre?.length > 0 && (
            <div className="card" style={{ padding: 16 }}>
              <SectionTitle>MITRE ATT&CK</SectionTitle>
              {stats.top_mitre.slice(0, 6).map((m) => (
                <div key={m.tactic} style={{ display: 'flex', justifyContent: 'space-between', padding: '4px 0', borderBottom: '1px solid #30363d' }}>
                  <span style={{ fontSize: 11, color: '#bc8cff' }}>{m.tactic}</span>
                  <span style={{ fontSize: 11, color: '#8b949e' }}>{m.count}</span>
                </div>
              ))}
            </div>
          )}

        </div>
      </div>
    </div>
  );
}

function StatCard({ label, value, color, bg, active, onClick, subtitle }) {
  return (
    <div className="card" onClick={onClick} style={{
      padding: '14px 16px', cursor: 'pointer',
      border: active ? ("1px solid " + color + "60") : '1px solid #30363d',
      background: active && bg ? bg : undefined,
      transition: 'all 0.15s', userSelect: 'none',
    }}>
      <div style={{ fontSize: 24, fontWeight: 700, color }}>{value ?? '-'}</div>
      <div style={{ fontSize: 11, color: '#8b949e', marginTop: 2 }}>{label}</div>
      {subtitle && <div style={{ fontSize: 10, color: active ? color : '#656d76', marginTop: 2 }}>{subtitle}</div>}
    </div>
  );
}

function SectionTitle({ children }) {
  return <div style={{ fontSize: 12, fontWeight: 600, color: '#8b949e', marginBottom: 12, textTransform: 'uppercase', letterSpacing: 1 }}>{children}</div>;
}

function FilterTag({ color, bg, onClick, children }) {
  return (
    <span onClick={onClick} style={{
      fontSize: 12, padding: '3px 10px', borderRadius: 20, cursor: 'pointer',
      background: bg, border: ("1px solid " + color + "50"), color,
    }}>{children}</span>
  );
}

const selectStyle = {
  background: '#1c2128', border: '1px solid #30363d', borderRadius: 6,
  color: '#e6edf3', padding: '5px 10px', fontSize: 12, cursor: 'pointer',
};

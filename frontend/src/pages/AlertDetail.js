import React, { useState, useEffect } from 'react';
import { useParams, Link } from 'react-router-dom';
import { getAlert, reprocessAlert } from '../utils/api';

const URGENCY_LABEL = {
  'inmediata': { label: '🚨 Inmediata', color: '#ff4d4f' },
  '1h': { label: '⏰ En 1 hora', color: '#ff7a00' },
  '4h': { label: '🕐 En 4 horas', color: '#faad14' },
  '24h': { label: '📅 En 24 horas', color: '#52c41a' },
  'rutina': { label: '📋 Rutina', color: '#1890ff' },
};

const PRIORITY_COLOR = (p) => {
  if (p >= 80) return '#ff4d4f';
  if (p >= 60) return '#ff7a00';
  if (p >= 40) return '#faad14';
  if (p >= 20) return '#52c41a';
  return '#1890ff';
};

function flattenObject(obj, prefix = '') {
  return Object.entries(obj || {}).reduce((acc, [key, val]) => {
    const fullKey = prefix ? `${prefix}.${key}` : key;
    if (val !== null && typeof val === 'object' && !Array.isArray(val)) {
      Object.assign(acc, flattenObject(val, fullKey));
    } else {
      acc[fullKey] = Array.isArray(val) ? val.join(', ') : String(val ?? '');
    }
    return acc;
  }, {});
}

function StructuredLog({ fullLog, rawData }) {
  const [tab, setTab] = useState('fields');

  const fields = flattenObject(rawData || {});
  const hasFields = Object.keys(fields).length > 0;

  const tabStyle = (active) => ({
    padding: '5px 14px',
    fontSize: 12,
    cursor: 'pointer',
    borderRadius: '4px 4px 0 0',
    border: '1px solid #30363d',
    borderBottom: active ? '1px solid #1c2128' : '1px solid #30363d',
    background: active ? '#1c2128' : '#0d1117',
    color: active ? '#e6edf3' : '#8b949e',
    marginRight: 4,
    userSelect: 'none',
  });

  return (
    <div>
      <div style={{ display: 'flex', marginBottom: -1, position: 'relative', zIndex: 1 }}>
        {hasFields && (
          <div style={tabStyle(tab === 'fields')} onClick={() => setTab('fields')}>
            Campos estructurados
          </div>
        )}
        <div style={tabStyle(tab === 'raw')} onClick={() => setTab('raw')}>
          Log raw
        </div>
      </div>

      <div style={{
        background: '#0d1117',
        border: '1px solid #30363d',
        borderRadius: tab === 'fields' && hasFields ? '0 4px 4px 4px' : '4px',
        padding: 12,
      }}>
        {tab === 'fields' && hasFields && (
          <table style={{ width: '100%', borderCollapse: 'collapse' }}>
            <tbody>
              {Object.entries(fields).map(([key, val]) => (
                <tr key={key} style={{ borderBottom: '1px solid #21262d' }}>
                  <td style={{
                    padding: '5px 10px 5px 0',
                    fontSize: 11,
                    color: '#388bfd',
                    fontFamily: 'monospace',
                    whiteSpace: 'nowrap',
                    verticalAlign: 'top',
                    width: '35%',
                  }}>
                    {key}
                  </td>
                  <td style={{
                    padding: '5px 0',
                    fontSize: 12,
                    color: '#e6edf3',
                    fontFamily: 'monospace',
                    wordBreak: 'break-all',
                  }}>
                    {val || <span style={{ color: '#656d76' }}>—</span>}
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        )}

        {tab === 'raw' && (
          <pre style={{
            fontSize: 11,
            color: '#8b949e',
            whiteSpace: 'pre-wrap',
            wordBreak: 'break-all',
            margin: 0,
            maxHeight: 300,
            overflow: 'auto',
          }}>
            {fullLog || JSON.stringify(rawData, null, 2) || 'Sin log disponible'}
          </pre>
        )}
      </div>
    </div>
  );
}

export default function AlertDetail() {
  const { id } = useParams();
  const [alert, setAlert] = useState(null);
  const [loading, setLoading] = useState(true);
  const [reprocessing, setReprocessing] = useState(false);

  useEffect(() => {
    getAlert(id)
      .then(({ data }) => setAlert(data))
      .catch(console.error)
      .finally(() => setLoading(false));
  }, [id]);

  async function handleReprocess() {
    setReprocessing(true);
    try {
      await reprocessAlert(id);
      setTimeout(() => {
        getAlert(id).then(({ data }) => setAlert(data));
        setReprocessing(false);
      }, 3000);
    } catch (e) {
      alert('Error: ' + e.message);
      setReprocessing(false);
    }
  }

  if (loading) return <div style={{ textAlign: 'center', padding: 60, color: '#8b949e' }}>Cargando alerta...</div>;
  if (!alert) return <div style={{ textAlign: 'center', padding: 60, color: '#ff4d4f' }}>Alerta no encontrada</div>;

  const analysis = alert.ai_analysis || {};
  const priority = alert.ai_priority || 0;

  return (
    <div style={{ maxWidth: 900, margin: '0 auto' }}>
      <div style={{ marginBottom: 20, fontSize: 13, color: '#8b949e' }}>
        <Link to="/" style={{ color: '#388bfd', textDecoration: 'none' }}>← Dashboard</Link>
        <span style={{ margin: '0 8px' }}>/</span>
        <span>Alerta #{alert.id}</span>
      </div>

      <div className="card" style={{ padding: 24, marginBottom: 20, borderLeft: `4px solid ${PRIORITY_COLOR(priority)}` }}>
        <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'flex-start', gap: 16 }}>
          <div style={{ flex: 1 }}>
            <div style={{ display: 'flex', alignItems: 'center', gap: 10, marginBottom: 8, flexWrap: 'wrap' }}>
              <span className={`badge badge-${alert.ai_severity}`}>{alert.ai_severity}</span>
              <span style={{ fontSize: 12, color: '#656d76' }}>Regla #{alert.rule_id}</span>
              <span style={{ fontSize: 12, color: '#656d76' }}>Nivel Wazuh: {alert.rule_level}/15</span>
            </div>
            <h1 style={{ fontSize: 18, fontWeight: 600, color: '#e6edf3', marginBottom: 10, lineHeight: 1.4 }}>
              {alert.rule_description}
            </h1>
            <div style={{ fontSize: 13, color: '#8b949e' }}>{analysis.executive_summary}</div>
          </div>
          <div style={{ textAlign: 'center', minWidth: 90 }}>
            <div style={{ fontSize: 36, fontWeight: 800, color: PRIORITY_COLOR(priority), lineHeight: 1 }}>{priority}</div>
            <div style={{ fontSize: 10, color: '#656d76', marginTop: 2, marginBottom: 6 }}>PRIORIDAD IA</div>
            <div className="priority-bar" style={{ width: 80 }}>
              <div className="priority-fill" style={{ width: `${priority}%`, background: PRIORITY_COLOR(priority) }} />
            </div>
          </div>
        </div>
      </div>

      <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: 20, marginBottom: 20 }}>
        <div className="card" style={{ padding: 18 }}>
          <SectionTitle>📡 Activos Afectados</SectionTitle>
          <InfoRow label="Agente" value={`${alert.agent_name} (${alert.agent_ip})`} />
          <InfoRow label="Manager" value={alert.manager_name} />
          <InfoRow label="Timestamp" value={new Date(alert.timestamp).toLocaleString('es-UY', {timeZone: 'America/Montevideo'})} />
          <InfoRow label="Activos en riesgo" value={analysis.affected_assets} />
          <InfoRow label="Falso positivo" value={analysis.false_positive_probability} />
        </div>

        <div className="card" style={{ padding: 18 }}>
          <SectionTitle>🎯 MITRE ATT&CK</SectionTitle>
          {Array.isArray(alert.mitre_id) && alert.mitre_id.length > 0 ? (
            <>
              <div style={{ display: 'flex', gap: 6, flexWrap: 'wrap', marginBottom: 10 }}>
                {alert.mitre_id.map((m) => (
                  <span key={m} style={{ padding: '3px 8px', borderRadius: 4, fontSize: 11, background: 'rgba(188,140,255,0.1)', border: '1px solid rgba(188,140,255,0.3)', color: '#bc8cff' }}>{m}</span>
                ))}
              </div>
              {analysis.mitre_analysis && (
                <div style={{ fontSize: 12, color: '#8b949e', lineHeight: 1.6 }}>{analysis.mitre_analysis}</div>
              )}
            </>
          ) : (
            <div style={{ fontSize: 12, color: '#656d76' }}>Sin técnicas MITRE identificadas</div>
          )}
          {Array.isArray(alert.rule_groups) && (
            <div style={{ marginTop: 12 }}>
              <div style={{ fontSize: 11, color: '#656d76', marginBottom: 6 }}>Grupos / Categorías:</div>
              <div style={{ display: 'flex', gap: 5, flexWrap: 'wrap' }}>
                {alert.rule_groups.map((g) => (
                  <span key={g} style={{ padding: '2px 7px', borderRadius: 4, fontSize: 11, background: '#21262d', border: '1px solid #30363d', color: '#8b949e' }}>{g}</span>
                ))}
              </div>
            </div>
          )}
        </div>
      </div>

      {analysis.threat_context && (
        <div className="card" style={{ padding: 18, marginBottom: 20, background: 'rgba(255,122,0,0.05)', borderColor: 'rgba(255,122,0,0.3)' }}>
          <SectionTitle>⚠️ Contexto de la Amenaza</SectionTitle>
          <div style={{ fontSize: 13, color: '#8b949e', lineHeight: 1.7 }}>{analysis.threat_context}</div>
        </div>
      )}

      {Array.isArray(analysis.resolution_steps) && analysis.resolution_steps.length > 0 && (
        <div className="card" style={{ padding: 20, marginBottom: 20 }}>
          <SectionTitle>🔧 Instructivo de Resolución</SectionTitle>
          <div style={{ marginTop: 12 }}>
            {analysis.resolution_steps.map((step, i) => {
              const urgency = URGENCY_LABEL[step.urgency] || { label: step.urgency, color: '#8b949e' };
              return (
                <div key={i} style={{ display: 'flex', gap: 16, padding: '14px 0', borderBottom: i < analysis.resolution_steps.length - 1 ? '1px solid #21262d' : 'none' }}>
                  <div style={{ minWidth: 36, height: 36, borderRadius: '50%', background: 'rgba(56,139,253,0.15)', border: '1px solid rgba(56,139,253,0.4)', display: 'flex', alignItems: 'center', justifyContent: 'center', fontSize: 14, fontWeight: 700, color: '#388bfd', flexShrink: 0 }}>
                    {step.step}
                  </div>
                  <div style={{ flex: 1 }}>
                    <div style={{ display: 'flex', alignItems: 'center', gap: 8, marginBottom: 4, flexWrap: 'wrap' }}>
                      <span style={{ fontWeight: 600, color: '#e6edf3', fontSize: 14 }}>{step.title}</span>
                      <span style={{ fontSize: 11, color: urgency.color, padding: '1px 7px', borderRadius: 4, background: `${urgency.color}15`, border: `1px solid ${urgency.color}30` }}>{urgency.label}</span>
                    </div>
                    <div style={{ fontSize: 13, color: '#8b949e', lineHeight: 1.7, marginBottom: step.commands?.length ? 8 : 0 }}>{step.description}</div>
                    {step.commands?.map((cmd, ci) => cmd && (
                      <div key={ci} style={{ background: '#0d1117', border: '1px solid #30363d', borderRadius: 6, padding: '8px 12px', fontFamily: 'monospace', fontSize: 12, color: '#39d353', marginTop: 6 }}>
                        $ {cmd}
                      </div>
                    ))}
                  </div>
                </div>
              );
            })}
          </div>
        </div>
      )}

      {Array.isArray(analysis.prevention_measures) && analysis.prevention_measures.length > 0 && (
        <div className="card" style={{ padding: 18, marginBottom: 20 }}>
          <SectionTitle>🛡️ Medidas Preventivas</SectionTitle>
          <ul style={{ paddingLeft: 20, marginTop: 10 }}>
            {analysis.prevention_measures.map((m, i) => (
              <li key={i} style={{ fontSize: 13, color: '#8b949e', marginBottom: 6, lineHeight: 1.6 }}>{m}</li>
            ))}
          </ul>
        </div>
      )}

      <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: 16, marginBottom: 20 }}>
        {Array.isArray(analysis.references) && analysis.references.length > 0 && (
          <div className="card" style={{ padding: 16 }}>
            <SectionTitle>🔗 Referencias</SectionTitle>
            <ul style={{ paddingLeft: 18, marginTop: 8 }}>
              {analysis.references.map((r, i) => (
                <li key={i} style={{ marginBottom: 4 }}>
                  <a href={r} target="_blank" rel="noreferrer" style={{ fontSize: 12, color: '#388bfd', wordBreak: 'break-all' }}>{r}</a>
                </li>
              ))}
            </ul>
          </div>
        )}

        <div className="card" style={{ padding: 16 }}>
          <SectionTitle>📋 Datos del Evento</SectionTitle>
          <div style={{ marginTop: 8 }}>
            <StructuredLog fullLog={alert.full_log} rawData={alert.raw_data} />
          </div>
        </div>
      </div>

      <div style={{ display: 'flex', gap: 10 }}>
        <button className="btn" onClick={handleReprocess} disabled={reprocessing}>
          {reprocessing ? '⟳ Re-procesando...' : '🤖 Re-analizar con IA'}
        </button>
        <Link to="/" className="btn">← Volver al Dashboard</Link>
      </div>
    </div>
  );
}

function SectionTitle({ children }) {
  return <div style={{ fontSize: 12, fontWeight: 600, color: '#8b949e', textTransform: 'uppercase', letterSpacing: 1, marginBottom: 12 }}>{children}</div>;
}

function InfoRow({ label, value }) {
  return (
    <div style={{ display: 'flex', gap: 8, marginBottom: 6 }}>
      <span style={{ fontSize: 12, color: '#656d76', minWidth: 110 }}>{label}:</span>
      <span style={{ fontSize: 12, color: '#e6edf3', flex: 1 }}>{value || '—'}</span>
    </div>
  );
}

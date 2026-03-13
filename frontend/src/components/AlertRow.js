import React from 'react';
import { Link } from 'react-router-dom';

const PRIORITY_COLOR = (p) => {
  if (p >= 80) return '#ff4d4f';
  if (p >= 60) return '#ff7a00';
  if (p >= 40) return '#faad14';
  if (p >= 20) return '#52c41a';
  return '#1890ff';
};

export default function AlertRow({ alert, rank }) {
  const priority = alert.ai_priority || 0;
  const analysis = alert.ai_analysis || {};

  return (
    <Link to={`/alert/${alert.id}`} style={{ textDecoration: 'none', display: 'block' }}>
      <div className="card" style={{
        padding: '14px 18px',
        marginBottom: 8,
        cursor: 'pointer',
        transition: 'all 0.15s',
        borderLeft: `3px solid ${PRIORITY_COLOR(priority)}`,
      }}>
        <div style={{ display: 'flex', alignItems: 'center', gap: 12 }}>
          {/* Rank */}
          <div style={{
            minWidth: 32,
            height: 32,
            borderRadius: 6,
            background: `${PRIORITY_COLOR(priority)}20`,
            border: `1px solid ${PRIORITY_COLOR(priority)}40`,
            display: 'flex', alignItems: 'center', justifyContent: 'center',
            fontSize: 12, fontWeight: 700, color: PRIORITY_COLOR(priority),
          }}>
            {rank}
          </div>

          {/* Main info */}
          <div style={{ flex: 1, minWidth: 0 }}>
            <div style={{ display: 'flex', alignItems: 'center', gap: 8, flexWrap: 'wrap', marginBottom: 4 }}>
              <span className={`badge badge-${alert.ai_severity}`}>
                {alert.ai_severity || 'sin clasificar'}
              </span>
              <span style={{ color: '#e6edf3', fontWeight: 500, fontSize: 13 }}>
                {alert.rule_description}
              </span>
            </div>
            <div style={{ fontSize: 12, color: '#8b949e' }}>
              {analysis.executive_summary?.slice(0, 120)}
              {analysis.executive_summary?.length > 120 ? '…' : ''}
            </div>
          </div>

          {/* Agent + time */}
          <div style={{ textAlign: 'right', minWidth: 130 }}>
            <div style={{ fontSize: 12, color: '#388bfd', marginBottom: 2 }}>
              📡 {alert.agent_name}
            </div>
            <div style={{ fontSize: 11, color: '#656d76' }}>
              {alert.timestamp ? new Date(alert.timestamp).toLocaleString('es-UY', {timeZone: 'America/Montevideo'}) : '—'}
            </div>
          </div>

          {/* Priority */}
          <div style={{ minWidth: 72, textAlign: 'center' }}>
            <div style={{ fontSize: 20, fontWeight: 700, color: PRIORITY_COLOR(priority) }}>
              {priority}
            </div>
            <div style={{ fontSize: 10, color: '#656d76', marginBottom: 4 }}>PRIORIDAD</div>
            <div className="priority-bar">
              <div className="priority-fill" style={{
                width: `${priority}%`,
                background: PRIORITY_COLOR(priority),
              }} />
            </div>
          </div>
        </div>

        {/* MITRE tags */}
        {Array.isArray(alert.mitre_id) && alert.mitre_id.length > 0 && (
          <div style={{ marginTop: 8, display: 'flex', gap: 6, flexWrap: 'wrap' }}>
            {alert.mitre_id.slice(0, 4).map((m) => (
              <span key={m} style={{
                fontSize: 10,
                padding: '1px 7px',
                borderRadius: 4,
                background: 'rgba(188,140,255,0.1)',
                border: '1px solid rgba(188,140,255,0.3)',
                color: '#bc8cff',
              }}>
                {m}
              </span>
            ))}
          </div>
        )}
      </div>
    </Link>
  );
}

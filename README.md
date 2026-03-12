# 🛡️ Wazuh AI Analyzer

Dashboard de seguridad que descarga alertas desde Wazuh SIEM, las analiza con Claude AI y las presenta priorizadas con instructivos de resolución paso a paso.

## ✨ Características

- **Descarga automática** de alertas desde la API REST de Wazuh v4
- **Análisis con IA** (Claude de Anthropic): prioridad 0-100, resumen ejecutivo, contexto de amenaza
- **Instructivos de resolución** detallados con comandos y urgencia por paso
- **Dashboard interactivo**: filtros por severidad/agente, gráficos, paginación
- **Mapeo MITRE ATT&CK**: identificación de técnicas y tácticas
- **Re-análisis**: vuelve a procesar cualquier alerta con un clic
- **SQLite integrado**: sin dependencias externas de BD

---

## 🚀 Inicio Rápido

### Opción A: Docker Compose (recomendado)

```bash
# 1. Clonar el proyecto
git clone <repo>
cd wazuh-ai-analyzer

# 2. Configurar variables de entorno
cp backend/.env.example backend/.env
# Editar backend/.env con tus credenciales

# 3. Levantar
docker-compose up -d

# Frontend: http://localhost:3000
# Backend API: http://localhost:8000/docs
```

### Opción B: Desarrollo local

**Backend:**
```bash
cd backend
python -m venv venv
source venv/bin/activate      # Windows: venv\Scripts\activate
pip install -r requirements.txt
cp .env.example .env           # Configurar credenciales
uvicorn main:app --reload
# API disponible en: http://localhost:8000
# Docs interactivos: http://localhost:8000/docs
```

**Frontend:**
```bash
cd frontend
npm install
npm start
# App en: http://localhost:3000
```

---

## ⚙️ Configuración (.env)

| Variable | Descripción | Ejemplo |
|---|---|---|
| `WAZUH_URL` | URL de tu Wazuh Manager | `https://192.168.1.100:55000` |
| `WAZUH_USERNAME` | Usuario con permiso de lectura | `wazuh-readonly` |
| `WAZUH_PASSWORD` | Contraseña | `MiPassword123` |
| `WAZUH_VERIFY_SSL` | Verificar SSL (false para certs autofirmados) | `false` |
| `ANTHROPIC_API_KEY` | API Key de Anthropic | `sk-ant-...` |
| `AI_MODEL` | Modelo de Claude a usar | `claude-opus-4-5` |
| `MAX_ALERTS_PER_SYNC` | Alertas por ciclo de sync | `500` |
| `AI_BATCH_SIZE` | Procesamiento paralelo con IA | `5` |

### Crear usuario de solo lectura en Wazuh

```bash
# En el servidor Wazuh
curl -k -X POST "https://localhost:55000/security/users" \
  -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" \
  -d '{
    "username": "wazuh-readonly",
    "password": "MiPassword123"
  }'

# Asignar rol de lectura
curl -k -X POST "https://localhost:55000/security/users/{user_id}/roles" \
  -H "Authorization: Bearer $TOKEN" \
  -d '{"role_ids": [1]}'
```

---

## 🔌 Endpoints de la API

| Método | Ruta | Descripción |
|---|---|---|
| `POST` | `/sync` | Inicia descarga y análisis IA |
| `GET` | `/sync/status` | Estado del último ciclo |
| `GET` | `/alerts` | Lista alertas (filtros, paginación) |
| `GET` | `/alerts/{id}` | Detalle con instructivo completo |
| `POST` | `/alerts/{id}/reprocess` | Re-analizar con IA |
| `GET` | `/alerts/summary/stats` | Estadísticas para el dashboard |
| `GET` | `/alerts/agents/list` | Lista de agentes únicos |

**Parámetros de `/alerts`:**
- `severity`: crítico|alto|medio|bajo|informativo
- `agent`: filtro por nombre de agente (parcial)
- `sort_by`: ai_priority|timestamp|rule_level
- `limit` / `offset`: paginación

---

## 🏗️ Arquitectura

```
┌─────────────────┐     REST API    ┌──────────────────────────┐
│   Wazuh SIEM    │ ──────────────► │   Backend (FastAPI)       │
│  (puerto 55000) │                 │  ┌─────────────────────┐  │
└─────────────────┘                 │  │  WazuhClient        │  │
                                    │  │  (descarga alertas) │  │
                                    │  └──────────┬──────────┘  │
┌─────────────────┐                 │             │              │
│  Anthropic API  │ ◄───────────────│  ┌──────────▼──────────┐  │
│  (Claude)       │                 │  │  AIProcessor        │  │
└─────────────────┘                 │  │  (analiza c/ IA)    │  │
                                    │  └──────────┬──────────┘  │
                                    │             │              │
                                    │  ┌──────────▼──────────┐  │
                                    │  │  SQLite Database    │  │
                                    │  └─────────────────────┘  │
                                    └────────────▲─────────────┘
                                                 │ JSON API
                                    ┌────────────┴─────────────┐
                                    │   Frontend (React)        │
                                    │   Dashboard + Detalle     │
                                    └───────────────────────────┘
```

---

## 📊 Análisis de IA por alerta

Cada alerta procesada incluye:

```json
{
  "ai_priority": 87,
  "ai_severity": "alto",
  "executive_summary": "Intento de escalada de privilegios detectado en el servidor...",
  "threat_context": "Patrón consistente con técnica T1068 de MITRE...",
  "affected_assets": "Servidor web prod-01, datos de usuarios",
  "false_positive_probability": "bajo",
  "resolution_steps": [
    {
      "step": 1,
      "title": "Aislar el proceso sospechoso",
      "description": "Identificar y detener el proceso que generó la alerta...",
      "commands": ["ps aux | grep suspicious", "kill -9 <PID>"],
      "urgency": "inmediata"
    }
  ],
  "prevention_measures": ["Actualizar parches del SO", "Revisar sudoers"],
  "mitre_analysis": "T1068 - Exploitation for Privilege Escalation..."
}
```

---

## 🛠️ Estructura del Proyecto

```
wazuh-ai-analyzer/
├── backend/
│   ├── main.py           # API FastAPI + endpoints
│   ├── config.py         # Configuración (pydantic-settings)
│   ├── wazuh_client.py   # Cliente API REST de Wazuh
│   ├── ai_processor.py   # Integración con Claude AI
│   ├── database.py       # SQLite con aiosqlite
│   ├── models.py         # Modelos Pydantic
│   ├── requirements.txt
│   ├── Dockerfile
│   └── .env.example
├── frontend/
│   ├── src/
│   │   ├── pages/
│   │   │   ├── Dashboard.js   # Lista priorizada + filtros
│   │   │   └── AlertDetail.js # Detalle + instructivo de resolución
│   │   ├── components/
│   │   │   ├── Layout.js      # Header + botón de sync
│   │   │   └── AlertRow.js    # Fila de alerta con prioridad
│   │   └── utils/api.js       # Cliente HTTP hacia el backend
│   ├── Dockerfile
│   └── nginx.conf
└── docker-compose.yml
```

---

## 🔒 Consideraciones de Seguridad

1. **Nunca** expongas el backend directamente a internet sin autenticación
2. Usa HTTPS para comunicación con Wazuh en producción
3. La API key de Anthropic y las credenciales de Wazuh son secretos — no las commitees al repositorio
4. Considera agregar autenticación JWT al backend para uso en equipos

---

## 📈 Próximas Mejoras

- [ ] Autenticación JWT en el backend
- [ ] Notificaciones por email/Slack para alertas críticas
- [ ] Sincronización automática cada N minutos (scheduler)
- [ ] Exportación de reportes a PDF
- [ ] Correlación de alertas relacionadas
- [ ] Historial de cambios de estado por alerta

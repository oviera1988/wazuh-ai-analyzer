# Wazuh AI Analyzer

Dashboard de seguridad que descarga alertas de Wazuh SIEM, las procesa con Azure OpenAI GPT-4.1 y presenta un análisis priorizado con instrucciones de resolución específicas para cada caso.

## Arquitectura
```
Wazuh SIEM (OpenSearch :9200)
        ↓
Backend FastAPI (Python)
        ↓
Azure OpenAI GPT-4.1
        ↓
SQLite (persistente)
        ↓
Frontend React (Nginx)
```

## Stack tecnológico

- **Backend**: Python 3.12, FastAPI, aiosqlite, httpx
- **IA**: Azure OpenAI GPT-4.1
- **Base de datos**: SQLite (persistente en volumen Docker)
- **Frontend**: React, Recharts, Nginx
- **Infraestructura**: Docker Compose

## Funcionalidades

### Recolección de alertas
- Conecta al indexer OpenSearch de Wazuh (puerto 9200, autenticación Basic)
- Agrupa alertas por `rule_id + agent_name + src_ip + hora` para evitar duplicados
- Solo procesa alertas con nivel Wazuh configurable (por defecto nivel 10+)
- Excluye reglas ruidosas configurables (por defecto excluye regla 100200)
- Acumula alertas por hora: cada sync trae grupos nuevos sin re-procesar anteriores

### Análisis con IA
- Cada grupo de alertas es analizado por Azure OpenAI GPT-4.1
- El prompt incluye contexto específico del servidor afectado (nombre, IP, labels)
- Detección automática de fuente real para eventos de dispositivos externos:
  - **Office 365**: redirige a security.microsoft.com, incluye usuario, remitente, destinatario, veredicto
  - **Fortigate**: redirige a consola del firewall, incluye IP origen/destino, política, acción
  - **Syslog genérico**: identifica dispositivo por srcip
- Genera por cada alerta:
  - Prioridad IA (1-100)
  - Severidad (crítico/alto/medio/bajo/informativo)
  - Resumen ejecutivo con datos específicos del evento
  - Contexto de amenaza
  - Pasos de resolución accionables con comandos listos para ejecutar
  - Medidas de prevención
  - Referencias
  - Análisis MITRE ATT&CK

### Dashboard
- **Cards de severidad clickeables**: filtran la lista al hacer click
- **Gráfico por severidad**: barras interactivas, click para filtrar
- **Gráfico top tipos de evento**: barras horizontales con los eventos más frecuentes
- **Top agentes clickeables**: click en un agente filtra la lista, con barra de proporción
- **Widget MITRE ATT&CK**: tácticas más frecuentes
- **Tags de filtros activos**: chips removibles mostrando filtros aplicados
- **Vista detalle de alerta**: pasos de resolución, análisis MITRE, log estructurado con tabs

## Configuración

### Variables de entorno (`backend/.env`)
```env
# Wazuh / OpenSearch
WAZUH_URL=https://<ip-wazuh>:9200
WAZUH_USERNAME=admin
WAZUH_PASSWORD=<password>
WAZUH_VERIFY_SSL=false

# Azure OpenAI
AZURE_OPENAI_ENDPOINT=https://<nombre>.openai.azure.com
AZURE_OPENAI_KEY=<key>
AZURE_OPENAI_DEPLOYMENT=gpt-4.1
AZURE_OPENAI_API_VERSION=2025-01-01-preview

# Sync
MAX_ALERTS_PER_SYNC=20          # Grupos máximos por sincronización
MIN_RULE_LEVEL=10               # Nivel mínimo de alerta Wazuh (1-15)
EXCLUDED_RULE_IDS=100200        # IDs de reglas a excluir (separados por coma)
AI_BATCH_SIZE=5                 # Alertas procesadas en paralelo por la IA
```

### Niveles de severidad Wazuh

| Nivel | Severidad     |
|-------|---------------|
| 1-3   | Informativo   |
| 4-7   | Bajo          |
| 8-10  | Medio         |
| 11-12 | Alto          |
| 13-15 | Crítico       |

## Despliegue

### Requisitos
- Docker y Docker Compose
- Acceso al indexer OpenSearch de Wazuh (puerto 9200)
- Cuenta Azure OpenAI con deployment GPT-4.1

### Instalación
```bash
git clone https://github.com/oviera1988/wazuh-ai-analyzer.git
cd wazuh-ai-analyzer

# Configurar variables
cp backend/.env.example backend/.env
nano backend/.env

# Crear directorio de datos persistentes
mkdir -p /docker/wazuh-ai-analyzer/data

# Levantar servicios
docker compose up -d
```

### URLs
- **Frontend**: http://\<servidor\>:8080
- **Backend API**: http://\<servidor\>:8000
- **Swagger docs**: http://\<servidor\>:8000/docs

## Comandos útiles
```bash
# Sincronizar alertas manualmente
curl -s http://localhost:8000/sync -X POST

# Ver estado de sync
curl -s http://localhost:8000/sync/status | python3 -m json.tool

# Ver logs del backend
docker compose logs backend -f

# Reconstruir después de cambios en código
docker compose build --no-cache backend
docker compose up -d backend

# Backup de la base de datos
cp /docker/wazuh-ai-analyzer/data/wazuh_alerts.db /docker/wazuh-ai-analyzer/data/wazuh_alerts.db.bak
```

## Estructura del proyecto
```
wazuh-ai-analyzer/
├── backend/
│   ├── main.py           # FastAPI: endpoints /sync, /alerts, /health
│   ├── config.py         # Configuración via pydantic-settings
│   ├── wazuh_client.py   # Cliente OpenSearch con agrupación compuesta
│   ├── ai_processor.py   # Azure OpenAI GPT-4.1 con prompt contextual
│   ├── database.py       # SQLite async (aiosqlite)
│   ├── models.py         # Modelos Pydantic
│   ├── requirements.txt
│   └── Dockerfile
├── frontend/
│   ├── src/
│   │   ├── pages/
│   │   │   ├── Dashboard.js    # Dashboard principal con filtros y gráficos
│   │   │   └── AlertDetail.js  # Detalle de alerta + resolución IA
│   │   ├── components/
│   │   │   ├── Layout.js       # Header con botón sync
│   │   │   └── AlertRow.js     # Fila de alerta con prioridad
│   │   └── utils/api.js        # Cliente HTTP
│   ├── Dockerfile
│   └── nginx.conf
└── docker-compose.yml
```

## Persistencia de datos

La base de datos SQLite se almacena en `/docker/wazuh-ai-analyzer/data/wazuh_alerts.db` en el host, mapeada al contenedor en `/app/data/wazuh_alerts.db`. Los datos sobreviven reinicios y reconstrucciones de la imagen.

## Lógica de acumulación

Cada sincronización genera IDs con formato `group_{rule_id}_{agent_name}_{src_ip}_{año-mes-día-hora}`. Esto permite:
- Evitar re-procesar el mismo grupo en la misma hora
- Acumular nuevos grupos hora a hora
- Detectar cambios en patrones de ataque por IP origen

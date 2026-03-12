import asyncio
import httpx
import json
import logging

logger = logging.getLogger(__name__)

ANALYSIS_PROMPT = """Eres un experto en ciberseguridad y respuesta a incidentes con más de 15 años de experiencia.
Analiza la siguiente alerta de Wazuh SIEM y proporciona un análisis ESPECÍFICO y ACCIONABLE.

CONTEXTO DEL SERVIDOR AFECTADO:
- Nombre del servidor: {agent_name}
- IP del servidor: {agent_ip}
- ID del agente Wazuh: {agent_id}
- Manager Wazuh: {manager_name}
- Labels/Tags: {agent_labels}

DETALLE DE LA ALERTA:
- ID Regla: {rule_id}
- Nivel Wazuh: {rule_level}/15 ({severity})
- Descripción: {rule_description}
- Grupos/Categorías: {rule_groups}
- Timestamp: {timestamp}
- MITRE ATT&CK ID: {mitre_id}
- MITRE Táctica: {mitre_tactic}
- MITRE Técnica: {mitre_technique}

DATOS DEL EVENTO:
{event_data}

LOG COMPLETO:
{full_log}

INSTRUCCIONES CRÍTICAS:
- Menciona SIEMPRE el servidor específico ({agent_name} / {agent_ip}) en cada paso
- Basa el instructivo en los datos reales del evento, no en recetas genéricas
- Si el log muestra un usuario específico, mencionarlo
- Si el log muestra una IP de origen, mencionarla y analizarla
- Si el log muestra una base de datos, archivo o servicio específico, mencionarlo
- Los comandos deben ser ejecutables directamente en {agent_name}
- Indica si hay que conectarse por SSH, RDP u otro método según el contexto

Responde ÚNICAMENTE con JSON válido sin markdown ni backticks:
{{
  "ai_priority": <entero 1-100, donde 100 es máxima urgencia>,
  "ai_severity": "<crítico|alto|medio|bajo|informativo>",
  "executive_summary": "<qué pasó exactamente en {agent_name}, con los datos específicos del evento>",
  "threat_context": "<análisis del patrón: quién, desde dónde, qué intentó hacer, basado en los datos reales del log>",
  "affected_assets": "<servidor {agent_name} ({agent_ip}), servicios/datos específicos mencionados en el log>",
  "false_positive_probability": "<bajo|medio|alto con justificación breve>",
  "resolution_steps": [
    {{
      "step": 1,
      "title": "<acción concreta y específica>",
      "description": "<instrucción detallada mencionando {agent_name}, usuarios/IPs/servicios del evento>",
      "commands": ["<comando listo para ejecutar en {agent_name}>"],
      "urgency": "<inmediata|1h|4h|24h|rutina>"
    }}
  ],
  "prevention_measures": ["<medida específica para {agent_name} basada en lo que ocurrió>"],
  "references": ["<url relevante>"],
  "mitre_analysis": "<explicación de cómo esta técnica aplica a lo que ocurrió en {agent_name}>"
}}"""

SEVERITY_MAP = {
    range(1, 4): "informativo",
    range(4, 8): "bajo",
    range(8, 11): "medio",
    range(11, 13): "alto",
    range(13, 16): "crítico",
}

class AIProcessor:
    def __init__(self, settings):
        self.endpoint = settings.azure_openai_endpoint.rstrip("/")
        self.key = settings.azure_openai_key
        self.deployment = settings.azure_openai_deployment
        self.api_version = settings.azure_openai_api_version
        self.batch_size = settings.ai_batch_size
        self.url = f"{self.endpoint}/openai/deployments/{self.deployment}/chat/completions?api-version={self.api_version}"

    async def process_batch(self, alerts):
        semaphore = asyncio.Semaphore(self.batch_size)
        tasks = [self._process_with_semaphore(a, semaphore) for a in alerts]
        results = await asyncio.gather(*tasks, return_exceptions=True)
        processed = []
        for alert, result in zip(alerts, results):
            if isinstance(result, Exception):
                logger.error(f"Error procesando {alert.get('wazuh_id')}: {result}")
                alert["ai_analysis"] = self._fallback(alert)
            else:
                alert["ai_analysis"] = result
            processed.append(alert)
        return processed

    async def _process_with_semaphore(self, alert, semaphore):
        async with semaphore:
            return await self.analyze_alert(alert)

    async def analyze_alert(self, alert):
        severity = self._severity(alert.get("rule_level", 0))

        # Extraer labels del agente si existen
        raw_data = alert.get("raw_data", {})
        agent_labels = raw_data.get("labels", {}) if isinstance(raw_data, dict) else {}
        labels_str = ", ".join(f"{k}: {v}" for k, v in agent_labels.items()) if agent_labels else "Sin labels"

        # Formatear datos del evento de forma legible
        event_fields = {}
        if isinstance(raw_data, dict):
            for k, v in raw_data.items():
                if k != "labels" and v:
                    event_fields[k] = v
        event_data_str = "\n".join(f"  {k}: {v}" for k, v in event_fields.items()) if event_fields else "Sin datos adicionales"

        prompt = ANALYSIS_PROMPT.format(
            agent_name=alert.get("agent_name", "desconocido"),
            agent_ip=alert.get("agent_ip", "desconocida"),
            agent_id=alert.get("agent_id", ""),
            manager_name=alert.get("manager_name", ""),
            agent_labels=labels_str,
            rule_id=alert.get("rule_id", ""),
            rule_level=alert.get("rule_level", 0),
            severity=severity,
            rule_description=alert.get("rule_description", ""),
            rule_groups=", ".join(alert.get("rule_groups", [])),
            timestamp=alert.get("timestamp", ""),
            mitre_id=", ".join(alert.get("mitre_id", [])) or "No identificado",
            mitre_tactic=", ".join(alert.get("mitre_tactic", [])) or "No identificada",
            mitre_technique=", ".join(alert.get("mitre_technique", [])) or "No identificada",
            event_data=event_data_str,
            full_log=str(alert.get("full_log", ""))[:800],
        )

        payload = {
            "messages": [{"role": "user", "content": prompt}],
            "max_tokens": 3000,
            "temperature": 0.1,
        }
        headers = {"api-key": self.key, "Content-Type": "application/json"}

        async with httpx.AsyncClient(timeout=60) as client:
            resp = await client.post(self.url, json=payload, headers=headers)
            resp.raise_for_status()
            content = resp.json()["choices"][0]["message"]["content"].strip()
            if content.startswith("```"):
                content = content.split("```")[1]
                if content.startswith("json"):
                    content = content[4:]
            return json.loads(content)

    async def reprocess_single(self, alert, db):
        analysis = await self.analyze_alert(alert)
        alert["ai_analysis"] = analysis
        await db.update_alert_analysis(alert["id"], analysis)

    def _severity(self, level):
        for r, label in SEVERITY_MAP.items():
            if level in r:
                return label
        return "desconocido"

    def _fallback(self, alert):
        level = alert.get("rule_level", 0)
        return {
            "ai_priority": min(100, level * 7),
            "ai_severity": self._severity(level),
            "executive_summary": f"Alerta nivel {level} en {alert.get('agent_name')}: {alert.get('rule_description', '')}.",
            "threat_context": "Análisis automático no disponible.",
            "affected_assets": f"Servidor: {alert.get('agent_name')} ({alert.get('agent_ip')})",
            "false_positive_probability": "medio",
            "resolution_steps": [{"step": 1, "title": "Revisión manual", "description": f"Conectarse a {alert.get('agent_name')} ({alert.get('agent_ip')}) y revisar manualmente.", "commands": [f"ssh admin@{alert.get('agent_ip')}"], "urgency": "4h"}],
            "prevention_measures": ["Revisar configuración de reglas de Wazuh"],
            "references": ["https://documentation.wazuh.com/"],
            "mitre_analysis": "",
        }

import asyncio
import httpx
import json
import logging

logger = logging.getLogger(__name__)

ANALYSIS_PROMPT = """Eres un experto en ciberseguridad y respuesta a incidentes con más de 15 años de experiencia.
Analiza la siguiente alerta de Wazuh SIEM y proporciona un análisis completo.

ALERTA:
- ID Regla: {rule_id}
- Nivel Wazuh: {rule_level}/15 ({severity})
- Descripción: {rule_description}
- Grupos/Categorías: {rule_groups}
- Agente afectado: {agent_name} ({agent_ip})
- Timestamp: {timestamp}
- MITRE ATT&CK: {mitre_info}
- Log completo: {full_log}
- Datos adicionales: {raw_data}

Responde ÚNICAMENTE con un JSON válido sin markdown ni backticks:
{{
  "ai_priority": <entero 1-100, donde 100 es máxima urgencia>,
  "ai_severity": "<crítico|alto|medio|bajo|informativo>",
  "executive_summary": "<resumen ejecutivo en 2-3 oraciones>",
  "threat_context": "<contexto de la amenaza y patrón de comportamiento>",
  "affected_assets": "<activos en riesgo>",
  "false_positive_probability": "<bajo|medio|alto>",
  "resolution_steps": [
    {{
      "step": 1,
      "title": "<título corto>",
      "description": "<descripción detallada>",
      "commands": ["<comando si aplica>"],
      "urgency": "<inmediata|1h|4h|24h|rutina>"
    }}
  ],
  "prevention_measures": ["<medida 1>", "<medida 2>"],
  "references": ["<url o referencia>"],
  "mitre_analysis": "<análisis MITRE si aplica>"
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
        mitre_info = "No disponible"
        if alert.get("mitre_id"):
            mitre_info = f"ID: {alert['mitre_id']}, Táctica: {alert.get('mitre_tactic', [])}"

        prompt = ANALYSIS_PROMPT.format(
            rule_id=alert.get("rule_id", ""),
            rule_level=alert.get("rule_level", 0),
            severity=severity,
            rule_description=alert.get("rule_description", ""),
            rule_groups=", ".join(alert.get("rule_groups", [])),
            agent_name=alert.get("agent_name", ""),
            agent_ip=alert.get("agent_ip", ""),
            timestamp=alert.get("timestamp", ""),
            mitre_info=mitre_info,
            full_log=str(alert.get("full_log", ""))[:500],
            raw_data=json.dumps(alert.get("raw_data", {}), ensure_ascii=False)[:300],
        )

        payload = {
            "messages": [{"role": "user", "content": prompt}],
            "max_tokens": 2000,
            "temperature": 0.2,
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
            "executive_summary": f"Alerta nivel {level}: {alert.get('rule_description', '')}. Requiere revisión manual.",
            "threat_context": "Análisis automático no disponible.",
            "affected_assets": f"Agente: {alert.get('agent_name', 'desconocido')}",
            "false_positive_probability": "medio",
            "resolution_steps": [{"step": 1, "title": "Revisión manual", "description": "Revisar esta alerta manualmente.", "commands": [], "urgency": "4h"}],
            "prevention_measures": ["Revisar configuración de reglas de Wazuh"],
            "references": ["https://documentation.wazuh.com/"],
            "mitre_analysis": "",
        }

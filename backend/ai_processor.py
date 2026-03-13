import asyncio
import httpx
import json
import logging

logger = logging.getLogger(__name__)

ANALYSIS_PROMPT = """Eres un experto en ciberseguridad y respuesta a incidentes con más de 15 años de experiencia.
Analiza la siguiente alerta de Wazuh SIEM y proporciona un análisis ESPECÍFICO y ACCIONABLE.

CONTEXTO DEL AGENTE WAZUH:
- Nombre del agente: {agent_name}
- IP del agente: {agent_ip}
- ID del agente: {agent_id}

{real_source_section}

DETALLE DE LA ALERTA:
- ID Regla: {rule_id}
- Nivel Wazuh: {rule_level}/15 ({severity})
- Descripción: {rule_description}
- Grupos/Categorías: {rule_groups}
- Timestamp: {timestamp}
- Ocurrencias en el período: {occurrence_count}
- Primera vez visto: {first_seen}
- Última vez visto: {last_seen}
- MITRE ATT&CK ID: {mitre_id}
- MITRE Táctica: {mitre_tactic}
- MITRE Técnica: {mitre_technique}

DATOS DEL EVENTO:
{event_data}

LOG COMPLETO:
{full_log}

INSTRUCCIONES CRÍTICAS:
- Si hay una FUENTE REAL identificada (no el agente Wazuh), los pasos de resolución deben referirse a ESA fuente, NO al servidor Wazuh
- Mencioná siempre el sistema/dispositivo específico donde hay que actuar
- Basá el instructivo en los datos reales del evento, no en recetas genéricas
- Si hay usuarios, IPs, remitentes, destinatarios específicos en el evento, mencionarlos
- Los comandos y acciones deben ser ejecutables en el sistema correcto

Responde ÚNICAMENTE con JSON válido sin markdown ni backticks:
{{
  "ai_priority": <entero 1-100>,
  "ai_severity": "<crítico|alto|medio|bajo|informativo>",
  "executive_summary": "<qué pasó exactamente, con datos específicos del evento>",
  "threat_context": "<análisis del patrón: quién, desde dónde, qué intentó hacer>",
  "affected_assets": "<sistema/dispositivo real afectado con detalles específicos>",
  "false_positive_probability": "<bajo|medio|alto con justificación>",
  "resolution_steps": [
    {{
      "step": 1,
      "title": "<acción concreta>",
      "description": "<instrucción detallada indicando EN QUÉ SISTEMA actuar>",
      "commands": ["<comando o URL o acción específica>"],
      "urgency": "<inmediata|1h|4h|24h|rutina>"
    }}
  ],
  "prevention_measures": ["<medida específica basada en lo ocurrido>"],
  "references": ["<url relevante>"],
  "mitre_analysis": "<cómo aplica esta técnica al evento específico>"
}}"""


def build_real_source_section(real_source):
    if not real_source:
        return ""
    details = real_source.get("real_source_details", {})
    details_str = "\n".join(f"  - {k}: {v}" for k, v in details.items() if v)
    return f"""
⚠️ FUENTE REAL DEL EVENTO (NO es el servidor Wazuh):
- Tipo: {real_source.get('real_source_type', '')}
- Sistema/Servicio: {real_source.get('real_source_name', '')}
- Cómo acceder: {real_source.get('real_source_access', '')}
- Detalles específicos del evento:
{details_str}
"""


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
        raw_data = alert.get("raw_data", {})
        real_source = alert.get("real_source")

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
            real_source_section=build_real_source_section(real_source),
            rule_id=alert.get("rule_id", ""),
            rule_level=alert.get("rule_level", 0),
            severity=severity,
            rule_description=alert.get("rule_description", ""),
            rule_groups=", ".join(alert.get("rule_groups", [])),
            timestamp=alert.get("timestamp", ""),
            occurrence_count=alert.get("occurrence_count", 1),
            first_seen=alert.get("first_seen", ""),
            last_seen=alert.get("last_seen", ""),
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
            result = json.loads(content)
            result["ai_severity"] = normalize_severity(result.get("ai_priority", 0))
            return result

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
        real_source = alert.get("real_source")
        system = real_source.get("real_source_name") if real_source else alert.get("agent_name")
        access = real_source.get("real_source_access") if real_source else f"ssh admin@{alert.get('agent_ip')}"
        return {
            "ai_priority": min(100, level * 7),
            "ai_severity": self._severity(level),
            "executive_summary": f"Alerta nivel {level} en {system}: {alert.get('rule_description', '')}.",
            "threat_context": "Análisis automático no disponible.",
            "affected_assets": system,
            "false_positive_probability": "medio",
            "resolution_steps": [{"step": 1, "title": "Revisión manual", "description": f"Acceder al sistema: {access}", "commands": [access], "urgency": "4h"}],
            "prevention_measures": ["Revisar configuración"],
            "references": ["https://documentation.wazuh.com/"],
            "mitre_analysis": "",
        }
  
  




def normalize_severity(priority: int) -> str:
    if priority >= 95: return "crítico"
    if priority >= 85: return "alto"
    if priority >= 65: return "medio"
    if priority >= 20: return "bajo"
    return "informativo"

"""
Cliente para Wazuh via OpenSearch/Indexer (puerto 9200)
Consulta directamente los índices wazuh-alerts-* en OpenSearch
"""

import httpx
import logging
from base64 import b64encode

logger = logging.getLogger(__name__)


class WazuhClient:
    def __init__(self, settings):
        self.base_url = settings.wazuh_url.rstrip("/")
        self.username = settings.wazuh_username
        self.password = settings.wazuh_password
        self.verify_ssl = settings.wazuh_verify_ssl
        self.timeout = settings.wazuh_timeout

        creds = b64encode(f"{self.username}:{self.password}".encode()).decode()
        self.headers = {
            "Authorization": f"Basic {creds}",
            "Content-Type": "application/json",
        }

    async def get_alerts(
        self,
        limit: int = 500,
        offset: int = 0,
        min_level: int = 3,
        hours_back: int = 24,
    ) -> list[dict]:
        index = "wazuh-alerts-*"
        alerts = []
        page_size = min(limit, 500)
        current_from = offset

        query = {
            "query": {
                "bool": {
                    "filter": [
                        {"range": {"rule.level": {"gte": min_level}}},
                        {"range": {"@timestamp": {"gte": f"now-{hours_back}h"}}},
                    ]
                }
            },
            "sort": [{"@timestamp": {"order": "desc"}}],
            "_source": [
                "id", "timestamp", "@timestamp",
                "rule.id", "rule.level", "rule.description",
                "rule.groups", "rule.mitre",
                "agent.id", "agent.name", "agent.ip",
                "manager.name", "data", "full_log",
            ],
        }

        async with httpx.AsyncClient(verify=self.verify_ssl, timeout=self.timeout) as client:
            while len(alerts) < limit:
                query["from"] = current_from
                query["size"] = min(page_size, limit - len(alerts))

                try:
                    resp = await client.post(
                        f"{self.base_url}/{index}/_search",
                        headers=self.headers,
                        json=query,
                    )
                    resp.raise_for_status()
                    data = resp.json()

                    hits = data.get("hits", {}).get("hits", [])
                    if not hits:
                        break

                    alerts.extend(self._normalize_alert(h["_source"], h["_id"]) for h in hits)
                    current_from += len(hits)

                    if len(hits) < page_size:
                        break

                except httpx.HTTPStatusError as e:
                    logger.error(f"Error HTTP consultando OpenSearch: {e}")
                    break
                except Exception as e:
                    logger.error(f"Error inesperado: {e}")
                    break

        logger.info(f"Obtenidas {len(alerts)} alertas desde OpenSearch")
        return alerts[:limit]

    def _normalize_alert(self, src: dict, doc_id: str) -> dict:
        rule = src.get("rule", {})
        agent = src.get("agent", {})
        mitre = rule.get("mitre", {})

        return {
            "wazuh_id": src.get("id") or doc_id,
            "timestamp": src.get("timestamp") or src.get("@timestamp", ""),
            "rule_id": str(rule.get("id", "")),
            "rule_level": int(rule.get("level", 0)),
            "rule_description": rule.get("description", ""),
            "rule_groups": rule.get("groups", []),
            "mitre_id": mitre.get("id", []),
            "mitre_tactic": mitre.get("tactic", []),
            "mitre_technique": mitre.get("technique", []),
            "agent_id": str(agent.get("id", "")),
            "agent_name": agent.get("name", "unknown"),
            "agent_ip": agent.get("ip", ""),
            "manager_name": src.get("manager", {}).get("name", ""),
            "raw_data": src.get("data", {}),
            "full_log": src.get("full_log", ""),
        }

import httpx
import logging
from base64 import b64encode

logger = logging.getLogger(__name__)

class WazuhClient:
    def __init__(self, settings):
        self.base_url = settings.wazuh_url.rstrip("/")
        self.verify_ssl = settings.wazuh_verify_ssl
        self.timeout = settings.wazuh_timeout
        creds = b64encode(f"{settings.wazuh_username}:{settings.wazuh_password}".encode()).decode()
        self.headers = {"Authorization": f"Basic {creds}", "Content-Type": "application/json"}

    async def get_alerts(self, limit=500, offset=0, min_level=3, hours_back=24):
        query = {
            "size": 0,
            "query": {"bool": {"filter": [
                {"range": {"rule.level": {"gte": min_level}}},
                {"range": {"@timestamp": {"gte": f"now-{hours_back}h"}}}
            ]}},
            "aggs": {
                "by_rule_agent": {
                    "composite": {
                        "size": limit,
                        "sources": [
                            {"rule_id": {"terms": {"field": "rule.id"}}},
                            {"agent_name": {"terms": {"field": "agent.name"}}}
                        ]
                    },
                    "aggs": {
                        "sample": {"top_hits": {"size": 1, "sort": [{"rule.level": {"order": "desc"}}]}},
                        "total_count": {"value_count": {"field": "rule.id"}},
                        "last_seen": {"max": {"field": "@timestamp"}},
                        "first_seen": {"min": {"field": "@timestamp"}}
                    }
                }
            }
        }

        alerts = []
        async with httpx.AsyncClient(verify=self.verify_ssl, timeout=self.timeout) as client:
            try:
                resp = await client.post(
                    f"{self.base_url}/wazuh-alerts-*/_search",
                    headers=self.headers,
                    json=query,
                )
                resp.raise_for_status()
                data = resp.json()
                buckets = data.get("aggregations", {}).get("by_rule_agent", {}).get("buckets", [])

                for bucket in buckets:
                    hits = bucket.get("sample", {}).get("hits", {}).get("hits", [])
                    if not hits:
                        continue
                    src = hits[0]["_source"]
                    doc_id = hits[0]["_id"]
                    count = bucket.get("total_count", {}).get("value", 1)
                    last_seen = bucket.get("last_seen", {}).get("value_as_string", "")
                    first_seen = bucket.get("first_seen", {}).get("value_as_string", "")

                    alert = self._normalize(src, doc_id)
                    alert["occurrence_count"] = count
                    alert["last_seen"] = last_seen
                    alert["first_seen"] = first_seen
                    alert["wazuh_id"] = f"group_{alert['rule_id']}_{alert['agent_name']}"
                    alerts.append(alert)

                logger.info(f"Obtenidos {len(alerts)} grupos únicos desde OpenSearch")

            except Exception as e:
                logger.error(f"Error consultando OpenSearch: {e}")

        return alerts

    def _normalize(self, src, doc_id):
        rule = src.get("rule", {})
        agent = src.get("agent", {})
        mitre = rule.get("mitre", {})
        raw_data = src.get("data", {}) or {}
        agent_labels = agent.get("labels", {})
        if agent_labels:
            raw_data["labels"] = agent_labels

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
            "raw_data": raw_data,
            "full_log": src.get("full_log", ""),
            "occurrence_count": 1,
            "last_seen": "",
            "first_seen": "",
        }

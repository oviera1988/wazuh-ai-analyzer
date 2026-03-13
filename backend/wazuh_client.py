import httpx
import logging
from base64 import b64encode
from datetime import datetime, timezone

logger = logging.getLogger(__name__)

# Detectores de fuente real cuando el agente es SRV-WAZUH
def detect_real_source(raw_data, rule_groups):
    """
    Cuando el agente es SRV-WAZUH, detecta el dispositivo/servicio real
    que generó el evento y retorna info para contextualizar la IA.
    """
    integration = raw_data.get("integration", "")
    groups_str = " ".join(rule_groups).lower()

    # Office 365
    if integration == "office365" or "office365" in groups_str:
        o365 = raw_data.get("office365", {})
        return {
            "real_source_type": "Office 365 / Microsoft Security",
            "real_source_name": "Microsoft 365 Tenant INAC",
            "real_source_access": "Acceder a https://security.microsoft.com o https://admin.microsoft.com",
            "real_source_details": {
                "workload": o365.get("Workload", ""),
                "operation": o365.get("Operation", ""),
                "user": o365.get("UserId") or o365.get("UserKey", ""),
                "client_ip": o365.get("ClientIP") or o365.get("SenderIp", ""),
                "sender": o365.get("P1Sender") or o365.get("P2Sender", ""),
                "recipients": o365.get("Recipients", []),
                "subject": o365.get("Subject", ""),
                "verdict": o365.get("Verdict", ""),
                "delivery_action": o365.get("DeliveryAction", ""),
                "deep_link": o365.get("EventDeepLink", ""),
            }
        }

    # Fortigate / Fortinet
    if "fortigate" in groups_str or "fortinet" in groups_str or integration in ["fortigate", "fortinet"]:
        return {
            "real_source_type": "Firewall Fortigate",
            "real_source_name": raw_data.get("devname", "Fortigate"),
            "real_source_access": f"Acceder a la consola web del Fortigate o via SSH: {raw_data.get('srcip', '')}",
            "real_source_details": {
                "src_ip": raw_data.get("srcip", ""),
                "dst_ip": raw_data.get("dstip", ""),
                "src_port": raw_data.get("srcport", ""),
                "dst_port": raw_data.get("dstport", ""),
                "action": raw_data.get("action", ""),
                "policy": raw_data.get("policyname", ""),
                "user": raw_data.get("unauthuser") or raw_data.get("user", ""),
                "app": raw_data.get("app", ""),
                "logdesc": raw_data.get("logdesc", ""),
            }
        }

    # Syslog genérico
    if raw_data.get("srcip"):
        return {
            "real_source_type": "Dispositivo externo via Syslog",
            "real_source_name": raw_data.get("hostname") or raw_data.get("srcip", "Dispositivo desconocido"),
            "real_source_access": f"Conectarse al dispositivo {raw_data.get('srcip', '')}",
            "real_source_details": {
                "src_ip": raw_data.get("srcip", ""),
                "dst_ip": raw_data.get("dstip", ""),
                "program": raw_data.get("program", ""),
            }
        }

    return None


class WazuhClient:
    def __init__(self, settings):
        self.base_url = settings.wazuh_url.rstrip("/")
        self.verify_ssl = settings.wazuh_verify_ssl
        self.timeout = settings.wazuh_timeout
        self.excluded_ids = [x.strip() for x in settings.excluded_rule_ids.split(",") if x.strip()]
        creds = b64encode(f"{settings.wazuh_username}:{settings.wazuh_password}".encode()).decode()
        self.headers = {"Authorization": f"Basic {creds}", "Content-Type": "application/json"}

    async def get_alerts(self, limit=500, min_level=3, hours_back=24, **kwargs):
        today = datetime.now(timezone.utc).strftime("%Y-%m-%d-%H")

        must_not = []
        if self.excluded_ids:
            must_not.append({"terms": {"rule.id": self.excluded_ids}})

        query = {
            "size": 0,
            "query": {"bool": {
                "filter": [
                    {"range": {"rule.level": {"gte": min_level}}},
                    {"range": {"@timestamp": {"gte": f"now-{hours_back}h"}}}
                ],
                "must_not": must_not
            }},
            "aggs": {
                "by_rule_agent_ip": {
                    "composite": {
                        "size": limit,
                        "sources": [
                            {"rule_id": {"terms": {"field": "rule.id"}}},
                            {"agent_name": {"terms": {"field": "agent.name"}}},
                            {"src_ip": {"terms": {"field": "data.srcip", "missing_bucket": True}}}
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
                    headers=self.headers, json=query)
                resp.raise_for_status()
                buckets = resp.json().get("aggregations", {}).get("by_rule_agent_ip", {}).get("buckets", [])

                for bucket in buckets:
                    hits = bucket.get("sample", {}).get("hits", {}).get("hits", [])
                    if not hits:
                        continue
                    src = hits[0]["_source"]
                    doc_id = hits[0]["_id"]
                    src_ip = bucket.get("key", {}).get("src_ip") or "noip"

                    alert = self._normalize(src, doc_id)
                    alert["occurrence_count"] = bucket.get("total_count", {}).get("value", 1)
                    alert["last_seen"] = bucket.get("last_seen", {}).get("value_as_string", "")
                    alert["first_seen"] = bucket.get("first_seen", {}).get("value_as_string", "")
                    alert["src_ip"] = src_ip if src_ip != "noip" else ""
                    alert["wazuh_id"] = f"group_{alert['rule_id']}_{alert['agent_name']}_{src_ip}_{today}"
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

        rule_groups = rule.get("groups", [])
        agent_name = agent.get("name", "unknown")

        # Detectar fuente real si el agente es el manager de Wazuh
        real_source = None
        if agent_name.upper() in ("SRV-WAZUH", "WAZUH-MANAGER") or agent.get("id") == "000":
            real_source = detect_real_source(raw_data, rule_groups)

        return {
            "wazuh_id": src.get("id") or doc_id,
            "timestamp": src.get("timestamp") or src.get("@timestamp", ""),
            "rule_id": str(rule.get("id", "")),
            "rule_level": int(rule.get("level", 0)),
            "rule_description": rule.get("description", ""),
            "rule_groups": rule_groups,
            "mitre_id": mitre.get("id", []),
            "mitre_tactic": mitre.get("tactic", []),
            "mitre_technique": mitre.get("technique", []),
            "agent_id": str(agent.get("id", "")),
            "agent_name": agent_name,
            "agent_ip": agent.get("ip", ""),
            "manager_name": src.get("manager", {}).get("name", ""),
            "raw_data": raw_data,
            "full_log": src.get("full_log", ""),
            "occurrence_count": 1,
            "last_seen": "",
            "first_seen": "",
            "src_ip": "",
            "real_source": real_source,
        }

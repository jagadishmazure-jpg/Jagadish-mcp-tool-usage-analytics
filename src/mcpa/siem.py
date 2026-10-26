"""Export alerts as OCSF-style JSON (Detection Finding shape, simplified) for SIEM ingestion."""
import json

SEV = {"low": 2, "medium": 3, "high": 4, "critical": 5}

def to_ocsf(alert: dict, product: str = "mcp-tool-analytics-lab") -> dict:
    return {"class_name": "Detection Finding", "class_uid": 2004, "severity_id": SEV[alert["severity"]],
            "time": alert["hour"] * 3600 * 1000, "metadata": {"product": {"name": product}},
            "finding_info": {"title": alert["rule"], "desc": alert["detail"]},
            "actor": {"user": {"uid": alert["user"]}}}

def export_jsonl(alerts) -> str:
    return "\n".join(json.dumps(to_ocsf(a), sort_keys=True) for a in alerts)

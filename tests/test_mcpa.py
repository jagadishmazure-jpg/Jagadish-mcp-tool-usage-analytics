import json
from itertools import pairwise

import pytest

from mcpa.analytics import by, daily_error_rate, pct
from mcpa.events import TOOLS, generate
from mcpa.risk import detect, robust_z, tool_risk_score
from mcpa.siem import export_jsonl, to_ocsf


@pytest.fixture(scope="module")
def ev():
    return generate()

def test_deterministic(ev):
    assert generate() == ev

def test_event_schema(ev):
    assert set(ev[0]) == {"ts", "user", "agent", "tool", "status", "latency_ms", "bytes_out", "anomaly"}

def test_sorted_by_time(ev):
    assert all(a["ts"] <= b["ts"] for a, b in pairwise(ev))

def test_pct():
    assert pct([1, 2, 3, 4], 0.5) == 2.5 and pct([], 0.9) == 0

def test_by_tool_totals(ev):
    t = by(ev, "tool")
    assert sum(v["calls"] for v in t.values()) == len(ev)
    assert all(v["p95_ms"] >= v["p50_ms"] for v in t.values())

def test_by_user_counts_30_users(ev):
    assert len(by(ev, "user")) == 30

def test_outage_visible(ev):
    d = daily_error_rate(ev, "erp.get_order")
    assert d[4] > 5 * d[3]

def test_denied_not_billed():
    es = [{"tool": "erp.create_refund", "status": "denied", "latency_ms": 1, "bytes_out": 1}]
    assert by(es, "tool")["erp.create_refund"]["usd"] == 0

def test_robust_z():
    assert robust_z([1, 1, 1, 2, 1], 50) > 8 and abs(robust_z([1, 2, 3], 2)) < 1e-9

@pytest.mark.parametrize("rule", ["volume_spike", "offhours_write", "repeated_denials", "unregistered_tool"])
def test_each_rule_fires(ev, rule):
    assert any(a["rule"] == rule for a in detect(ev))

def test_detectors_ignore_labels(ev):
    stripped = [{**e, "anomaly": ""} for e in ev]
    assert detect(stripped) == detect(ev)

def test_no_alerts_on_clean_traffic(ev):
    clean = [e for e in ev if not e["anomaly"]]
    assert detect(clean) == []

def test_low_and_slow_is_missed(ev):
    """Known failure kept visible: volume rules miss low-and-slow pulls."""
    alerts = detect(ev)
    assert not any(a["user"] == "u12" for a in alerts)

def test_lower_threshold_catches_more(ev):
    assert len(detect(ev, z_threshold=3.0)) >= len(detect(ev))

def test_risk_scores():
    assert tool_risk_score("files.delete") > tool_risk_score("crm.update_account") > tool_risk_score("kb.search")
    assert tool_risk_score("shell.exec") == 5

def test_ocsf_shape():
    o = to_ocsf({"rule": "x", "user": "u1", "hour": 2, "severity": "high", "detail": "d"})
    assert o["class_uid"] == 2004 and o["severity_id"] == 4 and o["time"] == 2 * 3600 * 1000

def test_export_jsonl_parses(ev):
    lines = export_jsonl(detect(ev)).splitlines()
    assert lines and all(json.loads(line)["class_name"] == "Detection Finding" for line in lines)

def test_catalog_kinds():
    assert {v[0] for v in TOOLS.values()} == {"read", "write", "delete"}

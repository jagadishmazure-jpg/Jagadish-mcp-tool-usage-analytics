"""SYNTHETIC 7-day event log; detection scored against injected ground truth (measured on synthetic data)."""
import json
import pathlib
import sys

ROOT = pathlib.Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))
from mcpa.analytics import by, daily_error_rate
from mcpa.events import generate
from mcpa.risk import detect
from mcpa.siem import export_jsonl


def score(ev, alerts):
    truth = {(e["user"], e["ts"] // 60) for e in ev if e["anomaly"]}
    hit = {(a["user"], a["hour"]) for a in alerts}
    tp_alerts = sum((a["user"], a["hour"]) in truth for a in alerts)
    return tp_alerts, len(alerts), len(truth & hit), len(truth)

def main():
    ev = generate()
    tools, users = by(ev, "tool"), by(ev, "user")
    alerts = detect(ev)
    tpa, na, rec, nt = score(ev, alerts)
    rules = {}
    for a in alerts:
        rules[a["rule"]] = rules.get(a["rule"], 0) + 1
    hit = {(a["user"], a["hour"]) for a in alerts}
    all_types = {e["anomaly"] for e in ev if e["anomaly"]}
    det_types = {e["anomaly"] for e in ev if e["anomaly"] and (e["user"], e["ts"] // 60) in hit}
    err = daily_error_rate(ev, "erp.get_order")
    top = next(iter(tools))
    m = {
        "Events": len(ev), "Users": len(users), "Distinct tools": len(tools),
        "Top tool by calls": f"{top} ({tools[top]['calls']})",
        "Illustrative tool cost, 7 days (USD)": round(sum(t["usd"] for t in tools.values()), 4),
        "erp.get_order error rate, day 4 vs day 3": f"{err[4]:.1%} vs {err[3]:.1%}",
        "Alerts raised": na, "Alerts by rule": ", ".join(f"{k}={v}" for k, v in sorted(rules.items())),
        "Alert precision vs injected truth": f"{tpa}/{na} ({tpa / na:.1%})",
        "Anomalous user-hours detected (recall)": f"{rec}/{nt} ({rec / nt:.1%})",
        "Injected incident types detected": f"{len(det_types)}/{len(all_types)} (missed: {', '.join(sorted(all_types - det_types)) or 'none'})",
        "SIEM records exported (OCSF-style)": len(export_jsonl(alerts).splitlines()),
    }
    out = {"label": "SYNTHETIC event log; detection scored against injected labels", "sample": f"{len(ev)} events, 30 users, 7 days, seed 11",
           "metrics": m, "by_tool": tools}
    (ROOT / "results").mkdir(exist_ok=True)
    (ROOT / "results" / "results.json").write_text(json.dumps(out, indent=2) + "\n")
    print(json.dumps(m, indent=2))

if __name__ == "__main__":
    main()

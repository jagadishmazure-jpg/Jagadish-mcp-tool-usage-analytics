"""Risk rules + robust anomaly detection (median/MAD z-score). Detectors never read the ground-truth label."""
from collections import Counter, defaultdict
from statistics import median

from .events import TOOLS


def robust_z(values: list[float], x: float) -> float:
    m = median(values); mad = median([abs(v - m) for v in values]) or 1.0
    return 0.6745 * (x - m) / mad

def detect(events, z_threshold: float = 8.0, known_tools=None, business=(7 * 60, 19 * 60)) -> list[dict]:
    known = set(known_tools or TOOLS)
    alerts = []
    hourly = defaultdict(int); bytes_h = defaultdict(int)
    for e in events:
        k = (e["user"], e["ts"] // 60); hourly[k] += 1; bytes_h[k] += e["bytes_out"]
    counts = list(hourly.values()); bvals = list(bytes_h.values())
    for (u, h), c in hourly.items():
        zc, zb = robust_z(counts, c), robust_z(bvals, bytes_h[(u, h)])
        if zc > z_threshold or zb > z_threshold:
            alerts.append({"rule": "volume_spike", "user": u, "hour": h, "severity": "high",
                           "detail": f"calls={c} z_calls={zc:.1f} z_bytes={zb:.1f}"})
    for e in events:
        kind = TOOLS.get(e["tool"], ("unknown",))[0]
        mod = e["ts"] % 1440
        if kind in ("write", "delete") and not (business[0] <= mod < business[1]) and e["status"] == "ok":
            alerts.append({"rule": "offhours_write", "user": e["user"], "hour": e["ts"] // 60, "severity": "high", "detail": e["tool"]})
        if e["tool"] not in known:
            alerts.append({"rule": "unregistered_tool", "user": e["user"], "hour": e["ts"] // 60, "severity": "critical", "detail": e["tool"]})
    denied = Counter((e["user"], e["ts"] // 60) for e in events if e["status"] == "denied")
    for (u, h), c in denied.items():
        if c >= 10:
            alerts.append({"rule": "repeated_denials", "user": u, "hour": h, "severity": "medium", "detail": f"denied={c}"})
    # de-duplicate per (rule, user, hour)
    seen, out = set(), []
    for a in alerts:
        k = (a["rule"], a["user"], a["hour"])
        if k not in seen:
            seen.add(k); out.append(a)
    return out

def tool_risk_score(tool: str) -> int:
    kind = TOOLS.get(tool, ("unknown",))[0]
    return {"read": 1, "write": 3, "delete": 5, "unknown": 5}[kind]

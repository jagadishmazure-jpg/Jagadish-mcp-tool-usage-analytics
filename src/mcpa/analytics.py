"""Usage, cost, error and latency analytics over MCP tool-call events."""
from collections import defaultdict
from .events import TOOLS

def pct(xs, p):
    xs = sorted(xs)
    if not xs:
        return 0
    k = (len(xs) - 1) * p
    lo, hi = int(k), min(int(k) + 1, len(xs) - 1)
    return xs[lo] + (xs[hi] - xs[lo]) * (k - lo)

def by(events, key):
    g = defaultdict(list)
    for e in events:
        g[e[key]].append(e)
    out = {}
    for k, es in g.items():
        lat = [e["latency_ms"] for e in es]
        out[k] = {"calls": len(es),
                  "error_rate": round(sum(e["status"] == "error" for e in es) / len(es), 4),
                  "denied": sum(e["status"] == "denied" for e in es),
                  "p50_ms": round(pct(lat, 0.5), 1), "p95_ms": round(pct(lat, 0.95), 1),
                  "usd": round(sum(TOOLS.get(e["tool"], ("", 0.001, 0))[1] for e in es if e["status"] == "ok"), 4),
                  "mb_out": round(sum(e["bytes_out"] for e in es) / 1e6, 2)}
    return dict(sorted(out.items(), key=lambda kv: -kv[1]["calls"]))

def daily_error_rate(events, tool):
    d = defaultdict(lambda: [0, 0])
    for e in events:
        if e["tool"] == tool:
            d[e["ts"] // 1440][0] += e["status"] == "error"; d[e["ts"] // 1440][1] += 1
    return {k: round(a / b, 3) for k, (a, b) in sorted(d.items())}

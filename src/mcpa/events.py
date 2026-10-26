"""SYNTHETIC MCP tool-call event log for a fictional distributor (Cobalt Ridge Supply).

Each event mirrors what a gateway sees for a JSON-RPC `tools/call`: who, which agent, which server/tool,
status, latency, bytes returned. Anomalies are injected with ground-truth labels for scoring."""
import random
from dataclasses import dataclass, asdict

TOOLS = {  # server.tool -> (kind, illustrative USD per call, base latency ms)
    "crm.search_accounts": ("read", 0.0004, 120), "crm.update_account": ("write", 0.0010, 300),
    "erp.get_order": ("read", 0.0005, 180), "erp.create_refund": ("write", 0.0020, 450),
    "kb.search": ("read", 0.0002, 80), "files.read": ("read", 0.0003, 150),
    "files.delete": ("delete", 0.0010, 200), "email.send": ("write", 0.0008, 250),
}
USERS = [f"u{i:02d}" for i in range(1, 31)]

@dataclass
class Event:
    ts: int          # minutes since start of the 7-day window
    user: str
    agent: str
    tool: str
    status: str      # ok | error | denied
    latency_ms: int
    bytes_out: int
    anomaly: str = ""  # ground truth label (empty = normal); NOT used by detectors

def generate(seed: int = 11, days: int = 7) -> list[dict]:
    rng = random.Random(seed)
    ev = []
    read_tools = [t for t, v in TOOLS.items() if v[0] == "read"]
    for day in range(days):
        for u in USERS:
            for _ in range(rng.randint(15, 40)):
                minute = day * 1440 + rng.randint(8 * 60, 18 * 60)      # business hours
                t = rng.choice(read_tools) if rng.random() < 0.85 else rng.choice(list(TOOLS))
                if TOOLS[t][0] == "delete" and rng.random() < 0.8:
                    t = "kb.search"
                st = "error" if rng.random() < 0.03 else "ok"
                if t == "erp.get_order" and day == 4 and rng.random() < 0.5:
                    st = "error"                                        # injected outage on day 4
                ev.append(Event(minute, u, rng.choice(["support-bot", "sales-copilot"]), t, st,
                                int(TOOLS[t][2] * rng.uniform(0.6, 1.8)), rng.randint(200, 6000)))
    # injected anomalies
    for i in range(300):     # burst: u07 scrapes CRM in one hour on day 3
        ev.append(Event(3 * 1440 + 14 * 60 + i // 5, "u07", "sales-copilot", "crm.search_accounts", "ok", 110, rng.randint(40_000, 90_000), "burst_exfil"))
    for i in range(6):       # off-hours deletes by u19 on day 5
        ev.append(Event(5 * 1440 + 2 * 60 + i * 7, "u19", "support-bot", "files.delete", "ok", 210, 300, "offhours_delete"))
    for i in range(25):      # u23 repeatedly denied on refunds (probing)
        ev.append(Event(6 * 1440 + 11 * 60 + i, "u23", "support-bot", "erp.create_refund", "denied", 15, 100, "denied_probing"))
    for i in range(4):       # brand-new tool seen for the first time
        ev.append(Event(6 * 1440 + 16 * 60 + i, "u02", "support-bot", "shell.exec", "ok", 90, 500, "new_tool"))
    for h in range(10):      # low-and-slow: u12 pulls a few extra large files each hour (designed to evade volume rules)
        for j in range(3):
            ev.append(Event(2 * 1440 + (8 + h) * 60 + j * 15, "u12", "support-bot", "files.read", "ok", 160, 5_000, "low_and_slow"))
    ev.sort(key=lambda e: e.ts)
    return [asdict(e) for e in ev]

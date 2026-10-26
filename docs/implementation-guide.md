# Implementation guide
1. Log every `tools/call` at the gateway: timestamp, pseudonymised user, agent, server.tool, status, latency, bytes out, approval id.
2. Maintain a tool registry with kind (read/write/delete) and owner; unregistered = critical.
3. Start with the four rules here; tune thresholds on two weeks of shadow data.
4. Ship findings to the SIEM (OCSF or your SIEM's native schema) and route high/critical to on-call.
5. Add per-user baselines and cumulative byte budgets to catch low-and-slow.
6. Use the per-tool cost table for chargeback and to spot runaway agents.

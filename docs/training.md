# Training module: telemetry and detection for agent tools
**Audience:** platform and security engineers, half a day.
## Learning objectives
1. Define the minimum event schema for MCP tool calls.
2. Compute usage, cost, error and latency KPIs per tool and user.
3. Write detection rules and score them against labelled data without leaking labels.
4. Explain why a known miss must stay visible.
## Labs
| # | Lab | Done when |
|---|---|---|
| 1 | Run the eval; find the outage day from analytics alone | Day and tool named |
| 2 | Add a per-user 7-day byte budget rule | Low-and-slow detected; precision reported |
| 3 | Add a rule for write tools without approval id | Test added |
| 4 | Sweep `z_threshold` 3..12 | Precision/recall table in results |
## Capstone
Detect the low-and-slow case without dropping alert precision below 80%, regenerate the README, and write a one-page runbook for the alert.

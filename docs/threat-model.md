# Threat model
| Threat | Signal | Rule | Gap |
|---|---|---|---|
| Bulk data scraping via agent | calls/bytes per hour | volume_spike | Low-and-slow evades |
| Destructive action at night | write/delete off-hours | offhours_write | Time zones |
| Privilege probing | repeated denials | repeated_denials | Spread across hours evades |
| Shadow / rogue MCP tool (supply chain, OWASP LLM03) | tool not in registry | unregistered_tool | Renamed malicious tool |

# SentinelOps Architecture

## Data Flow
Splunk Enterprise (real telemetry) → MCP Client → Agent Swarm → WebSocket → React Dashboard

## Components
- **Splunk Enterprise 10.4** — indexes real macOS system logs via Universal Forwarder
- **splunk/mcp_client.py** — queries Splunk via Python SDK, returns TelemetryEvent objects
- **agents/sentry_node.py** — threat detection and risk scoring
- **agents/controller.py** — cost optimization and ROSI calculation  
- **agents/orchestrator.py** — Pareto-optimal synthesis via NSGA-II
- **core/math_engine.py** — J-Score, EWM, CRITIC weighting, ALE
- **core/decision_logic.py** — sovereign execute vs human defer
- **api/auto_stepper.py** — 4s tick loop, hybrid Splunk+simulation mode
- **api/streamer.py** — WebSocket /ws/war-room with 50-event replay buffer
- **Frontend** — Next.js 16 + React 19, 6 dashboard views, Fast-Pass veto

## Splunk Integration
- Receives: real security telemetry via splunklib SDK on port 8089
- Sends back: agent decisions via HEC on port 8088 (sentinelops_decisions index)
- Universal Forwarder ships /var/log and /private/var/log/system.log to Splunk

## NIST AI RMF Compliance
- Monotone Invariant verification
- 1% Execution Floor
- CODE_VETO adversarial detection
- Full forensic audit trail
- 10-second human override (Fast-Pass)

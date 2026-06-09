<p align="center">
  <img src="public/logo.png" alt="SentinelOps Logo" width="80" />
</p>
<h1 align="center">SentinelOps</h1>
<p align="center">
  <strong>AI-Powered Autonomous Security Operations Platform</strong>
</p>
<p align="center">
  <img src="https://img.shields.io/badge/splunk-10.4-black?style=flat-square&logo=splunk&logoColor=white" alt="Splunk" />
  <img src="https://img.shields.io/badge/python-3.11+-3776AB?style=flat-square&logo=python&logoColor=white" alt="Python" />
  <img src="https://img.shields.io/badge/Next.js-16-black?style=flat-square&logo=next.js&logoColor=white" alt="Next.js" />
  <img src="https://img.shields.io/badge/FastAPI-0.110+-009688?style=flat-square&logo=fastapi&logoColor=white" alt="FastAPI" />
  <img src="https://img.shields.io/badge/track-Security-red?style=flat-square" alt="Track" />
  <img src="https://img.shields.io/badge/license-MIT-green?style=flat-square" alt="License" />
</p>

---

> **Splunk Agentic Ops Hackathon — Security Track**
> SentinelOps connects to Splunk Enterprise for real security telemetry, runs a multi-agent AI swarm for Pareto-optimal threat remediation, and keeps a human in the loop with a 10-second override window — all NIST AI RMF compliant.

---

## What It Does

| Capability | Description |
|---|---|
| **Detect** | Queries Splunk Enterprise for real security events — failed logins, privilege escalations, config changes, network anomalies |
| **Analyze** | Multi-agent swarm (Sentry + Controller + Orchestrator) negotiates remediation using J-Score optimization and ROSI/ALE economics |
| **Override** | 10-second Fast-Pass human veto window before any autonomous action executes |
| **Audit** | Every decision recorded in a NIST AI RMF-compliant forensic audit trail |

---

## Architecture

```
Splunk Enterprise (port 8089)
        │
        │  splunklib SDK — real security telemetry
        ▼
cloudguard/mcp_client.py
        │
        │  List[TelemetryEvent]
        ▼
kernel/sovereign.py  ←→  agents/sentry_node.py
                     ←→  agents/controller.py
                     ←→  agents/orchestrator.py
                     ←→  core/math_engine.py (J-Score, ROSI, ALE)
                     ←→  core/decision_logic.py
        │
        │  WebSocket /ws/war-room
        ▼
Next.js + React Frontend (port 3000)
  • Iron Dome hex-grid topology
  • Liaison Console (agent reasoning)
  • Fast-Pass veto timer
  • NIST Sovereign Audit Logs
```

See [`architecture.md`](./architecture.md) for the full component diagram.

---

## Key Features

**Splunk Integration**
- Connects to Splunk Enterprise via Python SDK on port 8089
- Queries real security telemetry: launchd errors, syslog failures, auth events
- Universal Forwarder ships live macOS system logs into Splunk
- Hybrid mode: real Splunk data first, simulation fallback if empty

**Multi-Agent Swarm**
- Sentry Node — threat detection and risk scoring
- Controller Agent — cost optimization and ROSI calculation
- Orchestrator — Pareto-optimal synthesis via NSGA-II
- Audit Surgeon — compliance verification with CODE_VETO detection

**J-Score Optimization**
```
J = min Σᵢ (w_R · P · Rᵢ + w_C · Cᵢ)
```
Weighted by Entropy Weight Method (EWM) and CRITIC — balances risk vs remediation cost across all resources.

**NIST AI RMF Compliance**
- Monotone Invariant verification
- 1% Execution Floor (no action on noise-level drifts)
- Full forensic audit trail with downloadable reports
- Human override window before every autonomous action

---

## Tech Stack

| Layer | Technology |
|---|---|
| Security Data | Splunk Enterprise 10.4 + Universal Forwarder |
| Backend | Python 3.11, FastAPI, splunklib SDK |
| Math Engine | NumPy, NetworkX, custom J-Score optimizer |
| Frontend | Next.js 16, React 19, Tailwind CSS, Framer Motion |
| Real-time | WebSocket streaming, 50-event replay buffer |

---

## Getting Started

### Prerequisites

- Python 3.11+
- Node.js 18+
- Splunk Enterprise (free trial at splunk.com/download)

### 1. Clone the Repository

```bash
git clone https://github.com/Mustafa11300/Splunk-Sentinental-Ops.git
cd Splunk-Sentinental-Ops
```

### 2. Set Up Python Environment

```bash
python -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
```

### 3. Configure Environment Variables

```bash
cp .env.example .env
```

Edit `.env` with your Splunk credentials:

```bash
SPLUNK_HOST=localhost
SPLUNK_PORT=8089
SPLUNK_USERNAME=admin
SPLUNK_PASSWORD=your_splunk_password
SPLUNK_MODE=true
NEXT_PUBLIC_API_URL=http://localhost:8001
NEXT_PUBLIC_WS_URL=ws://localhost:8001/ws/war-room
```

### 4. Set Up Splunk

1. Download and install [Splunk Enterprise](https://www.splunk.com/en_us/download/splunk-enterprise.html)
2. Start Splunk: `/Applications/Splunk/bin/splunk start --accept-license`
3. Enable receiving: `/Applications/Splunk/bin/splunk enable listen 9997 -auth admin:password`
4. (Optional) Install Universal Forwarder to ship real system logs

### 5. Start the Backend

```bash
source .venv/bin/activate
SPLUNK_MODE=true uvicorn cloudguard.app:app --port 8001
```

> **Note:** Backend runs on port 8001 to avoid conflict with Splunk Web UI on port 8000.

### 6. Start the Frontend

```bash
npm install
npm run dev
```

Dashboard available at `http://localhost:3000`

### 7. Verify Everything is Running

```bash
curl http://localhost:8001/api/splunk/status
# Expected: {"connected": true, "version": "10.4.0", ...}
```

---

## Dashboard Views

| View | Route | Description |
|---|---|---|
| Overview | `/dashboard` | KPI metrics, J-Score, live event feed, active remediations |
| Iron Dome | `/dashboard/findings` | Hex-grid topology — resource health (Green/Yellow/Red/Amber) |
| Friction HUD | `/dashboard/cost` | Agent negotiation + Fast-Pass 10s countdown |
| Liaison Console | `/dashboard/copilot` | Agent reasoning, ROSI trace, veto button |
| Audit Logs | `/dashboard/logs` | NIST forensic recorder, downloadable report |

---

## API Reference

| Endpoint | Method | Description |
|---|---|---|
| `/api/v2/health` | GET | System health + subsystem status |
| `/api/splunk/status` | GET | Splunk connection status |
| `/api/v2/simulation/state` | GET | Current simulation state |
| `/api/v2/math/j-score` | GET | J-Score breakdown |
| `/api/v2/events/veto` | POST | Trigger human override |
| `/ws/war-room` | WebSocket | Real-time event stream |

---

## Testing

```bash
pytest tests/ -v
```

---

## NIST AI RMF Compliance

| Behavior | RMF Category | Status |
|---|---|---|
| Monotone Invariant (J_forecast < J_actual) | MEASURE-2.1 | ✅ |
| 1% Execution Floor | MEASURE-2.2 | ✅ |
| Jailbreak Detection (CODE_VETO) | GOVERN-1.3 | ✅ |
| Full Audit Trail | GOVERN-6.1 | ✅ |
| Human Override Window | MANAGE-4.1 | ✅ |

---

## License

MIT © 2026 Mustafa Hussain

---

<p align="center">
  <sub>Built for the Splunk Agentic Ops Hackathon 2026 — Security Track</sub><br/>
  <sub>By <a href="https://github.com/Mustafa11300">Mustafa Hussain</a></sub>
</p>
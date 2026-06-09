"""
SENTINELOPS — UNIFIED API SERVER
===================================
Autonomous Security Operations Platform

Serves:
  - Foundation API (v2): /api/v2/simulation, /api/v2/math, etc.
  - War Room WebSocket: /ws/war-room
  - Splunk Integration: /api/splunk/*

Run with:
  uvicorn cloudguard.app:app --port 8001
"""

import os
import sys
import logging

# Load .env before anything reads env vars
from dotenv import load_dotenv
load_dotenv()

# Ensure project root is on path
sys.path.insert(0, os.path.dirname(os.path.dirname(__file__)))

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware

# Phase 1 Foundation routers
from cloudguard.api.routes import (
    simulation_router,
    math_router,
    branches_router,
    events_router,
    test_router,
)

# Phase 3 War Room — WebSocket streaming engine
from cloudguard.api.streamer import war_room_router, lifespan

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(name)s — %(message)s",
)

# ── App ───────────────────────────────────────────────────────────────────────

app = FastAPI(
    title="SentinelOps — Autonomous Security Operations",
    description=(
        "AI-Powered Autonomous Security Operations Platform.\n\n"
        "Real-time threat detection from Splunk telemetry.\n"
        "Multi-agent swarm with Pareto-optimal remediation.\n"
        "NIST AI RMF compliant with human-in-the-loop override."
    ),
    version="1.0.0",
    docs_url="/docs",
    redoc_url="/redoc",
    lifespan=lifespan,
)

# CORS
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*", "https://cloudgaurd.vercel.app"],
    allow_credentials=False,
    allow_methods=["*"],
    allow_headers=["*"],
)

# ── Phase 1 Foundation Routes (v2) ───────────────────────────────────────────
app.include_router(simulation_router)
app.include_router(math_router)
app.include_router(branches_router)
app.include_router(events_router)
app.include_router(test_router)

# ── Phase 3 War Room (WebSocket) ──────────────────────────────────────────────
app.include_router(war_room_router)

# ── Original CloudGuard Routes (v1) ──────────────────────────────────────────
try:
    from api.findings import router as findings_router
    from api.score import router as score_router
    from api.chat import router as chat_router

    app.include_router(findings_router, prefix="/api/findings", tags=["Findings (v1)"])
    app.include_router(score_router, prefix="/api/score", tags=["Score (v1)"])
    app.include_router(chat_router, prefix="/api/chat", tags=["Chat (v1)"])
except ImportError:
    logging.getLogger("cloudguard.app").info(
        "Original CloudGuard v1 routes not available (missing dependencies)"
    )


# ── Health Check ──────────────────────────────────────────────────────────────

@app.get("/", tags=["Health"])
def health_check():
    return {
        "status": "SentinelOps is running",
        "version": "1.0.0",
        "platform": "Autonomous Security Operations",
        "docs": "/docs",
    }


@app.get("/api/v2/health", tags=["Health"])
def health_v2():
    from cloudguard.api.streamer import CLIENTS, EVENT_BUFFER, TOPOLOGY
    return {
        "status": "healthy",
        "subsystems": {
            "simulation_engine": True,
            "math_engine": True,
            "branch_manager": True,
            "event_bus": True,
            "temporal_clock": True,
            "remediation_protocol": True,
            "swarm_interfaces": True,
            "telemetry_generator": True,
            "war_room_streamer": True,
        },
        "war_room": {
            "ws_endpoint": "ws://localhost:8001/ws/war-room",
            "active_clients": len(CLIENTS),
            "buffer_events": len(EVENT_BUFFER),
            "topology_resources": len(TOPOLOGY),
        },
    }


@app.get("/api/splunk/status", tags=["Splunk"])
def splunk_status():
    from cloudguard.mcp_client import get_splunk_status
    return get_splunk_status()

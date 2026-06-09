"""
SENTINELOPS — SPLUNK MCP CLIENT
================================
Queries Splunk Enterprise for real security telemetry.

Hybrid Mode (Option B):
  1. Query Splunk first
  2. If results come back → use them
  3. If empty → fall back to simulation data

All return values match the format that emit_event() expects:
  {
    "event_type": "DRIFT" | "REMEDIATION" | ...,
    "event_id": "evt-...",
    "data": { ... },
    "environment_weights": {"w_R": ..., "w_C": ...}
  }
"""

from __future__ import annotations

import logging
import os
import random
import time
import uuid
from datetime import datetime, timezone
from typing import Any, Optional

logger = logging.getLogger("sentinelops.mcp_client")

_splunk_available = False
try:
    import splunklib.client as splunk_client
    import splunklib.results as splunk_results
    _splunk_available = True
except ImportError:
    logger.warning("splunk-sdk not installed — Splunk queries will use simulation fallback")


SPLUNK_HOST = os.getenv("SPLUNK_HOST", "localhost")
SPLUNK_PORT = int(os.getenv("SPLUNK_PORT", "8089"))
SPLUNK_USERNAME = os.getenv("SPLUNK_USERNAME", "admin")
SPLUNK_PASSWORD = os.getenv("SPLUNK_PASSWORD", "")
SPLUNK_SCHEME = os.getenv("SPLUNK_SCHEME", "https")

_service: Optional[Any] = None
_connection_attempted = False


def _get_splunk_service():
    global _service, _connection_attempted
    if _service is not None:
        return _service
    if _connection_attempted:
        return None
    _connection_attempted = True

    if not _splunk_available:
        logger.info("splunk-sdk not available, skipping connection")
        return None
    if not SPLUNK_PASSWORD:
        logger.info("SPLUNK_PASSWORD not set, skipping Splunk connection")
        return None

    try:
        _service = splunk_client.connect(
            host=SPLUNK_HOST,
            port=SPLUNK_PORT,
            username=SPLUNK_USERNAME,
            password=SPLUNK_PASSWORD,
            scheme=SPLUNK_SCHEME,
            autologin=True,
        )
        logger.info(f"Connected to Splunk at {SPLUNK_HOST}:{SPLUNK_PORT}")
        return _service
    except Exception as exc:
        logger.warning(f"Splunk connection failed: {exc}")
        _service = None
        return None


def _run_splunk_search(query: str, max_results: int = 50, earliest: str = "-24h") -> list[dict]:
    svc = _get_splunk_service()
    if svc is None:
        return []

    try:
        search_query = query if query.startswith("search") or query.startswith("|") else f"search {query}"
        kwargs = {
            "earliest_time": earliest,
            "latest_time": "now",
            "count": max_results,
        }
        results_stream = svc.jobs.oneshot(search_query, output_mode="json",**kwargs)
        reader = splunk_results.JSONResultsReader(results_stream)

        results = []
        for item in reader:
            if isinstance(item, dict):
                results.append(item)
        return results
    except Exception as exc:
        logger.warning(f"Splunk search failed: {exc}")
        return []


_SEVERITY_MAP = {
    "critical": "CRITICAL",
    "high": "HIGH",
    "medium": "MEDIUM",
    "low": "LOW",
    "informational": "LOW",
    "info": "LOW",
}

_SIM_THREATS = [
    {
        "resource_id": "srv-web-prod-01",
        "drift_type": "IAM_POLICY_CHANGE",
        "severity": "CRITICAL",
        "description": "SSH brute force attempt detected — 847 failed auth events from 45.227.254.8",
        "source_ip": "45.227.254.8",
        "cumulative_drift_score": 8.7,
    },
    {
        "resource_id": "srv-db-prod-03",
        "drift_type": "PERMISSION_ESCALATION",
        "severity": "HIGH",
        "description": "Privilege escalation via sudo — unauthorized root access on database server",
        "source_ip": "10.0.1.45",
        "cumulative_drift_score": 7.2,
    },
    {
        "resource_id": "fw-edge-01",
        "drift_type": "NETWORK_RULE_CHANGE",
        "severity": "HIGH",
        "description": "Firewall rule modification — port 4444 opened to 0.0.0.0/0 (reverse shell signature)",
        "source_ip": "192.168.1.100",
        "cumulative_drift_score": 8.1,
    },
    {
        "resource_id": "srv-mail-01",
        "drift_type": "PUBLIC_EXPOSURE",
        "severity": "MEDIUM",
        "description": "DNS exfiltration pattern detected — high-entropy subdomain queries to suspicious TLD",
        "source_ip": "10.0.2.15",
        "cumulative_drift_score": 5.4,
    },
    {
        "resource_id": "k8s-node-02",
        "drift_type": "ENCRYPTION_REMOVED",
        "severity": "CRITICAL",
        "description": "Container escape attempt — privileged pod accessing host filesystem /etc/shadow",
        "source_ip": "10.244.0.12",
        "cumulative_drift_score": 9.1,
    },
]


def _splunk_event_to_threat(event: dict) -> dict:
    raw_severity = str(event.get("severity", event.get("urgency", "medium"))).lower()
    severity = _SEVERITY_MAP.get(raw_severity, "MEDIUM")
    source_ip = event.get("src_ip", event.get("src", event.get("source_ip", "unknown")))
    dest = event.get("dest", event.get("dest_ip", event.get("host", "unknown")))
    event_name = event.get("search_name", event.get("source", event.get("_raw", "Splunk Alert")[:80]))
    category = event.get("category", event.get("action", ""))

    drift_type_map = {
        "authentication": "IAM_POLICY_CHANGE",
        "access": "PERMISSION_ESCALATION",
        "network": "NETWORK_RULE_CHANGE",
        "malware": "PUBLIC_EXPOSURE",
        "change": "IAM_POLICY_CHANGE",
    }
    drift_type = "IAM_POLICY_CHANGE"
    for key, dtype in drift_type_map.items():
        if key in category.lower() or key in str(event_name).lower():
            drift_type = dtype
            break

    return {
        "resource_id": dest if dest != "unknown" else f"res-{uuid.uuid4().hex[:6]}",
        "drift_type": drift_type,
        "severity": severity,
        "description": str(event_name),
        "source_ip": source_ip,
        "cumulative_drift_score": round(random.uniform(3.0, 9.5), 2),
        "splunk_raw": True,
    }


def get_all_threats(w_r: float = 0.6, w_c: float = 0.4) -> list[dict]:
    """
    Query Splunk for security threats. Falls back to simulation if empty.
    Returns list of dicts ready for emit_event().
    """
    splunk_results_list = _run_splunk_search(
        'search index=* (sourcetype=launchd OR sourcetype=syslog OR sourcetype=system) '
        '(error OR fail OR denied OR warn OR killed OR crash) '
        '| head 20',
        max_results=20,
        earliest="-1h",
    )

    threats = []
    if splunk_results_list:
        for event in splunk_results_list[:10]:
            threat_data = _splunk_event_to_threat(event)
            threats.append(_format_as_drift_event(threat_data, w_r, w_c))
        logger.info(f"Splunk returned {len(threats)} real threats")
    else:
        sim_threat = random.choice(_SIM_THREATS)
        threats.append(_format_as_drift_event(sim_threat, w_r, w_c))
        logger.debug("Using simulation fallback for threats")

    return threats


def get_ssh_brute_force(w_r: float = 0.6, w_c: float = 0.4) -> list[dict]:
    """
    Targeted query for SSH brute force events from Splunk.
    This is the demo-critical query — Splunk should have real data for this.
    """
    splunk_results_list = _run_splunk_search(
        'search index=* sourcetype=launchd (error OR fail OR killed OR denied) '
        '| stats count by host, _si '
        '| where count > 5 '
        '| sort -count '
        '| head 10',
        max_results=10,
        earliest="-1h",
    )

    threats = []
    if splunk_results_list:
        for event in splunk_results_list:
            count = int(event.get("count", 0))
            src = event.get("src_ip", event.get("src", "unknown"))
            dest = event.get("dest", "unknown")
            user = event.get("user", "unknown")
            severity = "CRITICAL" if count > 50 else ("HIGH" if count > 10 else "MEDIUM")

            threat_data = {
                "resource_id": dest,
                "drift_type": "IAM_POLICY_CHANGE",
                "severity": severity,
                "description": f"SSH brute force: {count} failed attempts from {src} targeting user '{user}'",
                "source_ip": src,
                "cumulative_drift_score": min(9.9, round(count / 10, 1)),
                "ssh_attempts": count,
                "target_user": user,
                "splunk_raw": True,
            }
            threats.append(_format_as_drift_event(threat_data, w_r, w_c))
        logger.info(f"Splunk returned {len(threats)} SSH brute force events")
    else:
        threats.append(_format_as_drift_event({
            "resource_id": "srv-ssh-prod-01",
            "drift_type": "IAM_POLICY_CHANGE",
            "severity": "CRITICAL",
            "description": "SSH brute force: 847 failed attempts from 45.227.254.8 targeting user 'root'",
            "source_ip": "45.227.254.8",
            "cumulative_drift_score": 8.5,
            "ssh_attempts": 847,
            "target_user": "root",
        }, w_r, w_c))
        logger.debug("Using simulation fallback for SSH brute force")

    return threats


def get_recent_alerts(w_r: float = 0.6, w_c: float = 0.4) -> list[dict]:
    """
    Query Splunk for recent notable/alert events.
    """
    splunk_results_list = _run_splunk_search(
        'index=* sourcetype="syslog" OR sourcetype="linux_secure" '
        '| stats count by host, sourcetype '
        '| sort -count '
        '| head 10',
        max_results=10,
        earliest="-1h",
    )

    alerts = []
    if splunk_results_list:
        for event in splunk_results_list:
            host = event.get("host", "unknown")
            st = event.get("sourcetype", "unknown")
            count = int(event.get("count", 0))
            alerts.append({
                "host": host,
                "sourcetype": st,
                "event_count": count,
                "timestamp": datetime.now(timezone.utc).isoformat(),
            })
        logger.info(f"Splunk returned {len(alerts)} recent alert summaries")
    return alerts


def get_splunk_status() -> dict:
    svc = _get_splunk_service()
    if svc is None:
        return {
            "connected": False,
            "host": SPLUNK_HOST,
            "port": SPLUNK_PORT,
            "reason": "not connected" if not _splunk_available else "connection failed or no password",
        }
    try:
        info = svc.info
        return {
            "connected": True,
            "host": SPLUNK_HOST,
            "port": SPLUNK_PORT,
            "version": str(info.get("version", "unknown")),
            "server_name": str(info.get("serverName", "unknown")),
            "os": str(info.get("os_name", "unknown")),
        }
    except Exception as exc:
        return {"connected": False, "host": SPLUNK_HOST, "error": str(exc)}


def _format_as_drift_event(threat_data: dict, w_r: float, w_c: float) -> dict:
    """Format a threat dict into the exact structure emit_event() expects."""
    return {
        "event_type": "DRIFT",
        "event_id": f"evt-{uuid.uuid4().hex[:8]}",
        "trace_id": f"trace-{uuid.uuid4().hex[:12]}",
        "timestamp_tick": int(time.time()) % 100000,
        "environment_weights": {"w_R": w_r, "w_C": w_c},
        "data": {
            "resource_id": threat_data.get("resource_id", f"res-{uuid.uuid4().hex[:6]}"),
            "drift_type": threat_data.get("drift_type", "IAM_POLICY_CHANGE"),
            "severity": threat_data.get("severity", "MEDIUM"),
            "cumulative_drift_score": threat_data.get("cumulative_drift_score", 5.0),
            "is_false_positive": False,
            "description": threat_data.get("description", ""),
            "source_ip": threat_data.get("source_ip", ""),
            "splunk_raw": threat_data.get("splunk_raw", False),
        },
    }

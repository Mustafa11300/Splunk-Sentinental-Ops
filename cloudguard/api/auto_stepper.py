"""
SENTINELOPS — BACKGROUND AUTO-STEPPER
========================================
Continuously runs simulation ticks and emits structured events
through the War Room WebSocket so the frontend is never blank.

Hybrid Mode: Queries Splunk for real threats first, falls back
to simulation if Splunk is empty or unavailable.
"""

from __future__ import annotations

import asyncio
import logging
import os
import random
import uuid
from datetime import datetime, timezone

logger = logging.getLogger("sentinelops.auto_stepper")

STEP_INTERVAL_S    = 4.0
NARRATIVE_INTERVAL = 3
FORECAST_INTERVAL  = 5
TOPOLOGY_INTERVAL  = 6
TICKER_INTERVAL    = 2
SPLUNK_QUERY_INTERVAL = 4  # query Splunk every Nth tick

USE_SPLUNK = os.getenv("SPLUNK_MODE", "true").lower() == "true"
USE_CLAUDE = os.getenv("NARRATIVE_PROVIDER", "template").lower() == "claude"

_DRIFT_TYPES = [
    "IAM_POLICY_CHANGE", "PUBLIC_EXPOSURE", "ENCRYPTION_REMOVED",
    "PERMISSION_ESCALATION", "NETWORK_RULE_CHANGE", "BACKUP_DISABLED",
]
_SEVERITY_LEVELS = ["LOW", "MEDIUM", "HIGH", "CRITICAL"]
_RESOURCE_IDS = [f"res-{i:03d}" for i in range(1, 346)]

_THREAT_HEADINGS = [
    "⚔️ Sentry Assessment — CRITICAL Drift on IAM Policy",
    "⚔️ Sentry Assessment — HIGH Risk Encryption Removal",
    "⚔️ Sentry Assessment — PUBLIC_EXPOSURE Detected",
    "⚔️ Sentry Assessment — PERMISSION_ESCALATION Alert",
]
_THREAT_BODIES = [
    "IAM policy drift detected on production resource. Assessed severity: CRITICAL ⛔. "
    "This represents a direct violation of [NIST IA-2]. If unaddressed, the attack surface "
    "permits lateral movement and privilege escalation. Zero-tolerance posture mandated "
    "[NIST SP 800-207 Zero Trust].",
    "Encryption configuration removed from data-at-rest storage. Compliance gap: [CIS 2.1.1]. "
    "All regulated data is now exposed to insider threat vectors. "
    "Mandatory remediation per NIST SP 800-175B.",
    "Resource publicly accessible without authentication. Direct violation of [CIS 2.1.2]. "
    "Attack surface expanded to include unauthenticated internet traffic.",
    "Administrative privileges granted without MFA enforcement. Violation of [NIST AC-6]. "
    "Least-privilege principle compromised. Lateral movement risk elevated to CRITICAL.",
]
_ARGUMENT_HEADINGS = [
    "💰 Consultant Counter-Argument — ROI & Cost Model",
    "💰 Controller Economic Analysis — ROSI Projection",
]
_ARGUMENT_BODIES = [
    "Economic analysis: ALE reduction $48,000 → $12,000. "
    "Avoided L3 Engineer labor: 4h × $150/hr = $600. "
    "ROSI: 2.4x. Break-even: 1.2 months. Total value created: $36,600. "
    "[Gordon & Loeb (2002)]",
    "Remediation cost: $2,400. Annual risk reduction: $72,000 → $18,000. "
    "ROSI: 21.5x over 12 months. Labor savings: $600 per incident. "
    "[NIST AI RMF 1.0]",
]
_SYNTHESIS_HEADINGS = [
    "⚖️ Active Editor — Pareto-Optimal Path Selected",
    "⚖️ Orchestrator Synthesis — J-Score Equilibrium Achieved",
]
_SYNTHESIS_BODIES = [
    "Orchestrator Synthesis — Active Editor synthesized a Pareto-optimal path. "
    "J = min Σ (w_R·R̂ᵢ + w_C·Ĉᵢ). Weights: w_R=0.620, w_C=0.380. "
    "Pareto front: 3 solutions. Autonomous execution begins in 10s unless vetoed. "
    "[NSGA-II, Deb et al. (2002)] [NIST AI RMF 1.0 — Govern 1.1]",
    "J-Score converged. Risk-cost trade-off resolved via NSGA-II. "
    "Controller's cost-optimized fix selected as Pareto-dominant. "
    "[NIST AI RMF — Govern 1.1] [Sovereign Autonomy SLA]",
]
_FORECAST_TARGETS = [
    "res-042", "res-118", "res-201", "res-077", "res-305",
    "res-156", "res-089", "res-234", "res-012", "res-291",
]
_REMEDIATION_ACTIONS = [
    "rotate_credentials", "patch_security_group", "enable_encryption",
    "block_public_access", "enforce_mfa", "revoke_admin_policy",
]


def _build_direct_ui_narrative(chunk_type, heading, body, citation, decision_id,
                                j_before, j_after, w_r, w_c,
                                countdown_active=False, seconds_remaining=0,
                                is_fast_pass=False):
    agent_map = {
        "threat": "sentry_node", "argument": "consultant_node",
        "synthesis": "active_editor", "fast_pass": "sovereign_gate",
    }
    return {
        "event_id": f"chunk-{uuid.uuid4().hex[:8]}",
        "tick_timestamp": datetime.now(timezone.utc).isoformat(),
        "event_type": "NarrativeChunk",
        "agent_id": agent_map.get(chunk_type, "system"),
        "trace_id": decision_id,
        "message_body": {
            "chunk_type": chunk_type,
            "heading": heading,
            "body": body,
            "citation": citation,
            "is_final": chunk_type == "synthesis",
            "countdown_active": countdown_active,
            "seconds_remaining": seconds_remaining,
            "j_before": j_before,
            "j_after": j_after,
            "j_delta": round(j_after - j_before, 6),
            "j_improvement_pct": round(
                (j_before - j_after) / max(j_before, 1e-9) * 100, 2
            ),
            "is_fast_pass": is_fast_pass,
            "fast_pass_meta": {"accelerated_window_s": 10} if is_fast_pass else None,
            "roi_summary": {
                "ale_before_usd": round(random.uniform(30000, 90000), 2),
                "ale_after_usd": round(random.uniform(5000, 20000), 2),
                "ale_reduction_usd": round(random.uniform(20000, 70000), 2),
                "labor_savings_usd": 600.0,
                "remediation_cost_usd": round(random.uniform(500, 3000), 2),
                "rosi": round(random.uniform(1.5, 25.0), 2),
                "total_value_created": round(random.uniform(20000, 70000), 2),
            } if chunk_type == "synthesis" else None,
        },
        "w_R": w_r,
        "w_C": w_c,
        "j_score": round(j_before, 6),
    }


def _build_direct_ui_forecast(target, probability, signal_type, w_r, w_c,
                               j_score, is_shadow_ai=False):
    return {
        "event_id": f"evt-{uuid.uuid4().hex[:8]}",
        "tick_timestamp": datetime.now(timezone.utc).isoformat(),
        "event_type": "ForecastSignal",
        "agent_id": "threat_forecaster",
        "trace_id": f"forecast-{uuid.uuid4().hex[:12]}",
        "message_body": {
            "target": target,
            "probability": probability,
            "type": signal_type,
            "horizon": f"{random.randint(3, 8)} ticks",
            "predicted_drift": random.choice(_DRIFT_TYPES),
            "is_shadow_ai": is_shadow_ai,
            "j_forecast": round(j_score * probability, 4),
            "recon_chain": f"chain-{uuid.uuid4().hex[:6]}",
            "confidence_lo": round(max(0, probability - 0.15), 2),
            "confidence_hi": round(min(1.0, probability + 0.10), 2),
            "fast_pass_meta": {
                "accelerated_window_s": 10,
            } if probability >= 0.90 and is_shadow_ai else None,
        },
        "w_R": w_r, "w_C": w_c, "j_score": round(j_score, 6),
    }


def _build_narrative_from_splunk_threat(threat_data: dict, w_r: float, w_c: float,
                                         j_before: float, j_after: float) -> dict:
    """Build a NarrativeChunk from a real Splunk threat instead of hardcoded templates."""
    data = threat_data.get("data", threat_data)
    severity = data.get("severity", "MEDIUM")
    resource_id = data.get("resource_id", "unknown")
    description = data.get("description", "Security event detected")
    source_ip = data.get("source_ip", "")
    drift_type = data.get("drift_type", "IAM_POLICY_CHANGE")

    severity_emoji = {"CRITICAL": "⛔", "HIGH": "🔴", "MEDIUM": "🟡", "LOW": "🟢"}.get(severity, "⚠️")

    heading = f"⚔️ Sentry Assessment — {severity} {drift_type.replace('_', ' ').title()} on {resource_id}"
    body = (
        f"{description}. Assessed severity: {severity} {severity_emoji}. "
        f"Source: {source_ip}. "
        f"This event was detected from live Splunk telemetry and represents a real security signal "
        f"requiring immediate triage per [NIST SP 800-61r2]."
    )

    decision_id = f"dec-{uuid.uuid4().hex[:8]}"
    return _build_direct_ui_narrative(
        "threat", heading, body, "[NIST SP 800-61r2]",
        decision_id, j_before, j_before, w_r, w_c,
    ), decision_id


async def _generate_claude_narrative(threat_data: dict, chunk_type: str) -> Optional[str]:
    """Generate narrative text using Claude (direct or via OpenRouter). Returns None on failure."""
    if not USE_CLAUDE:
        return None

    api_key = os.getenv("ANTHROPIC_API_KEY", "")
    if not api_key:
        return None

    try:
        data = threat_data.get("data", threat_data)
        prompts = {
            "threat": (
                f"You are a security operations analyst for SentinelOps. A {data.get('severity', 'MEDIUM')} "
                f"severity {data.get('drift_type', 'security event')} was detected on resource "
                f"{data.get('resource_id', 'unknown')}. Source IP: {data.get('source_ip', 'unknown')}. "
                f"Description: {data.get('description', 'N/A')}. "
                f"Produce a 2-3 sentence threat assessment. Be direct. Include the compliance citation."
            ),
            "argument": (
                f"You are a cost-optimization controller. Given a {data.get('severity', 'MEDIUM')} "
                f"security event on {data.get('resource_id', 'unknown')}, produce a 2-3 sentence "
                f"economic counter-argument analyzing the ROSI and remediation cost tradeoff. "
                f"Include dollar figures and break-even timeline."
            ),
            "synthesis": (
                f"You are the orchestrator synthesizing a Pareto-optimal remediation path. "
                f"The threat is {data.get('severity', 'MEDIUM')} on {data.get('resource_id', 'unknown')}. "
                f"Produce a 2-3 sentence synthesis explaining the J-Score equilibrium achieved "
                f"and the autonomous execution window."
            ),
        }

        prompt = prompts.get(chunk_type, prompts["threat"])

        if api_key.startswith("sk-or-"):
            import httpx
            model = os.getenv("CLAUDE_MODEL", "anthropic/claude-sonnet-4-6")
            async with httpx.AsyncClient(timeout=15.0) as client:
                resp = await client.post(
                    "https://openrouter.ai/api/v1/chat/completions",
                    headers={
                        "Authorization": f"Bearer {api_key}",
                        "Content-Type": "application/json",
                    },
                    json={
                        "model": model,
                        "max_tokens": 200,
                        "messages": [
                            {"role": "system", "content": "You are a concise security analyst. No markdown. No bullet points. Plain English only."},
                            {"role": "user", "content": prompt},
                        ],
                    },
                )
                resp.raise_for_status()
                result = resp.json()
                return result["choices"][0]["message"]["content"]
        else:
            import anthropic
            client = anthropic.Anthropic(api_key=api_key)
            response = client.messages.create(
                model="claude-sonnet-4-6",
                max_tokens=200,
                messages=[{"role": "user", "content": prompt}],
                system="You are a concise security analyst. No markdown. No bullet points. Plain English only.",
            )
            return response.content[0].text
    except Exception as exc:
        logger.warning(f"Claude narrative generation failed: {exc}")
        return None


async def run_auto_stepper():
    """Background coroutine: continuously steps simulation and emits events."""
    from cloudguard.api.streamer import (
        _broadcast, emit_event, emit_ticker,
        build_topology_sync_message, TOPOLOGY, _update_topology, EVENT_BUFFER,
    )
    from cloudguard.api.routes import get_engine

    if USE_SPLUNK:
        from cloudguard.mcp_client import get_all_threats, get_ssh_brute_force, get_splunk_status
        status = get_splunk_status()
        logger.info(f"Splunk status: {status}")

    logger.info(f"🤖 Auto-Stepper: initializing (SPLUNK_MODE={USE_SPLUNK}, NARRATIVE={USE_CLAUDE})")
    await asyncio.sleep(2.0)

    try:
        engine = get_engine()
        if not engine._initialized:
            engine.initialize()
        logger.info("🤖 Auto-Stepper: engine initialized")
    except Exception as exc:
        logger.error(f"🤖 Auto-Stepper: init failed: {exc}")
        return

    for _ in range(5):
        try:
            engine.step()
        except Exception:
            pass

    tick = 0
    w_r, w_c, j_score = 0.60, 0.40, 0.50
    _last_splunk_threats: list[dict] = []

    for i in range(30):
        rid = f"res-{i+1:03d}"
        st = "GREEN" if random.random() > 0.3 else ("YELLOW" if random.random() > 0.4 else "RED")
        TOPOLOGY[rid] = st
    try:
        await _broadcast(build_topology_sync_message())
    except Exception:
        pass

    logger.info("🤖 Auto-Stepper: entering main loop")

    while True:
        try:
            tick += 1

            try:
                report = engine.step()
                j_score = report.j_score if report.j_score > 0 else j_score
            except Exception:
                pass

            w_r += random.uniform(-0.03, 0.03)
            w_r = round(max(0.40, min(0.75, w_r)), 3)
            w_c = round(1.0 - w_r, 3)
            j_score = round(max(0.15, min(0.85, j_score + random.uniform(-0.02, 0.015))), 4)

            # SPLUNK-SOURCED THREATS (hybrid: real data first, simulation fallback)
            if USE_SPLUNK and tick % SPLUNK_QUERY_INTERVAL == 0:
                try:
                    if tick % (SPLUNK_QUERY_INTERVAL * 3) == 0:
                        splunk_threats = get_ssh_brute_force(w_r, w_c)
                    else:
                        splunk_threats = get_all_threats(w_r, w_c)

                    if splunk_threats:
                        _last_splunk_threats = splunk_threats
                        for threat in splunk_threats[:3]:
                            await emit_event(threat)
                            data = threat.get("data", {})
                            rid = data.get("resource_id", "")
                            sev = data.get("severity", "MEDIUM")
                            if rid:
                                _update_topology(rid, sev)
                        logger.info(f"Emitted {min(3, len(splunk_threats))} Splunk threats")
                except Exception as exc:
                    logger.warning(f"Splunk query failed, using simulation: {exc}")

            # DRIFT (simulation fallback or supplementary)
            if random.random() < 0.4:
                rid = random.choice(_RESOURCE_IDS[:60])
                sev = random.choice(_SEVERITY_LEVELS)
                await emit_event({
                    "event_type": "DRIFT",
                    "event_id": f"evt-{uuid.uuid4().hex[:8]}",
                    "trace_id": f"trace-{uuid.uuid4().hex[:12]}",
                    "timestamp_tick": tick,
                    "environment_weights": {"w_R": w_r, "w_C": w_c},
                    "data": {
                        "resource_id": rid,
                        "drift_type": random.choice(_DRIFT_TYPES),
                        "severity": sev,
                        "cumulative_drift_score": round(random.uniform(1, 9), 2),
                        "is_false_positive": random.random() < 0.12,
                    },
                })
                _update_topology(rid, sev)

            # REMEDIATION
            if random.random() < 0.25:
                rid = random.choice(_RESOURCE_IDS[:60])
                j_b = j_score
                j_a = round(j_score - random.uniform(0.005, 0.03), 4)
                await emit_event({
                    "event_type": "REMEDIATION",
                    "event_id": f"evt-{uuid.uuid4().hex[:8]}",
                    "trace_id": f"trace-{uuid.uuid4().hex[:12]}",
                    "timestamp_tick": tick,
                    "environment_weights": {"w_R": w_r, "w_C": w_c},
                    "data": {
                        "resource_id": rid,
                        "action": random.choice(_REMEDIATION_ACTIONS),
                        "tier": random.choice(["silver", "gold"]),
                        "success": random.random() > 0.1,
                        "j_before": j_b, "j_after": j_a,
                    },
                })

            # NARRATIVE CHUNKS (enhanced with Splunk data + optional Claude)
            if tick % NARRATIVE_INTERVAL == 0:
                did = f"dec-{uuid.uuid4().hex[:8]}"
                j_b = j_score
                j_a = round(j_score - random.uniform(0.01, 0.04), 4)

                # Use Splunk threat data for narrative if available
                if _last_splunk_threats and USE_SPLUNK:
                    threat_source = random.choice(_last_splunk_threats)
                    threat_chunk, did = _build_narrative_from_splunk_threat(
                        threat_source, w_r, w_c, j_b, j_b
                    )
                    # Try Claude for richer body text
                    claude_body = await _generate_claude_narrative(threat_source, "threat")
                    if claude_body:
                        threat_chunk["message_body"]["body"] = claude_body
                else:
                    threat_chunk = _build_direct_ui_narrative(
                        "threat", random.choice(_THREAT_HEADINGS),
                        random.choice(_THREAT_BODIES), "[NIST IA-2]",
                        did, j_b, j_b, w_r, w_c,
                    )

                await _broadcast(threat_chunk)
                EVENT_BUFFER.append(threat_chunk)
                await asyncio.sleep(1.0)

                # Argument chunk (optionally Claude-enhanced)
                arg_body = random.choice(_ARGUMENT_BODIES)
                if _last_splunk_threats and USE_CLAUDE:
                    claude_arg = await _generate_claude_narrative(
                        random.choice(_last_splunk_threats) if _last_splunk_threats else {}, "argument"
                    )
                    if claude_arg:
                        arg_body = claude_arg

                argument = _build_direct_ui_narrative(
                    "argument", random.choice(_ARGUMENT_HEADINGS),
                    arg_body, "[Gordon & Loeb (2002)]",
                    did, j_b, j_b, w_r, w_c,
                )
                await _broadcast(argument)
                EVENT_BUFFER.append(argument)
                await asyncio.sleep(1.0)

                is_fp = random.random() < 0.3
                synth_body = random.choice(_SYNTHESIS_BODIES)
                if _last_splunk_threats and USE_CLAUDE:
                    claude_synth = await _generate_claude_narrative(
                        random.choice(_last_splunk_threats) if _last_splunk_threats else {}, "synthesis"
                    )
                    if claude_synth:
                        synth_body = claude_synth

                synthesis = _build_direct_ui_narrative(
                    "synthesis", random.choice(_SYNTHESIS_HEADINGS),
                    synth_body,
                    "[NSGA-II] [NIST AI RMF]", did, j_b, j_a, w_r, w_c,
                    countdown_active=True,
                    seconds_remaining=10 if is_fp else 60,
                    is_fast_pass=is_fp,
                )
                await _broadcast(synthesis)
                EVENT_BUFFER.append(synthesis)

            # FORECAST SIGNALS
            if tick % FORECAST_INTERVAL == 0:
                target = random.choice(_FORECAST_TARGETS)
                if random.random() < 0.4:
                    sig_type = "Amber_Alert"
                    prob = round(random.uniform(0.80, 0.98), 2)
                    shadow = random.random() < 0.5
                else:
                    sig_type = "Advisory"
                    prob = round(random.uniform(0.55, 0.78), 2)
                    shadow = False

                fc = _build_direct_ui_forecast(
                    target, prob, sig_type, w_r, w_c, j_score, shadow,
                )
                await _broadcast(fc)
                EVENT_BUFFER.append(fc)

            # TICKER UPDATE
            if tick % TICKER_INTERVAL == 0:
                await emit_ticker(w_r, w_c, j_score, trigger="auto_stepper")

            # TOPOLOGY SYNC
            if tick % TOPOLOGY_INTERVAL == 0:
                for _ in range(random.randint(1, 4)):
                    rid = random.choice(list(TOPOLOGY.keys()) or _RESOURCE_IDS[:30])
                    TOPOLOGY[rid] = random.choice(["GREEN", "GREEN", "GREEN", "YELLOW", "RED"])
                await _broadcast(build_topology_sync_message())

            await asyncio.sleep(STEP_INTERVAL_S)

        except asyncio.CancelledError:
            logger.info("🤖 Auto-Stepper: cancelled")
            return
        except Exception as exc:
            logger.warning(f"🤖 Auto-Stepper: error (continuing): {exc}")
            await asyncio.sleep(2.0)

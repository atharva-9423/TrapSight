"""SENTINEL backend — FastAPI. Safe by design: no subprocess, no host exec, virtual FS only."""
from __future__ import annotations
import asyncio
import os
import time
from typing import Dict, Set

from fastapi import FastAPI, WebSocket, WebSocketDisconnect, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from fastapi.staticfiles import StaticFiles
from fastapi.responses import FileResponse
from pydantic import BaseModel, Field

from .database import (init_db, upsert_session, end_session, clear_session_data,
                       clear_all_data, log_event, log_indicator, log_deception,
                       get_events, get_indicators, get_deceptions,
                       dashboard_counts, recent_events, event_stats)
from .engine import state_manager as sm
from .engine.command_parser import parse_and_execute
from .engine import behavior_engine as be
from .engine import deception_engine as de
from .engine.honeytokens import is_honeytoken
from .security.guardrails import sanitize_command
from .ai.analyzer import analyze_session
from .ai import groq_client
from .ai import interpreter as ai_interp
from .company.real_system import real_system_model

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
FRONTEND_DIR = os.path.normpath(os.path.join(BASE_DIR, "..", "frontend"))
ASSETS_DIR = os.path.normpath(os.path.join(BASE_DIR, "..", "assets"))

app = FastAPI(title="DECEPTR", version="1.0")
app.add_middleware(CORSMiddleware, allow_origins=["*"], allow_methods=["*"], allow_headers=["*"])

init_db()

# ---- websocket broadcast ----
dash_clients: Set[WebSocket] = set()
session_clients: Dict[str, Set[WebSocket]] = {}


async def broadcast_dashboard(msg: dict):
    dead = []
    for ws in list(dash_clients):
        try:
            await ws.send_json(msg)
        except Exception:
            dead.append(ws)
    for ws in dead:
        dash_clients.discard(ws)


async def broadcast_session(sid: str, msg: dict):
    for ws in list(session_clients.get(sid, set())):
        try:
            await ws.send_json(msg)
        except Exception:
            pass


class ExecBody(BaseModel):
    command: str


@app.get("/api/health")
def health():
    return {"status": "ok", "system": "protected",
            "groq_configured": groq_client.is_configured(),
            "groq_model": groq_client.active_model()}


@app.post("/api/sessions")
async def create_session():
    st = sm.create_session()
    upsert_session(st.session_id, "active")
    await broadcast_dashboard({"kind": "session_created", "session_id": st.session_id})
    return {"session_id": st.session_id, "cwd": st.cwd, "status": st.status}


@app.get("/api/sessions")
def list_sessions():
    out = []
    for st in sm.list_sessions():
        evs = get_events(st.session_id)
        out.append({"session_id": st.session_id, "status": st.status,
                    "created_at": st.created_at, "commands": len(st.history),
                    "events": len(evs), "cwd": st.cwd})
    return {"sessions": out}


@app.get("/api/sessions/{sid}")
def get_session(sid: str):
    st = sm.get_session(sid)
    if not st:
        raise HTTPException(404, "Unknown session")
    evs = get_events(sid)
    actor, conf = be.classify_actor(st.history)
    return {"session_id": sid, "status": st.status, "cwd": st.cwd,
            "commands": len(st.history), "events": len(evs),
            "threat": be.threat_level([{"severity": e.get("severity")} for e in evs]),
            "actor": actor, "actor_confidence": conf,
            "progression": be.progression_from_events(
                [{"stage": e.get("stage")} for e in evs]),
            "deception_active": bool(st.deception_actions)}


@app.post("/api/sessions/{sid}/exec")
async def exec_command(sid: str, body: ExecBody):
    return await _run_exec(sid, body.command or "", remote=False)


@app.post("/api/sessions/{sid}/remote-exec")
async def remote_exec_command(sid: str, body: ExecBody):
    """Same as exec, but flagged remote so open terminals render it live.

    Used by demo scripts / external drivers: commands appear in
    terminal.html in real time via the session WebSocket."""
    return await _run_exec(sid, body.command or "", remote=True)


async def _run_exec(sid: str, raw: str, remote: bool):
    st = sm.get_session(sid)
    if not st:
        raise HTTPException(404, "Unknown session")
    if st.status != "active":
        raise HTTPException(400, "Session is closed")
    cmd, warnings = sanitize_command(raw)
    if not cmd:
        return {"output": "", "command": "", "cwd": st.cwd, "events": [],
                "deception": [], "remote": remote}
    st.history.append(cmd)
    cwd_before = st.cwd
    if cmd == "/help":
        result = {"output": ai_interp.attack_help(st), "accessed_paths": [],
                  "clear": False, "exit": False}
    else:
        result = parse_and_execute(cmd, st)
    accessed = list(result.get("accessed_paths", []))

    # behavior analysis (deterministic authority)
    new_events = be.analyze_command(cmd, accessed)

    # ---- hybrid AI path (Phase D/E): Groq interprets, virtual state executes ----
    ai_used = False
    ai_confidence = None
    ai_fallback = None
    ai_suggestion = None
    ai_deception: list[dict] = []
    if ai_interp.should_route_to_ai(cmd, result.get("output", "")):
        prior_events = get_events(sid)
        interp, ai_used, ai_fallback = ai_interp.interpret_with_fallback(
            cmd, st, [{"event_type": e.get("type")} for e in prior_events])
        if interp is not None:
            ai_confidence = interp.confidence
            ai_result = ai_interp.execute_interpretation(interp, st, cmd)
            result = {"output": ai_result["output"],
                      "clear": result.get("clear", False),
                      "exit": result.get("exit", False)}
            for p in ai_result["accessed_paths"]:
                if p not in accessed:
                    accessed.append(p)
            # AI-suggested behavior → events only through the fixed registry
            for ev in ai_interp.behavior_events(interp, cmd):
                ev["detail"] = ev.get("detail", "") + " [via groq]"
                new_events.append(ev)
            # AI deception suggestion → policy-gated, path allow-listed
            ai_deception = ai_interp.apply_deception_suggestion(interp, st)
            ai_suggestion = ai_interp.suggestion_for(interp)
            if interp.normalized_command and interp.normalized_command != cmd:
                log_indicator(sid, "ai_normalized", interp.normalized_command[:256])

    # Reconcile: the deterministic engine re-examines the FINAL accessed
    # paths, so e.g. a honeytoken touched via an AI-interpreted command
    # (tail/head/…) still fires honeytoken_accessed with full evidence.
    for ev in be.analyze_command(cmd, accessed):
        if not any(e["event_type"] == ev["event_type"]
                   and e.get("evidence") == ev.get("evidence") for e in new_events):
            new_events.append(ev)

    # Learning: track per-area interest from the FINAL accessed paths,
    # then expand decoys where interest is sustained (bounded, policy-gated).
    for p in accessed:
        area = de.area_of(p)
        if area:
            st.interests[area] = st.interests.get(area, 0) + 1
    interest_expansions = de.maybe_expand(st)

    for ev in new_events:
        log_event(sid, ev)
    st.event_count += len(new_events)

    # indicators (only real observed values)
    if accessed:
        for p in accessed:
            log_indicator(sid, "accessed_path", p)
    log_indicator(sid, "command", cmd)

    # adaptive deception (policy-gated)
    deception_actions = de.maybe_deploy(st, new_events) + ai_deception + interest_expansions
    for a in deception_actions:
        log_deception(sid, a)

    if result.get("exit"):
        sm.close_session(sid)
        end_session(sid)

    # Persist the transcript so the terminal survives navigation/reload.
    st.transcript.append({"command": cmd, "output": result.get("output", ""),
                          "cwd": cwd_before,
                          "clear": bool(result.get("clear", False)),
                          "exit": bool(result.get("exit", False))})
    del st.transcript[:-200]
    st.command_log.append({"ts": time.time(), "command": cmd,
                           "events": [e["event_type"] for e in new_events]})
    del st.command_log[:-200]

    payload = {"output": result["output"], "command": cmd, "cwd": st.cwd, "clear": result.get("clear", False),
               "exit": result.get("exit", False), "warnings": warnings,
               "events": new_events, "deception": deception_actions,
               "ai_used": ai_used, "ai_confidence": ai_confidence,
               "ai_fallback": ai_fallback, "suggestion": ai_suggestion,
               "remote": remote}
    await broadcast_session(sid, {"kind": "exec", "session_id": sid,
                                  "remote": remote, **payload})
    await broadcast_dashboard({"kind": "event_batch", "session_id": sid,
                               "command": cmd, "events": new_events,
                               "deception": deception_actions,
                               "counts": dashboard_counts()})
    return payload


@app.get("/api/sessions/{sid}/events")
def session_events(sid: str):
    if not sm.get_session(sid):
        raise HTTPException(404, "Unknown session")
    return {"events": get_events(sid)}


@app.get("/api/sessions/{sid}/transcript")
def session_transcript(sid: str):
    """Full terminal transcript for replay after navigation/reload (display-only)."""
    st = sm.get_session(sid)
    if not st:
        raise HTTPException(404, "Unknown session")
    return {"session_id": sid, "cwd": st.cwd, "transcript": st.transcript[-200:]}


@app.get("/api/sessions/{sid}/browse")
def session_browse(sid: str, path: str = ""):
    """Read-only directory listing for the file-manager UI.

    Deliberately silent (no history, no events, no indicators): looking
    around is not an attack. OPENING a file must go through exec/cmd
    (cat) so honeytokens and behavior analysis still fire.
    """
    st = sm.get_session(sid)
    if not st:
        raise HTTPException(404, "Unknown session")
    import posixpath
    target = st.fs.resolve(st.cwd, path or ".")
    if st.fs.is_dir(target):
        try:
            children = st.fs.list_dir(target)
        except (FileNotFoundError, NotADirectoryError):
            raise HTTPException(404, "No such directory")
        items = []
        for name in sorted(children):
            full = target.rstrip("/") + "/" + name if target != "/" else "/" + name
            node = st.fs.files.get(full, {})
            items.append({"name": name, "type": children[name],
                          "size": len(node.get("content", "")) if children[name] == "file" else 0,
                          "owner": node.get("owner", "")})
        items.sort(key=lambda e: (e["type"] != "dir", e["name"].lower()))
        return {"path": target, "type": "dir", "children": items}
    if st.fs.is_file(target):
        node = st.fs.files[st.fs.normalize(target)]
        return {"path": target, "type": "file",
                "size": len(node.get("content", "")), "owner": node.get("owner", "")}
    raise HTTPException(404, "No such file or directory")


@app.get("/api/sessions/{sid}/timeline")
def session_timeline(sid: str):
    if not sm.get_session(sid):
        raise HTTPException(404, "Unknown session")
    evs = get_events(sid)
    tl = [{"timestamp": e["timestamp"], "event": e["type"], "severity": e["severity"],
           "evidence": e["command"], "stage": e["stage"], "detail": e["detail"]} for e in evs]
    return {"timeline": tl}


@app.get("/api/sessions/{sid}/intelligence")
def intelligence(sid: str):
    st = sm.get_session(sid)
    if not st:
        raise HTTPException(404, "Unknown session")
    evs = get_events(sid)
    ev_simple = [{"event_type": e["type"], "severity": e["severity"], "stage": e["stage"],
                  "evidence": [e["command"]], "detail": e["detail"],
                  "mitre": be.MITRE.get(_mitre_key(e["type"]), [])} for e in evs]
    actor, conf = be.classify_actor(st.history)
    analysis = analyze_session(st.history, ev_simple)
    mitre = []
    for e in ev_simple:
        for m in e["mitre"]:
            if m not in mitre:
                mitre.append(m)
    return {
        "session": {"session_id": sid, "start_time": st.created_at,
                    "duration_sec": time.time() - st.created_at,
                    "commands": len(st.history), "event_count": len(evs),
                    "status": st.status, "cwd": st.cwd},
        "actor": {"label": actor, "confidence": conf,
                  "behaviors": sorted({e["stage"] for e in ev_simple if e.get("stage")})},
        "threat": be.threat_level(ev_simple),
        "progression": be.progression_from_events(ev_simple),
        "mitre": mitre,
        "indicators": get_indicators(sid),
        "honeytokens": [e for e in evs if e["type"] == "honeytoken_accessed"],
        "deception_actions": get_deceptions(sid),
        "expansions": st.expansions,
        "interests": st.interests,
        "decoy_manifest": st.decoy_manifest,
        "ai_analysis": analysis,
        "history": st.history[-50:],
    }


def _mitre_key(etype: str) -> str:
    return {"reconnaissance": "recon", "discovery": "discovery",
            "credential_discovery": "credential_discovery",
            "privilege_escalation_attempt": "privilege_escalation",
            "data_discovery": "data_discovery",
            "persistence_attempt": "persistence",
            "honeytoken_accessed": "honeytoken"}.get(etype, "recon")


@app.get("/api/sessions/{sid}/report")
def report(sid: str):
    intel = intelligence(sid)
    evs = get_events(sid)
    ai = intel.get("ai_analysis") or {}
    assessment = {k: ai.get(k) for k in (
        "behavior", "confidence", "intent_hypothesis", "severity",
        "evidence", "mitre_techniques", "recommended_action")}
    return {
        "title": f"DECEPTR Incident Report — {sid}",
        "generated_at": time.time(),
        "executive_summary": _summary(intel),
        "session": intel["session"],
        "observed_behavior": intel["actor"],
        "timeline": [{"timestamp": e["timestamp"], "event": e["type"],
                      "severity": e["severity"], "evidence": e["command"],
                      "stage": e["stage"]} for e in evs],
        "mitre": intel["mitre"],
        "indicators": intel["indicators"],
        "honeytoken_events": intel["honeytokens"],
        "deception_actions": intel["deception_actions"],
        "assessment": assessment,
        "recommended_actions": ["Preserve session telemetry.",
                                "Review honeytoken access in context of surrounding commands.",
                                "Hunt for matching indicators elsewhere in the estate.",
                                "No counter-action taken — DECEPTR is defensive only."],
    }


def _summary(intel: dict) -> str:
    s = intel["session"]
    if s["event_count"] == 0:
        return (f"Session {s['session_id']} recorded {s['commands']} command(s) with no "
                "behavioral rule matches. Insufficient evidence of malicious staging.")
    stages = [p["stage"] for p in intel["progression"] if p["reached"]]
    return (f"Session {s['session_id']} recorded {s['commands']} command(s) and "
            f"{s['event_count']} security event(s). Observed stages: {', '.join(stages)}. "
            f"Threat level: {intel['threat']}. Actor profile: {intel['actor']['label']} "
            f"({intel['actor']['confidence']}% confidence).")


@app.post("/api/sessions/{sid}/reset")
async def reset_session(sid: str):
    st = sm.reset_session(sid)
    if not st:
        raise HTTPException(404, "Unknown session")
    clear_session_data(sid)
    upsert_session(sid, "active")
    await broadcast_dashboard({"kind": "session_reset", "session_id": sid,
                               "counts": dashboard_counts()})
    await broadcast_session(sid, {"kind": "reset", "session_id": sid})
    return {"ok": True, "cwd": st.cwd}


@app.post("/api/sessions/{sid}/close")
def close_session(sid: str):
    if not sm.get_session(sid):
        raise HTTPException(404, "Unknown session")
    sm.close_session(sid)
    end_session(sid)
    return {"ok": True}


@app.get("/api/dashboard")
def dashboard():
    counts = dashboard_counts()
    sessions = []
    feed: list[dict] = []
    for s in sm.list_sessions():
        if s.status != "active":
            continue
        evs = get_events(s.session_id)
        simple = [{"severity": e.get("severity"), "stage": e.get("stage")} for e in evs]
        prog = be.progression_from_events(simple)
        current = next((p["stage"] for p in reversed(prog) if p["reached"]), "—")
        sessions.append({"session_id": s.session_id, "status": s.status,
                         "commands": len(s.history),
                         "threat": be.threat_level(simple), "stage": current,
                         "interests": s.interests})
        for entry in s.command_log:
            feed.append({"ts": entry["ts"], "session_id": s.session_id,
                         "command": entry["command"], "events": entry["events"]})
    feed.sort(key=lambda e: e["ts"], reverse=True)
    evs = recent_events(20)
    # Aggregate threat + progression across all active sessions so the
    # home page always reflects real observed evidence (never static).
    flat: list[dict] = []
    for s in sm.list_sessions():
        if s.status != "active":
            continue
        for e in get_events(s.session_id):
            flat.append({"severity": e.get("severity"), "stage": e.get("stage")})
    return {"counts": counts, "active": sessions, "recent_events": evs,
            "recent_commands": feed[:12],
            "threat": be.threat_level(flat),
            "progression": be.progression_from_events(flat),
            "stats": event_stats(),
            "system": "protected"}


@app.get("/api/real-system")
def real_system():
    """Production-truth reference for the Real System tab (static demo data)."""
    return real_system_model()


class ResetAllBody(BaseModel):
    confirm: bool = False


@app.post("/api/admin/reset-all")
async def admin_reset_all(body: ResetAllBody):
    """Reset the whole honeypot: all sessions, events, indicators, deceptions,
    transcripts and learning state are permanently cleared. The real-system
    reference is static and untouched."""
    if not body.confirm:
        raise HTTPException(400, "Confirmation required.")
    cleared_sessions = sm.reset_all_sessions()
    cleared_tables = clear_all_data()
    await broadcast_dashboard({"kind": "full_reset", "counts": dashboard_counts()})
    return {"ok": True, "sessions_cleared": cleared_sessions,
            "tables_cleared": cleared_tables}


class RealSystemBody(BaseModel):
    company: dict | None = None
    credentials: list | None = None
    documents: list | None = None
    logs: list | None = None
    services: list | None = None


@app.put("/api/admin/real-system")
def admin_set_real_system(body: RealSystemBody):
    """Insert/replace Real System reference data (admin overrides)."""
    from .company.real_system import set_overrides
    try:
        model = set_overrides({k: v for k, v in body.model_dump().items()
                               if v is not None})
    except ValueError as e:
        raise HTTPException(400, str(e))
    return {"ok": True, "model": model}


@app.post("/api/admin/real-system/reset")
def admin_reset_real_system():
    from .company.real_system import clear_overrides
    return {"ok": True, "model": clear_overrides()}


SCENARIOS = {
    "credential_hunt": [
        "ls /srv/meridian",
        "cat /srv/meridian/docs/onboarding.txt",
        "cat /srv/meridian/customers.csv",
        "find / -name credentials.txt",
        "cat /srv/meridian/api/config.json",
        "cat /srv/meridian/api/.env",
        "cat /backup/cloud_credentials.txt",
        "ls /opt/backup",
        "cat /opt/backup/credentials.txt",
    ],
    "full_progression": [
        "whoami", "id", "uname -a", "ifconfig",
        "crontab -l", "mkdir -p ~/.ssh",
        "echo ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABAQDsYntH3t1c >> ~/.ssh/authorized_keys",
        "systemctl enable meridian-api", "systemctl status meridian-api",
        "cat /srv/meridian/customers.csv",
        "grep -i customer /srv/meridian/customers.csv",
        "cat /var/log/syslog", "cat /etc/passwd",
    ],
    "quick_recon": [
        "ls /srv/meridian",
        "cat /srv/meridian/docs/onboarding.txt",
        "whoami",
        "find / -name credentials.txt",
    ],
}


class AttackBody(BaseModel):
    session_id: str = Field(max_length=32)
    scenario: str = "credential_hunt"
    commands: list[str] | None = None
    delay_ms: int = 300


@app.post("/api/admin/attack")
async def admin_attack(body: AttackBody):
    """Run a demo attack into a chosen session via the remote pipeline.

    Commands execute exactly as if typed: state, events, deception,
    transcript, dashboard and live terminal streaming all behave normally.
    """
    st = sm.get_session(body.session_id)
    if not st:
        raise HTTPException(404, "Unknown session")
    if st.status != "active":
        raise HTTPException(400, "Session is closed")
    if body.commands is not None:
        if not isinstance(body.commands, list) or not body.commands:
            raise HTTPException(400, "commands must be a non-empty list.")
        cmds = [str(c)[:512] for c in body.commands[:20]]
    else:
        if body.scenario not in SCENARIOS:
            raise HTTPException(400, f"Unknown scenario. Choose: {sorted(SCENARIOS)}")
        cmds = SCENARIOS[body.scenario]
    delay = max(0, min(2000, body.delay_ms)) / 1000.0
    results = []
    for c in cmds:
        r = await _run_exec(body.session_id, c, remote=True)
        results.append({"command": r.get("command", c),
                        "events": [e["event_type"] for e in r.get("events", [])],
                        "deception": [d.get("target", "") for d in r.get("deception", [])],
                        "output": (r.get("output", "") or "")[:300]})
        if delay:
            await asyncio.sleep(delay)
    intel = intelligence(body.session_id)
    reached = [p["stage"] for p in intel["progression"] if p["reached"]]
    return {"ok": True, "session_id": body.session_id,
            "commands_run": len(results), "results": results,
            "threat": intel["threat"], "progression": reached}


@app.websocket("/ws/dashboard")
async def ws_dashboard(ws: WebSocket):
    await ws.accept()
    dash_clients.add(ws)
    try:
        await ws.send_json({"kind": "hello", "counts": dashboard_counts()})
        while True:
            await asyncio.sleep(30)
            await ws.send_json({"kind": "ping", "counts": dashboard_counts()})
    except WebSocketDisconnect:
        pass
    finally:
        dash_clients.discard(ws)


@app.websocket("/ws/session/{sid}")
async def ws_session(ws: WebSocket, sid: str):
    await ws.accept()
    session_clients.setdefault(sid, set()).add(ws)
    try:
        while True:
            data = await ws.receive_text()  # keepalive; exec goes over REST
            await ws.send_json({"kind": "ack"})
    except WebSocketDisconnect:
        pass
    finally:
        session_clients.get(sid, set()).discard(ws)


# ---- serve frontend ----
if os.path.isdir(FRONTEND_DIR):
    app.mount("/css", StaticFiles(directory=os.path.join(FRONTEND_DIR, "css")), name="css")
    app.mount("/js", StaticFiles(directory=os.path.join(FRONTEND_DIR, "js")), name="js")
    if os.path.isdir(ASSETS_DIR):
        app.mount("/assets", StaticFiles(directory=ASSETS_DIR), name="assets")

    @app.get("/", include_in_schema=False)
    def serve_index():
        return FileResponse(os.path.join(FRONTEND_DIR, "index.html"))

    @app.get("/{page}.html", include_in_schema=False)
    def serve_page(page: str):
        path = os.path.join(FRONTEND_DIR, page + ".html")
        if os.path.isfile(path):
            return FileResponse(path)
        return FileResponse(os.path.join(FRONTEND_DIR, "index.html"))

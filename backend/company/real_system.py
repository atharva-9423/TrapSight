"""The 'real' demo company — production truth for the Real System tab.

Fictional company, fictional values, demo scope only. Code-level values are
the DEFAULTS; the admin panel may override any section (stored in SQLite).
These values are the REFERENCE the honeypot decoys are compared against:
no AI-generated decoy may ever equal one of the EFFECTIVE values
(enforced by the decoy validator against real_secrets()).
"""
from __future__ import annotations
import copy
import json

COMPANY = {
    "name": "Meridian Logistics",
    "domain": "meridian.example",
    "prod_host": "prod-meridian-01",
    "db_host": "db.internal.meridian.example",
    "note": "Fictional demo company. Reference data for evaluation only.",
}

REAL_CREDENTIALS = [
    {"system": "Production database", "location": "db.internal.meridian.example",
     "username": "meridian_prod", "password": "M3r1dian#Prod-7741",
     "sensitivity": "critical"},
    {"system": "API service token", "location": "api.meridian.example",
     "username": "svc_api", "password": "meridian_live_7f3a9c2e51",
     "sensitivity": "high"},
    {"system": "AWS production", "location": "us-east-1",
     "username": "AKIA2F5N7EXAMPLE9QRS",
     "password": "9f2kD3mQEXAMPLE8x1vBn4s6hJ0aZcXeWw",
     "sensitivity": "critical"},
]

# Every real secret value — the decoy validator rejects any generated file
# containing one of these verbatim.
REAL_SECRETS = [c["password"] for c in REAL_CREDENTIALS] + \
               [c["username"] for c in REAL_CREDENTIALS
                if c["username"].startswith("AKIA")]

# Distinctive real-document tokens (client names, emails). Decoys must not
# reuse these either, so the terminal never shows Real-tab content.
REAL_DISTINCTIVE = [
    "Acme Industrial", "ops@client-a.example",
    "Bluefin Retail", "it@client-b.example",
    "Harbor Freightways", "dispatch@client-c.example",
    "241800", "256400", "249900",
]

REAL_DOCUMENTS = [
    {"path": "/srv/meridian/customers_real.csv", "label": "Customer master export",
     "preview": ("id,name,email,plan\n"
                 "201,Acme Industrial,ops@client-a.example,enterprise\n"
                 "202,Bluefin Retail,it@client-b.example,team\n"
                 "203,Harbor Freightways,dispatch@client-c.example,enterprise")},
    {"path": "/srv/meridian/finance_q3_real.csv", "label": "Q3 revenue (audited)",
     "preview": ("month,revenue_usd\n2024-07,241800\n2024-08,256400\n2024-09,249900")},
    {"path": "/srv/meridian/docs/backup_policy.txt", "label": "Backup policy",
     "preview": ("Nightly encrypted backups to vault storage.\n"
                 "Cloud credentials live in the secrets vault ONLY —\n"
                 "never in /backup or environment files.")},
]

REAL_LOGS = [
    {"path": "/var/log/auth.log", "label": "Production auth log (sample)",
     "preview": ("Jan 12 08:02:11 prod-meridian-01 sshd[410]: Accepted key "
                 "for admin from 10.0.1.20")},
]

REAL_SERVICES = [
    {"name": "meridian-api", "port": 8080, "host": "prod-meridian-01"},
    {"name": "postgres", "port": 5432, "host": "db.internal.meridian.example"},
    {"name": "nightly-backup", "port": None, "host": "cron 02:00 UTC"},
]


def real_system_model() -> dict:
    """Effective production-truth payload (defaults + admin overrides)."""
    data = {"company": copy.deepcopy(COMPANY),
            "credentials": copy.deepcopy(REAL_CREDENTIALS),
            "documents": copy.deepcopy(REAL_DOCUMENTS),
            "logs": copy.deepcopy(REAL_LOGS),
            "services": copy.deepcopy(REAL_SERVICES)}
    try:
        from ..database import get_real_overrides
        for k, v in get_real_overrides().items():
            if k in data:
                data[k] = v
    except Exception:
        pass
    return data


def real_secrets() -> list[str]:
    """Effective secret values (dynamic — honors admin edits)."""
    try:
        creds = real_system_model()["credentials"]
    except Exception:
        creds = REAL_CREDENTIALS
    out: list[str] = []
    for c in creds:
        if not isinstance(c, dict):
            continue
        pw = str(c.get("password", ""))
        if pw:
            out.append(pw)
        un = str(c.get("username", ""))
        if un.startswith("AKIA"):
            out.append(un)
    return out


SECTIONS = ("company", "credentials", "documents", "logs", "services")
MAX_OVERRIDE_BYTES = 50_000


def set_overrides(payload: dict) -> dict:
    """Validate + persist admin overrides. Returns the effective model."""
    if not isinstance(payload, dict):
        raise ValueError("Payload must be an object.")
    unknown = set(payload) - set(SECTIONS)
    if unknown:
        raise ValueError(f"Unknown sections: {sorted(unknown)}")
    if len(json.dumps(payload)) > MAX_OVERRIDE_BYTES:
        raise ValueError("Payload too large (50KB max).")
    clean: dict = {}
    if "company" in payload:
        co = payload["company"]
        if not isinstance(co, dict):
            raise ValueError("company must be an object.")
        clean["company"] = {k: str(v)[:300] for k, v in co.items()}
    if "credentials" in payload:
        rows = payload["credentials"]
        if not isinstance(rows, list) or len(rows) > 30:
            raise ValueError("credentials must be a list (max 30).")
        clean["credentials"] = [{
            "system": str(r.get("system", ""))[:120],
            "location": str(r.get("location", ""))[:200],
            "username": str(r.get("username", ""))[:200],
            "password": str(r.get("password", ""))[:300],
            "sensitivity": str(r.get("sensitivity", "high"))[:20].lower()
                           if str(r.get("sensitivity", "")).lower() in
                           ("low", "medium", "high", "critical") else "high",
        } for r in rows if isinstance(r, dict)]
    for key in ("documents", "logs"):
        if key in payload:
            rows = payload[key]
            if not isinstance(rows, list) or len(rows) > 30:
                raise ValueError(f"{key} must be a list (max 30).")
            clean[key] = [{
                "path": str(r.get("path", ""))[:300],
                "label": str(r.get("label", ""))[:200],
                "preview": str(r.get("preview", ""))[:4000],
            } for r in rows if isinstance(r, dict)]
    if "services" in payload:
        rows = payload["services"]
        if not isinstance(rows, list) or len(rows) > 30:
            raise ValueError("services must be a list (max 30).")
        clean["services"] = [{
            "name": str(r.get("name", ""))[:120],
            "host": str(r.get("host", ""))[:300],
            "port": r.get("port") if isinstance(r.get("port"), int) else None,
        } for r in rows if isinstance(r, dict)]
    from ..database import set_real_overrides
    set_real_overrides(clean)
    return real_system_model()


def clear_overrides() -> dict:
    from ..database import clear_real_overrides
    clear_real_overrides()
    return real_system_model()

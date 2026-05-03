"""FastAPI API server for ClawdBot DevOps dashboard."""
from __future__ import annotations

import asyncio
import hashlib
import hmac
import json
import logging
import os
import secrets
import time
from datetime import datetime

from fastapi import FastAPI, WebSocket, WebSocketDisconnect, Request, HTTPException, Depends, Form, UploadFile
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import StreamingResponse, JSONResponse, HTMLResponse, RedirectResponse
from fastapi.staticfiles import StaticFiles
from starlette.responses import FileResponse

import progress_broadcaster as broadcaster
from shell_executor import execute_shell, is_command_safe
from devops.monitors import (
    kubernetes_monitor, service_health_monitor, mongodb_monitor,
    nats_monitor, log_analyzer_monitor, issue_finder,
)
from devops.incident_manager import incident_manager
from devops.topology import build_topology, SERVICE_TOPOLOGY
from devops.playbooks import get_all_playbooks, get_playbook
from devops.remediation import execute_playbook, get_execution_history
from devops.approval import (
    get_pending as get_pending_approvals,
    approve as approve_request,
    reject as reject_request,
    get_all as get_all_approvals,
)
from devops.models import Severity
from devops.log_monitor import (
    scan_all_services as lm_scan_all,
    create_ticket as lm_create_ticket,
    get_tickets as lm_get_tickets,
    get_ticket as lm_get_ticket,
    update_ticket as lm_update_ticket,
    build_clawdbot_prompt as lm_build_prompt,
    start_auto_scan as lm_start_auto_scan,
    stop_auto_scan as lm_stop_auto_scan,
    get_last_scan_result as lm_get_last_scan,
)
from devops.ticket_db import (
    init_db as init_ticket_db,
    cleanup_old_tickets,
    reset_all_tickets,
    get_ticket_stats,
    save_passkey_credential,
    get_passkey_credential,
    get_passkey_credentials_for_user,
    update_passkey_sign_count,
)

logger = logging.getLogger(__name__)

app = FastAPI(title="ClawdBot DevOps API", version="1.0.0")

# CORS
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)


@app.on_event("startup")
async def _on_startup():
    """Start background tasks on API server startup."""
    # Initialize SQLite ticket database
    init_ticket_db()
    cleanup_old_tickets()
    logger.info("Ticket database initialized and cleaned up")

    # Schedule daily cleanup
    from apscheduler.schedulers.asyncio import AsyncIOScheduler
    _cleanup_scheduler = AsyncIOScheduler()
    _cleanup_scheduler.add_job(cleanup_old_tickets, "interval", hours=24)
    _cleanup_scheduler.start()

    # Auto-scan disabled - use "Scan Now" button in Log Monitor tab
    # lm_start_auto_scan(dispatch_fn=None, interval_seconds=300)
    logger.info("Log monitor ready (manual scan mode)")


# --- Auth ---

API_KEY = os.environ.get("DEVOPS_API_KEY", "")
DASHBOARD_USER = os.environ.get("DASHBOARD_USER", "admin")
DASHBOARD_PASS = os.environ.get("DASHBOARD_PASS", "")
SESSION_SECRET = os.environ.get("SESSION_SECRET", secrets.token_hex(32))
SESSION_MAX_AGE = 86400 * 7  # 7 days


def _sign_session(data: str) -> str:
    sig = hmac.new(SESSION_SECRET.encode(), data.encode(), hashlib.sha256).hexdigest()[:16]
    return f"{data}.{sig}"


def _verify_session(token: str) -> str | None:
    if "." not in token:
        return None
    data, sig = token.rsplit(".", 1)
    expected = hmac.new(SESSION_SECRET.encode(), data.encode(), hashlib.sha256).hexdigest()[:16]
    if not hmac.compare_digest(sig, expected):
        return None
    try:
        parts = data.split("|")
        if len(parts) == 2 and float(parts[1]) > time.time():
            return parts[0]
    except (ValueError, IndexError):
        pass
    return None


def _is_authenticated(request: Request) -> bool:
    if not DASHBOARD_PASS:
        return True  # No password = open access
    token = request.cookies.get("session", "")
    return _verify_session(token) is not None


async def require_auth(request: Request):
    if not _is_authenticated(request):
        raise HTTPException(status_code=401, detail="Not authenticated")


async def verify_api_key(request: Request):
    # Check session cookie first (browser), then API key (programmatic)
    if _is_authenticated(request):
        return
    if API_KEY:
        key = request.headers.get("X-API-Key", "") or request.query_params.get("api_key", "")
        if key == API_KEY:
            return
    if not DASHBOARD_PASS and not API_KEY:
        return  # No auth configured = open access
    raise HTTPException(status_code=401, detail="Not authenticated")


# --- Login ---

LOGIN_HTML = """<!DOCTYPE html>
<html><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>Login - AiDevOps</title>
<style>
*{margin:0;padding:0;box-sizing:border-box}
body{background:#0a0e1a;color:#e0e0e0;font-family:system-ui;display:flex;align-items:center;justify-content:center;min-height:100vh}
.login{background:#111827;border:1px solid #1e293b;border-radius:12px;padding:40px;width:380px;box-shadow:0 8px 32px rgba(0,0,0,.4)}
h1{font-size:24px;margin-bottom:8px;text-align:center}
.sub{color:#8b8fa3;font-size:13px;text-align:center;margin-bottom:24px}
label{display:block;font-size:13px;color:#8b8fa3;margin-bottom:4px}
input{width:100%;padding:10px 12px;background:#0a0e1a;border:1px solid #1e293b;border-radius:6px;color:#e0e0e0;font-size:14px;margin-bottom:16px;outline:none}
input:focus{border-color:#3b82f6}
button{width:100%;padding:10px;background:#3b82f6;color:#fff;border:none;border-radius:6px;font-size:14px;cursor:pointer}
button:hover{background:#2563eb}
.btn-passkey{background:#6366f1;margin-top:12px}
.btn-passkey:hover{background:#4f46e5}
.divider{display:flex;align-items:center;gap:12px;margin:20px 0;color:#4b5563;font-size:12px}
.divider::before,.divider::after{content:'';flex:1;border-top:1px solid #1e293b}
.error{color:#ef4444;font-size:13px;text-align:center;margin-bottom:12px}
.passkey-status{font-size:12px;text-align:center;margin-top:8px;color:#8b8fa3}
</style></head><body>
<div class="login">
<h1>AiDevOps</h1>
<div class="sub">OneShell Infrastructure Monitor</div>
<div class="error" id="err"></div>
<form method="POST" action="/login">
<label>Username</label><input name="username" required autofocus>
<label>Password</label><input name="password" type="password" required>
<button type="submit">Sign In</button>
</form>
<div id="passkey-section" style="display:none">
<div class="divider">or</div>
<button class="btn-passkey" onclick="loginWithPasskey()">Login with Passkey</button>
<div class="passkey-status" id="passkey-status"></div>
</div>
<div id="passkey-unavailable" style="display:none">
<div class="divider">passkey</div>
<div class="passkey-status">No passkeys registered yet. Log in with password first, then register a passkey from the dashboard.</div>
</div>
</div>
<script>
(async()=>{
if(!window.PublicKeyCredential){document.getElementById('passkey-unavailable').style.display='block';
document.getElementById('passkey-unavailable').querySelector('.passkey-status').textContent='Your browser does not support passkeys in this context. Use HTTPS or Chrome with a supported device.';return}
try{const r=await fetch('/api/v1/auth/passkey/login-options',{method:'POST'});
if(r.ok){document.getElementById('passkey-section').style.display='block'}
else{document.getElementById('passkey-unavailable').style.display='block'}}
catch(e){document.getElementById('passkey-unavailable').style.display='block'}})();
async function loginWithPasskey(){const s=document.getElementById('passkey-status');
try{s.textContent='Requesting passkey...';
const optResp=await fetch('/api/v1/auth/passkey/login-options',{method:'POST'});
if(!optResp.ok){s.textContent='No passkeys registered';return}
const opts=await optResp.json();
opts.challenge=_b64ToArr(opts.challenge);
if(opts.allowCredentials)opts.allowCredentials=opts.allowCredentials.map(c=>({...c,id:_b64ToArr(c.id)}));
const cred=await navigator.credentials.get({publicKey:opts});
const body={id:cred.id,rawId:_arrToB64(new Uint8Array(cred.rawId)),type:cred.type,
response:{authenticatorData:_arrToB64(new Uint8Array(cred.response.authenticatorData)),
clientDataJSON:_arrToB64(new Uint8Array(cred.response.clientDataJSON)),
signature:_arrToB64(new Uint8Array(cred.response.signature)),
userHandle:cred.response.userHandle?_arrToB64(new Uint8Array(cred.response.userHandle)):null}};
const vResp=await fetch('/api/v1/auth/passkey/login',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify(body)});
if(vResp.ok){window.location.href='/'}else{const e=await vResp.json();s.textContent='Failed: '+(e.detail||'Unknown error')}}
catch(e){s.textContent=e.name==='NotAllowedError'?'Cancelled':('Error: '+e.message)}}
function _b64ToArr(b){const s=b.replace(/-/g,'+').replace(/_/g,'/');const r=atob(s);const a=new Uint8Array(r.length);for(let i=0;i<r.length;i++)a[i]=r.charCodeAt(i);return a.buffer}
function _arrToB64(a){let s='';const b=new Uint8Array(a);for(let i=0;i<b.length;i++)s+=String.fromCharCode(b[i]);return btoa(s).replace(/\\+/g,'-').replace(/\\//g,'_').replace(/=/g,'')}
</script>
</body></html>"""


@app.get("/login")
async def login_page(request: Request):
    if _is_authenticated(request):
        return RedirectResponse("/", status_code=302)
    return HTMLResponse(LOGIN_HTML)


@app.post("/login")
async def login_submit(request: Request, username: str = Form(...), password: str = Form(...)):
    if username == DASHBOARD_USER and password == DASHBOARD_PASS:
        expires = time.time() + SESSION_MAX_AGE
        token = _sign_session(f"{username}|{expires}")
        response = RedirectResponse("/", status_code=302)
        response.set_cookie("session", token, max_age=SESSION_MAX_AGE, httponly=True, samesite="lax")
        return response
    return HTMLResponse(LOGIN_HTML.replace('id="err"', 'id="err" style="display:block"') .replace('</div>\n<form', 'Invalid username or password</div>\n<form'), status_code=401)


@app.get("/logout")
async def logout():
    response = RedirectResponse("/login", status_code=302)
    response.delete_cookie("session")
    return response


# --- Passkey (WebAuthn) Auth ---

RP_ID = os.environ.get("WEBAUTHN_RP_ID", "monitor.oneshell.in")
RP_NAME = "AiDevOps Dashboard"
RP_ORIGIN = os.environ.get("WEBAUTHN_ORIGIN", f"https://{RP_ID}")
_passkey_challenges: dict[str, tuple[bytes, float]] = {}  # user_id -> (challenge, expiry)


@app.post("/api/v1/auth/passkey/register-options")
async def passkey_register_options(request: Request):
    """Generate registration challenge. Must be authenticated first."""
    if not _is_authenticated(request):
        raise HTTPException(status_code=401, detail="Must be logged in to register a passkey")
    try:
        from webauthn import generate_registration_options
        from webauthn.helpers.structs import AuthenticatorSelectionCriteria, ResidentKeyRequirement, UserVerificationRequirement
        from webauthn.helpers import bytes_to_base64url

        existing_creds = get_passkey_credentials_for_user(DASHBOARD_USER)
        exclude = []
        for c in existing_creds:
            from webauthn.helpers.structs import PublicKeyCredentialDescriptor
            exclude.append(PublicKeyCredentialDescriptor(id=c["id"].encode() if isinstance(c["id"], str) else c["id"]))

        options = generate_registration_options(
            rp_id=RP_ID,
            rp_name=RP_NAME,
            user_id=DASHBOARD_USER.encode(),
            user_name=DASHBOARD_USER,
            user_display_name=DASHBOARD_USER,
            authenticator_selection=AuthenticatorSelectionCriteria(
                resident_key=ResidentKeyRequirement.PREFERRED,
                user_verification=UserVerificationRequirement.PREFERRED,
            ),
            exclude_credentials=exclude,
        )
        _passkey_challenges[DASHBOARD_USER] = (options.challenge, time.time() + 300)

        from webauthn.helpers import options_to_json
        return JSONResponse(content=json.loads(options_to_json(options)))
    except ImportError:
        raise HTTPException(status_code=501, detail="py-webauthn not installed")


@app.post("/api/v1/auth/passkey/register")
async def passkey_register(request: Request):
    """Verify registration and store credential."""
    if not _is_authenticated(request):
        raise HTTPException(status_code=401, detail="Not authenticated")
    try:
        from webauthn import verify_registration_response
        from webauthn.helpers import base64url_to_bytes

        data = await request.json()
        challenge_data = _passkey_challenges.pop(DASHBOARD_USER, None)
        if not challenge_data or time.time() > challenge_data[1]:
            raise HTTPException(status_code=400, detail="Challenge expired")

        verification = verify_registration_response(
            credential=data,
            expected_challenge=challenge_data[0],
            expected_rp_id=RP_ID,
            expected_origin=RP_ORIGIN,
        )

        cred_id = verification.credential_id.hex()
        save_passkey_credential(
            credential_id=cred_id,
            user_id=DASHBOARD_USER,
            public_key=verification.credential_public_key,
            sign_count=verification.sign_count,
        )
        return {"status": "ok", "credential_id": cred_id}
    except ImportError:
        raise HTTPException(status_code=501, detail="py-webauthn not installed")
    except Exception as e:
        raise HTTPException(status_code=400, detail=str(e))


@app.post("/api/v1/auth/passkey/login-options")
async def passkey_login_options():
    """Generate authentication challenge."""
    try:
        from webauthn import generate_authentication_options
        from webauthn.helpers.structs import PublicKeyCredentialDescriptor, UserVerificationRequirement

        creds = get_passkey_credentials_for_user(DASHBOARD_USER)
        allow = []
        for c in creds:
            allow.append(PublicKeyCredentialDescriptor(id=bytes.fromhex(c["id"])))

        if not allow:
            raise HTTPException(status_code=404, detail="No passkeys registered")

        options = generate_authentication_options(
            rp_id=RP_ID,
            allow_credentials=allow,
            user_verification=UserVerificationRequirement.PREFERRED,
        )
        _passkey_challenges["__login__"] = (options.challenge, time.time() + 300)

        from webauthn.helpers import options_to_json
        return JSONResponse(content=json.loads(options_to_json(options)))
    except ImportError:
        raise HTTPException(status_code=501, detail="py-webauthn not installed")


@app.post("/api/v1/auth/passkey/login")
async def passkey_login(request: Request):
    """Verify passkey assertion and create session."""
    try:
        from webauthn import verify_authentication_response

        data = await request.json()
        challenge_data = _passkey_challenges.pop("__login__", None)
        if not challenge_data or time.time() > challenge_data[1]:
            raise HTTPException(status_code=400, detail="Challenge expired")

        raw_id_hex = data.get("rawId", data.get("id", ""))
        # Try to find credential
        cred = get_passkey_credential(raw_id_hex)
        if not cred:
            # Try base64url decode
            from webauthn.helpers import base64url_to_bytes
            try:
                decoded = base64url_to_bytes(raw_id_hex).hex()
                cred = get_passkey_credential(decoded)
            except Exception:
                pass
        if not cred:
            raise HTTPException(status_code=400, detail="Unknown credential")

        verification = verify_authentication_response(
            credential=data,
            expected_challenge=challenge_data[0],
            expected_rp_id=RP_ID,
            expected_origin=RP_ORIGIN,
            credential_public_key=cred["public_key"],
            credential_current_sign_count=cred["sign_count"],
        )

        update_passkey_sign_count(cred["id"], verification.new_sign_count)

        expires = time.time() + SESSION_MAX_AGE
        token = _sign_session(f"{DASHBOARD_USER}|{expires}")
        response = JSONResponse(content={"status": "ok"})
        response.set_cookie("session", token, max_age=SESSION_MAX_AGE, httponly=True, samesite="lax")
        return response
    except ImportError:
        raise HTTPException(status_code=501, detail="py-webauthn not installed")
    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(status_code=400, detail=str(e))


# --- Health ---

@app.get("/api/v1/health")
async def health():
    return {"status": "ok", "service": "clawdbot-devops", "timestamp": datetime.utcnow().isoformat()}


# --- Dashboard ---

@app.get("/api/v1/dashboard/overview", dependencies=[Depends(verify_api_key)])
async def dashboard_overview():
    k8s = kubernetes_monitor.cluster_overview
    mongo = mongodb_monitor.health
    nats = nats_monitor.health

    services = service_health_monitor.services
    healthy = sum(1 for s in services.values() if s.status.value == "healthy")
    degraded = sum(1 for s in services.values() if s.status.value == "degraded")
    critical = sum(1 for s in services.values() if s.status.value == "critical")

    issues = issue_finder.current_issues
    active_incidents = incident_manager.get_active()

    # Calculate health score
    total_services = len(SERVICE_TOPOLOGY)
    score = round((healthy / total_services * 100) if total_services > 0 else 0)
    warnings = []
    critical_issues = []
    if k8s.failed_pods > 0:
        critical_issues.append(f"{k8s.failed_pods} failed pods")
    if critical > 0:
        critical_issues.append(f"{critical} services down")
    if degraded > 0:
        warnings.append(f"{degraded} services degraded")
    if k8s.warning_events > 5:
        warnings.append(f"{k8s.warning_events} K8s warning events")

    status = "healthy"
    if critical > 0 or k8s.failed_pods > 0:
        status = "critical"
        score = min(score, 50)
    elif degraded > 0:
        status = "degraded"
        score = min(score, 80)

    # Flat format expected by the dashboard HTML
    return {
        "health_score": {
            "overall": score,
            "status": status,
            "warnings": warnings,
            "critical_issues": critical_issues,
        },
        "services_healthy": healthy,
        "services_degraded": degraded,
        "services_critical": critical,
        "pods_running": k8s.running_pods,
        "pods_total": k8s.total_pods,
        "active_incidents": len(active_incidents),
        "timestamp": datetime.utcnow().isoformat(),
    }


# --- Kubernetes ---

@app.get("/api/v1/kubernetes/pods", dependencies=[Depends(verify_api_key)])
async def get_pods(namespace: str = "default"):
    from devops import k8s_client
    return await k8s_client.list_pods(namespace)


@app.get("/api/v1/kubernetes/deployments", dependencies=[Depends(verify_api_key)])
async def get_deployments(namespace: str = "default"):
    from devops import k8s_client
    return await k8s_client.list_deployments(namespace)


@app.get("/api/v1/kubernetes/events", dependencies=[Depends(verify_api_key)])
async def get_events(namespace: str = "default"):
    from devops import k8s_client
    return await k8s_client.get_events(namespace)


@app.get("/api/v1/kubernetes/nodes", dependencies=[Depends(verify_api_key)])
async def get_nodes():
    from devops import k8s_client
    return await k8s_client.get_nodes()


@app.get("/api/v1/kubernetes/logs/{service}", dependencies=[Depends(verify_api_key)])
async def get_service_logs(service: str, namespace: str = "default", tail: int = 200):
    from devops import k8s_client
    logs = await k8s_client.get_deployment_logs(service, namespace, tail)
    return {"service": service, "namespace": namespace, "logs": logs}


# --- Services ---

@app.get("/api/v1/services", dependencies=[Depends(verify_api_key)])
async def list_services():
    from devops import k8s_client

    # Get pod metrics for resource usage
    pod_metrics = {}
    for ns in ["default", "pos"]:
        try:
            raw = await k8s_client.get_top_pods(ns)
            for p in raw:
                # Match pod name to service (pod names start with deployment name)
                pod_metrics[p.get("name", "")] = p
        except Exception:
            pass

    services = []
    for name, info in SERVICE_TOPOLOGY.items():
        health = service_health_monitor.services.get(name)
        svc = {
            "name": name,
            "namespace": info.namespace,
            "port": info.port,
            "tier": info.tier.value,
            "health_path": info.health_path,
            "status": health.status.value if health else "unknown",
            "response_time_ms": health.response_time_ms if health else None,
            "error": health.error if health else None,
            "cpu_millicores": 0,
            "memory_mib": 0,
        }
        # Find matching pod metrics
        deploy_name = name.lower().replace("-", "")
        for pod_name, metrics in pod_metrics.items():
            if pod_name.startswith(deploy_name):
                cpu_str = metrics.get("cpu", "0m")
                mem_str = metrics.get("memory", "0Mi")
                svc["cpu_millicores"] = int(cpu_str.rstrip("m")) if cpu_str.endswith("m") else 0
                svc["memory_mib"] = int(mem_str.rstrip("Mi")) if mem_str.endswith("Mi") else 0
                break
        services.append(svc)
    return services


@app.get("/api/v1/services/topology", dependencies=[Depends(verify_api_key)])
async def get_topology():
    topo = build_topology()
    return topo.model_dump()


# --- MongoDB ---

@app.get("/api/v1/mongodb/health", dependencies=[Depends(verify_api_key)])
async def mongo_health():
    return mongodb_monitor.health.model_dump()


@app.get("/api/v1/mongodb/connections", dependencies=[Depends(verify_api_key)])
async def mongo_connections():
    from devops import mongodb_client
    return await mongodb_client.get_connection_pool()


@app.get("/api/v1/mongodb/replicas", dependencies=[Depends(verify_api_key)])
async def mongo_replicas():
    """Get MongoDB replica set health for all replica sets."""
    from devops import k8s_client
    results = []
    for rs_name in ["rs0"]:
        # Get replica set members by checking pods
        pods_raw = await k8s_client._run_kubectl(
            "get", "pods", "-n", "mongodb", "-l", f"app.kubernetes.io/replset={rs_name}",
            "-o", "jsonpath={range .items[*]}{.metadata.name}|{.status.phase}|{.status.podIP}|{.status.conditions[?(@.type=='Ready')].status}{\"\\n\"}{end}",
        )
        members = []
        for line in (pods_raw or "").strip().splitlines():
            parts = line.split("|")
            if len(parts) >= 4:
                members.append({
                    "name": parts[0],
                    "phase": parts[1],
                    "ip": parts[2],
                    "ready": parts[3] == "True",
                })
        # Get rs.status() from one running member
        # Get rs.status() + serverStatus() for memory, connections, opcounters per member
        rs_detail_raw = await k8s_client._run_kubectl(
            "exec", "-n", "mongodb", "prod-cluster-mongos-0",
            "--", "mongosh",
            "mongodb://clusterAdmin:tb3GSgY6U5ZSc7CNsvf6@prod-cluster-rs0-0.prod-cluster-rs0.mongodb.svc.cluster.local:27017/admin?authSource=admin&replicaSet=rs0",
            "--quiet", "--eval",
            """
            const rss = rs.status();
            const ss = db.serverStatus();
            const mem = ss.mem || {};
            const conns = ss.connections || {};
            const ops = ss.opcounters || {};
            const wt = ss.wiredTiger?.cache || {};
            const N = v => Number(v) || 0;
            JSON.stringify({
              members: rss.members.map(m => ({name: m.name, state: m.stateStr, health: m.health, uptime: m.uptime, optimeDate: m.optimeDate})),
              serverStatus: {
                host: ss.host,
                uptimeSeconds: N(ss.uptime),
                memResident: N(mem.resident),
                memVirtual: N(mem.virtual),
                connsCurrent: N(conns.current),
                connsAvailable: N(conns.available),
                connsTotalCreated: N(conns.totalCreated),
                opsInsert: N(ops.insert),
                opsQuery: N(ops.query),
                opsUpdate: N(ops.update),
                opsDelete: N(ops.delete),
                opsGetmore: N(ops.getmore),
                opsCommand: N(ops.command),
                cacheUsedBytes: N(wt['bytes currently in the cache']),
                cacheMaxBytes: N(wt['maximum bytes configured']),
                cacheDirtyBytes: N(wt['tracked dirty bytes in the cache']),
                replicationLag: rss.members.filter(m => m.stateStr !== 'PRIMARY').map(m => {
                  const primary = rss.members.find(p => p.stateStr === 'PRIMARY');
                  return {name: m.name, lagSeconds: primary ? Math.round((primary.optimeDate - m.optimeDate) / 1000) : null};
                })
              }
            });
            """,
        )
        rs_members = []
        server_status = {}
        try:
            import json as j
            parsed = j.loads(rs_detail_raw) if rs_detail_raw else {}
            rs_members = parsed.get("members", [])
            server_status = parsed.get("serverStatus", {})
        except Exception:
            pass
        results.append({
            "name": rs_name,
            "pods": members,
            "rs_members": rs_members,
            "server_status": server_status,
            "member_count": len(members),
        })
    # Also check config servers
    cfg_pods_raw = await k8s_client._run_kubectl(
        "get", "pods", "-n", "mongodb", "-l", "app.kubernetes.io/replset=cfg",
        "-o", "jsonpath={range .items[*]}{.metadata.name}|{.status.phase}|{.status.conditions[?(@.type=='Ready')].status}{\"\\n\"}{end}",
    )
    cfg_members = []
    for line in (cfg_pods_raw or "").strip().splitlines():
        parts = line.split("|")
        if len(parts) >= 3:
            cfg_members.append({"name": parts[0], "phase": parts[1], "ready": parts[2] == "True"})
    results.append({"name": "cfg", "pods": cfg_members, "rs_members": [], "member_count": len(cfg_members)})
    return results


@app.get("/api/v1/mongodb/sync-errors", dependencies=[Depends(verify_api_key)])
async def mongo_sync_errors(limit: int = 20):
    from devops import mongodb_client
    return await mongodb_client.get_sync_errors(limit)


# --- NATS ---

@app.get("/api/v1/nats/health", dependencies=[Depends(verify_api_key)])
async def nats_health():
    return nats_monitor.health.model_dump()


@app.get("/api/v1/nats/streams", dependencies=[Depends(verify_api_key)])
async def nats_streams():
    from devops import nats_client
    return await nats_client.get_all_streams()


@app.get("/api/v1/nats/consumers", dependencies=[Depends(verify_api_key)])
async def nats_consumers():
    from devops import nats_client
    return await nats_client.get_all_consumers()


# --- Logs ---

@app.get("/api/v1/logs/{service}", dependencies=[Depends(verify_api_key)])
async def analyze_service_logs(service: str, namespace: str = "default", tail: int = 200):
    result = await log_analyzer_monitor.analyze_service(service, namespace, tail)
    return result.model_dump()


# --- Issues ---

@app.get("/api/v1/issues", dependencies=[Depends(verify_api_key)])
async def list_issues():
    return issue_finder.last_scan_result or {"issues": [], "total_issues": 0}


@app.post("/api/v1/issues/scan", dependencies=[Depends(verify_api_key)])
async def scan_issues():
    await issue_finder.safe_check()
    return issue_finder.last_scan_result or {"issues": [], "total_issues": 0}


@app.post("/api/v1/issues/autodetect", dependencies=[Depends(verify_api_key)])
async def autodetect_issues():
    await issue_finder.safe_check()
    return issue_finder.last_scan_result or {"issues": [], "total_issues": 0}


_PROD_CONTEXT = (
    "=== ENVIRONMENT: PRODUCTION CLUSTER (Hetzner Cloud) ===\n"
    "\n"
    "KUBERNETES ACCESS:\n"
    "  PROD: KUBECONFIG=/root/.kube/prod-config kubectl --insecure-skip-tls-verify\n"
    "  QA:   KUBECONFIG=/root/.kube/qa-config kubectl --insecure-skip-tls-verify\n"
    "  IMPORTANT: ALWAYS prefix kubectl with the appropriate KUBECONFIG=... path\n"
    "\n"
    "PROD NAMESPACES:\n"
    "  default: MongoDbService, GatewayService, BusinessService, PosService, Scheduler, "
    "QuartzScheduler, EmailService, NotificationService, GstApiService, "
    "PosDataSyncService, PosDockerSyncService, PosDockerPullService, "
    "PosServerBackend, mongoeventlistner, authservice, WhatsappApiService, "
    "nodeinvoicethemes, PosAdmin, PosHome, CacheLayer (Dragonfly)\n"
    "  pos: PosClientBackend, PosPythonBackend, PosNodeBackend, PosFrontend, "
    "NATS, AzureOCR, Typesense\n"
    "  mongodb: Percona MongoDB Operator (prod-cluster-mongos-0)\n"
    "  redpanda: Redpanda broker + Debezium Connect\n"
    "  tekton-pipelines: CI/CD pipelines\n"
    "  argocd: GitOps deployments\n"
    "\n"
    "QA NAMESPACES: same structure but with qa-cluster-mongos-0 in mongodb namespace\n"
    "\n"
    "MONGODB:\n"
    "  Prod: KUBECONFIG=/root/.kube/prod-config kubectl exec -n mongodb prod-cluster-mongos-0 "
    "--insecure-skip-tls-verify -- mongosh "
    "'mongodb://databaseAdmin:akyFqNelEclMhlkNx06c@localhost:27017/oneshell?authSource=admin' --quiet --eval\n"
    "  QA: KUBECONFIG=/root/.kube/qa-config kubectl exec -n mongodb qa-cluster-mongos-0 "
    "--insecure-skip-tls-verify -- mongosh "
    "'mongodb://databaseAdmin:akyFqNelEclMhlkNx06c@localhost:27017/oneshell?authSource=admin' --quiet --eval\n"
    "\n"
    "SOURCE CODE & FIX WORKFLOW:\n"
    "  All repos cloned at /opt/clawdbot/repos/ (BusinessService, PosServerBackend, PosClientBackend, etc.)\n"
    "  GitHub org: github.com/OneShellSolutions\n"
    "  To fix a service:\n"
    "    1. Investigate: check logs, events, describe pods\n"
    "    2. Read source code at /opt/clawdbot/repos/<RepoName>/\n"
    "    3. Make the fix in the source code\n"
    "    4. Build: cd /opt/clawdbot/repos/<repo> && JAVA_HOME=/usr/lib/jvm/jdk-24 ./mvnw clean package -DskipTests\n"
    "    5. Test via port-forward to QA cluster: KUBECONFIG=/root/.kube/qa-config kubectl port-forward svc/<service> <port>:<port> -n <ns> --insecure-skip-tls-verify\n"
    "    6. Commit and push to master: git add . && git commit -m 'fix: description' && git push origin master\n"
    "    7. QA auto-deploys on master push (Tekton + ArgoCD)\n"
    "    8. For PROD release: git tag v1.x.x && git push origin v1.x.x\n"
    "  Java versions: read pom.xml <java.version> to pick JDK\n"
    "    JDK 17: /usr/lib/jvm/java-17-openjdk-amd64\n"
    "    JDK 21: /usr/lib/jvm/java-21-openjdk-amd64\n"
    "    JDK 24: /usr/lib/jvm/jdk-24\n"
    "  NEVER commit/push without explicit user approval\n"
)


# --- Active AI tasks (streaming) ---
_ai_tasks: dict[str, dict] = {}


_MEMORY_FILE = "/opt/clawdbot/.claude/projects/-opt-clawdbot/memory/incident-learnings.md"


def _build_prompt(issue_text: str, service: str = "", auto_fix: bool = True) -> str:
    """Build the Claude prompt for AI investigation."""
    action = "INVESTIGATE AND FIX" if auto_fix else "DIAGNOSE"
    fix_instructions = (
        "Apply safe fixes directly (restart pods, clear sessions, scale up, etc.).\n"
        "If it's a code bug, identify it, describe the fix needed, but do NOT commit/push.\n"
        "Verify the fix worked after applying it.\n"
    ) if auto_fix else (
        "Find the root cause and explain what's happening and how to fix it.\n"
        "Be thorough in your investigation.\n"
    )
    return (
        f"{_PROD_CONTEXT}\n\n"
        f"{'Service: ' + service + chr(10) if service else ''}"
        f"Issue: {issue_text}\n\n"
        f"{action} this issue on the PRODUCTION cluster.\n\n"
        f"STEP 1 - CHECK MEMORY FIRST:\n"
        f"Read {_MEMORY_FILE} and check if this issue (or a similar one) was solved before.\n"
        f"If a known fix exists, tell the user: 'Found a previous fix for this issue:' and show it.\n"
        f"Then ask: 'Should I apply this known fix, or investigate fresh?'\n"
        f"If no match is found in memory, proceed to investigate.\n\n"
        f"STEP 2 - INVESTIGATE:\n"
        f"Use kubectl to check pods, logs, events, MongoDB queries — whatever is needed.\n"
        f"{fix_instructions}\n"
        f"STEP 3 - SAVE LEARNING:\n"
        f"After resolving (or diagnosing), append a concise entry to {_MEMORY_FILE} with:\n"
        f"- Date, issue summary, root cause, fix applied, verification result\n"
        f"- Keep entries short (10-15 lines max). Do NOT duplicate existing entries.\n"
        f"- If the same issue already exists in memory, update the existing entry instead.\n"
    )


async def _start_claude_stream(task_id: str, prompt: str):
    """Spawn claude CLI with stream-json output and collect events."""
    cmd = [
        "claude", "-p", "--model", "claude-opus-4-6",
        "--output-format", "stream-json",
        "--verbose", "--dangerously-skip-permissions",
    ]
    env = os.environ.copy()
    env.pop("ANTHROPIC_API_KEY", None)
    env.pop("CLAUDECODE", None)

    task = _ai_tasks[task_id]
    def _ts():
        return datetime.now().strftime("%H:%M:%S")

    task["status"] = "running"
    task["events"].append({"type": "status", "message": "Starting Claude AI...", "ts": _ts()})

    try:
        proc = await asyncio.create_subprocess_exec(
            *cmd,
            stdin=asyncio.subprocess.PIPE,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
            env=env,
            cwd="/opt/clawdbot",
        )
        task["process"] = proc
        proc.stdin.write(prompt.encode())
        await proc.stdin.drain()
        proc.stdin.close()

        # Read stdout line by line (stream-json outputs one JSON per line)
        # Format: {"type":"system",...}, {"type":"assistant","message":{"content":[...]},...},
        #         {"type":"result","result":"..."}
        final_text_parts = []

        async def _read_stderr():
            """Read stderr in background to prevent pipe blocking."""
            stderr_data = await proc.stderr.read()
            if stderr_data:
                err_msg = stderr_data.decode("utf-8", errors="replace").strip()
                if err_msg:
                    task["events"].append({"type": "error", "message": err_msg[:500], "ts": _ts()})

        stderr_task = asyncio.create_task(_read_stderr())

        while True:
            line = await proc.stdout.readline()
            if not line:
                break
            line_str = line.decode("utf-8", errors="replace").strip()
            if not line_str:
                continue
            try:
                evt = json.loads(line_str)
            except json.JSONDecodeError:
                task["events"].append({"type": "text", "message": line_str, "ts": _ts()})
                continue

            etype = evt.get("type", "")

            if etype == "assistant":
                # Parse nested message.content array
                msg_obj = evt.get("message", {})
                content_blocks = msg_obj.get("content", [])
                for block in content_blocks:
                    block_type = block.get("type", "")
                    if block_type == "text":
                        text = block.get("text", "")
                        if text:
                            final_text_parts.append(text)
                            # Show truncated text in log
                            display = text[:300] + "..." if len(text) > 300 else text
                            task["events"].append({"type": "text", "message": display, "ts": _ts()})
                    elif block_type == "tool_use":
                        tool_name = block.get("name", "")
                        tool_input = block.get("input", {})
                        desc = ""
                        if isinstance(tool_input, dict):
                            desc = tool_input.get("description", tool_input.get("command", tool_input.get("pattern", "")))
                            if not desc and tool_input.get("file_path"):
                                desc = f"Reading {tool_input['file_path']}"
                            if not desc and tool_input.get("query"):
                                desc = tool_input["query"]
                        task["events"].append({
                            "type": "tool_use",
                            "message": f"Tool: {tool_name} — {desc}" if desc else f"Tool: {tool_name}",
                            "ts": _ts(),
                        })
                    elif block_type == "tool_result":
                        content = block.get("content", "")
                        if isinstance(content, list):
                            content = " ".join(c.get("text", "") for c in content if isinstance(c, dict))
                        display = str(content)[:400] + "..." if len(str(content)) > 400 else str(content)
                        task["events"].append({"type": "tool_result", "message": display or "(empty)", "ts": _ts()})

            elif etype == "result":
                result_text = evt.get("result", "")
                if result_text:
                    final_text_parts.append(result_text)
                task["events"].append({
                    "type": "status",
                    "message": f"Done. Turns: {evt.get('num_turns', '?')}",
                    "ts": _ts(),
                })

            elif etype == "user":
                # Tool result comes back as type "user" with tool_result content
                msg_obj = evt.get("message", {})
                content_blocks = msg_obj.get("content", [])
                for block in content_blocks:
                    if block.get("type") == "tool_result":
                        content = block.get("content", "")
                        if isinstance(content, list):
                            content = " ".join(c.get("text", "") for c in content if isinstance(c, dict))
                        display = str(content)[:400] + "..." if len(str(content)) > 400 else str(content)
                        task["events"].append({"type": "tool_result", "message": display or "(empty)", "ts": _ts()})
                # Also check tool_use_result at top level
                tur = evt.get("tool_use_result", {})
                if tur and not content_blocks:
                    stdout = tur.get("stdout", "")
                    stderr = tur.get("stderr", "")
                    output = stdout or stderr
                    display = output[:400] + "..." if len(output) > 400 else output
                    if display:
                        task["events"].append({"type": "tool_result", "message": display, "ts": _ts()})

            elif etype == "system":
                # Init event — show model info
                model = evt.get("model", "")
                if model:
                    task["events"].append({"type": "status", "message": f"Using model: {model}", "ts": _ts()})

            elif etype == "error":
                err = evt.get("error", {})
                err_msg = err.get("message", str(err)) if isinstance(err, dict) else str(err)
                task["events"].append({
                    "type": "error",
                    "message": err_msg[:500],
                    "ts": _ts(),
                })

            else:
                msg = evt.get("message", evt.get("text", ""))
                if msg:
                    task["events"].append({"type": "info", "message": str(msg)[:300], "ts": _ts()})

        await proc.wait()
        await stderr_task
        task["final_output"] = "\n".join(final_text_parts) if final_text_parts else "(no output)"
        task["status"] = "done"
        task["events"].append({"type": "status", "message": "Investigation complete.", "ts": _ts()})

    except asyncio.CancelledError:
        task["status"] = "stopped"
        task["events"].append({"type": "status", "message": "Stopped by user.", "ts": _ts()})
        try:
            proc.kill()
        except Exception:
            pass
    except Exception as e:
        task["status"] = "error"
        task["events"].append({"type": "error", "message": f"Error: {e}", "ts": _ts()})


@app.post("/api/v1/ai/start", dependencies=[Depends(verify_api_key)])
async def ai_start(request: Request):
    """Start a streaming AI investigation. Returns task_id for SSE stream."""
    data = await request.json()
    issue_text = data.get("issue", data.get("error_text", ""))
    service = data.get("service", "")
    auto_fix = data.get("auto_fix", True)
    if not issue_text:
        raise HTTPException(400, "Missing issue text")

    task_id = secrets.token_hex(8)
    _ai_tasks[task_id] = {
        "status": "starting",
        "events": [],
        "process": None,
        "final_output": "",
        "started_at": time.time(),
        "issue": issue_text,
        "service": service,
    }
    # Launch in background
    asyncio.create_task(_start_claude_stream(task_id, _build_prompt(issue_text, service, auto_fix)))
    return {"task_id": task_id}


@app.get("/api/v1/ai/stream/{task_id}", dependencies=[Depends(verify_api_key)])
async def ai_stream(task_id: str):
    """SSE stream of AI investigation events."""
    if task_id not in _ai_tasks:
        raise HTTPException(404, "Task not found")

    async def event_generator():
        last_idx = 0
        while True:
            task = _ai_tasks.get(task_id)
            if not task:
                break
            events = task["events"]
            while last_idx < len(events):
                evt = events[last_idx]
                yield f"data: {json.dumps(evt)}\n\n"
                last_idx += 1
            if task["status"] in ("done", "error", "stopped"):
                yield f"data: {json.dumps({'type': 'done', 'message': task['status'], 'final_output': task.get('final_output', ''), 'duration_ms': int((time.time() - task['started_at']) * 1000)})}\n\n"
                break
            await asyncio.sleep(0.3)

    return StreamingResponse(event_generator(), media_type="text/event-stream")


@app.post("/api/v1/ai/stop/{task_id}", dependencies=[Depends(verify_api_key)])
async def ai_stop(task_id: str):
    """Stop a running AI investigation."""
    task = _ai_tasks.get(task_id)
    if not task:
        raise HTTPException(404, "Task not found")
    proc = task.get("process")
    if proc and proc.returncode is None:
        try:
            proc.kill()
        except Exception:
            pass
    task["status"] = "stopped"
    task["events"].append({"type": "status", "message": "Stopped by user."})
    return {"status": "stopped"}


@app.post("/api/v1/ai/message/{task_id}", dependencies=[Depends(verify_api_key)])
async def ai_send_message(task_id: str, request: Request):
    """Send a follow-up message to override or guide the AI. Starts a new Claude call with context."""
    task = _ai_tasks.get(task_id)
    if not task:
        raise HTTPException(404, "Task not found")
    data = await request.json()
    user_msg = data.get("message", "")
    if not user_msg:
        raise HTTPException(400, "Missing message")

    # Stop current process if running
    proc = task.get("process")
    if proc and proc.returncode is None:
        try:
            proc.kill()
        except Exception:
            pass

    # Build follow-up prompt with context of what was done so far
    context_events = [e["message"] for e in task["events"] if e.get("message")]
    prior_context = "\n".join(context_events[-20:])  # Last 20 events for context
    prompt = (
        f"{_PROD_CONTEXT}\n\n"
        f"Service: {task.get('service', '')}\n"
        f"Original issue: {task.get('issue', '')}\n\n"
        f"Previous investigation summary:\n{prior_context}\n\n"
        f"USER OVERRIDE: {user_msg}\n\n"
        f"Follow the user's instruction above. Continue investigating or apply the fix as directed."
    )

    task["status"] = "running"
    task["events"].append({"type": "user", "message": f"User: {user_msg}"})
    asyncio.create_task(_start_claude_stream(task_id, prompt))
    return {"status": "ok"}


@app.post("/api/v1/ai/save-learning/{task_id}", dependencies=[Depends(verify_api_key)])
async def ai_save_learning(task_id: str, request: Request):
    """Trigger Claude to save/update the learning from a completed investigation."""
    task = _ai_tasks.get(task_id)
    if not task:
        raise HTTPException(404, "Task not found")

    data = await request.json()
    user_note = data.get("note", "")

    context_events = [e["message"] for e in task["events"] if e.get("message")]
    investigation_summary = "\n".join(context_events[-30:])

    prompt = (
        f"You previously investigated this issue:\n"
        f"Issue: {task.get('issue', '')}\n"
        f"Service: {task.get('service', '')}\n\n"
        f"Investigation log:\n{investigation_summary}\n\n"
        f"Final output:\n{task.get('final_output', '')}\n\n"
        f"{'User note: ' + user_note + chr(10) if user_note else ''}"
        f"TASK: Save a concise learning entry to {_MEMORY_FILE}\n"
        f"Format: ## Date: Issue Title\\n### Root Cause\\n### Fix Applied\\n### Verification\\n"
        f"Keep it to 10-15 lines. If a similar entry already exists, UPDATE it instead of duplicating.\n"
        f"Read the file first to check for duplicates."
    )

    # Reuse the same task_id — reset it for the save operation
    task["status"] = "running"
    task["events"].append({"type": "status", "message": "Saving learning to memory..."})
    asyncio.create_task(_start_claude_stream(task_id, prompt))
    return {"status": "saving"}


# Keep old endpoints as aliases for backward compat
@app.post("/api/v1/issues/fix-one", dependencies=[Depends(verify_api_key)])
async def fix_one_issue(request: Request):
    """Redirects to streaming AI start."""
    return await ai_start(request)


@app.post("/api/v1/issues/execute-plan", dependencies=[Depends(verify_api_key)])
async def execute_plan(request: Request):
    """Execute approved steps or start AI agent."""
    data = await request.json()
    if data.get("use_agent", False):
        return await ai_start(request)
    executed = []
    for step in data.get("steps", []):
        cmd = step.get("command", "")
        if not cmd:
            executed.append({"command": cmd, "success": False, "output": "Empty command"})
            continue
        safe, reason = is_command_safe(cmd)
        if not safe:
            executed.append({"command": cmd, "success": False, "output": f"Blocked: {reason}"})
            continue
        output = await execute_shell(cmd, timeout=30)
        success = "[exit code: 0]" in output
        executed.append({"command": cmd, "success": success, "output": output})
    return {"status": "done", "executed_steps": executed}


@app.post("/api/v1/issues/run-step", dependencies=[Depends(verify_api_key)])
async def run_step(request: Request):
    data = await request.json()
    command = data.get("command", "")
    if not command:
        raise HTTPException(400, "Missing command")
    safe, reason = is_command_safe(command)
    if not safe:
        return {"success": False, "output": f"Blocked: {reason}"}
    output = await execute_shell(command, timeout=30)
    success = "[exit code: 0]" in output
    return {"success": success, "output": output}


@app.post("/api/v1/issues/deploy", dependencies=[Depends(verify_api_key)])
async def deploy_issue(service: str = "", namespace: str = "default"):
    return {"status": "not_implemented", "message": "Deploy via Telegram /task command"}


@app.post("/api/v1/issues/analyze-and-fix", dependencies=[Depends(verify_api_key)])
async def analyze_and_fix(dry_run: bool = True):
    await issue_finder.safe_check()
    return issue_finder.last_scan_result or {"issues": [], "total_issues": 0}


@app.post("/api/v1/analysis/ai-fix", dependencies=[Depends(verify_api_key)])
async def ai_fix(request: Request):
    """AI Error Diagnosis panel — starts streaming AI investigation."""
    data = await request.json()
    error_text = data.get("error_text", "")
    service = data.get("service", "")
    auto_execute = data.get("auto_execute", False)
    if not error_text:
        raise HTTPException(400, "Missing error_text")

    task_id = secrets.token_hex(8)
    _ai_tasks[task_id] = {
        "status": "starting",
        "events": [],
        "process": None,
        "final_output": "",
        "started_at": time.time(),
        "issue": error_text,
        "service": service,
    }
    asyncio.create_task(_start_claude_stream(task_id, _build_prompt(error_text, service, auto_execute)))
    return {"task_id": task_id}



@app.post("/api/v1/logs/{service}/analyze", dependencies=[Depends(verify_api_key)])
async def analyze_logs_post(service: str, request: Request):
    namespace = "pos" if service.lower().startswith("pos") else "default"
    result = await log_analyzer_monitor.analyze_service(service, namespace, 200)
    return result.model_dump()


@app.post("/api/v1/incidents/{incident_id}/postmortem", dependencies=[Depends(verify_api_key)])
async def incident_postmortem(incident_id: str):
    incident = incident_manager.get(incident_id)
    if not incident:
        raise HTTPException(404, "Incident not found")
    return {"incident_id": incident_id, "postmortem": "Use ClawdBot Telegram for AI postmortem analysis"}


# --- OpenObserve (stub) ---

@app.get("/api/v1/openobserve/status", dependencies=[Depends(verify_api_key)])
async def openobserve_status():
    return {"healthy": False, "status": "not_configured", "message": "OpenObserve integration not configured. Set OPENOBSERVE_URL in .env to enable.", "recent_error_count": 0}


@app.get("/api/v1/openobserve/errors/{service}", dependencies=[Depends(verify_api_key)])
async def openobserve_errors(service: str, minutes: int = 60):
    return {"errors": [], "service": service}


@app.get("/api/v1/openobserve/traces/slow", dependencies=[Depends(verify_api_key)])
async def openobserve_slow_traces(minutes: int = 60):
    return {"traces": []}


# --- Incidents ---

@app.get("/api/v1/incidents", dependencies=[Depends(verify_api_key)])
async def list_incidents(status: str | None = None):
    if status == "active":
        incidents = incident_manager.get_active()
    else:
        incidents = incident_manager.get_all()
    return [i.model_dump() for i in incidents]


@app.post("/api/v1/incidents", dependencies=[Depends(verify_api_key)])
async def create_incident(request: Request):
    data = await request.json()
    incident = incident_manager.create(
        title=data["title"],
        severity=Severity(data.get("severity", "warning")),
        affected_services=data.get("affected_services", []),
        description=data.get("description", ""),
    )
    return incident.model_dump()


@app.get("/api/v1/incidents/{incident_id}", dependencies=[Depends(verify_api_key)])
async def get_incident(incident_id: str):
    incident = incident_manager.get(incident_id)
    if not incident:
        raise HTTPException(404, "Incident not found")
    return incident.model_dump()


@app.post("/api/v1/incidents/{incident_id}/resolve", dependencies=[Depends(verify_api_key)])
async def resolve_incident(incident_id: str, request: Request):
    data = await request.json()
    incident = incident_manager.resolve(incident_id, data.get("message", ""))
    if not incident:
        raise HTTPException(404, "Incident not found")
    return incident.model_dump()


# --- Remediation ---

@app.get("/api/v1/remediation/playbooks", dependencies=[Depends(verify_api_key)])
async def list_playbooks():
    return [p.model_dump() for p in get_all_playbooks()]


@app.get("/api/v1/remediation/playbooks/{name}", dependencies=[Depends(verify_api_key)])
async def get_playbook_detail(name: str):
    pb = get_playbook(name)
    if not pb:
        raise HTTPException(404, "Playbook not found")
    return pb.model_dump()


@app.post("/api/v1/remediation/execute", dependencies=[Depends(verify_api_key)])
async def execute_playbook_api(request: Request):
    data = await request.json()
    result = await execute_playbook(
        data["playbook"],
        context=data.get("context", {}),
        dry_run=data.get("dry_run", True),
    )
    return result


@app.get("/api/v1/remediation/history", dependencies=[Depends(verify_api_key)])
async def remediation_history():
    return get_execution_history()


@app.get("/api/v1/remediation/approvals", dependencies=[Depends(verify_api_key)])
async def list_approvals():
    return get_pending_approvals()


@app.post("/api/v1/remediation/approvals/{approval_id}/approve", dependencies=[Depends(verify_api_key)])
async def approve_action(approval_id: str):
    result = approve_request(approval_id)
    if not result:
        raise HTTPException(404, "Approval not found or already decided")
    return result


@app.post("/api/v1/remediation/approvals/{approval_id}/reject", dependencies=[Depends(verify_api_key)])
async def reject_action(approval_id: str):
    result = reject_request(approval_id)
    if not result:
        raise HTTPException(404, "Approval not found or already decided")
    return result


# --- K8s routes (aliases for dashboard compatibility) ---

@app.get("/api/v1/k8s/pods", dependencies=[Depends(verify_api_key)])
async def k8s_pods(namespace: str = "default"):
    from devops import k8s_client
    return await k8s_client.list_pods(namespace)


@app.get("/api/v1/k8s/events", dependencies=[Depends(verify_api_key)])
async def k8s_events(namespace: str = "default"):
    from devops import k8s_client
    return await k8s_client.get_events(namespace)


# --- Nodes ---

@app.get("/api/v1/nodes/metrics", dependencies=[Depends(verify_api_key)])
async def node_metrics():
    from devops import k8s_client
    return await k8s_client.get_nodes()


@app.get("/api/v1/nodes/pods", dependencies=[Depends(verify_api_key)])
async def node_pods(namespace: str = "default"):
    from devops import k8s_client
    raw = await k8s_client.get_top_pods(namespace)
    result = []
    for p in raw:
        cpu_str = p.get("cpu", "0m")
        mem_str = p.get("memory", "0Mi")
        cpu_m = int(cpu_str.rstrip("m")) if cpu_str.endswith("m") else 0
        mem_m = int(mem_str.rstrip("Mi")) if mem_str.endswith("Mi") else 0
        result.append({"name": p["name"], "cpu_millicores": cpu_m, "memory_mib": mem_m})
    result.sort(key=lambda x: x["cpu_millicores"], reverse=True)
    return result


# --- Dragonfly ---

@app.get("/api/v1/dragonfly/health", dependencies=[Depends(verify_api_key)])
async def dragonfly_health():
    from devops import k8s_client
    pods = await k8s_client.list_pods("default")
    df_pods = [p for p in pods if p["name"].startswith("dragonfly") and p["status"] == "Running"]
    if not df_pods:
        return {"status": "critical", "error": "No Dragonfly pods", "memory_used": "?", "hit_rate": 0, "connected_clients": 0, "memory_percent": 0}
    mem_raw = await k8s_client.exec_in_pod(df_pods[0]["name"], "default", ["redis-cli", "info", "memory"])
    stats_raw = await k8s_client.exec_in_pod(df_pods[0]["name"], "default", ["redis-cli", "info", "stats"])
    clients_raw = await k8s_client.exec_in_pod(df_pods[0]["name"], "default", ["redis-cli", "info", "clients"])

    def parse_info(raw):
        d = {}
        for line in (raw or "").splitlines():
            if ":" in line and not line.startswith("#"):
                k, v = line.split(":", 1)
                d[k.strip()] = v.strip()
        return d

    mem = parse_info(mem_raw)
    stats = parse_info(stats_raw)
    clients = parse_info(clients_raw)

    used = mem.get("used_memory_human", "?")
    maxmem = int(mem.get("maxmemory", "1") or "1")
    used_bytes = int(mem.get("used_memory", "0") or "0")
    mem_pct = round(used_bytes / maxmem * 100, 1) if maxmem > 0 else 0

    hits = int(stats.get("keyspace_hits", "0") or "0")
    misses = int(stats.get("keyspace_misses", "0") or "0")
    hit_rate = round(hits / (hits + misses) * 100, 1) if (hits + misses) > 0 else 0

    return {
        "status": "healthy",
        "memory_used": used,
        "memory_percent": mem_pct,
        "hit_rate": hit_rate,
        "connected_clients": int(clients.get("connected_clients", "0") or "0"),
    }


@app.get("/api/v1/dragonfly/blocks", dependencies=[Depends(verify_api_key)])
async def dragonfly_blocks():
    from devops import k8s_client
    pods = await k8s_client.list_pods("default")
    df_pods = [p for p in pods if p["name"].startswith("dragonfly") and p["status"] == "Running"]
    if not df_pods:
        return []
    raw = await k8s_client.exec_in_pod(df_pods[0]["name"], "default", ["redis-cli", "keys", "ratelimit:block:*"])
    return [k.strip() for k in raw.splitlines() if k.strip()] if raw else []


@app.get("/api/v1/dragonfly/locks", dependencies=[Depends(verify_api_key)])
async def dragonfly_locks():
    from devops import k8s_client
    pods = await k8s_client.list_pods("default")
    df_pods = [p for p in pods if p["name"].startswith("dragonfly") and p["status"] == "Running"]
    if not df_pods:
        return []
    raw = await k8s_client.exec_in_pod(df_pods[0]["name"], "default", ["redis-cli", "keys", "lock:posserverbackend:*"])
    return [k.strip() for k in raw.splitlines() if k.strip()] if raw else []


@app.post("/api/v1/dragonfly/blocks/{business_id}/unblock", dependencies=[Depends(verify_api_key)])
async def unblock_business(business_id: str):
    from devops import k8s_client
    pods = await k8s_client.list_pods("default")
    df_pods = [p for p in pods if p["name"].startswith("dragonfly") and p["status"] == "Running"]
    if not df_pods:
        return {"error": "No Dragonfly pods"}
    result = await k8s_client.exec_in_pod(df_pods[0]["name"], "default", ["redis-cli", "del", f"ratelimit:block:{business_id}"])
    return {"result": result}


# --- Redpanda ---

@app.get("/api/v1/redpanda/health", dependencies=[Depends(verify_api_key)])
async def redpanda_health():
    from devops import k8s_client
    raw, brokers_raw, topics_raw = await asyncio.gather(
        k8s_client.exec_in_pod("redpanda-0", "kafka", ["curl", "-s", "http://localhost:9644/v1/status/ready"], timeout=10),
        k8s_client.exec_in_pod("redpanda-0", "kafka", ["curl", "-s", "http://localhost:9644/v1/brokers"], timeout=10),
        k8s_client.exec_in_pod("redpanda-0", "kafka", ["rpk", "topic", "list", "--format", "json"], timeout=10),
    )
    import json as j
    brokers = []
    try:
        brokers = j.loads(brokers_raw) if brokers_raw else []
    except Exception:
        pass
    partition_count = 0
    topic_count = 0
    try:
        topics = j.loads(topics_raw) if topics_raw else []
        if isinstance(topics, list):
            topic_count = len(topics)
            for t in topics:
                partition_count += t.get("partitions", t.get("partition_count", 0))
    except Exception:
        pass
    return {
        "ready": bool(raw),
        "status": "healthy" if raw else "critical",
        "brokers": brokers,
        "partition_count": partition_count,
        "topic_count": topic_count,
    }


async def _find_debezium_pod():
    from devops import k8s_client
    pods = await k8s_client.list_pods("kafka")
    for p in pods:
        if p["name"].startswith("debezium-connect") and p["status"] == "Running":
            return p["name"]
    return None


@app.get("/api/v1/redpanda/debezium", dependencies=[Depends(verify_api_key)])
async def debezium_status():
    from devops import k8s_client
    pod = await _find_debezium_pod()
    if not pod:
        return {"connectors": [], "error": "No debezium pod found"}
    raw = await k8s_client.exec_in_pod(pod, "kafka", ["curl", "-s", "http://localhost:8083/connectors?expand=status"], timeout=10)
    import json as j
    try:
        data = j.loads(raw) if raw else {}
        connectors = []
        for name, info in data.items():
            status = info.get("status", {})
            connector_state = status.get("connector", {}).get("state", "UNKNOWN")
            tasks = status.get("tasks", [])
            running_tasks = sum(1 for t in tasks if t.get("state") == "RUNNING")
            failed_tasks = sum(1 for t in tasks if t.get("state") == "FAILED")
            connectors.append({
                "name": name,
                "state": connector_state,
                "tasks": len(tasks),
                "running_tasks": running_tasks,
                "failed_tasks": failed_tasks,
                "task_states": tasks,
            })
        return {"connectors": connectors}
    except Exception:
        return {"connectors": [], "raw": raw}


@app.get("/api/v1/redpanda/debezium/detail", dependencies=[Depends(verify_api_key)])
async def debezium_detail():
    from devops import k8s_client
    import json as j
    pod = await _find_debezium_pod()
    if not pod:
        return {"error": "No debezium pod found"}
    connector_name = "oneshell-mongodb-connector"
    # Fetch status, config, and topics in parallel
    status_raw, config_raw, topics_raw = await asyncio.gather(
        k8s_client.exec_in_pod(pod, "kafka", ["curl", "-s", f"http://localhost:8083/connectors/{connector_name}/status"], timeout=10),
        k8s_client.exec_in_pod(pod, "kafka", ["curl", "-s", f"http://localhost:8083/connectors/{connector_name}/config"], timeout=10),
        k8s_client.exec_in_pod("redpanda-0", "kafka", ["rpk", "topic", "list", "--format", "json"], timeout=10),
    )
    result = {}
    # Parse status for tasks
    try:
        status = j.loads(status_raw) if status_raw else {}
        tasks_raw = status.get("tasks", [])
        result["tasks"] = [{"id": t.get("id", 0), "state": t.get("state", "?"), "worker": t.get("worker_id", "?")} for t in tasks_raw]
        result["connector_state"] = status.get("connector", {}).get("state", "UNKNOWN")
    except Exception:
        result["tasks"] = []
    # Parse config for connector details
    try:
        cfg = j.loads(config_raw) if config_raw else {}
        result["connector_class"] = cfg.get("connector.class", "")
        result["capture_mode"] = cfg.get("capture.mode", cfg.get("signal.enabled.channels", "?"))
        result["snapshot_mode"] = cfg.get("snapshot.mode", "?")
        result["error_tolerance"] = cfg.get("errors.tolerance", "none")
        result["dlq_topic"] = cfg.get("errors.deadletterqueue.topic.name", "none")
        result["mongodb_connection"] = cfg.get("mongodb.connection.string", "?")
        # Extract monitored collections
        coll_str = cfg.get("collection.include.list", "")
        if coll_str:
            result["collections"] = [c.split(".")[-1] if "." in c else c for c in coll_str.split(",")]
        else:
            result["collections"] = []
    except Exception:
        pass
    # Parse Redpanda topics (rpk topic list --format json)
    try:
        topics = j.loads(topics_raw) if topics_raw else []
        if isinstance(topics, list):
            result["topics"] = sorted([t.get("name", str(t)) if isinstance(t, dict) else str(t) for t in topics])
        else:
            result["topics"] = []
    except Exception:
        result["topics"] = []
    return result


@app.get("/api/v1/redpanda/consumer-lag", dependencies=[Depends(verify_api_key)])
async def kafka_consumer_lag():
    """Get Kafka consumer group lag for all monitored consumer groups."""
    from devops.monitors import kafka_consumer_lag_monitor
    result = await kafka_consumer_lag_monitor.safe_check()
    health = kafka_consumer_lag_monitor.health
    return {
        "status": health.status.value,
        "total_lag": health.total_lag,
        "consumer_groups": [g.model_dump() for g in health.consumer_groups],
        "last_checked": health.last_checked.isoformat() if health.last_checked else None,
        "error": health.error,
    }


@app.post("/api/v1/redpanda/debezium/{connector}/restart", dependencies=[Depends(verify_api_key)])
async def restart_debezium(connector: str):
    from devops import k8s_client
    pod = await _find_debezium_pod()
    if not pod:
        return {"error": "No debezium pod found"}
    raw = await k8s_client.exec_in_pod(pod, "kafka", ["curl", "-s", "-X", "POST", f"http://localhost:8083/connectors/{connector}/tasks/0/restart"], timeout=10)
    return {"result": raw}


# --- Harbor ---

@app.get("/api/v1/harbor/health", dependencies=[Depends(verify_api_key)])
async def harbor_health():
    """Check Harbor container registry health at docker.oneshell.in."""
    from devops import k8s_client
    exec_pods = await k8s_client.list_pods("default")
    exec_pod = next(
        (p["name"] for p in exec_pods
         if p["status"] == "Running" and p["name"].startswith("nginx")),
        None,
    )
    if not exec_pod:
        return {"status": "unknown", "error": "No exec pod available"}

    raw = await k8s_client.exec_in_pod(
        exec_pod, "default",
        ["curl", "-sk", "--max-time", "8", "https://docker.oneshell.in/api/v2.0/health"],
        timeout=15,
    )
    if not raw:
        return {"status": "critical", "error": "Harbor unreachable"}

    try:
        data = json.loads(raw)
        components = data.get("components", [])
        unhealthy = [c for c in components if c.get("status", "").lower() != "healthy"]
        return {
            "status": "critical" if unhealthy else "healthy",
            "components": components,
            "unhealthy": [c["name"] for c in unhealthy] if unhealthy else [],
        }
    except (json.JSONDecodeError, KeyError):
        return {"status": "degraded", "raw": raw[:500]}


# --- Certificates ---
# Monitors the oneshell-credential TLS secret in default namespace.
# This is a manually-managed cert (not cert-manager), created via:
#   kubectl create -n default secret tls oneshell-credential --key=oneshell.key --cert=oneshell.crt

_CERT_SECRET_NAME = "oneshell-credential"
_CERT_SECRET_NAMESPACE = "default"


async def _parse_tls_secret(secret_name: str, namespace: str) -> dict:
    """Extract certificate details from a TLS secret."""
    from devops import k8s_client
    import base64

    raw = await k8s_client._run_kubectl(
        "get", "secret", secret_name, "-n", namespace, "-o", "json",
    )
    if not raw or "not found" in raw.lower():
        return {"name": secret_name, "namespace": namespace, "error": "Secret not found"}

    try:
        data = json.loads(raw)
    except Exception:
        return {"name": secret_name, "namespace": namespace, "error": "Failed to parse secret"}

    cert_b64 = data.get("data", {}).get("tls.crt", "")
    if not cert_b64:
        return {"name": secret_name, "namespace": namespace, "error": "No tls.crt in secret"}

    # Decode and parse cert using openssl via kubectl exec or local openssl
    cert_pem = base64.b64decode(cert_b64).decode("utf-8", errors="replace")

    # Use openssl to extract cert details
    proc = await asyncio.create_subprocess_exec(
        "openssl", "x509", "-noout", "-subject", "-issuer",
        "-dates", "-serial", "-ext", "subjectAltName",
        stdin=asyncio.subprocess.PIPE,
        stdout=asyncio.subprocess.PIPE,
        stderr=asyncio.subprocess.PIPE,
    )
    stdout, stderr = await asyncio.wait_for(proc.communicate(cert_pem.encode()), timeout=10)
    output = stdout.decode("utf-8", errors="replace")

    result = {
        "name": secret_name,
        "namespace": namespace,
        "type": "TLS Secret",
        "ready": True,
    }

    # Parse openssl output
    for line in output.splitlines():
        line = line.strip()
        if line.startswith("subject="):
            result["subject"] = line.split("=", 1)[1].strip()
            # Extract domain from CN
            cn_parts = [p.strip() for p in result["subject"].split(",")]
            for p in cn_parts:
                if p.startswith("CN =") or p.startswith("CN="):
                    result["domain"] = p.split("=", 1)[1].strip()
        elif line.startswith("issuer="):
            result["issuer"] = line.split("=", 1)[1].strip()
        elif line.startswith("notBefore="):
            result["not_before"] = line.split("=", 1)[1].strip()
        elif line.startswith("notAfter="):
            not_after_str = line.split("=", 1)[1].strip()
            result["not_after"] = not_after_str
            # Calculate days remaining
            try:
                from datetime import datetime as dt
                # openssl format: "Mon DD HH:MM:SS YYYY GMT"
                expiry = dt.strptime(not_after_str, "%b %d %H:%M:%S %Y %Z")
                now = dt.utcnow()
                delta = expiry - now
                result["days_remaining"] = delta.days
                result["expired"] = delta.days < 0
                result["expiring_soon"] = 0 <= delta.days <= 14
            except Exception:
                pass
        elif "DNS:" in line:
            sans = [s.strip().replace("DNS:", "") for s in line.split(",") if "DNS:" in s]
            result["san_domains"] = sans

    return result


_CERT_SECRETS = [
    {"name": "oneshell-credential", "namespace": "default"},
    {"name": "oneshellsolutions-tls", "namespace": "default"},
]


@app.get("/api/v1/certificates", dependencies=[Depends(verify_api_key)])
async def list_certificates():
    certs = await asyncio.gather(*[
        _parse_tls_secret(c["name"], c["namespace"]) for c in _CERT_SECRETS
    ])
    # Also check cert-manager certificates if any
    from devops import k8s_client
    cm_raw = await k8s_client._run_kubectl(
        "get", "certificates", "-A",
        "-o", "jsonpath={range .items[*]}{.metadata.name}|{.metadata.namespace}|{.status.conditions[0].status}|{.status.notAfter}{\"\\n\"}{end}",
    )
    for line in (cm_raw or "").strip().splitlines():
        parts = line.split("|")
        if len(parts) >= 4 and not any(c.get("name") == parts[0] for c in certs):
            days_rem = None
            expired = False
            expiring_soon = False
            if parts[3]:
                try:
                    from datetime import datetime as dt
                    exp = dt.fromisoformat(parts[3].replace("Z", "+00:00"))
                    now = dt.utcnow().replace(tzinfo=exp.tzinfo)
                    days_rem = (exp - now).days
                    expired = days_rem < 0
                    expiring_soon = 0 <= days_rem <= 14
                except Exception:
                    pass
            certs.append({
                "name": parts[0], "namespace": parts[1],
                "type": "cert-manager", "ready": parts[2] == "True",
                "not_after": parts[3], "days_remaining": days_rem,
                "expired": expired, "expiring_soon": expiring_soon,
            })
    return list(certs)


@app.get("/api/v1/certificates/status", dependencies=[Depends(verify_api_key)])
async def certificate_status():
    certs = await asyncio.gather(*[
        _parse_tls_secret(c["name"], c["namespace"]) for c in _CERT_SECRETS
    ])
    return list(certs)


@app.post("/api/v1/certificates/{name}/renew", dependencies=[Depends(verify_api_key)])
async def renew_certificate(name: str):
    """Delete the TLS secret so it can be re-created with a new cert.
    User must re-create it manually: kubectl create -n default secret tls oneshell-credential --key=oneshell.key --cert=oneshell.crt
    """
    from devops import k8s_client
    result = await k8s_client._run_kubectl("delete", "secret", name, "-n", _CERT_SECRET_NAMESPACE)
    return {"result": result, "note": f"Secret deleted. Re-create with: kubectl create -n {_CERT_SECRET_NAMESPACE} secret tls {name} --key=oneshell.key --cert=oneshell.crt"}


# --- Tasks (ClawdBot task queue) ---

@app.get("/api/v1/tasks", dependencies=[Depends(verify_api_key)])
async def list_tasks():
    # This will be populated by bot.py injecting the task_queue reference
    if not hasattr(app.state, "task_queue"):
        return []
    return [
        {
            "id": t.id,
            "context": t.context,
            "prompt": t.prompt[:100],
            "status": t.status.value,
            "tools_used": t.tools_used,
            "created_at": t.created_at,
            "started_at": t.started_at,
            "finished_at": t.finished_at,
        }
        for t in app.state.task_queue.get_recent(None, limit=20)
    ]


@app.post("/api/v1/tasks", dependencies=[Depends(verify_api_key)])
async def create_task(request: Request):
    data = await request.json()
    if not hasattr(app.state, "task_queue"):
        raise HTTPException(500, "Task queue not initialized")

    context = data.get("context", "vm")
    prompt = data["prompt"]
    chat_id = data.get("chat_id", 0)

    task = app.state.task_queue.add(chat_id, context, prompt)
    return {"id": task.id, "status": "pending", "context": context}


# --- SSE Streaming ---

@app.get("/api/v1/tasks/{task_id}/stream", dependencies=[Depends(verify_api_key)])
async def stream_task(task_id: int):
    queue = broadcaster.subscribe_sse(task_id)

    async def event_stream():
        try:
            while True:
                try:
                    event = await asyncio.wait_for(queue.get(), timeout=30)
                    yield f"data: {json.dumps(event)}\n\n"
                except asyncio.TimeoutError:
                    yield f"data: {json.dumps({'type': 'keepalive'})}\n\n"
        except asyncio.CancelledError:
            pass
        finally:
            broadcaster.unsubscribe_sse(task_id, queue)

    return StreamingResponse(event_stream(), media_type="text/event-stream")


# --- WebSocket ---

async def _handle_ws(websocket: WebSocket):
    await websocket.accept()
    broadcaster.add_ws(websocket)
    try:
        while True:
            data = await websocket.receive_text()
    except WebSocketDisconnect:
        broadcaster.remove_ws(websocket)


@app.websocket("/api/v1/ws")
async def websocket_endpoint(websocket: WebSocket):
    await _handle_ws(websocket)


@app.websocket("/api/v1/dashboard/ws")
async def websocket_dashboard(websocket: WebSocket):
    await _handle_ws(websocket)


# --- Log Monitor ---

@app.post("/api/v1/logmonitor/scan", dependencies=[Depends(verify_api_key)])
async def logmonitor_scan():
    """Scan all core services for log issues."""
    result = await lm_scan_all()
    return result


@app.get("/api/v1/logmonitor/latest", dependencies=[Depends(verify_api_key)])
async def logmonitor_latest():
    """Get the latest auto-scan result (cached, no new scan triggered)."""
    result = lm_get_last_scan()
    if result:
        return result
    # No cached result yet, trigger a scan
    return await lm_scan_all()


@app.post("/api/v1/logmonitor/autoscan", dependencies=[Depends(verify_api_key)])
async def logmonitor_autoscan_control(request: Request):
    """Control auto-scan: POST {enabled: true/false, interval: 300}."""
    data = await request.json()
    if data.get("enabled", True):
        interval = data.get("interval", 300)
        lm_start_auto_scan(dispatch_fn=None, interval_seconds=interval)
        return {"status": "started", "interval": interval}
    else:
        lm_stop_auto_scan()
        return {"status": "stopped"}


@app.get("/api/v1/logmonitor/tickets", dependencies=[Depends(verify_api_key)])
async def logmonitor_tickets(
    status: str | None = None,
    service: str | None = None,
    severity: str | None = None,
    limit: int = 50,
):
    """Get log monitor tickets with optional filters."""
    return lm_get_tickets(status=status, service=service, severity=severity, limit=limit)


@app.get("/api/v1/logmonitor/ticket-stats", dependencies=[Depends(verify_api_key)])
async def logmonitor_ticket_stats():
    """Get ticket statistics for dashboard overview."""
    return get_ticket_stats()


@app.delete("/api/v1/logmonitor/tickets", dependencies=[Depends(verify_api_key)])
async def logmonitor_reset_tickets():
    """Delete all tickets (reset)."""
    deleted = reset_all_tickets()
    return {"deleted": deleted, "status": "reset"}


@app.post("/api/v1/logmonitor/ticket", dependencies=[Depends(verify_api_key)])
async def logmonitor_create_ticket(request: Request):
    """Create a ticket. AI fix is manual via the 'Fix via AI' button."""
    data = await request.json()
    ticket = lm_create_ticket(
        service=data["service"],
        namespace=data.get("namespace", "default"),
        severity=data.get("severity", "WARNING"),
        category=data.get("category", ""),
        description=data["description"],
        matched_line=data.get("matched_line", ""),
        recommendation=data.get("recommendation", ""),
    )

    return {"ticket": ticket}


@app.put("/api/v1/logmonitor/tickets/{ticket_id}", dependencies=[Depends(verify_api_key)])
async def logmonitor_update_ticket(ticket_id: int, request: Request):
    """Update a ticket status or fields."""
    data = await request.json()
    updated = lm_update_ticket(ticket_id, data)
    if not updated:
        raise HTTPException(404, "Ticket not found")
    return updated


@app.post("/api/v1/logmonitor/tickets/{ticket_id}/ai-fix", dependencies=[Depends(verify_api_key)])
async def logmonitor_ai_fix_ticket(ticket_id: int):
    """Dispatch a ticket to ClawdBot for AI fix."""
    ticket = lm_get_ticket(ticket_id)
    if not ticket:
        raise HTTPException(404, "Ticket not found")
    asyncio.create_task(_dispatch_to_clawdbot(ticket))
    return {"status": "dispatched", "ticket_id": ticket_id}


@app.post("/api/v1/logmonitor/diagnose", dependencies=[Depends(verify_api_key)])
async def logmonitor_diagnose(request: Request):
    """Quick AI diagnosis of an issue without creating a ticket."""
    data = await request.json()
    service = data.get("service", "")
    description = data.get("description", "")
    matched_line = data.get("matched_line", "")

    prompt = f"Quickly diagnose this issue in {service}:\n{description}\nLog: {matched_line}\nCheck recent logs and suggest the likely root cause in 2-3 sentences."

    task_id = secrets.token_hex(8)
    _ai_tasks[task_id] = {
        "status": "starting", "events": [], "process": None,
        "final_output": "", "started_at": time.time(),
        "issue": description, "service": service,
    }

    # Run Claude for quick diagnosis (blocking, short timeout)
    try:
        await _start_claude_stream(task_id, prompt)
        # Wait briefly for output
        for _ in range(30):
            await asyncio.sleep(1)
            task = _ai_tasks.get(task_id, {})
            if task.get("status") == "done" or task.get("final_output"):
                break
        diagnosis = _ai_tasks.get(task_id, {}).get("final_output", "No diagnosis available")
        return {"diagnosis": diagnosis}
    except Exception as e:
        return {"diagnosis": f"Diagnosis failed: {str(e)}"}


async def _dispatch_to_clawdbot(ticket: dict):
    """Dispatch a ticket to ClawdBot for investigation and fix."""
    ticket_id = ticket["id"]
    lm_update_ticket(ticket_id, {"status": "investigating"})

    prompt = lm_build_prompt(ticket)

    # Use the AI task streaming mechanism
    task_id = secrets.token_hex(8)
    _ai_tasks[task_id] = {
        "status": "starting", "events": [], "process": None,
        "final_output": "", "started_at": time.time(),
        "issue": ticket["description"], "service": ticket["service"],
    }
    lm_update_ticket(ticket_id, {"clawdbot_task_id": task_id})

    try:
        await _start_claude_stream(task_id, prompt)

        # Monitor the task until completion (max 10 min)
        for _ in range(600):
            await asyncio.sleep(1)
            task = _ai_tasks.get(task_id, {})
            if task.get("status") == "done" or task.get("final_output"):
                break

        output = _ai_tasks.get(task_id, {}).get("final_output", "")
        lm_update_ticket(ticket_id, {
            "clawdbot_output": output[:2000],
            "status": "testing",
        })

        # Check if MR was created (look for github.com URL in output)
        import re
        mr_match = re.search(r'https://github\.com/\S+/pull/\d+', output)
        if mr_match:
            lm_update_ticket(ticket_id, {
                "mr_url": mr_match.group(0),
                "status": "mr_created",
            })

        # Send Telegram notification
        await _notify_telegram(ticket)

        lm_update_ticket(ticket_id, {"telegram_notified": True})

        # If MR was created, mark as resolved
        if mr_match:
            lm_update_ticket(ticket_id, {"status": "resolved"})
        else:
            lm_update_ticket(ticket_id, {"status": "investigated"})

    except Exception as e:
        logger.error("ClawdBot dispatch failed for ticket %d: %s", ticket_id, e)
        lm_update_ticket(ticket_id, {
            "status": "failed",
            "clawdbot_output": f"Error: {str(e)}",
        })


async def _notify_telegram(ticket: dict):
    """Send ticket status to Telegram."""
    bot_token = os.environ.get("TELEGRAM_BOT_TOKEN", "")
    chat_id = os.environ.get("ALERT_CHAT_ID", "")
    if not bot_token or not chat_id:
        logger.warning("Telegram not configured, skipping notification")
        return

    status_emoji = {
        "resolved": "OK", "mr_created": "PR", "investigated": "INFO",
        "failed": "FAIL", "testing": "TEST",
    }.get(ticket["status"], "TICKET")

    text = (
        f"[{status_emoji}] Log Monitor Ticket #{ticket['id']}\n"
        f"Service: {ticket['service']}\n"
        f"Severity: {ticket['severity']}\n"
        f"Issue: {ticket['description'][:200]}\n"
        f"Status: {ticket['status']}\n"
    )
    if ticket.get("mr_url"):
        text += f"MR: {ticket['mr_url']}\n"
    if ticket.get("clawdbot_output"):
        text += f"\nOutput (truncated):\n{ticket['clawdbot_output'][:500]}"

    try:
        import urllib.request
        req = urllib.request.Request(
            f"https://api.telegram.org/bot{bot_token}/sendMessage",
            data=json.dumps({"chat_id": chat_id, "text": text}).encode(),
            headers={"Content-Type": "application/json"},
            method="POST",
        )
        loop = asyncio.get_event_loop()
        await loop.run_in_executor(None, lambda: urllib.request.urlopen(req, timeout=10))
    except Exception as e:
        logger.error("Telegram notification failed: %s", e)


# --- Admin Tasks ---

@app.get("/api/v1/admin/search-businesses", dependencies=[Depends(verify_api_key)])
async def admin_search_businesses(q: str = ""):
    """Search businesses by name for autocomplete via mongosh."""
    if len(q.strip()) < 2:
        return {"businesses": []}
    try:
        from devops.mongodb_client import search_businesses
        results = await search_businesses(q.strip(), limit=10)
        return {"businesses": results}
    except Exception as e:
        logger.error("Business search failed: %s", e)
        return {"businesses": [], "error": str(e)}


@app.post("/api/v1/admin/copy-categories", dependencies=[Depends(verify_api_key)])
async def admin_copy_categories(request: Request):
    """Copy categories to a destination business via internal K8s service."""
    body = await request.json()
    business_id = body.get("businessId")
    business_city = body.get("businessCity")
    source_business_id = (body.get("sourceBusinessId") or "").strip() or None
    if not business_id or not business_city:
        raise HTTPException(400, "businessId and businessCity are required")
    try:
        from devops import k8s_client
        payload_obj = {"businessCity": business_city, "businessId": business_id}
        if source_business_id:
            payload_obj["sourceBusinessId"] = source_business_id
        payload = json.dumps(payload_obj)
        result = await k8s_client.exec_in_pod(
            "prod-cluster-mongos-0", "mongodb",
            ["curl", "-s", "-w", "\n%{http_code}", "-X", "POST",
             "-H", "Content-Type: application/json",
             "-d", payload,
             "http://businessservice.default.svc.cluster.local:8092/v1/admin/updateCategories"],
            timeout=30,
        )
        lines = result.strip().rsplit("\n", 1)
        response_body = lines[0] if len(lines) > 1 else result
        status_code = int(lines[-1]) if len(lines) > 1 and lines[-1].isdigit() else 0
        if 200 <= status_code < 300:
            try:
                data = json.loads(response_body)
                if isinstance(data, dict) and data.get("success") is False:
                    return {"success": False, "error": data.get("errorMessage", "Operation failed")}
                return {"success": True, "result": data}
            except (json.JSONDecodeError, TypeError):
                return {"success": True, "result": response_body}
        return {"success": False, "error": f"API returned {status_code}: {response_body[:500]}"}
    except Exception as e:
        logger.error("Copy categories failed: %s", e)
        return {"success": False, "error": str(e)}


@app.post("/api/v1/admin/update-ap-code", dependencies=[Depends(verify_api_key)])
async def admin_update_ap_code(request: Request):
    """Update AP/partner mapping code for a business."""
    body = await request.json()
    business_id = body.get("businessId")
    partner_code = body.get("partnerCode")
    open_stock_date = body.get("openStockAsOnDate")
    if not business_id or not partner_code or not open_stock_date:
        raise HTTPException(400, "businessId, partnerCode, and openStockAsOnDate are required")
    try:
        from devops import k8s_client
        payload = json.dumps({"businessId": business_id, "partnerCode": partner_code, "openStockAsOnDate": open_stock_date})
        result = await k8s_client.exec_in_pod(
            "prod-cluster-mongos-0", "mongodb",
            ["curl", "-s", "-w", "\n%{http_code}", "-X", "POST",
             "-H", "Content-Type: application/json",
             "-d", payload,
             "http://businessservice.default.svc.cluster.local:8092/v1/admin/updateBusinessMappingCode"],
            timeout=30,
        )
        lines = result.strip().rsplit("\n", 1)
        response_body = lines[0] if len(lines) > 1 else result
        status_code = int(lines[-1]) if len(lines) > 1 and lines[-1].isdigit() else 0
        if 200 <= status_code < 300:
            try:
                data = json.loads(response_body)
                msg = data.get("message", "AP Code updated successfully")
                return {"success": True, "message": msg, "result": data}
            except (json.JSONDecodeError, TypeError):
                return {"success": True, "message": "AP Code updated successfully"}
        return {"success": False, "error": f"API returned {status_code}: {response_body[:500]}"}
    except Exception as e:
        logger.error("Update AP code failed: %s", e)
        return {"success": False, "error": str(e)}


@app.post("/api/v1/admin/bulk-update-ap-codes", dependencies=[Depends(verify_api_key)])
async def admin_bulk_update_ap_codes(file: UploadFile):
    """Bulk update AP codes from an uploaded Excel file."""
    import tempfile
    try:
        import openpyxl
    except ImportError:
        return {"successful": [], "unmatched": [], "failed": [{"partnerName": "System", "error": "openpyxl not installed on server"}]}

    successful = []
    unmatched = []
    failed = []

    try:
        # Save uploaded file to temp
        contents = await file.read()
        with tempfile.NamedTemporaryFile(suffix=".xlsx", delete=False) as tmp:
            tmp.write(contents)
            tmp_path = tmp.name

        wb = openpyxl.load_workbook(tmp_path)
        ws = wb.active

        from devops.mongodb_client import search_businesses
        from devops import k8s_client

        for row in ws.iter_rows(min_row=2, values_only=True):
            if not row or not row[0]:
                continue
            ap_code = str(row[0]).strip()
            partner_name = str(row[1]).strip() if row[1] else ""
            stock_date = row[2]
            if not partner_name:
                continue

            # Format date to dd/MM/yyyy
            if hasattr(stock_date, 'strftime'):
                formatted_date = stock_date.strftime("%d/%m/%Y")
            elif stock_date:
                formatted_date = str(stock_date).strip()
            else:
                formatted_date = ""

            # Search for business by name
            matches = await search_businesses(partner_name, limit=1)
            if not matches:
                unmatched.append({"partnerName": partner_name, "apCode": ap_code})
                continue

            business = matches[0]
            business_id = business.get("businessId", "")

            # Call the API
            try:
                payload = json.dumps({"businessId": business_id, "partnerCode": ap_code, "openStockAsOnDate": formatted_date})
                result = await k8s_client.exec_in_pod(
                    "prod-cluster-mongos-0", "mongodb",
                    ["curl", "-s", "-w", "\n%{http_code}", "-X", "POST",
                     "-H", "Content-Type: application/json",
                     "-d", payload,
                     "http://businessservice.default.svc.cluster.local:8092/v1/admin/updateBusinessMappingCode"],
                    timeout=30,
                )
                lines = result.strip().rsplit("\n", 1)
                status_code = int(lines[-1]) if len(lines) > 1 and lines[-1].isdigit() else 0
                if 200 <= status_code < 300:
                    successful.append({"partnerName": partner_name, "apCode": ap_code, "businessId": business_id})
                else:
                    response_body = lines[0] if len(lines) > 1 else result
                    failed.append({"partnerName": partner_name, "apCode": ap_code, "error": response_body[:200]})
            except Exception as e:
                failed.append({"partnerName": partner_name, "apCode": ap_code, "error": str(e)})

        # Cleanup temp file
        import os
        os.unlink(tmp_path)

    except Exception as e:
        logger.error("Bulk AP code upload failed: %s", e)
        failed.append({"partnerName": "System", "error": str(e)})

    return {"successful": successful, "unmatched": unmatched, "failed": failed}


# --- Static files (dashboard) ---

static_dir = os.path.join(os.path.dirname(__file__), "static")
if os.path.exists(static_dir):
    app.mount("/static", StaticFiles(directory=static_dir), name="static")

    @app.get("/")
    async def serve_dashboard(request: Request):
        if not _is_authenticated(request):
            return RedirectResponse("/login", status_code=302)
        return FileResponse(os.path.join(static_dir, "index.html"))

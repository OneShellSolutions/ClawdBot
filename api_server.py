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

from fastapi import FastAPI, WebSocket, WebSocketDisconnect, Request, HTTPException, Depends, Form
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
.login{background:#111827;border:1px solid #1e293b;border-radius:12px;padding:40px;width:360px;box-shadow:0 8px 32px rgba(0,0,0,.4)}
h1{font-size:24px;margin-bottom:8px;text-align:center}
.sub{color:#8b8fa3;font-size:13px;text-align:center;margin-bottom:24px}
label{display:block;font-size:13px;color:#8b8fa3;margin-bottom:4px}
input{width:100%;padding:10px 12px;background:#0a0e1a;border:1px solid #1e293b;border-radius:6px;color:#e0e0e0;font-size:14px;margin-bottom:16px;outline:none}
input:focus{border-color:#3b82f6}
button{width:100%;padding:10px;background:#3b82f6;color:#fff;border:none;border-radius:6px;font-size:14px;cursor:pointer}
button:hover{background:#2563eb}
.error{color:#ef4444;font-size:13px;text-align:center;margin-bottom:12px}
</style></head><body>
<div class="login">
<h1>AiDevOps</h1>
<div class="sub">OneShell Infrastructure Monitor</div>
<div class="error" id="err"></div>
<form method="POST" action="/login">
<label>Username</label><input name="username" required autofocus>
<label>Password</label><input name="password" type="password" required>
<button type="submit">Sign In</button>
</form></div></body></html>"""


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
    services = []
    for name, info in SERVICE_TOPOLOGY.items():
        health = service_health_monitor.services.get(name)
        services.append({
            "name": name,
            "namespace": info.namespace,
            "port": info.port,
            "tier": info.tier.value,
            "health_path": info.health_path,
            "status": health.status.value if health else "unknown",
            "response_time_ms": health.response_time_ms if health else None,
            "error": health.error if health else None,
        })
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
                    "message": f"Done. Cost: ${evt.get('total_cost_usd', 0):.3f}, Turns: {evt.get('num_turns', '?')}",
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
    return {"status": "not_configured", "message": "OpenObserve not connected"}


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


@app.post("/api/v1/redpanda/debezium/{connector}/restart", dependencies=[Depends(verify_api_key)])
async def restart_debezium(connector: str):
    from devops import k8s_client
    pod = await _find_debezium_pod()
    if not pod:
        return {"error": "No debezium pod found"}
    raw = await k8s_client.exec_in_pod(pod, "kafka", ["curl", "-s", "-X", "POST", f"http://localhost:8083/connectors/{connector}/tasks/0/restart"], timeout=10)
    return {"result": raw}


# --- Certificates ---

@app.get("/api/v1/certificates", dependencies=[Depends(verify_api_key)])
async def list_certificates():
    from devops import k8s_client
    raw = await k8s_client._run_kubectl("get", "certificates", "-A", "-o", "json")
    import json as j
    try:
        data = j.loads(raw) if raw else {"items": []}
        return [{"name": i["metadata"]["name"], "namespace": i["metadata"]["namespace"],
                 "ready": any(c.get("type") == "Ready" and c.get("status") == "True" for c in i.get("status", {}).get("conditions", []))}
                for i in data.get("items", [])]
    except Exception:
        return []


@app.get("/api/v1/certificates/status", dependencies=[Depends(verify_api_key)])
async def certificate_status():
    from devops import k8s_client
    raw = await k8s_client._run_kubectl("get", "certificates", "-A")
    return {"status": raw}


@app.post("/api/v1/certificates/{name}/renew", dependencies=[Depends(verify_api_key)])
async def renew_certificate(name: str):
    from devops import k8s_client
    result = await k8s_client._run_kubectl("delete", "secret", name, "-n", "default")
    return {"result": result}


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


# --- Static files (dashboard) ---

static_dir = os.path.join(os.path.dirname(__file__), "static")
if os.path.exists(static_dir):
    app.mount("/static", StaticFiles(directory=static_dir), name="static")

    @app.get("/")
    async def serve_dashboard(request: Request):
        if not _is_authenticated(request):
            return RedirectResponse("/login", status_code=302)
        return FileResponse(os.path.join(static_dir, "index.html"))

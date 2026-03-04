# ClawdBot

A Telegram bot that wraps [Claude Code CLI](https://docs.anthropic.com/en/docs/claude-code) (Max subscription OAuth) into a personal AI assistant with an integrated DevOps monitoring dashboard. Send a message in Telegram and Claude reads files, edits code, runs shell commands, queries databases, and manages Kubernetes clusters on your behalf.

## Architecture

```
                    ┌─────────────────────┐
                    │   Telegram Bot      │ ← User sends messages, gets alerts
                    │   (bot.py)          │ → Approval callbacks for remediation
                    └────────┬────────────┘
                             │
        ┌────────────────────┴────────────────────┐
        │           ClawdBot Process              │
        │  (bot.py + FastAPI + APScheduler)        │
        ├─────────────────────────────────────────┤
        │ Executor (Claude Agent SDK)             │
        │ Task Queue (SQLite)                     │
        │ Progress Broadcaster (SSE + WebSocket)  │
        ├─────────────────────────────────────────┤
        │ devops/ module:                         │
        │  ├─ monitors (K8s, MongoDB, NATS, Logs) │
        │  ├─ patterns (51 error patterns)        │
        │  ├─ playbooks (10 remediations)         │
        │  ├─ incident manager                    │
        │  ├─ approval workflow                   │
        │  └─ k8s/mongodb/nats clients (kubectl)  │
        └────────┬────────────────────────────────┘
                 │ FastAPI :8000
                 │ SSE + WebSocket
        ┌────────┴────────────────────┐
        │  DevOps Web Dashboard       │
        │  (Alpine.js + D3.js)        │
        │  Served as static files     │
        └─────────────────────────────┘
```

### Message Flow

1. **User sends message** in Telegram — text, photo, or document (with optional caption)
2. **bot.py** authenticates the user, resolves the active context (working directory), downloads any attachments, sends a status message, and queues the task in SQLite
3. **Executor** polls for pending tasks every 2 seconds. One task per context runs at a time; others queue
4. **Agent SDK execution** — all tasks use `claude-agent-sdk` with 5 specialized sub-agents. If the SDK isn't installed or fails mid-run, it falls back to raw CLI subprocess automatically
5. **Live status** — tool calls and agent delegations are streamed as Telegram status updates with elapsed time. A heartbeat updates the status every 10 seconds even during long-running operations
6. **Result** — final response is sent back to Telegram, status message is deleted, session ID is saved for `--resume`

### Sub-Agents

All messages go through the Agent SDK path by default. The orchestrator Claude delegates via the `Task` tool:

| Agent | Tools | Purpose |
|-------|-------|---------|
| planner | Read, Glob, Grep | Break tasks into ordered steps |
| architect | Read, Glob, Grep | Design technical solutions |
| coder | Read, Write, Edit, Bash, Glob, Grep | Implement changes |
| tester | Bash, Read, Glob, Grep | Run tests, validate |
| reviewer | Read, Glob, Grep | Code review, security check |

**Fallback**: If the SDK isn't installed or crashes mid-run, the executor automatically falls back to raw `claude -p` subprocess with `--resume` for session continuity.

## DevOps Dashboard

Web-based monitoring dashboard at `http://<server>:8000/` with 15 tabs:

| Tab | Description |
|-----|-------------|
| Overview | Health score, service status, pod counts, infrastructure cards |
| Services | All 19 microservices with health status and response times |
| Topology | D3.js service dependency graph |
| Kubernetes | Pod listing across namespaces, warning events |
| Nodes | Cluster node CPU/memory usage, per-pod resource metrics |
| MongoDB | Connection pool, sessions, sync errors, version info |
| NATS | JetStream streams, consumers, DLQ messages |
| Redpanda | Broker health, Debezium CDC status, monitored collections, Kafka topics |
| Dragonfly | Redis-compatible cache status, memory, hit rate |
| Certs | TLS certificate status and expiry |
| OpenObserve | Observability platform integration (stub) |
| Log Analysis | AI-powered log scanning against 51 error patterns |
| Issues | Automated issue detection across all systems |
| Incidents | Incident lifecycle management |
| Remediation | 10 playbooks with dry-run and execute capabilities |

### Background Monitors

APScheduler runs 6 monitors alongside the Telegram bot:

| Monitor | Interval | What it checks |
|---------|----------|----------------|
| KubernetesMonitor | 60s | Pods, deployments, events across all namespaces |
| ServiceHealthMonitor | 60s | HTTP health checks for all services via kubectl exec |
| MongoDBMonitor | 120s | Connections, sessions, sync errors, server status |
| NATSMonitor | 60s | Streams, consumers, DLQ messages |
| LogAnalyzerMonitor | 300s | Scans pod logs against 51 error patterns |
| IssueFinder | 300s | Aggregates issues, detects problems |

### Remediation & Approval

- **LOW risk** actions: auto-execute (check connections, fetch logs)
- **MEDIUM risk**: auto-execute unless `requires_approval=True`
- **HIGH risk**: always request approval via Telegram inline keyboard or web UI

## Commands

| Command | Description |
|---------|-------------|
| `/start` | Welcome message |
| `/help` | Show all commands |
| `/ctx <name>` | Switch context (working directory) |
| `/ctx list` | List all available contexts |
| `/ctx` | Show current context |
| `/newctx <name> [path]` | Create custom context |
| `/rmctx <name>` | Remove custom context |
| `/task <prompt>` | Force multi-agent pipeline (same as regular message) |
| `/q <prompt>` | Queue task silently (no status message) |
| `/stop` | Kill the currently running task |
| `/stopall` | Kill running task + cancel all pending in context |
| `/clear` | Clear conversation history and session |
| `/tasks` | Show 10 most recent tasks |
| `/status` | Show running tasks and queue depth |
| `/shell <cmd>` | Run shell command directly (no Claude) |

## Setup

### Prerequisites

- Python 3.11+
- [Claude Code CLI](https://docs.anthropic.com/en/docs/claude-code) installed and authenticated (Max subscription)
- Telegram bot token from [@BotFather](https://t.me/BotFather)
- kubectl access to Kubernetes cluster (for DevOps monitoring)

### Install

```bash
git clone https://github.com/OneShellSolutions/ClawdBot.git
cd ClawdBot
python3 -m venv venv
source venv/bin/activate
pip install -r requirements.txt
```

### Configure

```bash
cp .env.template .env
# Edit .env with your values
```

| Variable | Required | Default | Description |
|----------|----------|---------|-------------|
| `TELEGRAM_BOT_TOKEN` | Yes | — | From BotFather |
| `ALLOWED_USER_IDS` | No | (all) | Comma-separated Telegram user IDs |
| `DB_PATH` | No | `/opt/clawdbot/conversations.db` | SQLite database path |
| `REPOS_DIR` | No | `/opt/clawdbot/repos` | Auto-discovered repo contexts |
| `SHELL_TIMEOUT` | No | `60` | Shell command timeout (seconds) |
| `DEVOPS_ENABLED` | No | `true` | Enable DevOps monitoring and dashboard |
| `API_PORT` | No | `8000` | Dashboard/API port |
| `DEVOPS_API_KEY` | No | (none) | API key for dashboard endpoints |
| `ALERT_CHAT_ID` | No | `0` | Telegram chat ID for DevOps alerts |

### Run

```bash
python bot.py
```

### Deploy

```bash
./deploy.sh
```

The deploy script SSHs into the server (`77.42.68.16`), copies all files via scp, installs dependencies in a venv, and configures a systemd service that auto-restarts on failure. No CI/CD pipelines — purely manual deployment.

## File Structure

```
ClawdBot/
├── bot.py                  # Telegram handlers, approval callbacks, API server startup
├── executor.py             # Task execution — Agent SDK + CLI fallback, progress broadcasting
├── api_server.py           # FastAPI server (69 endpoints), serves dashboard
├── progress_broadcaster.py # SSE + WebSocket broadcast for real-time updates
├── agents.py               # Sub-agent definitions (planner, architect, coder, tester, reviewer)
├── task_queue.py           # SQLite-backed task queue with status tracking
├── context_manager.py      # Working directories, session IDs, conversation history
├── config.py               # Environment variable loading
├── tools.py                # Tool call description formatting for status updates
├── shell_executor.py       # Direct shell command execution with safety checks
├── devops/
│   ├── models.py           # Pydantic models (ServiceHealth, Incident, etc.)
│   ├── monitors.py         # 6 background monitors (K8s, MongoDB, NATS, etc.)
│   ├── scheduler.py        # APScheduler setup
│   ├── k8s_client.py       # kubectl subprocess client
│   ├── mongodb_client.py   # mongosh via kubectl exec
│   ├── nats_client.py      # NATS monitoring via kubectl exec
│   ├── patterns.py         # 51 error patterns for log analysis
│   ├── topology.py         # Service dependency graph (19 services)
│   ├── correlator.py       # Error correlation engine
│   ├── playbooks.py        # 10 remediation playbooks
│   ├── remediation.py      # Playbook execution engine
│   ├── incident_manager.py # Incident lifecycle management
│   ├── approval.py         # Approval workflow (Telegram + web)
│   ├── auto_remediation.py # Incident → playbook matching + cooldown
│   ├── notifications.py    # Telegram alert notifications
│   └── event_bus.py        # Async pub/sub event system
├── static/
│   ├── index.html          # Dashboard UI (Alpine.js)
│   ├── css/dashboard.css   # Dashboard styles
│   └── js/
│       ├── app.js          # Dashboard logic, API calls, tab management
│       ├── charts.js       # Chart.js doughnut chart
│       ├── topology.js     # D3.js service topology graph
│       └── websocket.js    # WebSocket client for real-time updates
├── requirements.txt
├── deploy.sh               # Manual scp deployment script
├── sync-context.sh         # Sync CLAUDE.md + memory to server
├── clawdbot.service        # systemd unit file
├── .env.template
└── CLAUDE.md               # System prompt for Claude
```

## Session Continuity

Each (chat_id, context) pair stores a Claude CLI session ID in SQLite. When the user sends a follow-up message, the executor passes `--resume <session_id>` to the CLI, giving Claude full conversation history without re-sending it. The `/clear` command deletes the session, starting fresh.

## Safety

- **User allowlist**: Only Telegram user IDs in `ALLOWED_USER_IDS` can interact
- **Shell blocklist**: Destructive commands (`rm -rf /`, `mkfs`, `dd`, `shutdown`, etc.) are blocked
- **No API key exposure**: `ANTHROPIC_API_KEY` is stripped from the subprocess environment so Claude CLI uses Max subscription OAuth instead
- **Permission bypass**: Uses `bypassPermissions` since the bot runs unattended — the CLAUDE.md system prompt constrains behavior (never auto-commit, confirm before destructive ops)
- **Remediation approval**: High-risk DevOps actions require explicit approval via Telegram inline keyboard

#!/bin/bash
set -euo pipefail

SERVER="77.42.68.16"
REPO_ROOT="$(cd "$(dirname "$0")/.." && pwd)"
REMOTE_CLAWDBOT="/opt/clawdbot"

echo "=== Syncing context files to ClawdBot VM ==="

# Sync CLAUDE.md to repos directory on server
if [ -f "${REPO_ROOT}/CLAUDE.md" ]; then
    echo "[1/2] Syncing CLAUDE.md..."
    ssh root@${SERVER} "mkdir -p ${REMOTE_CLAWDBOT}/repos/codeRepo"
    scp "${REPO_ROOT}/CLAUDE.md" root@${SERVER}:${REMOTE_CLAWDBOT}/repos/codeRepo/CLAUDE.md
    echo "  -> Copied to ${REMOTE_CLAWDBOT}/repos/codeRepo/CLAUDE.md"
else
    echo "[1/2] CLAUDE.md not found at ${REPO_ROOT}/CLAUDE.md, skipping"
fi

# Sync memory files to all relevant project paths on VM
MEMORY_DIR="${REPO_ROOT}/.claude/projects/-Users-manip-Documents-codeRepo/memory"
if [ -d "${MEMORY_DIR}" ]; then
    echo "[2/3] Syncing memory files..."
    # Primary path: Claude running from /opt/clawdbot
    ssh root@${SERVER} "mkdir -p ${REMOTE_CLAWDBOT}/.claude/projects/-opt-clawdbot/memory"
    scp -r "${MEMORY_DIR}"/* root@${SERVER}:${REMOTE_CLAWDBOT}/.claude/projects/-opt-clawdbot/memory/ 2>/dev/null || true
    echo "  -> Copied to ${REMOTE_CLAWDBOT}/.claude/projects/-opt-clawdbot/memory/"
    # Secondary path: Claude running from /opt/clawdbot/repos
    ssh root@${SERVER} "mkdir -p ${REMOTE_CLAWDBOT}/.claude/projects/-opt-clawdbot-repos/memory"
    cp_cmd="cp ${REMOTE_CLAWDBOT}/.claude/projects/-opt-clawdbot/memory/* ${REMOTE_CLAWDBOT}/.claude/projects/-opt-clawdbot-repos/memory/"
    ssh root@${SERVER} "${cp_cmd}"
    echo "  -> Copied to repos project path"
else
    echo "[2/3] Memory directory not found at ${MEMORY_DIR}, skipping"
fi

# Fix ownership
echo "[3/3] Fixing file ownership..."
ssh root@${SERVER} "chown -R clawdbot:clawdbot ${REMOTE_CLAWDBOT}/.claude/ ${REMOTE_CLAWDBOT}/repos/codeRepo/CLAUDE.md 2>/dev/null || true"

echo "=== Context sync complete ==="

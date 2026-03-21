"""MongoDB access via kubectl exec mongosh."""
from __future__ import annotations

import asyncio
import json
import logging

from devops import k8s_client

logger = logging.getLogger(__name__)

MONGOS_POD = "prod-cluster-mongos-0"
MONGO_NS = "mongodb"
ADMIN_URI = "mongodb://clusterAdmin:tb3GSgY6U5ZSc7CNsvf6@localhost:27017/admin?authSource=admin"
APP_URI = "mongodb://databaseAdmin:akyFqNelEclMhlkNx06c@localhost:27017/oneshell?authSource=admin"


async def _mongosh(eval_cmd: str, uri: str | None = None) -> str:
    """Run a mongosh command via kubectl exec."""
    uri = uri or ADMIN_URI
    return await k8s_client.exec_in_pod(
        MONGOS_POD, MONGO_NS,
        ["mongosh", uri, "--quiet", "--eval", eval_cmd],
        timeout=30,
    )


async def _mongosh_json(eval_cmd: str, uri: str | None = None) -> dict | list:
    raw = await _mongosh(eval_cmd, uri)
    if not raw or raw.startswith("ERROR"):
        return {"error": raw[:500] if raw else "No output"}
    try:
        return json.loads(raw)
    except (json.JSONDecodeError, TypeError):
        logger.error(f"Failed to parse mongosh JSON: {raw[:200]}")
        return {"error": raw[:500]}


async def get_server_status() -> dict:
    return await _mongosh_json(
        "var s=db.serverStatus(); var c=s.connections; var o=s.opcounters; var ss=s.logicalSessionRecordCache; "
        "JSON.stringify({version:s.version, uptime:Number(s.uptime), uptimeMillis:Number(s.uptimeMillis), host:s.host, process:s.process, "
        "connections:{current:Number(c.current),available:Number(c.available),totalCreated:Number(c.totalCreated),active:Number(c.active)}, "
        "opcounters:{insert:Number(o.insert),query:Number(o.query),update:Number(o.update),delete:Number(o.delete),getmore:Number(o.getmore),command:Number(o.command)}, "
        "activeSessionsCount:ss?Number(ss.activeSessionsCount):0, "
        "mem:s.mem})"
    )


async def get_connection_pool() -> dict:
    return await _mongosh_json("JSON.stringify(db.serverStatus().connections)")


async def get_current_ops(min_seconds: int = 5) -> list:
    result = await _mongosh_json(
        f'JSON.stringify(db.currentOp({{"secs_running":{{"$gt":{min_seconds}}}}}).inprog.slice(0,20))'
    )
    return result if isinstance(result, list) else []


async def kill_all_sessions() -> str:
    return await _mongosh("JSON.stringify(db.adminCommand({killAllSessions: []}))")


async def get_sync_errors(limit: int = 20) -> list:
    result = await _mongosh_json(
        f'JSON.stringify(db.changeStreamEventErrors.find({{resolved: false}}).sort({{createdAt: -1}}).limit({limit}).toArray())',
        uri=APP_URI,
    )
    return result if isinstance(result, list) else []


async def get_sync_error_summary() -> list:
    result = await _mongosh_json(
        'JSON.stringify(db.changeStreamEventErrors.aggregate(['
        '{$match: {resolved: false}},'
        '{$group: {_id: {collection: "$collection", errorType: "$errorType"}, count: {$sum: 1}}},'
        '{$sort: {count: -1}}, {$limit: 10}'
        ']).toArray())',
        uri=APP_URI,
    )
    return result if isinstance(result, list) else []


async def search_businesses(keyword: str, limit: int = 10) -> list:
    """Search businessProfile by name (case-insensitive prefix match)."""
    safe_kw = keyword.replace("\\", "\\\\").replace("'", "\\'").replace('"', '\\"')
    result = await _mongosh_json(
        f'JSON.stringify(db.businessProfile.find('
        f'{{"businessName": {{$regex: "^{safe_kw}", $options: "i"}}}}'
        f', {{businessName: 1, businessCity: 1}})'
        f'.limit({limit}).toArray().map(function(b){{ return {{businessId: b._id, businessName: b.businessName, businessCity: b.businessCity}}; }}))',
        uri=APP_URI,
    )
    return result if isinstance(result, list) else []

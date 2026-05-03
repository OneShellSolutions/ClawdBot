"""MongoDB access via kubectl exec mongosh."""
from __future__ import annotations

import asyncio
import json
import logging
import time

from devops import k8s_client

logger = logging.getLogger(__name__)

MONGOS_POD = "prod-cluster-mongos-0"
MONGO_NS = "mongodb"
ADMIN_URI = "mongodb://clusterAdmin:tb3GSgY6U5ZSc7CNsvf6@localhost:27017/admin?authSource=admin"
APP_URI = "mongodb://databaseAdmin:akyFqNelEclMhlkNx06c@localhost:27017/oneshell?authSource=admin"

# In-process cache for businessProfile (1.7K docs, full collection fits trivially)
_BUSINESS_CACHE_TTL = 60  # seconds — short TTL so newly created businesses appear quickly
_business_cache: list[dict] | None = None
_business_cache_ts: float = 0.0
_business_cache_lock = asyncio.Lock()
_business_cache_refresh_task: asyncio.Task | None = None


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


async def _load_business_cache() -> list[dict]:
    """Pull all businessProfile rows in one mongosh call."""
    result = await _mongosh_json(
        'JSON.stringify(db.businessProfile.find({}, {businessName: 1, businessCity: 1})'
        '.toArray().map(function(b){ return {businessId: b._id, businessName: b.businessName || "", businessCity: b.businessCity || ""}; }))',
        uri=APP_URI,
    )
    if not isinstance(result, list):
        return []
    # Pre-compute lowercase form for fast filtering
    for b in result:
        b["_nameLower"] = (b.get("businessName") or "").lower()
    return result


async def _ensure_business_cache(force: bool = False) -> list[dict]:
    global _business_cache, _business_cache_ts, _business_cache_refresh_task
    now = time.monotonic()
    fresh = _business_cache is not None and (now - _business_cache_ts) < _BUSINESS_CACHE_TTL
    if fresh and not force:
        return _business_cache  # type: ignore[return-value]

    if _business_cache is not None and not force:
        # Stale-while-revalidate: serve current cache, refresh in background once
        if _business_cache_refresh_task is None or _business_cache_refresh_task.done():
            _business_cache_refresh_task = asyncio.create_task(_refresh_business_cache())
        return _business_cache

    # Cold path: nothing cached yet, must wait
    async with _business_cache_lock:
        if _business_cache is not None and (time.monotonic() - _business_cache_ts) < _BUSINESS_CACHE_TTL and not force:
            return _business_cache
        try:
            data = await _load_business_cache()
            if data:
                _business_cache = data
                _business_cache_ts = time.monotonic()
        except Exception as e:
            logger.error("businessProfile cache load failed: %s", e)
        return _business_cache or []


async def _refresh_business_cache() -> None:
    global _business_cache, _business_cache_ts
    async with _business_cache_lock:
        try:
            data = await _load_business_cache()
            if data:
                _business_cache = data
                _business_cache_ts = time.monotonic()
        except Exception as e:
            logger.error("businessProfile cache refresh failed: %s", e)


def _filter_cache(cache: list[dict], kw: str, limit: int) -> list[dict]:
    matches: list[dict] = []
    for b in cache:
        if kw in b["_nameLower"]:
            matches.append({"businessId": b["businessId"], "businessName": b["businessName"], "businessCity": b["businessCity"]})
            if len(matches) >= limit:
                break
    return matches


async def search_businesses(keyword: str, limit: int = 10) -> list:
    """Search businessProfile by name (case-insensitive substring match) using in-memory cache."""
    kw = (keyword or "").strip().lower()
    if not kw:
        return []
    cache = await _ensure_business_cache()
    matches = _filter_cache(cache, kw, limit)
    # Zero-hit fallback: a brand-new business may not be in the cached snapshot yet.
    # Force a refresh and re-filter once before giving up.
    if not matches:
        await _refresh_business_cache()
        if _business_cache:
            matches = _filter_cache(_business_cache, kw, limit)
    return matches


async def invalidate_business_cache() -> None:
    """Force the next search to refresh the cache."""
    global _business_cache_ts
    _business_cache_ts = 0.0

"""Background monitors for K8s, services, MongoDB, NATS, logs, and issues."""
from __future__ import annotations

import asyncio
import logging
import time
from abc import ABC, abstractmethod
from datetime import datetime

import json

from devops import k8s_client, mongodb_client, nats_client
from devops.models import (
    ClusterOverview, HealthStatus, ServiceHealth, MongoHealth,
    ConnectionInfo, NatsHealth, StreamInfo, ConsumerInfo, AnalysisResult,
    KafkaConsumerLagHealth, KafkaConsumerGroup,
)
from devops.event_bus import event_bus
from devops.topology import SERVICE_TOPOLOGY
from devops.patterns import scan_logs, determine_root_cause

logger = logging.getLogger(__name__)

MONITORED_NAMESPACES = ["default", "pos", "mongodb", "kafka", "cert-manager"]

# Thresholds
POD_RESTART_THRESHOLD = 5
MONGODB_CONNECTION_WARNING = 400
MONGODB_CONNECTION_CRITICAL = 800
NATS_CONSUMER_LAG_THRESHOLD = 500
KAFKA_CONSUMER_LAG_THRESHOLD = 100

# External service URLs (not in-cluster, checked via HTTPS)
EXTERNAL_SERVICE_URLS = {
    "harbor": "https://docker.oneshell.in/api/v2.0/health",
}


class BaseMonitor(ABC):
    def __init__(self, name: str):
        self.name = name
        self.last_check: datetime | None = None
        self.last_error: str | None = None

    @abstractmethod
    async def check(self) -> dict:
        pass

    async def safe_check(self) -> dict:
        try:
            result = await self.check()
            self.last_check = datetime.utcnow()
            self.last_error = None
            return result
        except Exception as e:
            self.last_error = str(e)
            logger.exception(f"Monitor {self.name} check failed")
            return {"status": "error", "error": str(e)}


class KubernetesMonitor(BaseMonitor):
    def __init__(self):
        super().__init__("kubernetes")
        self.cluster_overview = ClusterOverview()

    async def check(self) -> dict:
        nodes = await k8s_client.get_nodes()
        all_pods = []
        all_events = []

        for ns in MONITORED_NAMESPACES:
            pods = await k8s_client.list_pods(ns)
            events = await k8s_client.get_events(ns, limit=30)
            all_pods.extend(pods)
            all_events.extend(events)

        running = sum(1 for p in all_pods if p["status"] == "Running" and p["ready"])
        failed = sum(1 for p in all_pods if p["status"] in ("Failed", "CrashLoopBackOff", "Error"))
        warning_events = len(all_events)

        self.cluster_overview = ClusterOverview(
            nodes=[{
                "name": n["name"],
                "status": HealthStatus.HEALTHY if n["ready"] else HealthStatus.CRITICAL,
                "cpu_capacity": n["cpu_capacity"],
                "memory_capacity": n["memory_capacity"],
            } for n in nodes],
            total_pods=len(all_pods),
            running_pods=running,
            failed_pods=failed,
            warning_events=warning_events,
            namespaces=MONITORED_NAMESPACES,
        )

        for pod in all_pods:
            if pod["restarts"] >= POD_RESTART_THRESHOLD:
                event_bus.emit_nowait("pod_crash_loop", pod=pod)

        return {
            "status": "ok",
            "nodes": len(nodes),
            "pods": len(all_pods),
            "running": running,
            "failed": failed,
            "warning_events": warning_events,
        }


class ServiceHealthMonitor(BaseMonitor):
    def __init__(self):
        super().__init__("service_health")
        self.services: dict[str, ServiceHealth] = {}

    async def check(self) -> dict:
        tasks = [self._check_service(name, info) for name, info in SERVICE_TOPOLOGY.items()]
        results = await asyncio.gather(*tasks, return_exceptions=True)

        healthy = degraded = critical = unknown = 0
        for result in results:
            if isinstance(result, Exception):
                unknown += 1
                continue
            match result.status:
                case HealthStatus.HEALTHY:
                    healthy += 1
                case HealthStatus.DEGRADED:
                    degraded += 1
                case HealthStatus.CRITICAL:
                    critical += 1
                    event_bus.emit_nowait("service_critical", service=result.name)
                case _:
                    unknown += 1

        return {"status": "ok", "healthy": healthy, "degraded": degraded, "critical": critical, "unknown": unknown}

    async def _check_service(self, name: str, info) -> ServiceHealth:
        health = ServiceHealth(name=name, namespace=info.namespace)
        svc_name = name.lower()
        start = time.time()
        try:
            # External services (e.g. Harbor) - check via curl from exec pod using external URL
            if info.namespace == "external":
                raw = await self._check_external_service(name, info)
            else:
                # In-cluster services - use kubectl exec curl
                exec_info = await self._get_exec_pod()
                if not exec_info:
                    health.status = HealthStatus.CRITICAL
                    health.error = "No exec pod available"
                    self.services[name] = health
                    return health
                exec_pod, exec_ns = exec_info
                raw = await k8s_client.exec_in_pod(
                    exec_pod, exec_ns,
                    ["curl", "-s", "--max-time", "5",
                     f"http://{svc_name}.{info.namespace}.svc:{info.port}{info.health_path}"],
                    timeout=10,
                )
            health.response_time_ms = round((time.time() - start) * 1000, 1)
            if not raw:
                health.status = HealthStatus.DEGRADED
                health.error = "Empty response"
            else:
                # Parse actuator/health JSON to detect DOWN status
                health.status = self._parse_health_response(raw)
                if health.status in (HealthStatus.CRITICAL, HealthStatus.DEGRADED):
                    health.error = self._extract_health_error(raw)
        except Exception as e:
            health.status = HealthStatus.CRITICAL
            health.error = f"Connection failed: {str(e)[:100]}"
            health.response_time_ms = round((time.time() - start) * 1000, 1)

        self.services[name] = health
        return health

    async def _check_external_service(self, name: str, info) -> str:
        """Check external services via curl from an exec pod."""
        urls = EXTERNAL_SERVICE_URLS.get(name)
        if not urls:
            return ""
        exec_info = await self._get_exec_pod()
        if not exec_info:
            return ""
        exec_pod, exec_ns = exec_info
        return await k8s_client.exec_in_pod(
            exec_pod, exec_ns,
            ["curl", "-sk", "--max-time", "8", urls],
            timeout=15,
        )

    @staticmethod
    def _parse_health_response(raw: str) -> HealthStatus:
        """Parse health response body. Handles Spring Boot actuator and Harbor health formats."""
        try:
            data = json.loads(raw)
            status = data.get("status", "").upper()

            # Spring Boot actuator format: {"status": "UP/DOWN", "components": {...}}
            if status in ("DOWN", "OUT_OF_SERVICE"):
                return HealthStatus.CRITICAL
            if status == "UP":
                components = data.get("components", {})
                for comp_name, comp in components.items():
                    if isinstance(comp, dict) and comp.get("status", "").upper() in ("DOWN", "OUT_OF_SERVICE"):
                        return HealthStatus.DEGRADED
                return HealthStatus.HEALTHY

            # Harbor format: {"status": "healthy", "components": [{"name": "...", "status": "healthy"}]}
            if status == "HEALTHY":
                return HealthStatus.HEALTHY
            components = data.get("components", [])
            if isinstance(components, list) and components:
                unhealthy = [c for c in components if isinstance(c, dict) and c.get("status", "").lower() != "healthy"]
                if unhealthy:
                    return HealthStatus.DEGRADED
                return HealthStatus.HEALTHY
        except (json.JSONDecodeError, AttributeError):
            pass
        # Non-JSON response (e.g. plain text from nginx / frontend) — treat any response as healthy
        return HealthStatus.HEALTHY

    @staticmethod
    def _extract_health_error(raw: str) -> str:
        """Extract error details from a health response for logging."""
        try:
            data = json.loads(raw)
            components = data.get("components", {})
            if isinstance(components, dict):
                down = [k for k, v in components.items()
                        if isinstance(v, dict) and v.get("status", "").upper() in ("DOWN", "OUT_OF_SERVICE")]
                if down:
                    return f"Components DOWN: {', '.join(down)}"
            if isinstance(components, list):
                unhealthy = [c.get("name", "?") for c in components
                             if isinstance(c, dict) and c.get("status", "").lower() != "healthy"]
                if unhealthy:
                    return f"Unhealthy: {', '.join(unhealthy)}"
            return f"Status: {data.get('status', 'unknown')}"
        except Exception:
            return "Health check returned non-OK"

    async def _get_exec_pod(self) -> tuple[str, str] | None:
        """Get a running pod with curl for internal HTTP calls. Returns (pod_name, namespace)."""
        pods = await k8s_client.list_pods("default")
        for p in pods:
            if p["status"] == "Running" and p["name"].startswith("nginx-6"):
                return (p["name"], "default")
        for p in pods:
            if p["status"] == "Running" and p["name"].startswith("nginx"):
                return (p["name"], "default")
        return None


class MongoDBMonitor(BaseMonitor):
    def __init__(self):
        super().__init__("mongodb")
        self.health = MongoHealth()
        self.full_health: dict = {}

    async def check(self) -> dict:
        status = await mongodb_client.get_server_status()
        if isinstance(status, dict) and "error" in status:
            self.health.status = HealthStatus.CRITICAL
            self.health.error = status["error"]
            return {"status": "error", "error": status["error"]}

        conns = status.get("connections", {})
        self.health.connections = ConnectionInfo(
            current=conns.get("current", 0),
            available=conns.get("available", 0),
            total_created=conns.get("totalCreated", 0),
            active=conns.get("active", 0),
        )
        self.health.opcounters = status.get("opcounters", {})
        self.health.uptime_seconds = int(status.get("uptime", 0) or 0)
        self.health.version = status.get("version", "")
        self.health.logical_sessions = int(status.get("activeSessionsCount", 0))

        current = self.health.connections.current
        if current >= MONGODB_CONNECTION_CRITICAL:
            self.health.status = HealthStatus.CRITICAL
            event_bus.emit_nowait("mongodb_connection_critical", connections=current)
        elif current >= MONGODB_CONNECTION_WARNING:
            self.health.status = HealthStatus.DEGRADED
        else:
            self.health.status = HealthStatus.HEALTHY

        self.health.error = None
        self.full_health = {
            "connections": conns,
            "opcounters": self.health.opcounters,
            "mem": status.get("mem", {}),
            "host": status.get("host", ""),
        }

        return {
            "status": self.health.status.value,
            "connections": current,
            "available": self.health.connections.available,
            "active": self.health.connections.active,
            "sessions": self.health.logical_sessions,
        }


class NATSMonitor(BaseMonitor):
    def __init__(self):
        super().__init__("nats")
        self.health = NatsHealth()

    async def check(self) -> dict:
        varz = await nats_client.get_varz()
        if "error" in varz:
            self.health.status = HealthStatus.CRITICAL
            self.health.error = varz["error"]
            return {"status": "error", "error": varz["error"]}

        self.health.server_id = varz.get("server_id", "")
        self.health.version = varz.get("version", "")
        self.health.connections = varz.get("connections", 0)
        self.health.subscriptions = varz.get("subscriptions", 0)
        self.health.in_msgs = varz.get("in_msgs", 0)
        self.health.out_msgs = varz.get("out_msgs", 0)

        streams_data = await nats_client.get_all_streams()
        consumers_data = await nats_client.get_all_consumers()

        self.health.streams = [StreamInfo(**s) for s in streams_data]
        self.health.consumers = [ConsumerInfo(**c) for c in consumers_data]

        dlq_msgs = 0
        for s in streams_data:
            if "dlq" in s.get("name", "").lower():
                dlq_msgs += s.get("messages", 0)
        self.health.dlq_messages = dlq_msgs

        for consumer in consumers_data:
            pending = consumer.get("num_pending", 0)
            if pending > NATS_CONSUMER_LAG_THRESHOLD:
                event_bus.emit_nowait(
                    "nats_consumer_lag",
                    consumer=consumer["name"],
                    stream=consumer["stream"],
                    pending=pending,
                )

        self.health.status = HealthStatus.HEALTHY
        self.health.error = None
        return {
            "status": "ok",
            "connections": self.health.connections,
            "streams": len(streams_data),
            "consumers": len(consumers_data),
            "dlq_messages": dlq_msgs,
        }


KAFKA_CONSUMER_GROUPS = [
    "mongo-event-listener",
    "mongo-event-listener-sync-rules",
]


class KafkaConsumerLagMonitor(BaseMonitor):
    """Monitors Kafka (Redpanda) consumer group lag via rpk group describe."""

    def __init__(self):
        super().__init__("kafka_consumer_lag")
        self.health = KafkaConsumerLagHealth()

    async def check(self) -> dict:
        groups = []
        total_lag = 0

        for group_name in KAFKA_CONSUMER_GROUPS:
            group_data = await self._describe_group(group_name)
            groups.append(group_data)
            total_lag += group_data.total_lag

            if group_data.total_lag > KAFKA_CONSUMER_LAG_THRESHOLD:
                event_bus.emit_nowait(
                    "kafka_consumer_lag",
                    consumer_group=group_name,
                    lag=group_data.total_lag,
                    state=group_data.state,
                )

        self.health.consumer_groups = groups
        self.health.total_lag = total_lag
        self.health.status = (
            HealthStatus.CRITICAL if total_lag > KAFKA_CONSUMER_LAG_THRESHOLD * 5
            else HealthStatus.DEGRADED if total_lag > KAFKA_CONSUMER_LAG_THRESHOLD
            else HealthStatus.HEALTHY
        )
        self.health.error = None
        self.health.last_checked = datetime.utcnow()

        return {
            "status": self.health.status.value,
            "total_lag": total_lag,
            "groups": len(groups),
        }

    async def _describe_group(self, group_name: str) -> KafkaConsumerGroup:
        """Parse rpk group describe text output.

        Format:
            GROUP        <name>
            COORDINATOR  0
            STATE        Stable
            TOTAL-LAG    123

            TOPIC          PARTITION  CURRENT-OFFSET  LOG-START-OFFSET  LOG-END-OFFSET  LAG  ...
            topic.name     0          100             0                 110             10   ...
        """
        try:
            raw = await k8s_client.exec_in_pod(
                "redpanda-0", "kafka",
                ["rpk", "group", "describe", group_name],
                timeout=10,
            )
            if not raw:
                return KafkaConsumerGroup(group=group_name, state="UNKNOWN", total_lag=0)

            state = "UNKNOWN"
            total_lag = 0
            topics = []
            in_table = False

            for line in raw.strip().splitlines():
                line = line.strip()
                if not line:
                    continue

                if line.startswith("STATE"):
                    state = line.split(None, 1)[1].strip() if len(line.split(None, 1)) > 1 else "UNKNOWN"
                elif line.startswith("TOTAL-LAG"):
                    try:
                        total_lag = int(line.split(None, 1)[1].strip())
                    except (ValueError, IndexError):
                        pass
                elif line.startswith("TOPIC") and "PARTITION" in line:
                    in_table = True
                    continue
                elif in_table:
                    parts = line.split()
                    if len(parts) >= 6:
                        try:
                            topic_name = parts[0]
                            partition = int(parts[1])
                            current_offset = int(parts[2])
                            log_end_offset = int(parts[4])
                            lag = int(parts[5])
                            if lag > 0:
                                topics.append({
                                    "topic": topic_name,
                                    "partition": partition,
                                    "lag": lag,
                                    "current_offset": current_offset,
                                    "log_end_offset": log_end_offset,
                                })
                        except (ValueError, IndexError):
                            pass

            return KafkaConsumerGroup(
                group=group_name,
                state=state,
                total_lag=total_lag,
                topics=topics,
            )
        except Exception as e:
            logger.warning(f"Failed to describe Kafka consumer group {group_name}: {e}")
            return KafkaConsumerGroup(group=group_name, state="ERROR", total_lag=0)


AUTO_SCAN_SERVICES = {
    "posserverbackend": {"ns": "default", "tail": 500},
    "posclientbackend": {"ns": "pos", "tail": 300},
    "mongodbservice": {"ns": "default", "tail": 300},
    "gatewayservice": {"ns": "default", "tail": 200},
    "posservice": {"ns": "default", "tail": 200},
    "scheduler": {"ns": "default", "tail": 200},
    "quartzscheduler": {"ns": "default", "tail": 200},
}


class LogAnalyzerMonitor(BaseMonitor):
    def __init__(self):
        super().__init__("log_analyzer")
        self.latest_results: dict[str, AnalysisResult] = {}

    async def check(self) -> dict:
        total_issues = 0
        for service, cfg in AUTO_SCAN_SERVICES.items():
            result = await self.analyze_service(service, cfg["ns"], cfg["tail"])
            if result.matches:
                total_issues += len(result.matches)
        return {"status": "ok", "services_scanned": len(AUTO_SCAN_SERVICES), "issues_found": total_issues}

    async def analyze_service(self, service: str, namespace: str, tail: int = 200) -> AnalysisResult:
        start = time.time()
        logs = await k8s_client.get_deployment_logs(service, namespace, tail)
        matches = scan_logs(logs, service)
        duration_ms = int((time.time() - start) * 1000)

        result = AnalysisResult(
            service=service,
            total_lines=len(logs.splitlines()),
            matches=matches,
            duration_ms=duration_ms,
        )

        if matches:
            result.root_cause = determine_root_cause(matches)
            result.recommended_actions = list({m.recommendation for m in matches if m.recommendation})
            result.summary = f"Found {len(matches)} issues in {service}: " + ", ".join(sorted({m.category for m in matches}))
        else:
            result.summary = f"No issues found in {service}"

        self.latest_results[service] = result
        return result


CRITICAL_DEPLOYMENTS = {
    "default": [
        "mongodbservice", "posserverbackend", "gatewayservice", "businessservice",
        "posservice", "scheduler", "quartzscheduler", "emailservice",
        "notificationservice", "whatsappapiservice", "gstapiservice",
        "posdatasyncservice",
    ],
    "pos": ["posclientbackend", "pospythonbackend"],
}

SCAN_NAMESPACES = ["default", "pos"]


class IssueFinder(BaseMonitor):
    def __init__(self):
        super().__init__("issue_finder")
        self.current_issues: list[dict] = []
        self.last_scan_result: dict | None = None

    async def check(self) -> dict:
        self.current_issues = []
        for ns in SCAN_NAMESPACES:
            await self._scan_namespace(ns)

        self.last_scan_result = {
            "timestamp": datetime.utcnow().isoformat(),
            "total_issues": len(self.current_issues),
            "critical": sum(1 for i in self.current_issues if i["severity"] == "critical"),
            "warning": sum(1 for i in self.current_issues if i["severity"] == "warning"),
            "issues": self.current_issues,
        }
        return {"status": "ok", "issues": len(self.current_issues)}

    async def _scan_namespace(self, namespace: str):
        pods = await k8s_client.list_pods(namespace)
        for pod in pods:
            if pod["status"] in ("CrashLoopBackOff", "Error", "Failed", "ImagePullBackOff"):
                self.current_issues.append({
                    "type": "pod_unhealthy",
                    "severity": "critical",
                    "namespace": namespace,
                    "resource": pod["name"],
                    "detail": f"Pod {pod['name']} in {pod['status']} (restarts: {pod['restarts']})",
                })
            elif not pod["ready"] and pod["status"] == "Running":
                self.current_issues.append({
                    "type": "pod_not_ready",
                    "severity": "warning",
                    "namespace": namespace,
                    "resource": pod["name"],
                    "detail": f"Pod {pod['name']} running but not ready",
                })
            elif pod["restarts"] > 10:
                self.current_issues.append({
                    "type": "high_restarts",
                    "severity": "warning",
                    "namespace": namespace,
                    "resource": pod["name"],
                    "detail": f"Pod {pod['name']} has {pod['restarts']} restarts",
                })

        deployments = await k8s_client.list_deployments(namespace)
        for dep in deployments:
            desired = dep.get("replicas", 0)
            ready = dep.get("ready_replicas", 0)
            if desired > 0 and ready < desired:
                self.current_issues.append({
                    "type": "deployment_degraded",
                    "severity": "critical" if ready == 0 else "warning",
                    "namespace": namespace,
                    "resource": dep["name"],
                    "detail": f"Deployment {dep['name']}: {ready}/{desired} replicas ready",
                })

        events = await k8s_client.get_events(namespace, limit=50)
        reasons: dict[str, list] = {}
        for ev in events:
            key = f"{ev.get('reason', 'Unknown')}:{ev.get('object', '')}"
            reasons.setdefault(key, []).append(ev)

        for key, evts in reasons.items():
            count = sum(e.get("count", 1) for e in evts)
            if count >= 3:
                self.current_issues.append({
                    "type": "k8s_warning",
                    "severity": "warning",
                    "namespace": namespace,
                    "resource": evts[0].get("object", ""),
                    "detail": f"{evts[0].get('reason', '')}: {evts[0].get('message', '')[:200]} (x{count})",
                })

        for dep_name in CRITICAL_DEPLOYMENTS.get(namespace, []):
            try:
                logs = await k8s_client.get_deployment_logs(dep_name, namespace, 100)
                if not logs or "Error fetching" in logs or "No pods found" in logs:
                    continue
                matches = scan_logs(logs, dep_name)
                critical_matches = [m for m in matches if m.severity.value == "critical"]
                if critical_matches:
                    self.current_issues.append({
                        "type": "log_errors",
                        "severity": "critical",
                        "namespace": namespace,
                        "resource": dep_name,
                        "detail": f"{len(critical_matches)} critical log patterns: " + ", ".join(m.category for m in critical_matches[:3]),
                        "patterns": [m.model_dump() for m in critical_matches[:5]],
                    })
            except Exception:
                pass


# Singleton instances
kubernetes_monitor = KubernetesMonitor()
service_health_monitor = ServiceHealthMonitor()
mongodb_monitor = MongoDBMonitor()
nats_monitor = NATSMonitor()
kafka_consumer_lag_monitor = KafkaConsumerLagMonitor()
log_analyzer_monitor = LogAnalyzerMonitor()
issue_finder = IssueFinder()

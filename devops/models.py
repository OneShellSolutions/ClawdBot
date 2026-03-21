"""Consolidated Pydantic models for DevOps monitoring."""
from __future__ import annotations

import uuid
from enum import Enum
from datetime import datetime
from pydantic import BaseModel, Field


# --- Enums ---

class Severity(str, Enum):
    CRITICAL = "critical"
    WARNING = "warning"
    INFO = "info"


class IncidentStatus(str, Enum):
    OPEN = "open"
    INVESTIGATING = "investigating"
    MITIGATING = "mitigating"
    RESOLVED = "resolved"


class HealthStatus(str, Enum):
    HEALTHY = "healthy"
    DEGRADED = "degraded"
    CRITICAL = "critical"
    UNKNOWN = "unknown"


class ServiceTier(str, Enum):
    CRITICAL = "critical"
    IMPORTANT = "important"
    STANDARD = "standard"


class RiskLevel(str, Enum):
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"


class ActionStatus(str, Enum):
    PENDING = "pending"
    APPROVED = "approved"
    EXECUTING = "executing"
    COMPLETED = "completed"
    FAILED = "failed"
    REJECTED = "rejected"


# --- Analysis models ---

class PatternMatch(BaseModel):
    pattern_name: str
    category: str
    severity: Severity
    description: str
    matched_line: str
    service: str = ""
    recommendation: str = ""


class AnalysisResult(BaseModel):
    service: str
    total_lines: int = 0
    matches: list[PatternMatch] = Field(default_factory=list)
    summary: str = ""
    root_cause: str | None = None
    recommended_actions: list[str] = Field(default_factory=list)
    ai_analysis: str | None = None
    duration_ms: int = 0
    analyzed_at: datetime = Field(default_factory=datetime.utcnow)


class CorrelationResult(BaseModel):
    correlated_services: list[str] = Field(default_factory=list)
    root_cause_service: str | None = None
    cascade_chain: list[str] = Field(default_factory=list)
    summary: str = ""
    confidence: float = 0.0


# --- Service models ---

class ServiceInfo(BaseModel):
    name: str
    namespace: str
    port: int
    tier: ServiceTier = ServiceTier.STANDARD
    replicas: int = 1
    dependencies: list[str] = Field(default_factory=list)
    health_path: str = "/actuator/health"


class ServiceHealth(BaseModel):
    name: str
    namespace: str
    status: HealthStatus = HealthStatus.UNKNOWN
    response_time_ms: float | None = None
    error: str | None = None
    pod_count: int = 0
    ready_pods: int = 0
    restarts: int = 0
    cpu_usage: str | None = None
    memory_usage: str | None = None
    last_checked: datetime = Field(default_factory=datetime.utcnow)


class ServiceTopology(BaseModel):
    services: list[ServiceInfo] = Field(default_factory=list)
    edges: list[dict] = Field(default_factory=list)


# --- Kubernetes models ---

class ClusterOverview(BaseModel):
    nodes: list[dict] = Field(default_factory=list)
    total_pods: int = 0
    running_pods: int = 0
    failed_pods: int = 0
    warning_events: int = 0
    namespaces: list[str] = Field(default_factory=list)


# --- MongoDB models ---

class ConnectionInfo(BaseModel):
    current: int = 0
    available: int = 0
    total_created: int = 0
    active: int = 0


class MongoHealth(BaseModel):
    status: HealthStatus = HealthStatus.UNKNOWN
    connections: ConnectionInfo = Field(default_factory=ConnectionInfo)
    logical_sessions: int = 0
    opcounters: dict = Field(default_factory=dict)
    replication_lag_seconds: float = 0.0
    uptime_seconds: int = 0
    version: str = ""
    error: str | None = None
    last_checked: datetime = Field(default_factory=datetime.utcnow)


# --- NATS models ---

class StreamInfo(BaseModel):
    name: str
    subjects: list[str] = Field(default_factory=list)
    messages: int = 0
    bytes: int = 0
    consumer_count: int = 0


class ConsumerInfo(BaseModel):
    name: str
    stream: str
    num_pending: int = 0
    num_ack_pending: int = 0
    num_redelivered: int = 0


class KafkaConsumerGroup(BaseModel):
    group: str
    state: str = ""
    total_lag: int = 0
    topics: list[dict] = Field(default_factory=list)


class KafkaConsumerLagHealth(BaseModel):
    status: HealthStatus = HealthStatus.UNKNOWN
    consumer_groups: list[KafkaConsumerGroup] = Field(default_factory=list)
    total_lag: int = 0
    error: str | None = None
    last_checked: datetime = Field(default_factory=datetime.utcnow)


class NatsHealth(BaseModel):
    status: HealthStatus = HealthStatus.UNKNOWN
    server_id: str = ""
    version: str = ""
    connections: int = 0
    subscriptions: int = 0
    in_msgs: int = 0
    out_msgs: int = 0
    in_bytes: int = 0
    out_bytes: int = 0
    streams: list[StreamInfo] = Field(default_factory=list)
    consumers: list[ConsumerInfo] = Field(default_factory=list)
    dlq_messages: int = 0
    error: str | None = None
    last_checked: datetime = Field(default_factory=datetime.utcnow)


# --- Incident models ---

class IncidentEvent(BaseModel):
    timestamp: datetime = Field(default_factory=datetime.utcnow)
    type: str
    message: str
    data: dict | None = None


class Incident(BaseModel):
    id: str = Field(default_factory=lambda: str(uuid.uuid4())[:8])
    title: str
    description: str = ""
    severity: Severity = Severity.WARNING
    status: IncidentStatus = IncidentStatus.OPEN
    affected_services: list[str] = Field(default_factory=list)
    root_cause: str | None = None
    events: list[IncidentEvent] = Field(default_factory=list)
    actions_taken: list[str] = Field(default_factory=list)
    detected_at: datetime = Field(default_factory=datetime.utcnow)
    resolved_at: datetime | None = None
    postmortem: str | None = None

    def add_event(self, type: str, message: str, data: dict | None = None):
        self.events.append(IncidentEvent(type=type, message=message, data=data))

    def resolve(self, message: str = ""):
        self.status = IncidentStatus.RESOLVED
        self.resolved_at = datetime.utcnow()
        self.add_event("resolved", message or "Incident resolved")


# --- Remediation models ---

class RemediationAction(BaseModel):
    name: str
    description: str
    command: str = ""
    risk_level: RiskLevel = RiskLevel.LOW
    status: ActionStatus = ActionStatus.PENDING
    dry_run: bool = True
    result: str | None = None
    error: str | None = None
    executed_at: datetime | None = None
    duration_ms: int = 0


class Playbook(BaseModel):
    name: str
    description: str
    trigger_pattern: str
    severity: str = "warning"
    actions: list[RemediationAction] = Field(default_factory=list)
    requires_approval: bool = True
    cooldown_minutes: int = 30
    last_executed: datetime | None = None

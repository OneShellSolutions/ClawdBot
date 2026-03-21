"""APScheduler setup for background monitoring jobs."""
from __future__ import annotations

import logging
from apscheduler.schedulers.asyncio import AsyncIOScheduler

from devops.monitors import (
    kubernetes_monitor,
    service_health_monitor,
    mongodb_monitor,
    nats_monitor,
    kafka_consumer_lag_monitor,
    log_analyzer_monitor,
    issue_finder,
)

logger = logging.getLogger(__name__)

scheduler = AsyncIOScheduler()


def setup_scheduler():
    """Configure and start all monitoring jobs."""
    scheduler.add_job(
        kubernetes_monitor.safe_check,
        "interval", seconds=60, id="kubernetes_monitor",
        max_instances=1, replace_existing=True,
    )
    scheduler.add_job(
        service_health_monitor.safe_check,
        "interval", seconds=60, id="service_health_monitor",
        max_instances=1, replace_existing=True,
    )
    scheduler.add_job(
        mongodb_monitor.safe_check,
        "interval", seconds=120, id="mongodb_monitor",
        max_instances=1, replace_existing=True,
    )
    scheduler.add_job(
        nats_monitor.safe_check,
        "interval", seconds=60, id="nats_monitor",
        max_instances=1, replace_existing=True,
    )
    scheduler.add_job(
        kafka_consumer_lag_monitor.safe_check,
        "interval", seconds=60, id="kafka_consumer_lag_monitor",
        max_instances=1, replace_existing=True,
    )
    scheduler.add_job(
        log_analyzer_monitor.safe_check,
        "interval", seconds=300, id="log_analyzer_monitor",
        max_instances=1, replace_existing=True,
    )
    scheduler.add_job(
        issue_finder.safe_check,
        "interval", seconds=300, id="issue_finder",
        max_instances=1, replace_existing=True,
    )

    scheduler.start()
    logger.info("DevOps scheduler started with 7 monitors")


def stop_scheduler():
    if scheduler.running:
        scheduler.shutdown(wait=False)
        logger.info("DevOps scheduler stopped")

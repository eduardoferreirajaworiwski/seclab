from __future__ import annotations

import asyncio
import logging
from collections.abc import Awaitable, Callable
from dataclasses import dataclass

logger = logging.getLogger("seclab.scheduler")


@dataclass
class ScheduledJob:
    name: str
    func: Callable[[], Awaitable[None]]
    interval_seconds: float


class Scheduler:
    """Lightweight in-process asyncio scheduler.

    Deliberately not Celery/APScheduler: this is a personal lab, and periodic
    jobs (e.g. the CT-stream monitor's housekeeping, paste/leak polling) don't
    need a distributed task queue. Long-running listeners (like a WebSocket
    feed) should run as their own asyncio task via `run_background` instead
    of being modeled as a fixed-interval job.
    """

    def __init__(self) -> None:
        self._jobs: list[ScheduledJob] = []
        self._tasks: list[asyncio.Task] = []
        self._background_factories: list[Callable[[], Awaitable[None]]] = []

    def every(
        self, interval_seconds: float, name: str
    ) -> Callable[[Callable[[], Awaitable[None]]], Callable[[], Awaitable[None]]]:
        def decorator(func: Callable[[], Awaitable[None]]) -> Callable[[], Awaitable[None]]:
            self._jobs.append(ScheduledJob(name=name, func=func, interval_seconds=interval_seconds))
            return func

        return decorator

    def run_background(self, factory: Callable[[], Awaitable[None]]) -> None:
        """Register a long-running coroutine (e.g. a WebSocket listener) to be
        started alongside the periodic jobs."""
        self._background_factories.append(factory)

    async def _run_job_forever(self, job: ScheduledJob) -> None:
        while True:
            try:
                await job.func()
            except Exception:
                logger.exception("scheduled_job_failed", extra={"job": job.name})
            await asyncio.sleep(job.interval_seconds)

    async def start(self) -> None:
        for job in self._jobs:
            self._tasks.append(
                asyncio.create_task(self._run_job_forever(job), name=f"job:{job.name}")
            )
        for factory in self._background_factories:
            self._tasks.append(asyncio.create_task(factory(), name="background"))

    async def stop(self) -> None:
        for task in self._tasks:
            task.cancel()
        for task in self._tasks:
            try:
                await task
            except (asyncio.CancelledError, Exception):
                logger.debug("scheduler_task_stopped", extra={"task": task.get_name()})
        self._tasks.clear()


_scheduler: Scheduler | None = None


def get_scheduler() -> Scheduler:
    global _scheduler
    if _scheduler is None:
        _scheduler = Scheduler()
    return _scheduler

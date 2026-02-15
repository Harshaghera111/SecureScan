"""
SecureScan Backend — Celery Application
Async task queue for background scan processing
"""

from celery import Celery

from app.config import get_settings

settings = get_settings()

celery_app = Celery(
    "securescan",
    broker=settings.REDIS_URL,
    backend=settings.REDIS_URL,
)

celery_app.conf.update(
    task_serializer="json",
    accept_content=["json"],
    result_serializer="json",
    timezone="UTC",
    enable_utc=True,
    task_track_started=True,
    task_acks_late=True,
    worker_prefetch_multiplier=1,
)


@celery_app.task(name="run_scan_async", bind=True, max_retries=3)
def run_scan_async(self, scan_id: str, scan_type: str, content: str, language: str = None):
    """
    Background task to run a security scan.
    Updates the Scan record in the database when complete.
    """
    import asyncio
    from app.services.scan_service import run_scan

    try:
        # Run the async scan in a sync context
        loop = asyncio.new_event_loop()
        asyncio.set_event_loop(loop)
        result = loop.run_until_complete(run_scan(scan_type, content, language))
        loop.close()

        # TODO: Update the database record with the result
        # This will be implemented when we add full async DB support to workers

        return {
            "scan_id": scan_id,
            "status": "completed",
            "score": result.get("score"),
            "issues_count": len(result.get("issues", [])),
        }
    except Exception as exc:
        self.retry(exc=exc, countdown=60)

import asyncio
from contextlib import asynccontextmanager
from fastapi import FastAPI, WebSocket, WebSocketDisconnect
from fastapi.middleware.cors import CORSMiddleware
import structlog

from app.config import get_settings
from app.database import init_db
from app.api import api_router
from app.websocket.manager import manager
from app.detection.anomaly_detector import get_detector

logger = structlog.get_logger(__name__)
settings = get_settings()

# ── Live event streamer ────────────────────────────────────────────────────────
_streamer_task: asyncio.Task | None = None


async def _live_event_streamer() -> None:
    """
    Push one synthetic event to connected WS clients every 5 s.
    Yields to real dataset replay when it is active.
    """
    import random
    from datetime import datetime, timezone
    from app.data.synthetic_generator import generate_event_batch
    from app.detection.threat_classifier import classify_event

    while True:
        try:
            await asyncio.sleep(5)
            if manager.connection_count == 0:
                continue

            # Skip synthetic emission while real dataset replay is running
            from app.datasets.replay import get_replayer
            if get_replayer().get_status().get("running"):
                continue

            event = random.choice(generate_event_batch(count=3, scenario_mix=True))
            classification = classify_event(event)
            await manager.broadcast_event("live_event", {
                "event": event,
                "classification": classification.to_dict(),
                "timestamp": datetime.now(timezone.utc).isoformat(),
            })
        except asyncio.CancelledError:
            break
        except Exception as exc:
            logger.warning("streamer_error", error=str(exc))


# ── Lifespan ──────────────────────────────────────────────────────────────────

@asynccontextmanager
async def lifespan(app: FastAPI):
    global _streamer_task
    logger.info("threatvision_startup", version=settings.version)

    await init_db()
    logger.info("database_initialized")

    get_detector()
    logger.info("anomaly_detector_ready")

    # Start ingestion pipeline
    from app.ingestion.pipeline import get_pipeline
    pipeline = get_pipeline()
    await pipeline.start()
    logger.info("ingestion_pipeline_started")

    # Start SLA monitor (Phase 5)
    from app.services.sla_monitor import sla_monitor
    await sla_monitor.start()
    logger.info("sla_monitor_started")

    _streamer_task = asyncio.create_task(_live_event_streamer())
    logger.info("live_streamer_started")

    yield

    # ── Shutdown ──────────────────────────────────────────────────────────────
    if _streamer_task:
        _streamer_task.cancel()
        try:
            await _streamer_task
        except asyncio.CancelledError:
            pass

    from app.services.sla_monitor import sla_monitor
    await sla_monitor.stop()

    await pipeline.stop()
    logger.info("threatvision_shutdown")


# ── App ───────────────────────────────────────────────────────────────────────

app = FastAPI(
    title="ThreatVision API",
    description="AI-Driven Threat Detection & Simulation Engine | Hack Malenadu '26",
    version="1.0.0",
    lifespan=lifespan,
    docs_url="/docs",
    redoc_url="/redoc",
    openapi_tags=[
        {"name": "incidents",   "description": "Security incident management — CRUD + Claude AI analysis"},
        {"name": "threats",     "description": "Threat detection, classification & event ingestion"},
        {"name": "simulation",  "description": "Red Team vs Blue Team autonomous agent simulation"},
        {"name": "playbooks",   "description": "AI-generated IR playbooks — generate, explain, execute"},
        {"name": "ingestion",   "description": "Redis-backed event ingestion pipeline"},
        {"name": "dashboard",   "description": "SOC dashboard metrics & health"},
        {"name": "alerts",      "description": "Rule-triggered alert management"},
        {"name": "analysts",    "description": "Analyst management — CRUD, workload, leaderboard"},
        {"name": "tickets",     "description": "Ticket engine — lifecycle, SLA, escalation, activities"},
        {"name": "projects",    "description": "Project management — security score, analyst assignment"},
        {"name": "audit",       "description": "Immutable hash-chained audit log — query, search, verify"},
        {"name": "datasets",    "description": "Real public dataset ML — download NSL-KDD / UNSW-NB15, train IsolationForest, benchmark accuracy"},
    ],
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=settings.cors_origins,
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Phase 6 — Audit middleware (fire-and-forget, adds zero latency to hot path)
from app.middleware.audit_middleware import AuditMiddleware
app.add_middleware(AuditMiddleware)

app.include_router(api_router)


@app.get("/health")
async def health_check():
    return {
        "status": "ok",
        "service": settings.app_name,
        "version": settings.version,
    }


@app.websocket("/ws")
async def websocket_endpoint(websocket: WebSocket):
    await manager.connect(websocket)
    try:
        while True:
            data = await websocket.receive_text()
            await manager.send_personal({"type": "ack", "data": data}, websocket)
    except WebSocketDisconnect:
        manager.disconnect(websocket)
    except Exception as exc:
        logger.warning("ws_error", error=str(exc))
        manager.disconnect(websocket)

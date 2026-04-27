from fastapi import APIRouter
from .incidents import router as incidents_router
from .alerts import router as alerts_router
from .simulation import router as simulation_router
from .threats import router as threats_router
from .playbooks import router as playbooks_router
from .dashboard import router as dashboard_router
from .ingestion import router as ingestion_router
from .analysts import router as analysts_router
from .tickets import router as tickets_router
from .projects import router as projects_router
from .audit_logs import router as audit_logs_router
from .datasets import router as datasets_router

api_router = APIRouter(prefix="/api/v1")
api_router.include_router(incidents_router, prefix="/incidents",  tags=["incidents"])
api_router.include_router(alerts_router,    prefix="/alerts",     tags=["alerts"])
api_router.include_router(simulation_router,prefix="/simulation", tags=["simulation"])
api_router.include_router(threats_router,   prefix="/threats",    tags=["threats"])
api_router.include_router(playbooks_router, prefix="/playbooks",  tags=["playbooks"])
api_router.include_router(dashboard_router, prefix="/dashboard",  tags=["dashboard"])
api_router.include_router(ingestion_router, prefix="/ingestion",  tags=["ingestion"])
# Phase 5 — Analyst System & Ticket Engine
api_router.include_router(analysts_router,  prefix="/analysts",   tags=["analysts"])
api_router.include_router(tickets_router,   prefix="/tickets",    tags=["tickets"])
api_router.include_router(projects_router,  prefix="/projects",   tags=["projects"])
# Phase 6 — Audit Logger & Log Intelligence
api_router.include_router(audit_logs_router, prefix="/audit",     tags=["audit"])
# Phase 7 — Real Dataset ML Training & Benchmarking
api_router.include_router(datasets_router,  prefix="/datasets",   tags=["datasets"])

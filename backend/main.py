"""
Wazuh AI Analyzer - Backend API
Descarga alertas de Wazuh, las procesa con Claude AI y las sirve priorizadas
"""

from fastapi import FastAPI, HTTPException, BackgroundTasks
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse
import uvicorn
import logging
from datetime import datetime

from config import settings
from wazuh_client import WazuhClient
from ai_processor import AIProcessor
from database import Database
from models import AlertFilter, SyncStatus

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

app = FastAPI(
    title="Wazuh AI Analyzer",
    description="Analiza y prioriza alertas de Wazuh usando IA",
    version="1.0.0"
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_methods=["*"],
    allow_headers=["*"],
)

db = Database()
wazuh = WazuhClient(settings)
ai = AIProcessor(settings)


@app.on_event("startup")
async def startup():
    await db.init()
    logger.info("Base de datos inicializada")


@app.get("/health")
async def health():
    return {"status": "ok", "timestamp": datetime.utcnow().isoformat()}


# ──────────────────────────────────────────────
# SINCRONIZACIÓN
# ──────────────────────────────────────────────

@app.post("/sync")
async def sync_alerts(background_tasks: BackgroundTasks):
    """Inicia descarga y procesamiento de alertas en background"""
    background_tasks.add_task(run_full_sync)
    return {"message": "Sincronización iniciada", "status": "running"}


@app.get("/sync/status", response_model=SyncStatus)
async def sync_status():
    return await db.get_sync_status()


async def run_full_sync():
    """Pipeline completo: descarga → procesa con IA → guarda"""
    try:
        await db.update_sync_status("running", "Descargando alertas de Wazuh...")
        logger.info("Iniciando sincronización con Wazuh")

        # 1. Descargar alertas desde Wazuh
        raw_alerts = await wazuh.get_alerts(limit=settings.max_alerts_per_sync)
        logger.info(f"Descargadas {len(raw_alerts)} alertas")

        if not raw_alerts:
            await db.update_sync_status("completed", "No hay alertas nuevas")
            return

        # 2. Filtrar las que no están procesadas aún
        new_alerts = await db.filter_unprocessed(raw_alerts)
        logger.info(f"{len(new_alerts)} alertas nuevas para procesar")

        # 3. Procesar con IA en lotes
        await db.update_sync_status("running", f"Procesando {len(new_alerts)} alertas con IA...")
        processed = await ai.process_batch(new_alerts)

        # 4. Guardar en BD
        await db.save_alerts(processed)
        await db.update_sync_status(
            "completed",
            f"Sincronización completa: {len(processed)} alertas procesadas",
            total=len(processed)
        )
        logger.info("Sincronización completada")

    except Exception as e:
        logger.error(f"Error en sincronización: {e}")
        await db.update_sync_status("error", str(e))


# ──────────────────────────────────────────────
# ALERTAS
# ──────────────────────────────────────────────

@app.get("/alerts")
async def list_alerts(
    severity: str = None,
    agent: str = None,
    rule_group: str = None,
    limit: int = 100,
    offset: int = 0,
    sort_by: str = "ai_priority",
):
    """Lista alertas priorizadas por IA con filtros opcionales"""
    filters = AlertFilter(
        severity=severity,
        agent=agent,
        rule_group=rule_group,
        limit=limit,
        offset=offset,
        sort_by=sort_by,
    )
    alerts = await db.get_alerts(filters)
    total = await db.count_alerts(filters)
    return {"alerts": alerts, "total": total, "offset": offset, "limit": limit}


@app.get("/alerts/{alert_id}")
async def get_alert(alert_id: str):
    """Detalle completo de una alerta con instructivo de resolución"""
    alert = await db.get_alert_by_id(alert_id)
    if not alert:
        raise HTTPException(status_code=404, detail="Alerta no encontrada")
    return alert


@app.post("/alerts/{alert_id}/reprocess")
async def reprocess_alert(alert_id: str, background_tasks: BackgroundTasks):
    """Re-procesa una alerta con IA (útil si el modelo mejoró)"""
    alert = await db.get_alert_by_id(alert_id)
    if not alert:
        raise HTTPException(status_code=404, detail="Alerta no encontrada")
    background_tasks.add_task(ai.reprocess_single, alert, db)
    return {"message": "Re-procesando alerta"}


@app.get("/alerts/summary/stats")
async def get_stats():
    """Estadísticas generales del dashboard"""
    return await db.get_dashboard_stats()


@app.get("/alerts/agents/list")
async def list_agents():
    return await db.get_unique_agents()


@app.get("/alerts/groups/list")
async def list_groups():
    return await db.get_unique_rule_groups()


if __name__ == "__main__":
    uvicorn.run("main:app", host="0.0.0.0", port=8000, reload=True)

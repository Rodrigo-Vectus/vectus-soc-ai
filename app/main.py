"""
Vectus SOC Engine — API REST pura, multi-agente (Fase 1).

Endpoints (brief §10):
  GET  /                  → info y versión
  GET  /health            → healthcheck simple
  POST /api/alert/ingest  → recibe alerta cruda de Wazuh, dispara la cadena
  GET  /api/alert/{id}    → recupera el resultado (para alertas lentas → 202)
  POST /api/rag/bulk-load → reservado (Fase 2): responde 501 con mensaje claro

Autenticación: header `X-API-Key` contra env API_KEY. Si API_KEY está
vacía, la API queda abierta (compatibilidad en red interna).

Códigos: 200 ok/done · 202 procesando · 401 sin auth · 404 id inexistente
· 422 alerta mal formada · 501 endpoint de fase futura.
"""
import asyncio
import logging
from contextlib import asynccontextmanager

from fastapi import FastAPI, Header, HTTPException, Request
from fastapi.responses import JSONResponse

from app import config, db, pipeline

logging.basicConfig(level=logging.INFO,
                    format="%(asctime)s %(name)s %(levelname)s %(message)s")
logger = logging.getLogger("vectus.api")


@asynccontextmanager
async def lifespan(_app: FastAPI):
    db.init_db()
    requeued = await pipeline.requeue_orphans()   # [F3] ninguna alerta se pierde
    logger.info("%s %s iniciado (DB: %s, huérfanas reencoladas: %d)",
                config.APP_NAME, config.APP_VERSION, config.DB_PATH, requeued)
    yield


app = FastAPI(title=config.APP_NAME, version=config.APP_VERSION,
              lifespan=lifespan, docs_url="/docs")


@app.middleware("http")
async def limit_payload_size(request: Request, call_next):
    """[F3] Endurecimiento: rechaza payloads que exceden MAX_PAYLOAD_KB."""
    length = request.headers.get("content-length")
    if length and length.isdigit() and int(length) > config.MAX_PAYLOAD_KB * 1024:
        return JSONResponse(status_code=413, content={
            "detail": f"payload excede el máximo de {config.MAX_PAYLOAD_KB} KB"})
    return await call_next(request)


def _check_auth(x_api_key: str | None) -> None:
    """API key simple. Vacía en config = abierta (red interna)."""
    if config.API_KEY and x_api_key != config.API_KEY:
        raise HTTPException(status_code=401, detail="API key inválida o ausente")


@app.get("/")
async def root():
    return {
        "name": config.APP_NAME,
        "version": config.APP_VERSION,
        "phase": "2",
        "description": "Motor de inteligencia SOC: ingesta de alertas Wazuh, "
                       "cadena de agentes, contrato JSON estandarizado.",
        "endpoints": ["/health", "/api/alert/ingest", "/api/alert/{id}",
                      "/api/rag/bulk-load"],
    }


@app.get("/health")
async def health():
    return {"status": "ok", "version": config.APP_VERSION}


@app.post("/api/alert/ingest")
async def ingest_alert(request: Request, x_api_key: str | None = Header(default=None)):
    _check_auth(x_api_key)
    try:
        raw = await request.json()
    except Exception:
        raise HTTPException(status_code=422, detail="el body no es JSON válido")
    if not isinstance(raw, dict):
        raise HTTPException(status_code=422, detail="se espera un objeto JSON (alerta de Wazuh)")
    try:
        code, body = await pipeline.ingest(raw, max_wait=config.INGEST_MAX_WAIT)
    except ValueError as exc:        # alerta mal formada (la detecta el normalizador)
        raise HTTPException(status_code=422, detail=str(exc))
    return JSONResponse(status_code=code, content=body)


@app.get("/api/alert/{alert_id}")
async def get_alert(alert_id: str, x_api_key: str | None = Header(default=None)):
    _check_auth(x_api_key)
    record = db.get_alert(alert_id)
    if record is None:
        raise HTTPException(status_code=404, detail=f"alerta '{alert_id}' inexistente")
    if record["status"] == "processing":
        # [F3] processing colgado más allá del timeout → error recuperable
        stuck = db.find_stuck_processing(config.PROCESSING_TIMEOUT_MINUTES)
        if any(s["alert_id"] == alert_id for s in stuck):
            db.mark_timed_out(alert_id)
            return JSONResponse(status_code=500, content={
                "alert_id": alert_id, "status": "error",
                "detail": "análisis excedió el timeout; recuperable con "
                          f"POST /api/alert/{alert_id}/reprocess"})
        return JSONResponse(status_code=202,
                            content={"alert_id": alert_id, "status": "processing"})
    if record["status"] == "error":
        return JSONResponse(status_code=200,
                            content={"alert_id": alert_id, "status": "error",
                                     "detail": record["result"]})
    return JSONResponse(status_code=200, content=record["result"])


@app.post("/api/rag/bulk-load")
async def rag_bulk_load(request: Request, x_api_key: str | None = Header(default=None)):
    """
    Carga masiva de histórico a la línea base (ChromaDB). Acepta un array
    JSON de alertas crudas de Wazuh, o {"alerts": [...]}. Lotes sugeridos
    de hasta 500 alertas por request.
    """
    _check_auth(x_api_key)
    from app.agents import baseline

    if not baseline.is_configured():
        return JSONResponse(
            status_code=503,
            content={"detail": "el RAG requiere OPENAI_API_KEY configurada "
                               "(embeddings de la línea base)"})
    try:
        body = await request.json()
    except Exception:
        raise HTTPException(status_code=422, detail="el body no es JSON válido")
    alerts = body.get("alerts") if isinstance(body, dict) else body
    if not isinstance(alerts, list) or not alerts:
        raise HTTPException(status_code=422,
                            detail="se espera un array de alertas o {\"alerts\": [...]}")
    if len(alerts) > 500:
        raise HTTPException(status_code=422,
                            detail="máximo 500 alertas por request; dividir en lotes")
    try:
        summary = await asyncio.to_thread(baseline.bulk_load, alerts)
    except RuntimeError as exc:
        return JSONResponse(status_code=503, content={"detail": str(exc)})
    return JSONResponse(status_code=200, content=summary)


# ============================================================================
# Fase 3 — Anti-ruido supervisado, reproceso y métricas
# ============================================================================

@app.get("/api/noise/candidates")
async def noise_candidates(x_api_key: str | None = Header(default=None)):
    """
    Firmas candidatas a supresión: tasa >= NOISE_MIN_COUNT en la ventana
    NOISE_WINDOW_HOURS, con veredictos consistentemente benignos. El motor
    SUGIERE con evidencia; la decisión de suprimir es siempre humana.
    """
    _check_auth(x_api_key)
    candidates = db.noise_candidates(config.NOISE_WINDOW_HOURS, config.NOISE_MIN_COUNT)
    return JSONResponse(status_code=200, content={
        "window_hours": config.NOISE_WINDOW_HOURS,
        "min_count": config.NOISE_MIN_COUNT,
        "candidates": candidates,
    })


@app.post("/api/noise/suppress")
async def noise_suppress(request: Request, x_api_key: str | None = Header(default=None)):
    """
    Aprueba la supresión de una firma: {"signature": "...", "approved_by":
    "...", "note": "..."}. approved_by es OBLIGATORIO: toda supresión queda
    con autoría y timestamp, y es reversible.
    """
    _check_auth(x_api_key)
    try:
        body = await request.json()
    except Exception:
        raise HTTPException(status_code=422, detail="el body no es JSON válido")
    signature = (body or {}).get("signature", "").strip()
    approved_by = (body or {}).get("approved_by", "").strip()
    note = (body or {}).get("note", "").strip()
    if not signature or not approved_by:
        raise HTTPException(status_code=422,
                            detail="se requieren 'signature' y 'approved_by'")
    try:
        record = db.add_suppression(signature, approved_by, note)
    except ValueError as exc:
        raise HTTPException(status_code=409, detail=str(exc))
    logger.info("supresión aprobada por %s para firma %s", approved_by, signature)
    return JSONResponse(status_code=201, content=record)


@app.delete("/api/noise/suppress/{supp_id}")
async def noise_unsuppress(supp_id: int, revoked_by: str = "",
                           x_api_key: str | None = Header(default=None)):
    """Revoca una supresión por id (?revoked_by=nombre). La fila queda como
    registro de auditoría; la firma vuelve al análisis normal."""
    _check_auth(x_api_key)
    if not revoked_by.strip():
        raise HTTPException(status_code=422,
                            detail="se requiere ?revoked_by= (autoría de la reversión)")
    if not db.revoke_suppression(supp_id, revoked_by.strip()):
        raise HTTPException(status_code=404,
                            detail=f"no hay supresión activa con id {supp_id}")
    return JSONResponse(status_code=200, content={"id": supp_id, "revoked": True,
                                                  "revoked_by": revoked_by.strip()})


@app.get("/api/noise/suppressions")
async def noise_suppressions(active: bool = False,
                             x_api_key: str | None = Header(default=None)):
    """Listado de supresiones (auditoría completa; ?active=true solo vigentes)."""
    _check_auth(x_api_key)
    return JSONResponse(status_code=200,
                        content={"suppressions": db.list_suppressions(active)})


@app.post("/api/alert/{alert_id}/reprocess")
async def alert_reprocess(alert_id: str, x_api_key: str | None = Header(default=None)):
    """
    Reanaliza una alerta ya conocida con las reglas/keys/línea base ACTUALES.
    El resultado anterior se archiva versionado en result_history. Responde
    el contrato puro (mismas keys que ingest) o 202 + GET.
    """
    _check_auth(x_api_key)
    code, body = await pipeline.reprocess(alert_id)
    return JSONResponse(status_code=code, content=body)


@app.get("/api/stats")
async def stats(x_api_key: str | None = Header(default=None)):
    """Métricas operativas para tablero: veredictos, fuentes, caché, supresiones."""
    _check_auth(x_api_key)
    return JSONResponse(status_code=200, content=db.stats())

"""
Pipeline — orquesta la cadena de agentes para una alerta (Fase 2).

Camino corto (regla curada final): Normalizador → Router → Reglas →
Reporter. El ruido benigno identificado con certeza se resuelve en
milisegundos sin gastar tokens ni cuota de APIs.

Camino profundo (decisión preliminar o hay observables externos):
Normalizador → Router → Reglas → Enricher (reputación) → Reglas
post-enriquecimiento → Línea base (rareza) → Correlador → Analista GPT
→ Reporter. El veredicto final lo emite el analista con el dossier
completo; sin analista configurado, vale la mejor decisión basada en
evidencia disponible (nunca se inventa certeza).

Patrón de ingesta (brief §10): POST espera hasta INGEST_MAX_WAIT; si el
análisis sigue (p.ej. rate limit de VirusTotal), 202 + GET posterior.
Degradación elegante: un error no pierde la alerta (status 'error').
"""
import asyncio
import logging

from app import config, db
from app.agents import (analyst, baseline, correlator, enricher, normalizer,
                        reporter, router, rules)

logger = logging.getLogger("vectus.pipeline")


def _process_sync(alert_id: str, raw: dict, normalized: dict) -> dict:
    """Cadena de agentes (corre en thread para no bloquear el event loop)."""
    routing = router.route(normalized)                       # Agente 2
    decision = rules.evaluate(normalized)                    # Reglas curadas
    signature_count = db.touch_signature(normalized["signature"], alert_id)

    # Bloques por defecto del camino corto (regla curada resolvió sola).
    enrichment_block = {
        "status": "skipped_curated_rule",
        "virustotal": {"status": "skipped"}, "abuseipdb": {"status": "skipped"},
        "otx": {"status": "skipped"}, "shodan": {"status": "not_configured"},
    }
    baseline_block = {"baseline": {"status": "skipped_curated_rule"},
                      "rarity": {"status": "skipped_curated_rule"}}
    correlation_block = {"status": "skipped_curated_rule",
                         "related_count": 0, "related": [], "chain": []}
    analyst_meta = {"status": "skipped_curated_rule"}
    verdict_source = "curated_rule"

    # ---- Anti-ruido SUPERVISADO (Fase 3) --------------------------------
    # Si la firma tiene una supresión aprobada por un humano, la alerta se
    # resuelve como ruido conocido... salvo que traiga observables externos
    # con señales: la reputación SIEMPRE se verifica primero, y evidencia
    # maliciosa/sospechosa PISA la supresión (el silenciado jamás tapa
    # evidencia real). La alerta suprimida queda registrada y consultable.
    suppression = db.get_active_suppression(normalized["signature"])
    enrichment_done = False
    if suppression is not None:
        signals = False
        if routing["external_observables"]:
            enrichment_block = enricher.enrich(normalized, routing)
            enrichment_done = True
            signals = any(o.get("verdict") in ("suspicious", "malicious")
                          for o in normalized["observables"])
        if not signals:
            decision = rules.Decision(
                verdict="false_positive", confidence=96,
                rule_id="R-SUP-001", rule_name="Supresión supervisada de firma",
                rationale=(
                    f"La firma de comportamiento de esta alerta "
                    f"({normalized['signature']}) tiene una supresión vigente "
                    f"aprobada por '{suppression['approved_by']}' el "
                    f"{suppression['created_at']}"
                    + (f" (nota: {suppression['note']})" if suppression.get("note") else "")
                    + f". La firma se observó {signature_count} veces. "
                    "La alerta queda registrada y consultable; no genera ruido. "
                    "La supresión es reversible (DELETE /api/noise/suppress/"
                    f"{suppression['id']})."
                    + (" La reputación de sus observables externos fue verificada "
                       "antes de aplicar la supresión y no mostró señales."
                       if enrichment_done else "")
                ),
                key_factors=[
                    f"Supresión id {suppression['id']} aprobada por {suppression['approved_by']}",
                    f"Firma observada {signature_count} veces",
                ],
                next_steps=[], mitre=normalized["mitre"], final=True,
            )
            verdict_source = "supervised_suppression"
            analyst_meta = {"status": "skipped_suppressed"}
            baseline.store(normalized)
            result = reporter.build_result(
                alert_id, normalized, decision, routing, signature_count,
                enrichment_block, baseline_block, correlation_block,
                analyst_meta, None, verdict_source)
            db.save_result(alert_id, result, normalized)
            return result
        # Hubo señales: la evidencia pisa la supresión y se sigue el camino
        # profundo normal (el enriquecimiento ya está hecho). La nota de
        # auditoría se agrega AL FINAL (suppression_override) para que
        # sobreviva al reemplazo de decisión por R-ENR/analista.
        logger.warning("supresión de %s IGNORADA por señales de reputación en %s",
                       normalized["signature"], alert_id)
        suppression_override = (
            f"Supresión activa (id {suppression['id']}, aprobada por "
            f"{suppression['approved_by']}) IGNORADA por evidencia de "
            "reputación en observables")
    else:
        suppression_override = None

    deep = (not decision.final) or bool(routing["external_observables"])
    if deep:
        # --- Agente 3: reputación externa (solo observables públicos) -----
        if not enrichment_done:
            enrichment_block = enricher.enrich(normalized, routing)

        # Reglas con evidencia de reputación verificada
        post = rules.evaluate_post_enrichment(normalized, decision)
        if post is not None:
            decision = post
            verdict_source = "evidence_rule"

        # --- Agente 4: línea base / rareza (antes de guardar la actual) ---
        baseline_block = baseline.analyze(normalized)

        # --- Agente 5: correlación temporal/por observables ----------------
        correlation_block = correlator.correlate(normalized)

        # --- Agente 6: analista final GPT ----------------------------------
        # Solo interviene si hay algo que analizar: decisión preliminar,
        # evidencia de reputación, u observables con señales. El benigno
        # curado con reputación limpia NO gasta tokens (p.ej. FIM de snap
        # cuyo hash se verificó y vino limpio: la regla curada ya resolvió).
        signals = any(o.get("verdict") in ("suspicious", "malicious")
                      for o in normalized["observables"])
        run_analyst = (not decision.final) or verdict_source == "evidence_rule" or signals
        analyst_result = None
        if run_analyst:
            analyst_out = analyst.analyze(normalized, decision, routing,
                                          enrichment_block, baseline_block,
                                          correlation_block, signature_count)
            analyst_meta = {"status": analyst_out["status"]}
            if analyst_out["status"] == "done":
                verdict_source = "analyst"
            elif analyst_out["status"] == "error" and verdict_source != "evidence_rule":
                # Fallo técnico del analista sin evidencia firme detrás:
                # needs_review honesto, nunca un veredicto inventado.
                decision = rules.Decision(
                    verdict="needs_review", confidence=40,
                    rule_id="R-SYS-001", rule_name="Analista no disponible (fallo técnico)",
                    rationale=(
                        "El analista final no pudo completar el análisis por un fallo "
                        "técnico y la evidencia disponible no alcanza para un veredicto "
                        "firme. Se deriva a revisión humana con el dossier adjunto."
                    ),
                    key_factors=decision.key_factors,
                    next_steps=["Revisión manual con el dossier adjunto"],
                    mitre=decision.mitre, final=False,
                )
                verdict_source = "fallback"
            analyst_result = analyst_out["result"]
        else:
            analyst_meta = {"status": "skipped_clean_reputation"}
    else:
        analyst_result = None

    # Memoria: la alerta entra a la línea base SIEMPRE (después de analizar,
    # para no contaminar su propia consulta de rareza).
    baseline.store(normalized)

    # Auditoría: si una supresión fue ignorada por evidencia, el factor
    # queda visible en el resultado final, lo haya emitido quien lo haya emitido.
    if suppression_override:
        if analyst_result is not None:
            analyst_result["key_factors"] = ([suppression_override]
                                             + analyst_result["key_factors"])[:10]
        else:
            decision.key_factors = [suppression_override] + decision.key_factors

    result = reporter.build_result(
        alert_id, normalized, decision, routing, signature_count,
        enrichment_block, baseline_block, correlation_block,
        analyst_meta, analyst_result, verdict_source,
    )
    db.save_result(alert_id, result, normalized)              # Agente 7 (SQLite)
    return result


async def _run(alert_id: str, raw: dict, normalized: dict) -> dict:
    try:
        return await asyncio.to_thread(_process_sync, alert_id, raw, normalized)
    except Exception as exc:                                  # noqa: BLE001
        logger.exception("Fallo procesando %s", alert_id)
        db.save_error(alert_id, str(exc))
        return {"alert_id": alert_id, "status": "error", "error": str(exc)}


async def ingest(raw: dict, max_wait: float) -> tuple[int, dict]:
    """
    POST /api/alert/ingest → (status_code, body):
      200 contrato completo | 202 processing | ValueError → 422 en main.
    """
    normalized = normalizer.normalize(raw)                   # Agente 1
    alert_id = normalized["alert_id"]

    if not db.insert_alert_processing(alert_id, raw):        # idempotencia
        existing = db.get_alert(alert_id)
        if existing and existing["status"] == "done":
            return 200, existing["result"]
        return 202, {"alert_id": alert_id, "status": "processing"}

    task = asyncio.create_task(_run(alert_id, raw, normalized))
    done, _pending = await asyncio.wait({task}, timeout=max_wait)
    if task in done:
        result = task.result()
        code = 200 if result.get("status") == "done" else 500
        return code, result
    return 202, {"alert_id": alert_id, "status": "processing"}


async def requeue_orphans() -> int:
    """
    Idempotencia robusta (Fase 3): al arrancar, las alertas que quedaron en
    'processing' por una caída del contenedor a mitad de análisis se
    reencolan automáticamente. Ninguna alerta se pierde por un reinicio.
    """
    stuck = db.find_stuck_processing()
    requeued = 0
    for s in stuck:
        if s["raw"] is None:
            db.save_error(s["alert_id"], "huérfana sin payload crudo; irrecuperable")
            continue
        try:
            normalized = normalizer.normalize(s["raw"])
        except ValueError as exc:
            db.save_error(s["alert_id"], f"huérfana no normalizable: {exc}")
            continue
        asyncio.create_task(_run(s["alert_id"], s["raw"], normalized))
        requeued += 1
    if requeued:
        logger.info("reencoladas %d alertas huérfanas tras el arranque", requeued)
    return requeued


async def reprocess(alert_id: str) -> tuple[int, dict]:
    """
    Reproceso explícito (Fase 3): archiva el resultado vigente en
    result_history (versionado) y reanaliza la alerta con las reglas, keys
    y línea base ACTUALES. Devuelve (status_code, body) como ingest.
    """
    raw = db.get_raw(alert_id)
    if raw is None:
        return 404, {"detail": "alert_id desconocido o sin payload crudo"}
    db.archive_and_reset(alert_id)
    try:
        normalized = normalizer.normalize(raw)
    except ValueError as exc:
        db.save_error(alert_id, f"reproceso: payload no normalizable: {exc}")
        return 422, {"detail": str(exc)}
    task = asyncio.create_task(_run(alert_id, raw, normalized))
    done, _ = await asyncio.wait({task}, timeout=config.INGEST_MAX_WAIT)
    if task in done:
        result = task.result()
        code = 200 if result.get("status") == "done" else 500
        # Se devuelve el contrato PURO (mismas keys que ingest: Shuffle puede
        # reutilizar el mismo parseo). La versión archivada queda en
        # result_history y el processed_at nuevo delata el reanálisis.
        return code, result
    return 202, {"alert_id": alert_id, "status": "processing"}

"""
Agente 5 — Correlador (Fase 2, brief §5).

Busca alertas relacionadas dentro de la ventana temporal configurable:
  a) mismo host (asset),
  b) observables compartidos NO genéricos — que dos alertas mencionen
     `root` o `SYSTEM` no las relaciona (esos vienen marcados is_generic
     por el normalizador y se excluyen acá).

Construye el bloque `correlation` del contrato: lista de relacionadas con
la razón del vínculo y la cadena temporal ordenada. La correlación es
EVIDENCIA para el analista final: una desconexión de agente precedida de
actividad anómala en el mismo host cuenta otra historia que una suelta.
"""
import logging

from app import config, db

logger = logging.getLogger("vectus.correlator")


def correlate(normalized: dict) -> dict:
    """Devuelve el bloque `correlation` del contrato."""
    try:
        observable_values = [
            o["value"] for o in normalized["observables"] if not o["is_generic"]
        ]
        related = db.find_related_alerts(
            alert_id=normalized["alert_id"],
            asset=normalized["asset"],
            observable_values=observable_values,
            window_hours=config.CORRELATION_WINDOW_HOURS,
            limit=config.CORRELATION_MAX_RELATED,
        )
        if related:
            db.save_correlations(normalized["alert_id"], related)

        # Cadena temporal: las relacionadas + la actual, ordenadas por tiempo.
        chain = sorted(
            [{"alert_id": r["alert_id"], "title": r["title"],
              "verdict": r["verdict"], "at": r["created_at"]} for r in related]
            + [{"alert_id": normalized["alert_id"], "title": "(esta alerta)",
                "verdict": None, "at": ""}],
            key=lambda x: x["at"],
        )
        return {
            "status": "done",
            "related_count": len(related),
            "related": related,
            "chain": chain if related else [],
        }
    except Exception as exc:                                  # noqa: BLE001
        logger.warning("correlación falló para %s: %s",
                       normalized["alert_id"], exc)
        return {"status": "error", "related_count": 0, "related": [], "chain": []}

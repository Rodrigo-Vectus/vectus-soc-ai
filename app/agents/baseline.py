"""
Agente 4 — Línea base / RAG (Fase 2, brief §5).

Responde la pregunta "¿esto es normal en MI entorno?" sin reputación
externa: cada alerta normalizada se convierte en un documento de
comportamiento, se vectoriza (OpenAI text-embedding-3-small) y se guarda
en ChromaDB (persistente en /data/chroma). Las alertas nuevas se comparan
contra el histórico del MISMO activo para producir un score de rareza.

Cold start honesto (brief §7): con menos de COLDSTART_MIN_BASELINE
eventos para el activo, la línea base declara "cold_start" y NO emite
juicio de normalidad — nunca finge un histórico que no tiene. El
bulk-load existe justamente para acortar ese período con el histórico
real de OpenSearch.

Sin OPENAI_API_KEY el agente queda "not_configured" y la cadena sigue.
"""
import hashlib
import logging

from app import config

logger = logging.getLogger("vectus.baseline")

_client = None
_collection = None
_openai_client = None

COLLECTION = "vectus_baseline"


def _get_collection():
    """Cliente ChromaDB persistente, perezoso (no se crea si nadie lo usa)."""
    global _client, _collection
    if _collection is None:
        import chromadb
        _client = chromadb.PersistentClient(path=config.CHROMA_DIR)
        _collection = _client.get_or_create_collection(
            name=COLLECTION, metadata={"hnsw:space": "cosine"})
    return _collection


def _get_openai():
    global _openai_client
    if _openai_client is None:
        from openai import OpenAI
        _openai_client = OpenAI(api_key=config.OPENAI_API_KEY)
    return _openai_client


def is_configured() -> bool:
    return bool(config.OPENAI_API_KEY)


def behavior_document(normalized: dict) -> str:
    """
    Documento textual de COMPORTAMIENTO (no de texto crudo): describe qué
    pasó en términos de la abstracción acción, para que la similitud
    semántica compare conductas y no formatos de log.
    """
    a = normalized["action"]
    obs = " ".join(
        f"{o['type']}:{o['value']}" for o in normalized["observables"]
        if not o["is_generic"]
    )
    return (
        f"activo:{normalized['asset']} familia:{normalized['family']} "
        f"regla:{normalized['rule']['id']} {normalized['rule']['description']} "
        f"actor:{a.get('actor', '')} operacion:{a.get('operation', '')} "
        f"recurso:{a.get('resource', '')} resultado:{a.get('outcome', '')} "
        f"{obs}"
    ).strip()


def embed(texts: list[str]) -> list[list[float]]:
    """Embeddings vía OpenAI. Separado para poder mockearlo en tests."""
    client = _get_openai()
    resp = client.embeddings.create(model=config.EMBEDDING_MODEL, input=texts)
    return [item.embedding for item in resp.data]


def _doc_id(normalized: dict) -> str:
    return hashlib.sha256(
        f"{normalized['alert_id']}".encode()).hexdigest()[:32]


def store(normalized: dict) -> bool:
    """Guarda la alerta en la línea base. Devuelve False si está deshabilitado."""
    if not is_configured():
        return False
    try:
        doc = behavior_document(normalized)
        vec = embed([doc])[0]
        _get_collection().upsert(
            ids=[_doc_id(normalized)],
            embeddings=[vec],
            documents=[doc],
            metadatas=[{
                "asset": normalized["asset"],
                "family": normalized["family"],
                "rule_id": normalized["rule"]["id"],
                "alert_id": normalized["alert_id"],
                "timestamp": normalized.get("timestamp", ""),
            }],
        )
        return True
    except Exception as exc:                                  # noqa: BLE001
        logger.warning("línea base: no se pudo guardar %s: %s",
                       normalized["alert_id"], exc)
        return False


def analyze(normalized: dict) -> dict:
    """
    Bloque `internal_analysis.baseline` + `rarity` del contrato.
    status: not_configured | cold_start | ok | error
    """
    if not is_configured():
        return {"baseline": {"status": "not_configured"},
                "rarity": {"status": "not_configured"}}
    try:
        col = _get_collection()
        asset = normalized["asset"]
        asset_count = len(col.get(where={"asset": asset}, include=[])["ids"])

        if asset_count < config.COLDSTART_MIN_BASELINE:
            return {
                "baseline": {
                    "status": "cold_start",
                    "asset_events": asset_count,
                    "required": config.COLDSTART_MIN_BASELINE,
                    "note": "histórico insuficiente para juicio de normalidad; "
                            "usar bulk-load para acortar el período de cold start",
                },
                "rarity": {"status": "cold_start"},
            }

        doc = behavior_document(normalized)
        vec = embed([doc])[0]
        res = col.query(query_embeddings=[vec], n_results=5,
                        where={"asset": asset})
        distances = (res.get("distances") or [[]])[0]
        # distancia coseno → similitud. La alerta actual NO está en la
        # colección todavía (store corre después de analyze), así que una
        # distancia ~0 es un histórico idéntico: señal máxima de "habitual".
        sims = [1.0 - d for d in distances]
        if not sims:
            sims = [0.0]
        avg_sim = sum(sims) / len(sims)
        max_sim = max(sims)
        # rareza: 0 = idéntico a lo habitual, 100 = nunca visto nada parecido
        rarity_score = round((1.0 - max_sim) * 100)
        if max_sim >= (1.0 - config.RAG_SIM_THRESHOLD):
            label = "habitual"
        elif rarity_score >= 60:
            label = "inusual"
        else:
            label = "poco_frecuente"
        return {
            "baseline": {
                "status": "ok",
                "asset_events": asset_count,
                "nearest_similarity": round(max_sim, 3),
                "avg_similarity_top5": round(avg_sim, 3),
            },
            "rarity": {"status": "ok", "score": rarity_score, "label": label},
        }
    except Exception as exc:                                  # noqa: BLE001
        logger.warning("línea base: análisis falló para %s: %s",
                       normalized["alert_id"], exc)
        return {"baseline": {"status": "error", "detail": str(exc)},
                "rarity": {"status": "error"}}


def bulk_load(alerts: list[dict]) -> dict:
    """
    Carga masiva de histórico (endpoint /api/rag/bulk-load).
    Normaliza cada alerta, embebe en lotes y guarda en ChromaDB.
    Devuelve {cargadas, duplicadas, errores, detalle_errores[:5]}.
    """
    from app.agents import normalizer

    if not is_configured():
        raise RuntimeError("OPENAI_API_KEY no configurada: el RAG requiere embeddings")

    col = _get_collection()
    loaded = dup = errors = 0
    error_samples: list[str] = []
    batch_ids, batch_docs, batch_meta = [], [], []

    existing = set(col.get(include=[])["ids"])

    for raw in alerts:
        try:
            n = normalizer.normalize(raw)
            did = _doc_id(n)
            if did in existing or did in batch_ids:
                dup += 1
                continue
            batch_ids.append(did)
            batch_docs.append(behavior_document(n))
            batch_meta.append({
                "asset": n["asset"], "family": n["family"],
                "rule_id": n["rule"]["id"], "alert_id": n["alert_id"],
                "timestamp": n.get("timestamp", ""),
            })
        except ValueError as exc:
            errors += 1
            if len(error_samples) < 5:
                error_samples.append(str(exc))

        if len(batch_ids) >= 100:
            loaded += _flush(col, batch_ids, batch_docs, batch_meta)
            batch_ids, batch_docs, batch_meta = [], [], []

    if batch_ids:
        loaded += _flush(col, batch_ids, batch_docs, batch_meta)

    return {"cargadas": loaded, "duplicadas": dup, "errores": errors,
            "detalle_errores": error_samples}


def _flush(col, ids: list[str], docs: list[str], metas: list[dict]) -> int:
    vecs = embed(docs)
    col.upsert(ids=ids, embeddings=vecs, documents=docs, metadatas=metas)
    return len(ids)



def prune_old_vectors(retain_days: int) -> dict:
    """
    Elimina de la linea base (ChromaDB) los vectores mas viejos que
    retain_days. Mantiene el baseline fresco.
    """
    if not is_configured():
        return {"status": "not_configured"}
    try:
        from datetime import datetime, timezone, timedelta
        cutoff = (datetime.now(timezone.utc) - timedelta(days=retain_days)).isoformat()
        col = _get_collection()
        data = col.get(include=["metadatas"])
        ids = data.get("ids", [])
        metas = data.get("metadatas", []) or []
        viejos = [
            ids[i] for i, m in enumerate(metas)
            if (m or {}).get("timestamp", "") and m["timestamp"] < cutoff
        ]
        if viejos:
            col.delete(ids=viejos)
        return {"deleted": len(viejos), "total_antes": len(ids)}
    except Exception as exc:                                  # noqa: BLE001
        logger.warning("prune de vectores fallo: %s", exc)
        return {"status": f"error: {exc}"}

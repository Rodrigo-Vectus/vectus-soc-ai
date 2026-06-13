"""
Capa de persistencia SQLite del motor Vectus SOC.

Principios (brief §4.5 y §12):
- Todo se guarda, nada se descarta (incluso informativas).
- Migraciones idempotentes: se chequea PRAGMA table_info antes de ALTER.
- En Fase 1 se usan `alerts` y `observables` (idempotencia + resultado
  recuperable por GET). El resto de las tablas del modelo de datos quedan
  creadas para que las fases 2/3 no requieran migración destructiva.
"""
import json
import os
import sqlite3
import threading
from datetime import datetime, timedelta, timezone

from app import config

# SQLite es accedido desde el event loop y desde tasks; un lock simple
# alcanza para el volumen de un motor de triage (no es alta concurrencia).
_lock = threading.Lock()
_conn: sqlite3.Connection | None = None


def _now() -> str:
    return datetime.now(timezone.utc).isoformat()


def get_conn() -> sqlite3.Connection:
    """Conexión singleton, con check_same_thread=False (protegida por lock)."""
    global _conn
    if _conn is None:
        os.makedirs(config.DATA_DIR, exist_ok=True)
        _conn = sqlite3.connect(config.DB_PATH, check_same_thread=False)
        _conn.row_factory = sqlite3.Row
    return _conn


# --------------------------------------------------------------------------
# Esquema y migraciones
# --------------------------------------------------------------------------

_SCHEMA = {
    "clients": """
        CREATE TABLE IF NOT EXISTS clients (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            name TEXT UNIQUE,
            created_at TEXT
        )""",
    "alerts": """
        CREATE TABLE IF NOT EXISTS alerts (
            alert_id TEXT PRIMARY KEY,        -- id idempotente derivado de Wazuh
            signature TEXT,                   -- firma de comportamiento (agente|regla|recurso)
            alert_class TEXT,                 -- familia detectada por el normalizador
            classification TEXT,              -- externa | interna | ambas (router)
            priority_score INTEGER,           -- rule.level de Wazuh
            verdict TEXT,                     -- informational | false_positive | true_positive
            status TEXT,                      -- processing | done | error
            raw_json TEXT,                    -- alerta cruda tal como llegó
            result_json TEXT,                 -- contrato de salida completo
            created_at TEXT,
            updated_at TEXT
        )""",
    "observables": """
        CREATE TABLE IF NOT EXISTS observables (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            alert_id TEXT,
            type TEXT,
            value TEXT,
            is_public INTEGER DEFAULT 0,
            verdict TEXT DEFAULT 'unknown',
            created_at TEXT
        )""",
    "correlations": """
        CREATE TABLE IF NOT EXISTS correlations (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            alert_id TEXT,
            related_alert_id TEXT,
            reason TEXT,
            created_at TEXT
        )""",
    "analyses": """
        CREATE TABLE IF NOT EXISTS analyses (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            alert_id TEXT,
            stage TEXT,
            detail_json TEXT,
            created_at TEXT
        )""",
    "behavior_signatures": """
        CREATE TABLE IF NOT EXISTS behavior_signatures (
            signature TEXT PRIMARY KEY,
            first_seen TEXT,
            last_seen TEXT,
            count INTEGER DEFAULT 0,
            marked_noise INTEGER DEFAULT 0    -- anti-ruido SUPERVISADO (Fase 3)
        )""",
    "signature_events": """
        CREATE TABLE IF NOT EXISTS signature_events (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            signature TEXT,
            alert_id TEXT,
            created_at TEXT
        )""",
    "enrichment_cache": """
        CREATE TABLE IF NOT EXISTS enrichment_cache (
            cache_key TEXT PRIMARY KEY,       -- fuente:tipo:valor (ej. vt:ip:1.2.3.4)
            value_json TEXT,
            fetched_at TEXT
        )""",
    "suppressions": """
        CREATE TABLE IF NOT EXISTS suppressions (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            signature TEXT NOT NULL,          -- firma de comportamiento suprimida
            approved_by TEXT NOT NULL,        -- QUIÉN la aprobó (auditoría)
            note TEXT,
            active INTEGER DEFAULT 1,
            created_at TEXT,
            revoked_by TEXT,
            revoked_at TEXT
        )""",
    "result_history": """
        CREATE TABLE IF NOT EXISTS result_history (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            alert_id TEXT NOT NULL,
            version INTEGER NOT NULL,         -- versión archivada (1 = primer análisis)
            result_json TEXT,
            archived_at TEXT
        )""",
}

# Columnas que podrían agregarse en fases futuras: {tabla: {col: tipo}}.
# El patrón de migración idempotente queda establecido desde Fase 1.
_MIGRATIONS: dict[str, dict[str, str]] = {}


def _existing_columns(conn: sqlite3.Connection, table: str) -> set[str]:
    rows = conn.execute(f"PRAGMA table_info({table})").fetchall()
    return {r["name"] for r in rows}


def init_db() -> None:
    """Crea el esquema y aplica migraciones de forma idempotente."""
    conn = get_conn()
    with _lock:
        for ddl in _SCHEMA.values():
            conn.execute(ddl)
        for table, cols in _MIGRATIONS.items():
            existing = _existing_columns(conn, table)
            for col, coltype in cols.items():
                if col not in existing:
                    conn.execute(f"ALTER TABLE {table} ADD COLUMN {col} {coltype}")
        conn.commit()


# --------------------------------------------------------------------------
# Operaciones sobre alertas (Fase 1)
# --------------------------------------------------------------------------

def get_alert(alert_id: str) -> dict | None:
    """Devuelve {status, result} para un alert_id, o None si no existe."""
    conn = get_conn()
    with _lock:
        row = conn.execute(
            "SELECT status, result_json FROM alerts WHERE alert_id = ?", (alert_id,)
        ).fetchone()
    if row is None:
        return None
    result = json.loads(row["result_json"]) if row["result_json"] else None
    return {"status": row["status"], "result": result}


def insert_alert_processing(alert_id: str, raw: dict) -> bool:
    """
    Registra la alerta como 'processing'. Devuelve False si ya existía
    (idempotencia: un reintento de Shuffle no dispara doble análisis).
    """
    conn = get_conn()
    with _lock:
        try:
            conn.execute(
                "INSERT INTO alerts (alert_id, status, raw_json, created_at, updated_at) "
                "VALUES (?, 'processing', ?, ?, ?)",
                (alert_id, json.dumps(raw, ensure_ascii=False), _now(), _now()),
            )
            conn.commit()
            return True
        except sqlite3.IntegrityError:
            return False


def save_result(alert_id: str, result: dict, normalized: dict) -> None:
    """Persiste el contrato final + metadatos + observables de la alerta."""
    conn = get_conn()
    with _lock:
        conn.execute(
            """UPDATE alerts SET status='done', result_json=?, verdict=?,
               alert_class=?, classification=?, priority_score=?, signature=?,
               updated_at=? WHERE alert_id=?""",
            (
                json.dumps(result, ensure_ascii=False),
                result.get("verdict"),
                result.get("alert_class"),
                normalized.get("classification"),
                normalized.get("rule", {}).get("level"),
                normalized.get("signature"),
                _now(),
                alert_id,
            ),
        )
        # idempotente ante reproceso: los observables previos de esta alerta
        # se reemplazan por los del resultado vigente
        conn.execute("DELETE FROM observables WHERE alert_id=?", (alert_id,))
        for obs in result.get("observables", []):
            conn.execute(
                "INSERT INTO observables (alert_id, type, value, is_public, verdict, created_at) "
                "VALUES (?, ?, ?, ?, ?, ?)",
                (alert_id, obs.get("type"), obs.get("value"),
                 1 if obs.get("is_public") else 0, obs.get("verdict", "unknown"), _now()),
            )
        conn.commit()


def save_error(alert_id: str, message: str) -> None:
    """Marca la alerta como errónea sin perderla (degradación elegante)."""
    conn = get_conn()
    with _lock:
        conn.execute(
            "UPDATE alerts SET status='error', result_json=?, updated_at=? WHERE alert_id=?",
            (json.dumps({"error": message}, ensure_ascii=False), _now(), alert_id),
        )
        conn.commit()


def touch_signature(signature: str, alert_id: str) -> int:
    """
    Cuenta repeticiones de una firma de comportamiento (base del anti-ruido
    SUPERVISADO de Fase 3: el motor cuenta y puede sugerir, nunca auto-silencia).
    Devuelve el contador actualizado.
    """
    conn = get_conn()
    with _lock:
        row = conn.execute(
            "SELECT count FROM behavior_signatures WHERE signature=?", (signature,)
        ).fetchone()
        if row is None:
            conn.execute(
                "INSERT INTO behavior_signatures (signature, first_seen, last_seen, count) "
                "VALUES (?, ?, ?, 1)",
                (signature, _now(), _now()),
            )
            count = 1
        else:
            count = row["count"] + 1
            conn.execute(
                "UPDATE behavior_signatures SET count=?, last_seen=? WHERE signature=?",
                (count, _now(), signature),
            )
        conn.execute(
            "INSERT INTO signature_events (signature, alert_id, created_at) VALUES (?, ?, ?)",
            (signature, alert_id, _now()),
        )
        conn.commit()
    return count


# --------------------------------------------------------------------------
# Caché de enriquecimiento (Fase 2): la misma IP/hash no gasta cuota dos veces
# --------------------------------------------------------------------------

def cache_get(cache_key: str, ttl_hours: int) -> dict | None:
    """Devuelve el valor cacheado si existe y no expiró el TTL."""
    conn = get_conn()
    with _lock:
        row = conn.execute(
            "SELECT value_json, fetched_at FROM enrichment_cache WHERE cache_key=?",
            (cache_key,),
        ).fetchone()
    if row is None:
        return None
    fetched = datetime.fromisoformat(row["fetched_at"])
    if datetime.now(timezone.utc) - fetched > timedelta(hours=ttl_hours):
        return None
    return json.loads(row["value_json"])


def cache_set(cache_key: str, value: dict) -> None:
    conn = get_conn()
    with _lock:
        conn.execute(
            "INSERT OR REPLACE INTO enrichment_cache (cache_key, value_json, fetched_at) "
            "VALUES (?, ?, ?)",
            (cache_key, json.dumps(value, ensure_ascii=False), _now()),
        )
        conn.commit()


# --------------------------------------------------------------------------
# Correlación (Fase 2): vecinos por host y por observables compartidos
# --------------------------------------------------------------------------

def find_related_alerts(alert_id: str, asset: str, observable_values: list[str],
                        window_hours: int, limit: int) -> list[dict]:
    """
    Alertas relacionadas dentro de la ventana temporal:
      a) mismas del MISMO host (asset), o
      b) que compartan algún observable NO genérico (IPs, hashes, cuentas
         nombradas, archivos) — que dos alertas mencionen 'root' no las
         relaciona; los genéricos ya vienen filtrados por el llamador.
    Devuelve [{alert_id, verdict, alert_class, title, reason, created_at}].
    """
    conn = get_conn()
    since = (datetime.now(timezone.utc) - timedelta(hours=window_hours)).isoformat()
    related: dict[str, dict] = {}
    with _lock:
        # a) mismo host
        rows = conn.execute(
            """SELECT a.alert_id, a.verdict, a.alert_class, a.result_json, a.created_at
               FROM alerts a
               WHERE a.alert_id != ? AND a.created_at >= ? AND a.status='done'
                 AND a.result_json IS NOT NULL
                 AND json_extract(a.result_json, '$.asset') = ?
               ORDER BY a.created_at DESC LIMIT ?""",
            (alert_id, since, asset, limit),
        ).fetchall()
        for r in rows:
            related[r["alert_id"]] = _related_row(r, f"mismo host ({asset})")
        # b) observables compartidos
        if observable_values:
            placeholders = ",".join("?" for _ in observable_values)
            rows = conn.execute(
                f"""SELECT DISTINCT a.alert_id, a.verdict, a.alert_class,
                           a.result_json, a.created_at, o.value AS shared
                    FROM alerts a JOIN observables o ON o.alert_id = a.alert_id
                    WHERE a.alert_id != ? AND a.created_at >= ? AND a.status='done'
                      AND o.value IN ({placeholders})
                    ORDER BY a.created_at DESC LIMIT ?""",
                (alert_id, since, *observable_values, limit),
            ).fetchall()
            for r in rows:
                if r["alert_id"] not in related:
                    related[r["alert_id"]] = _related_row(
                        r, f"observable compartido: {r['shared']}")
    out = sorted(related.values(), key=lambda x: x["created_at"], reverse=True)
    return out[:limit]


def _related_row(row, reason: str) -> dict:
    title = ""
    if row["result_json"]:
        try:
            title = json.loads(row["result_json"]).get("title", "")
        except (ValueError, TypeError):
            title = ""
    return {
        "alert_id": row["alert_id"],
        "verdict": row["verdict"],
        "alert_class": row["alert_class"],
        "title": title,
        "reason": reason,
        "created_at": row["created_at"],
    }


def save_correlations(alert_id: str, related: list[dict]) -> None:
    conn = get_conn()
    with _lock:
        for r in related:
            conn.execute(
                "INSERT INTO correlations (alert_id, related_alert_id, reason, created_at) "
                "VALUES (?, ?, ?, ?)",
                (alert_id, r["alert_id"], r["reason"], _now()),
            )
        conn.commit()


# --------------------------------------------------------------------------
# Anti-ruido SUPERVISADO (Fase 3): el motor cuenta y sugiere; el humano
# decide. Toda supresión queda con autoría y timestamp (auditable) y es
# reversible. Nunca hay silenciado automático.
# --------------------------------------------------------------------------

def noise_candidates(window_hours: int, min_count: int) -> list[dict]:
    """
    Firmas candidatas a supresión: TASA de repetición en la ventana
    (>= min_count eventos en las últimas window_hours) con veredictos
    consistentemente benignos (solo informational/false_positive) y sin
    supresión activa. Si UNA sola alerta de la firma fue true_positive o
    needs_review en la ventana, la firma queda fuera: no es ruido.
    """
    conn = get_conn()
    since = (datetime.now(timezone.utc) - timedelta(hours=window_hours)).isoformat()
    out: list[dict] = []
    with _lock:
        rows = conn.execute(
            """SELECT se.signature, COUNT(*) AS n,
                      MIN(se.created_at) AS first_in_window,
                      MAX(se.created_at) AS last_in_window
               FROM signature_events se
               WHERE se.created_at >= ?
                 AND se.signature NOT IN
                     (SELECT signature FROM suppressions WHERE active=1)
               GROUP BY se.signature
               HAVING n >= ?
               ORDER BY n DESC""",
            (since, min_count),
        ).fetchall()
        for r in rows:
            verdicts = conn.execute(
                """SELECT a.verdict, COUNT(*) AS c FROM alerts a
                   WHERE a.signature = ? AND a.created_at >= ? AND a.status='done'
                   GROUP BY a.verdict""",
                (r["signature"], since),
            ).fetchall()
            breakdown = {v["verdict"]: v["c"] for v in verdicts if v["verdict"]}
            if any(k not in ("informational", "false_positive") for k in breakdown):
                continue   # hubo algo no benigno: no es candidata
            samples = [s["alert_id"] for s in conn.execute(
                "SELECT alert_id FROM signature_events WHERE signature=? "
                "ORDER BY created_at DESC LIMIT 3", (r["signature"],)).fetchall()]
            out.append({
                "signature": r["signature"],
                "count_in_window": r["n"],
                "window_hours": window_hours,
                "first_in_window": r["first_in_window"],
                "last_in_window": r["last_in_window"],
                "verdicts": breakdown,
                "sample_alert_ids": samples,
            })
    return out


def get_active_suppression(signature: str) -> dict | None:
    conn = get_conn()
    with _lock:
        row = conn.execute(
            "SELECT id, signature, approved_by, note, created_at FROM suppressions "
            "WHERE signature=? AND active=1 ORDER BY id DESC LIMIT 1",
            (signature,),
        ).fetchone()
    return dict(row) if row else None


def add_suppression(signature: str, approved_by: str, note: str = "") -> dict:
    """Registra la supresión. Exige que la firma exista (se vio al menos una vez)."""
    conn = get_conn()
    with _lock:
        known = conn.execute(
            "SELECT 1 FROM behavior_signatures WHERE signature=?", (signature,)
        ).fetchone()
        if known is None:
            raise ValueError("firma desconocida: nunca fue observada por el motor")
        existing = conn.execute(
            "SELECT id FROM suppressions WHERE signature=? AND active=1", (signature,)
        ).fetchone()
        if existing:
            raise ValueError(f"la firma ya tiene una supresión activa (id {existing['id']})")
        cur = conn.execute(
            "INSERT INTO suppressions (signature, approved_by, note, active, created_at) "
            "VALUES (?, ?, ?, 1, ?)",
            (signature, approved_by, note, _now()),
        )
        conn.execute("UPDATE behavior_signatures SET marked_noise=1 WHERE signature=?",
                     (signature,))
        conn.commit()
        return {"id": cur.lastrowid, "signature": signature,
                "approved_by": approved_by, "note": note}


def revoke_suppression(supp_id: int, revoked_by: str) -> bool:
    """Revoca (no borra: la fila queda como registro de auditoría)."""
    conn = get_conn()
    with _lock:
        row = conn.execute(
            "SELECT signature FROM suppressions WHERE id=? AND active=1", (supp_id,)
        ).fetchone()
        if row is None:
            return False
        conn.execute(
            "UPDATE suppressions SET active=0, revoked_by=?, revoked_at=? WHERE id=?",
            (revoked_by, _now(), supp_id),
        )
        conn.execute("UPDATE behavior_signatures SET marked_noise=0 WHERE signature=?",
                     (row["signature"],))
        conn.commit()
        return True


def list_suppressions(active_only: bool = False) -> list[dict]:
    conn = get_conn()
    q = "SELECT * FROM suppressions"
    if active_only:
        q += " WHERE active=1"
    q += " ORDER BY id DESC"
    with _lock:
        return [dict(r) for r in conn.execute(q).fetchall()]


# --------------------------------------------------------------------------
# Idempotencia robusta (Fase 3): huérfanas, timeout y reproceso versionado
# --------------------------------------------------------------------------

def get_raw(alert_id: str) -> dict | None:
    conn = get_conn()
    with _lock:
        row = conn.execute(
            "SELECT raw_json FROM alerts WHERE alert_id=?", (alert_id,)
        ).fetchone()
    if row is None or not row["raw_json"]:
        return None
    return json.loads(row["raw_json"])


def find_stuck_processing(older_than_minutes: int = 0) -> list[dict]:
    """Alertas en 'processing' (opcionalmente más viejas que N minutos)."""
    conn = get_conn()
    cutoff = (datetime.now(timezone.utc)
              - timedelta(minutes=older_than_minutes)).isoformat()
    with _lock:
        rows = conn.execute(
            "SELECT alert_id, raw_json, updated_at FROM alerts "
            "WHERE status='processing' AND updated_at <= ?",
            (cutoff,),
        ).fetchall()
    return [{"alert_id": r["alert_id"],
             "raw": json.loads(r["raw_json"]) if r["raw_json"] else None,
             "updated_at": r["updated_at"]} for r in rows]


def mark_timed_out(alert_id: str) -> None:
    save_error(alert_id, "análisis excedió PROCESSING_TIMEOUT_MINUTES; "
                         "recuperable con POST /api/alert/{id}/reprocess")


def archive_and_reset(alert_id: str) -> int | None:
    """
    Archiva el resultado vigente en result_history y vuelve la alerta a
    'processing' para reanálisis. Devuelve la versión archivada, o None
    si la alerta no existe. Una alerta sin resultado (error temprano)
    se reanaliza sin archivar nada.
    """
    conn = get_conn()
    with _lock:
        row = conn.execute(
            "SELECT result_json, status FROM alerts WHERE alert_id=?", (alert_id,)
        ).fetchone()
        if row is None:
            return None
        version = 0
        if row["result_json"] and row["status"] == "done":
            last = conn.execute(
                "SELECT MAX(version) AS v FROM result_history WHERE alert_id=?",
                (alert_id,),
            ).fetchone()
            version = (last["v"] or 0) + 1
            conn.execute(
                "INSERT INTO result_history (alert_id, version, result_json, archived_at) "
                "VALUES (?, ?, ?, ?)",
                (alert_id, version, row["result_json"], _now()),
            )
        conn.execute(
            "UPDATE alerts SET status='processing', updated_at=? WHERE alert_id=?",
            (_now(), alert_id),
        )
        conn.commit()
        return version


def get_result_history(alert_id: str) -> list[dict]:
    conn = get_conn()
    with _lock:
        rows = conn.execute(
            "SELECT version, archived_at FROM result_history WHERE alert_id=? "
            "ORDER BY version", (alert_id,)).fetchall()
    return [dict(r) for r in rows]


# --------------------------------------------------------------------------
# Métricas operativas (Fase 3)
# --------------------------------------------------------------------------

def stats() -> dict:
    conn = get_conn()
    since_24h = (datetime.now(timezone.utc) - timedelta(hours=24)).isoformat()
    with _lock:
        by_status = {r["status"]: r["c"] for r in conn.execute(
            "SELECT status, COUNT(*) c FROM alerts GROUP BY status").fetchall()}
        by_verdict = {r["verdict"]: r["c"] for r in conn.execute(
            "SELECT verdict, COUNT(*) c FROM alerts WHERE verdict IS NOT NULL "
            "GROUP BY verdict").fetchall()}
        by_source = {r["s"]: r["c"] for r in conn.execute(
            "SELECT json_extract(result_json, '$.internal_analysis.verdict_source') s, "
            "COUNT(*) c FROM alerts WHERE result_json IS NOT NULL AND status='done' "
            "GROUP BY s").fetchall() if r["s"]}
        last_24h = conn.execute(
            "SELECT COUNT(*) c FROM alerts WHERE created_at >= ?", (since_24h,)
        ).fetchone()["c"]
        cache_entries = conn.execute(
            "SELECT COUNT(*) c FROM enrichment_cache").fetchone()["c"]
        signatures = conn.execute(
            "SELECT COUNT(*) c FROM behavior_signatures").fetchone()["c"]
        active_supp = conn.execute(
            "SELECT COUNT(*) c FROM suppressions WHERE active=1").fetchone()["c"]
    return {
        "alerts_by_status": by_status,
        "alerts_by_verdict": by_verdict,
        "alerts_by_verdict_source": by_source,
        "alerts_last_24h": last_24h,
        "enrichment_cache_entries": cache_entries,
        "behavior_signatures": signatures,
        "active_suppressions": active_supp,
    }

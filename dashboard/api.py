"""
Vectus SOC Dashboard — backend (FastAPI, un solo archivo).

Panel de visualización SOLO-LECTURA sobre la base del Vectus SOC Engine.
NO toca el motor: monta su base SQLite en modo read-only y la consulta.
Su única escritura es su propia base (usuarios + OTP), separada de la del motor.

Secciones: config → bases → init → modelos → auth (OTP+JWT+roles) →
rate limit → rutas públicas → rutas de panel → API de lectura del motor →
API de gestión de usuarios.
"""
import hashlib
import os
import secrets
import sqlite3
import time
from collections import defaultdict
from contextlib import contextmanager
from datetime import datetime, timedelta, timezone

import jwt  # PyJWT
from fastapi import FastAPI, Header, Request
from fastapi.responses import FileResponse, JSONResponse, RedirectResponse
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel

# ===========================================================================
# CONFIG (todo desde entorno, defaults seguros)
# ===========================================================================
# Base del MOTOR (solo lectura). Se monta read-only en el contenedor.
ENGINE_DB_PATH = os.getenv("ENGINE_DB_PATH", "/engine-data/vectus.db").strip()
# Base PROPIA del dashboard (usuarios + OTP). Separada de la del motor.
DASH_DB_PATH = os.getenv("DASH_DB_PATH", "data/dashboard.db").strip()

APP_PORT = int(os.getenv("APP_PORT", "8005"))
JWT_SECRET = os.getenv("JWT_SECRET", "").strip() or secrets.token_hex(32)
JWT_HOURS = int(os.getenv("JWT_HOURS", "8"))
COOKIE_SECURE = os.getenv("COOKIE_SECURE", "false").lower() in ("1", "true", "yes")
ADMIN_EMAIL = os.getenv("ADMIN_EMAIL", "").strip().lower()

# SMTP para enviar el OTP (si no está configurado, el código se loguea —
# útil en desarrollo; en producción configurar SMTP real).
SMTP_HOST = os.getenv("SMTP_HOST", "").strip()
SMTP_PORT = int(os.getenv("SMTP_PORT", "587"))
SMTP_EMAIL = os.getenv("SMTP_EMAIL", "").strip()
SMTP_PASSWORD = os.getenv("SMTP_PASSWORD", "").strip()

OTP_TTL_MIN = int(os.getenv("OTP_TTL_MIN", "10"))

# Conexión al MOTOR para acciones (reprocesar). Solo para POST de acciones;
# la lectura sigue siendo directa sobre la DB read-only.
ENGINE_URL = os.getenv("ENGINE_URL", "http://vectus-soc-engine:8003").rstrip("/")
ENGINE_API_KEY = os.getenv("ENGINE_API_KEY", "").strip()
ENGINE_TIMEOUT = int(os.getenv("ENGINE_TIMEOUT", "30"))

app = FastAPI(title="Vectus SOC Dashboard", docs_url=None, redoc_url=None)
# Servir archivos estáticos (logo, imágenes) desde /static
app.mount("/static", StaticFiles(directory="static"), name="static")


# ===========================================================================
# BASES DE DATOS
# ===========================================================================
@contextmanager
def engine_db():
    """Base del MOTOR — SOLO LECTURA. Abre en modo ro vía URI."""
    uri = f"file:{ENGINE_DB_PATH}?mode=ro"
    conn = sqlite3.connect(uri, uri=True, check_same_thread=False)
    conn.row_factory = sqlite3.Row
    try:
        yield conn
    finally:
        conn.close()


@contextmanager
def dash_db():
    """Base PROPIA del dashboard — lectura/escritura (usuarios, OTP)."""
    conn = sqlite3.connect(DASH_DB_PATH, check_same_thread=False)
    conn.row_factory = sqlite3.Row
    try:
        yield conn
        conn.commit()
    finally:
        conn.close()


def init_dash_db():
    """Crea las tablas propias del dashboard y siembra el primer admin."""
    os.makedirs(os.path.dirname(DASH_DB_PATH) or ".", exist_ok=True)
    with dash_db() as conn:
        conn.execute("""
            CREATE TABLE IF NOT EXISTS users (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                email TEXT UNIQUE NOT NULL,
                name TEXT,
                role TEXT NOT NULL DEFAULT 'viewer',   -- admin | viewer
                active INTEGER NOT NULL DEFAULT 1,
                last_login TEXT,
                created_at TEXT
            )""")
        conn.execute("""
            CREATE TABLE IF NOT EXISTS otp_tokens (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                email TEXT NOT NULL,
                code_hash TEXT NOT NULL,
                expires_at TEXT NOT NULL,
                used INTEGER NOT NULL DEFAULT 0,
                created_at TEXT
            )""")
        conn.execute("""
            CREATE TABLE IF NOT EXISTS audit_log (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                actor TEXT,
                action TEXT,
                detail TEXT,
                ip TEXT,
                created_at TEXT
            )""")
        conn.execute("""
            CREATE TABLE IF NOT EXISTS alert_notes (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                alert_id TEXT NOT NULL,
                author TEXT NOT NULL,
                note TEXT NOT NULL,
                created_at TEXT
            )""")
        # Sembrar primer admin si no hay usuarios
        n = conn.execute("SELECT COUNT(*) c FROM users").fetchone()["c"]
        if n == 0 and ADMIN_EMAIL:
            conn.execute(
                "INSERT INTO users (email, name, role, active, created_at) "
                "VALUES (?,?,?,1,?)",
                (ADMIN_EMAIL, "Admin", "admin", _now()),
            )


def _now() -> str:
    return datetime.now(timezone.utc).isoformat()


def _audit(actor: str, action: str, detail: str, ip: str):
    try:
        with dash_db() as conn:
            conn.execute(
                "INSERT INTO audit_log (actor, action, detail, ip, created_at) "
                "VALUES (?,?,?,?,?)", (actor, action, detail, ip, _now()))
    except Exception:
        pass


@app.on_event("startup")
def _startup():
    init_dash_db()


# ===========================================================================
# MODELOS
# ===========================================================================
class LoginRequest(BaseModel):
    email: str


class VerifyRequest(BaseModel):
    email: str
    code: str


class UserCreate(BaseModel):
    email: str
    name: str = ""
    role: str = "viewer"


class UserPatch(BaseModel):
    name: str | None = None
    role: str | None = None
    active: bool | None = None


class NoteCreate(BaseModel):
    note: str


# ===========================================================================
# AUTH: OTP + JWT + roles
# ===========================================================================
def crear_otp(email: str) -> str:
    code = f"{secrets.randbelow(10**6):06d}"
    code_hash = hashlib.sha256(code.encode()).hexdigest()
    expires = (datetime.now(timezone.utc) + timedelta(minutes=OTP_TTL_MIN)).isoformat()
    with dash_db() as conn:
        conn.execute(
            "INSERT INTO otp_tokens (email, code_hash, expires_at, used, created_at) "
            "VALUES (?,?,?,0,?)", (email.lower(), code_hash, expires, _now()))
    return code


def verificar_otp(email: str, code: str) -> bool:
    code_hash = hashlib.sha256(code.encode()).hexdigest()
    with dash_db() as conn:
        row = conn.execute(
            "SELECT id FROM otp_tokens WHERE email=? AND code_hash=? AND used=0 "
            "AND expires_at > ? ORDER BY id DESC LIMIT 1",
            (email.lower(), code_hash, _now())).fetchone()
        if not row:
            return False
        conn.execute("UPDATE otp_tokens SET used=1 WHERE id=?", (row["id"],))
        return True


def crear_token(email: str, role: str) -> str:
    payload = {"sub": email, "role": role,
               "exp": datetime.now(timezone.utc) + timedelta(hours=JWT_HOURS)}
    return jwt.encode(payload, JWT_SECRET, algorithm="HS256")


def usuario_actual(request: Request) -> dict | None:
    tok = request.cookies.get("session")
    if not tok:
        return None
    try:
        data = jwt.decode(tok, JWT_SECRET, algorithms=["HS256"])
    except jwt.PyJWTError:
        return None
    with dash_db() as conn:
        u = conn.execute("SELECT * FROM users WHERE email=? AND active=1",
                         (data["sub"],)).fetchone()
    return dict(u) if u else None


def _admin_or_error(request: Request):
    u = usuario_actual(request)
    if not u:
        return None, JSONResponse({"ok": False, "error": "No autenticado"}, status_code=401)
    if u["role"] != "admin":
        return None, JSONResponse({"ok": False, "error": "Sin permiso"}, status_code=403)
    return u, None


def _send_email_otp(email: str, code: str):
    """Envía el OTP por SMTP. Si no hay SMTP configurado, lo loguea (dev)."""
    if not (SMTP_HOST and SMTP_EMAIL and SMTP_PASSWORD):
        print(f"[OTP][dev] código para {email}: {code}")
        return
    import smtplib
    from email.mime.text import MIMEText
    msg = MIMEText(f"Tu código de acceso al Vectus SOC Dashboard es: {code}\n"
                   f"Válido por {OTP_TTL_MIN} minutos.")
    msg["Subject"] = "Vectus SOC Dashboard — código de acceso"
    msg["From"] = SMTP_EMAIL
    msg["To"] = email
    try:
        with smtplib.SMTP(SMTP_HOST, SMTP_PORT) as s:
            s.starttls()
            s.login(SMTP_EMAIL, SMTP_PASSWORD)
            s.send_message(msg)
    except Exception as e:
        print(f"[OTP] fallo SMTP para {email}: {e}; código: {code}")


# ===========================================================================
# RATE LIMIT (por IP, en memoria — suficiente para un contenedor)
# ===========================================================================
_intentos = defaultdict(list)


def rate_limited(ip: str, max_intentos=5, ventana=900) -> bool:
    ahora = time.time()
    _intentos[ip] = [t for t in _intentos[ip] if ahora - t < ventana]
    if len(_intentos[ip]) >= max_intentos:
        return True
    _intentos[ip].append(ahora)
    return False


def _client_ip(request: Request) -> str:
    fwd = request.headers.get("x-forwarded-for", "")
    if fwd:
        return fwd.split(",")[0].strip()
    return request.client.host if request.client else "unknown"


# ===========================================================================
# RUTAS: páginas
# ===========================================================================
@app.get("/")
def root(request: Request):
    if usuario_actual(request):
        return RedirectResponse("/dashboard", status_code=307)
    return RedirectResponse("/login", status_code=307)


@app.get("/login")
def login_page():
    return FileResponse("static/login.html")


@app.get("/dashboard")
def dashboard_page(request: Request):
    if not usuario_actual(request):
        return RedirectResponse("/login", status_code=307)
    return FileResponse("static/dashboard.html")


@app.get("/usuarios")
def usuarios_page(request: Request):
    u = usuario_actual(request)
    if not u:
        return RedirectResponse("/login", status_code=307)
    return FileResponse("static/usuarios.html")


@app.get("/inteligencia")
def inteligencia_page(request: Request):
    if not usuario_actual(request):
        return RedirectResponse("/login", status_code=307)
    return FileResponse("static/inteligencia.html")


@app.get("/auditoria")
def auditoria_page(request: Request):
    u = usuario_actual(request)
    if not u:
        return RedirectResponse("/login", status_code=307)
    return FileResponse("static/auditoria.html")


@app.get("/status")
def status():
    return {"ok": True, "service": "vectus-soc-dashboard", "version": "1.0.0"}


# ===========================================================================
# RUTAS: auth
# ===========================================================================
@app.post("/auth/request-code")
def request_code(body: LoginRequest, request: Request):
    ip = _client_ip(request)
    if rate_limited(ip):
        return JSONResponse({"ok": False, "error": "Demasiados intentos. Esperá unos minutos."},
                            status_code=429)
    email = body.email.strip().lower()
    with dash_db() as conn:
        u = conn.execute("SELECT * FROM users WHERE email=? AND active=1",
                         (email,)).fetchone()
    # Respuesta uniforme aunque el email no exista (no revela usuarios)
    if u:
        code = crear_otp(email)
        _send_email_otp(email, code)
        _audit(email, "request_code", "", ip)
    return {"ok": True, "message": "Si el email está habilitado, se envió un código."}


@app.post("/auth/verify")
def verify(body: VerifyRequest, request: Request):
    ip = _client_ip(request)
    if rate_limited(ip, max_intentos=10):
        return JSONResponse({"ok": False, "error": "Demasiados intentos."}, status_code=429)
    email = body.email.strip().lower()
    if not verificar_otp(email, body.code.strip()):
        _audit(email, "verify_fail", "", ip)
        return JSONResponse({"ok": False, "error": "Código inválido o expirado."},
                            status_code=401)
    with dash_db() as conn:
        u = conn.execute("SELECT * FROM users WHERE email=? AND active=1",
                         (email,)).fetchone()
        if not u:
            return JSONResponse({"ok": False, "error": "Usuario no habilitado."},
                                status_code=403)
        conn.execute("UPDATE users SET last_login=? WHERE id=?", (_now(), u["id"]))
    token = crear_token(email, u["role"])
    _audit(email, "login", "", ip)
    resp = JSONResponse({"ok": True})
    resp.set_cookie("session", token, httponly=True, samesite="lax",
                    secure=COOKIE_SECURE, max_age=JWT_HOURS * 3600, path="/")
    return resp


@app.post("/auth/logout")
def logout(request: Request):
    u = usuario_actual(request)
    if u:
        _audit(u["email"], "logout", "", _client_ip(request))
    resp = JSONResponse({"ok": True})
    resp.delete_cookie("session", path="/")
    return resp


@app.get("/auth/me")
def me(request: Request):
    u = usuario_actual(request)
    if not u:
        return JSONResponse({"ok": False}, status_code=401)
    return {"ok": True, "email": u["email"], "name": u["name"], "role": u["role"]}


# ===========================================================================
# API DE LECTURA DEL MOTOR (consulta la DB del motor, read-only)
# ===========================================================================
def _require_user(request: Request):
    u = usuario_actual(request)
    if not u:
        return None, JSONResponse({"ok": False, "error": "No autenticado"}, status_code=401)
    return u, None


@app.get("/api/overview")
def api_overview(request: Request, range: str = "7d",
                 from_ts: str = "", to_ts: str = ""):
    """Métricas para las tarjetas y gráficos del dashboard.
    range: preset rápido (15m,30m,1h,3h,6h,12h,24h,7d,30d,90d,all)
    from_ts/to_ts: rango personalizado ISO (tienen prioridad sobre range)."""
    u, err = _require_user(request)
    if err:
        return err
    now = datetime.now(timezone.utc)
    since = None
    until = None
    if from_ts or to_ts:
        since = from_ts or None
        until = to_ts or None
    else:
        preset_minutes = {
            "15m": 15, "30m": 30, "1h": 60, "3h": 180, "6h": 360,
            "12h": 720, "24h": 1440, "7d": 10080, "30d": 43200, "90d": 129600,
        }
        if range != "all":
            mins = preset_minutes.get(range, 10080)
            since = (now - timedelta(minutes=mins)).isoformat()
    since_24h = (now - timedelta(hours=24)).isoformat()
    # Cláusula temporal reutilizable (since y/o until)
    conds = []
    if since:
        conds.append(f"created_at >= '{since}'")
    if until:
        conds.append(f"created_at <= '{until}'")
    tfilter = ("WHERE " + " AND ".join(conds)) if conds else ""
    tfilter_and = ("AND " + " AND ".join(conds)) if conds else ""
    try:
        with engine_db() as conn:
            total = conn.execute(
                f"SELECT COUNT(*) c FROM alerts {tfilter}").fetchone()["c"]
            # Veredictos reales (solo alertas done con verdict no nulo)
            by_verdict = {r["verdict"]: r["c"] for r in conn.execute(
                f"SELECT verdict, COUNT(*) c FROM alerts "
                f"WHERE verdict IS NOT NULL AND verdict != '' {tfilter_and} "
                f"GROUP BY verdict").fetchall()}
            # Alertas sin veredicto final (processing/error) — se cuentan aparte
            pending = conn.execute(
                f"SELECT COUNT(*) c FROM alerts "
                f"WHERE (verdict IS NULL OR verdict = '') "
                f"{tfilter_and}").fetchone()["c"]
            by_status = {r["status"] or "?": r["c"] for r in conn.execute(
                f"SELECT status, COUNT(*) c FROM alerts {tfilter} GROUP BY status").fetchall()}
            by_source = {r["s"] or "?": r["c"] for r in conn.execute(
                f"SELECT json_extract(result_json,'$.internal_analysis.verdict_source') s, "
                f"COUNT(*) c FROM alerts WHERE result_json IS NOT NULL AND status='done' "
                f"{tfilter_and} GROUP BY s").fetchall() if r["s"]}
            by_class = {r["alert_class"] or "?": r["c"] for r in conn.execute(
                f"SELECT alert_class, COUNT(*) c FROM alerts {tfilter} "
                f"GROUP BY alert_class").fetchall()}
            last_24h = conn.execute(
                "SELECT COUNT(*) c FROM alerts WHERE created_at >= ?", (since_24h,)
            ).fetchone()["c"]
            # Serie temporal: granularidad por hora si la ventana es corta (<48h), si no por día
            serie_since = since or (now - timedelta(days=90)).isoformat()
            short_window = False
            if since:
                try:
                    delta = now - datetime.fromisoformat(since.replace("Z", "+00:00"))
                    short_window = delta <= timedelta(hours=48)
                except (ValueError, TypeError):
                    short_window = False
            gran = 13 if short_window else 10  # 13=YYYY-MM-DDTHH (hora), 10=YYYY-MM-DD (día)
            serie_conds = [f"created_at >= '{serie_since}'"]
            if until:
                serie_conds.append(f"created_at <= '{until}'")
            serie_where = "WHERE " + " AND ".join(serie_conds)
            serie = conn.execute(
                f"SELECT substr(created_at,1,{gran}) d, COUNT(*) c FROM alerts "
                f"{serie_where} GROUP BY d ORDER BY d").fetchall()
            timeline = [{"date": r["d"], "count": r["c"]} for r in serie]
            signatures = conn.execute(
                "SELECT COUNT(*) c FROM behavior_signatures").fetchone()["c"]
            active_supp = conn.execute(
                "SELECT COUNT(*) c FROM suppressions WHERE active=1").fetchone()["c"]
            observables = conn.execute(
                "SELECT COUNT(*) c FROM observables").fetchone()["c"]
    except sqlite3.Error as e:
        return JSONResponse({"ok": False, "error": f"DB del motor: {e}"}, status_code=503)

    return {
        "ok": True,
        "range": range,
        "from": since,
        "to": until,
        "granularity": "hour" if short_window else "day",
        "total_alertas": total,
        "by_verdict": by_verdict,
        "pending": pending,
        "by_status": by_status,
        "by_source": by_source,
        "by_class": by_class,
        "last_24h": last_24h,
        "timeline": timeline,
        "signatures": signatures,
        "suppressions_active": active_supp,
        "observables": observables,
    }


@app.get("/api/alerts")
def api_alerts(request: Request, verdict: str = "", alert_class: str = "",
               source: str = "", observable: str = "", q: str = "", limit: int = 50, offset: int = 0):
    """Lista de alertas con filtros y búsqueda. Para la tabla principal."""
    u, err = _require_user(request)
    if err:
        return err
    limit = max(1, min(limit, 200))
    where, params = [], []
    if verdict:
        where.append("verdict = ?")
        params.append(verdict)
    if alert_class:
        where.append("alert_class = ?")
        params.append(alert_class)
    if source:
        where.append("json_extract(result_json,'$.internal_analysis.verdict_source') = ?")
        params.append(source)
    if observable:
        where.append("alert_id IN (SELECT alert_id FROM observables WHERE value = ?)")
        params.append(observable)
    if q:
        where.append("(alert_id LIKE ? OR signature LIKE ?)")
        params.extend([f"%{q}%", f"%{q}%"])
    clause = ("WHERE " + " AND ".join(where)) if where else ""
    try:
        with engine_db() as conn:
            total = conn.execute(
                f"SELECT COUNT(*) c FROM alerts {clause}", params).fetchone()["c"]
            rows = conn.execute(
                f"SELECT alert_id, signature, alert_class, classification, "
                f"priority_score, verdict, status, created_at FROM alerts {clause} "
                f"ORDER BY created_at DESC LIMIT ? OFFSET ?",
                params + [limit, offset]).fetchall()
    except sqlite3.Error as e:
        return JSONResponse({"ok": False, "error": f"DB del motor: {e}"}, status_code=503)
    return {"ok": True, "total": total, "limit": limit, "offset": offset,
            "alerts": [dict(r) for r in rows]}


@app.get("/api/alert/{alert_id}")
def api_alert_detail(alert_id: str, request: Request):
    """Detalle completo de una alerta (el contrato JSON del motor)."""
    u, err = _require_user(request)
    if err:
        return err
    try:
        with engine_db() as conn:
            row = conn.execute(
                "SELECT alert_id, verdict, status, priority_score, alert_class, "
                "classification, signature, result_json, raw_json, created_at "
                "FROM alerts WHERE alert_id=?",
                (alert_id,)).fetchone()
            if not row:
                return JSONResponse({"ok": False, "error": "No existe"}, status_code=404)
            obs = conn.execute(
                "SELECT type, value, is_public, verdict FROM observables WHERE alert_id=?",
                (alert_id,)).fetchall()
            corr = conn.execute(
                "SELECT related_alert_id, reason FROM correlations WHERE alert_id=?",
                (alert_id,)).fetchall()
    except sqlite3.Error as e:
        return JSONResponse({"ok": False, "error": f"DB del motor: {e}"}, status_code=503)
    import json as _json
    d = dict(row)
    try:
        d["result"] = _json.loads(d.pop("result_json")) if d.get("result_json") else None
    except (ValueError, TypeError):
        d["result"] = None
        d.pop("result_json", None)
    # raw_json: el JSON crudo original que recibió el motor (parseado si se puede)
    try:
        d["raw"] = _json.loads(d.pop("raw_json")) if d.get("raw_json") else None
    except (ValueError, TypeError):
        d["raw"] = d.get("raw_json")
        d.pop("raw_json", None)
    d["observables"] = [dict(o) for o in obs]
    d["correlations"] = [dict(c) for c in corr]
    return {"ok": True, "alert": d}


@app.post("/api/alert/{alert_id}/reprocess")
async def api_alert_reprocess(alert_id: str, request: Request):
    """Pide al MOTOR que re-analice una alerta con reglas/keys/línea base
    actuales. Acción sensible (modifica datos): solo admin. Auditada."""
    u, err = _admin_or_error(request)
    if err:
        return err
    # Verificar que la alerta exista (lectura read-only)
    try:
        with engine_db() as conn:
            row = conn.execute(
                "SELECT alert_id FROM alerts WHERE alert_id=?", (alert_id,)).fetchone()
            if not row:
                return JSONResponse({"ok": False, "error": "La alerta no existe"},
                                    status_code=404)
    except sqlite3.Error as e:
        return JSONResponse({"ok": False, "error": f"DB del motor: {e}"}, status_code=503)
    # Llamar al motor por HTTP (NO tocamos su DB; el motor reprocesa y escribe)
    import httpx
    headers = {}
    if ENGINE_API_KEY:
        headers["X-API-Key"] = ENGINE_API_KEY
    url = f"{ENGINE_URL}/api/alert/{alert_id}/reprocess"
    try:
        async with httpx.AsyncClient(timeout=ENGINE_TIMEOUT) as client:
            resp = await client.post(url, headers=headers)
    except httpx.RequestError as e:
        _audit(u["email"], "reprocess_fail", f"{alert_id}: {e}", _client_ip(request))
        return JSONResponse(
            {"ok": False, "error": f"No se pudo contactar al motor: {e}"},
            status_code=502)
    _audit(u["email"], "reprocess", alert_id, _client_ip(request))
    # El motor responde 200 (contrato) o 202 (processing)
    try:
        body = resp.json()
    except ValueError:
        body = {"raw": resp.text}
    return {"ok": True, "engine_status": resp.status_code, "result": body}


@app.get("/api/alert/{alert_id}/notes")
def api_alert_notes(alert_id: str, request: Request):
    """Notas de analistas sobre una alerta (en la DB del dashboard, no del motor)."""
    u, err = _require_user(request)
    if err:
        return err
    with dash_db() as conn:
        rows = conn.execute(
            "SELECT id, author, note, created_at FROM alert_notes "
            "WHERE alert_id=? ORDER BY id DESC", (alert_id,)).fetchall()
    return {"ok": True, "notes": [dict(r) for r in rows]}


@app.post("/api/alert/{alert_id}/notes")
def api_alert_note_create(alert_id: str, body: NoteCreate, request: Request):
    """Agrega una nota a una alerta. Cualquier usuario logueado puede comentar."""
    u, err = _require_user(request)
    if err:
        return err
    note = (body.note or "").strip()
    if not note:
        return JSONResponse({"ok": False, "error": "La nota está vacía"}, status_code=400)
    if len(note) > 2000:
        return JSONResponse({"ok": False, "error": "Nota demasiado larga (máx 2000)"},
                            status_code=400)
    with dash_db() as conn:
        conn.execute(
            "INSERT INTO alert_notes (alert_id, author, note, created_at) "
            "VALUES (?,?,?,?)", (alert_id, u["email"], note, _now()))
    _audit(u["email"], "note_add", alert_id, _client_ip(request))
    return {"ok": True}


@app.delete("/api/alert/{alert_id}/notes/{note_id}")
def api_alert_note_delete(alert_id: str, note_id: int, request: Request):
    """Borra una nota. Solo el autor o un admin."""
    u, err = _require_user(request)
    if err:
        return err
    with dash_db() as conn:
        n = conn.execute("SELECT author FROM alert_notes WHERE id=? AND alert_id=?",
                         (note_id, alert_id)).fetchone()
        if not n:
            return JSONResponse({"ok": False, "error": "No existe"}, status_code=404)
        if n["author"] != u["email"] and u["role"] != "admin":
            return JSONResponse({"ok": False, "error": "Solo el autor o un admin"},
                                status_code=403)
        conn.execute("DELETE FROM alert_notes WHERE id=?", (note_id,))
    _audit(u["email"], "note_delete", f"{alert_id}#{note_id}", _client_ip(request))
    return {"ok": True}


@app.get("/api/suppressions")
def api_suppressions(request: Request):
    """Supresiones de ruido (las firmas que el motor NO convierte en caso)."""
    u, err = _require_user(request)
    if err:
        return err
    try:
        with engine_db() as conn:
            rows = conn.execute(
                "SELECT signature, approved_by, active, created_at FROM suppressions "
                "ORDER BY created_at DESC LIMIT 200").fetchall()
    except sqlite3.Error as e:
        return JSONResponse({"ok": False, "error": f"DB del motor: {e}"}, status_code=503)
    return {"ok": True, "suppressions": [dict(r) for r in rows]}


@app.get("/api/top-iocs")
def api_top_iocs(request: Request, limit: int = 10):
    """IOCs (observables) que más se repiten en alertas maliciosas (true_positive).
    Lo que más aparece en lo que el motor confirmó como amenaza."""
    u, err = _require_user(request)
    if err:
        return err
    limit = max(1, min(limit, 50))
    try:
        with engine_db() as conn:
            # Observables de alertas true_positive, agrupados por valor
            rows = conn.execute(
                "SELECT o.type, o.value, COUNT(DISTINCT o.alert_id) c, "
                "MAX(o.verdict) verdict "
                "FROM observables o "
                "JOIN alerts a ON a.alert_id = o.alert_id "
                "WHERE a.verdict = 'true_positive' "
                "GROUP BY o.type, o.value "
                "ORDER BY c DESC, o.value LIMIT ?", (limit,)).fetchall()
    except sqlite3.Error as e:
        return JSONResponse({"ok": False, "error": f"DB del motor: {e}"}, status_code=503)
    return {"ok": True, "iocs": [dict(r) for r in rows]}


@app.get("/api/signatures")
def api_signatures(request: Request):
    """Firmas de comportamiento: las que más se repiten nutren la línea base.
    Son las alertas recurrentes que el motor usa para aprender qué es normal."""
    u, err = _require_user(request)
    if err:
        return err
    try:
        with engine_db() as conn:
            rows = conn.execute(
                "SELECT signature, first_seen, last_seen, count, marked_noise "
                "FROM behavior_signatures ORDER BY count DESC LIMIT 100").fetchall()
    except sqlite3.Error as e:
        return JSONResponse({"ok": False, "error": f"DB del motor: {e}"}, status_code=503)
    return {"ok": True, "signatures": [dict(r) for r in rows]}


@app.get("/api/audit")
def api_audit(request: Request):
    """Log de auditoría del panel (quién entró, qué tocó). Solo admin."""
    u, err = _admin_or_error(request)
    if err:
        return err
    with dash_db() as conn:
        rows = conn.execute(
            "SELECT actor, action, detail, ip, created_at FROM audit_log "
            "ORDER BY id DESC LIMIT 200").fetchall()
    return {"ok": True, "events": [dict(r) for r in rows]}


# ===========================================================================
# API DE GESTIÓN DE USUARIOS (solo admin)
# ===========================================================================
@app.get("/api/users")
def api_users(request: Request):
    u, err = _admin_or_error(request)
    if err:
        return err
    with dash_db() as conn:
        rows = conn.execute(
            "SELECT id, email, name, role, active, last_login, created_at "
            "FROM users ORDER BY id").fetchall()
    return {"ok": True, "users": [dict(r) for r in rows]}


@app.post("/api/users")
def api_user_create(body: UserCreate, request: Request):
    u, err = _admin_or_error(request)
    if err:
        return err
    email = body.email.strip().lower()
    role = body.role if body.role in ("admin", "viewer") else "viewer"
    if not email or "@" not in email:
        return JSONResponse({"ok": False, "error": "Email inválido"}, status_code=400)
    try:
        with dash_db() as conn:
            conn.execute(
                "INSERT INTO users (email, name, role, active, created_at) "
                "VALUES (?,?,?,1,?)", (email, body.name.strip(), role, _now()))
    except sqlite3.IntegrityError:
        return JSONResponse({"ok": False, "error": "Ese email ya existe"}, status_code=409)
    _audit(u["email"], "user_create", email, _client_ip(request))
    return {"ok": True}


@app.patch("/api/users/{uid}")
def api_user_patch(uid: int, body: UserPatch, request: Request):
    u, err = _admin_or_error(request)
    if err:
        return err
    with dash_db() as conn:
        target = conn.execute("SELECT * FROM users WHERE id=?", (uid,)).fetchone()
        if not target:
            return JSONResponse({"ok": False, "error": "No existe"}, status_code=404)
        target = dict(target)
        new_role = body.role if body.role in ("admin", "viewer") else target["role"]
        new_active = target["active"] if body.active is None else (1 if body.active else 0)
        new_name = target["name"] if body.name is None else body.name.strip()
        # Salvaguarda anti-lockout: no dejar 0 admins activos
        if target["role"] == "admin" and target["active"] == 1 and \
                (new_role != "admin" or new_active == 0):
            admins = conn.execute(
                "SELECT COUNT(*) c FROM users WHERE role='admin' AND active=1").fetchone()["c"]
            if admins <= 1:
                return JSONResponse(
                    {"ok": False, "error": "No podés dejar el panel sin admins activos."},
                    status_code=409)
        conn.execute("UPDATE users SET name=?, role=?, active=? WHERE id=?",
                     (new_name, new_role, new_active, uid))
    _audit(u["email"], "user_patch", f"id={uid}", _client_ip(request))
    return {"ok": True}


@app.delete("/api/users/{uid}")
def api_user_delete(uid: int, request: Request):
    u, err = _admin_or_error(request)
    if err:
        return err
    with dash_db() as conn:
        target = conn.execute("SELECT * FROM users WHERE id=?", (uid,)).fetchone()
        if not target:
            return JSONResponse({"ok": False, "error": "No existe"}, status_code=404)
        target = dict(target)
        # No auto-eliminación
        if target["email"] == u["email"]:
            return JSONResponse({"ok": False, "error": "No podés eliminarte a vos mismo."},
                                status_code=409)
        # No dejar 0 admins activos
        if target["role"] == "admin" and target["active"] == 1:
            admins = conn.execute(
                "SELECT COUNT(*) c FROM users WHERE role='admin' AND active=1").fetchone()["c"]
            if admins <= 1:
                return JSONResponse(
                    {"ok": False, "error": "No podés eliminar al último admin activo."},
                    status_code=409)
        conn.execute("DELETE FROM users WHERE id=?", (uid,))
    _audit(u["email"], "user_delete", f"id={uid}", _client_ip(request))
    return {"ok": True}


if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=APP_PORT)

"""
Agente 3 — Enricher de reputación externa (Fase 2, brief §5).

Consulta VirusTotal, AbuseIPDB, OTX y MISP para los observables PÚBLICOS
(IPs globales, hashes, dominios) que el Router marcó como enriquecibles.
Shodan queda declarado pero nunca se usa (tier free sin créditos API).

MISP es distinto a las otras fuentes: no es reputación de terceros sino
la inteligencia PROPIA del SOC (eventos curados + feeds confiables). Un
hit con to_ids=true es señal fuerte; aporta además contexto rico (evento,
threat level, tags, galaxies) para el dossier del analista.

Principios:
- CACHÉ primero (SQLite, TTL configurable, default 24 h): la misma IP
  atacante reportada 50 veces gasta UNA consulta de cuota.
- RATE LIMIT para VirusTotal (tier free: 4 req/min) → VT_MIN_INTERVAL
  segundos entre llamadas. Acá es donde una alerta puede superar los 25 s
  del POST y disparar el camino 202 → GET.
- DEGRADACIÓN ELEGANTE: si una fuente falla o no tiene key, su bloque
  queda {"status": "error"|"not_configured"} y se sigue con el resto.
  El motor NUNCA inventa reputación: sin dato verificado, no opina.
- Cada fuente devuelve evidencia cruda resumida + un sub-veredicto;
  el veredicto agregado del observable sale de umbrales documentados.
"""
import logging
import threading
import time

import httpx

from app import config, db

logger = logging.getLogger("vectus.enricher")

_TIMEOUT = httpx.Timeout(10.0, connect=5.0)

# Rate limit de VirusTotal: lock global + timestamp de última llamada real.
_vt_lock = threading.Lock()
_vt_last_call = 0.0

# Umbrales de veredicto por fuente (documentados para auditoría):
VT_MALICIOUS_MIN = 5        # motores que marcan malicioso → malicious
VT_SUSPICIOUS_MIN = 2       # → suspicious
ABUSE_MALICIOUS_MIN = 80    # abuseConfidenceScore → malicious
ABUSE_SUSPICIOUS_MIN = 25   # → suspicious
OTX_PULSES_SUSPICIOUS = 3   # presencia en pulsos de la comunidad → suspicious

# MISP: mapa de threat_level_id a etiqueta legible, y tope de matches.
_MISP_THREAT_LEVEL = {"1": "High", "2": "Medium", "3": "Low", "4": "Undefined"}
_MISP_MAX_MATCHES = 5


def _vt_wait_slot() -> None:
    """Respeta el intervalo mínimo entre llamadas reales a VT (tier free)."""
    global _vt_last_call
    with _vt_lock:
        elapsed = time.monotonic() - _vt_last_call
        if elapsed < config.VT_MIN_INTERVAL:
            time.sleep(config.VT_MIN_INTERVAL - elapsed)
        _vt_last_call = time.monotonic()


# Backoff entre reintentos (segundos). Módulo-level para tests.
_RETRY_BACKOFFS = (0.5, 1.5)


def _http_get(url: str, headers: dict, params: dict | None = None) -> dict:
    """
    GET con reintentos y backoff (Fase 3): los errores transitorios (timeouts,
    cortes de red, 5xx) se reintentan hasta ENRICH_RETRIES veces; los 4xx son
    definitivos y no se reintentan (un 404 es una respuesta, no una falla).
    Lanza la última excepción para que el caller degrade con elegancia.
    """
    last_exc: Exception = RuntimeError("sin intentos")
    for attempt in range(1 + config.ENRICH_RETRIES):
        try:
            resp = httpx.get(url, headers=headers, params=params, timeout=_TIMEOUT)
            resp.raise_for_status()
            return resp.json()
        except httpx.HTTPStatusError as exc:
            if exc.response.status_code < 500:
                raise                       # 4xx: definitivo, no reintentar
            last_exc = exc
        except httpx.HTTPError as exc:      # timeouts, transporte
            last_exc = exc
        if attempt < config.ENRICH_RETRIES:
            time.sleep(_RETRY_BACKOFFS[min(attempt, len(_RETRY_BACKOFFS) - 1)])
    raise last_exc


def _http_post(url: str, headers: dict, json_body: dict, verify: bool = True) -> dict:
    """
    POST con reintentos/backoff, misma semántica que _http_get. MISP usa POST
    en /attributes/restSearch. `verify` permite desactivar la validación TLS
    para el certificado self-signed de MISP en red interna.
    """
    last_exc: Exception = RuntimeError("sin intentos")
    for attempt in range(1 + config.ENRICH_RETRIES):
        try:
            resp = httpx.post(url, headers=headers, json=json_body,
                              timeout=_TIMEOUT, verify=verify)
            resp.raise_for_status()
            return resp.json()
        except httpx.HTTPStatusError as exc:
            if exc.response.status_code < 500:
                raise                       # 4xx: definitivo, no reintentar
            last_exc = exc
        except httpx.HTTPError as exc:      # timeouts, transporte
            last_exc = exc
        if attempt < config.ENRICH_RETRIES:
            time.sleep(_RETRY_BACKOFFS[min(attempt, len(_RETRY_BACKOFFS) - 1)])
    raise last_exc


# --------------------------------------------------------------------------
# Fuentes
# --------------------------------------------------------------------------

def query_virustotal(obs_type: str, value: str) -> dict:
    """VT v3: /ip_addresses, /files o /domains según el tipo de observable."""
    if not config.VIRUSTOTAL_API_KEY:
        return {"status": "not_configured"}
    path = {"ip": "ip_addresses", "hash_sha256": "files", "hash_md5": "files",
            "domain": "domains", "url": None, "cve": None}.get(obs_type)
    if path is None:
        return {"status": "not_applicable"}

    cache_key = f"vt:{obs_type}:{value}"
    cached = db.cache_get(cache_key, config.ENRICH_CACHE_TTL_HOURS)
    if cached is not None:
        return {**cached, "from_cache": True}

    _vt_wait_slot()
    try:
        data = _http_get(f"https://www.virustotal.com/api/v3/{path}/{value}",
                         headers={"x-apikey": config.VIRUSTOTAL_API_KEY})
    except httpx.HTTPStatusError as exc:
        if exc.response.status_code == 404:
            result = {"status": "done", "found": False}
            db.cache_set(cache_key, result)
            return result
        logger.warning("VT error %s para %s", exc.response.status_code, value)
        return {"status": "error", "detail": f"HTTP {exc.response.status_code}"}
    except httpx.HTTPError as exc:
        logger.warning("VT inaccesible para %s: %s", value, exc)
        return {"status": "error", "detail": str(exc)}

    attrs = (data.get("data", {}) or {}).get("attributes", {}) or {}
    stats = attrs.get("last_analysis_stats", {}) or {}
    result = {
        "status": "done",
        "found": True,
        "malicious": stats.get("malicious", 0),
        "suspicious": stats.get("suspicious", 0),
        "harmless": stats.get("harmless", 0),
        "undetected": stats.get("undetected", 0),
        "reputation": attrs.get("reputation"),
        "tags": (attrs.get("tags") or [])[:10],
        "as_owner": attrs.get("as_owner", ""),
        "country": attrs.get("country", ""),
    }
    db.cache_set(cache_key, result)
    return result


def query_abuseipdb(obs_type: str, value: str) -> dict:
    """AbuseIPDB /check: solo aplica a IPs."""
    if obs_type != "ip":
        return {"status": "not_applicable"}
    if not config.ABUSEIPDB_API_KEY:
        return {"status": "not_configured"}

    cache_key = f"abuse:ip:{value}"
    cached = db.cache_get(cache_key, config.ENRICH_CACHE_TTL_HOURS)
    if cached is not None:
        return {**cached, "from_cache": True}

    try:
        data = _http_get("https://api.abuseipdb.com/api/v2/check",
                         headers={"Key": config.ABUSEIPDB_API_KEY,
                                  "Accept": "application/json"},
                         params={"ipAddress": value, "maxAgeInDays": 90})
    except httpx.HTTPError as exc:
        logger.warning("AbuseIPDB inaccesible para %s: %s", value, exc)
        return {"status": "error", "detail": str(exc)}

    d = data.get("data", {}) or {}
    result = {
        "status": "done",
        "abuse_confidence": d.get("abuseConfidenceScore", 0),
        "total_reports": d.get("totalReports", 0),
        "country": d.get("countryCode", ""),
        "isp": d.get("isp", ""),
        "usage_type": d.get("usageType", ""),
        "is_tor": d.get("isTor", False),
        "last_reported_at": d.get("lastReportedAt", ""),
    }
    db.cache_set(cache_key, result)
    return result


def query_otx(obs_type: str, value: str) -> dict:
    """AlienVault OTX: sección general del indicador (pulsos de comunidad)."""
    if not config.OTX_API_KEY:
        return {"status": "not_configured"}
    section = {"ip": "IPv4", "domain": "domain",
               "hash_sha256": "file", "hash_md5": "file"}.get(obs_type)
    if section is None:
        return {"status": "not_applicable"}

    cache_key = f"otx:{obs_type}:{value}"
    cached = db.cache_get(cache_key, config.ENRICH_CACHE_TTL_HOURS)
    if cached is not None:
        return {**cached, "from_cache": True}

    try:
        data = _http_get(
            f"https://otx.alienvault.com/api/v1/indicators/{section}/{value}/general",
            headers={"X-OTX-API-KEY": config.OTX_API_KEY})
    except httpx.HTTPError as exc:
        logger.warning("OTX inaccesible para %s: %s", value, exc)
        return {"status": "error", "detail": str(exc)}

    pulses = (data.get("pulse_info", {}) or {})
    pulse_list = pulses.get("pulses", []) or []
    result = {
        "status": "done",
        "pulse_count": pulses.get("count", 0),
        "pulse_names": [p.get("name", "") for p in pulse_list[:5]],
    }
    db.cache_set(cache_key, result)
    return result


def query_misp(obs_type: str, value: str) -> dict:
    """
    Inteligencia PROPIA en MISP (/attributes/restSearch). A diferencia de
    VT/Abuse/OTX (reputación de terceros), MISP es inteligencia curada del
    SOC: un hit con to_ids=true es señal fuerte. Devuelve contexto rico
    (evento, threat level, tags, galaxies) hasta _MISP_MAX_MATCHES matches.
    Cachea como las demás fuentes. Self-signed cert → verify configurable.
    """
    if not config.MISP_URL or not config.MISP_API_KEY:
        return {"status": "not_configured"}
    if obs_type not in ("ip", "domain", "url", "hash_sha256", "hash_md5", "file"):
        return {"status": "not_applicable"}

    cache_key = f"misp:{obs_type}:{value}"
    cached = db.cache_get(cache_key, config.ENRICH_CACHE_TTL_HOURS)
    if cached is not None:
        return {**cached, "from_cache": True}

    headers = {
        "Authorization": config.MISP_API_KEY,
        "Accept": "application/json",
        "Content-Type": "application/json",
    }
    body = {
        "returnFormat": "json",
        "value": value,
        "limit": _MISP_MAX_MATCHES * 4,   # traemos algo más y recortamos tras parsear
        "includeEventTags": True,
        "includeContext": True,
        "enforceWarninglist": False,
    }
    try:
        data = _http_post(f"{config.MISP_URL}/attributes/restSearch",
                          headers=headers, json_body=body,
                          verify=config.MISP_VERIFY_SSL)
    except httpx.HTTPError as exc:
        logger.warning("MISP inaccesible para %s: %s", value, exc)
        return {"status": "error", "detail": str(exc)}

    attrs = (data.get("response", {}) or {}).get("Attribute", []) or []
    if not attrs:
        result = {"status": "done", "found": False}
        db.cache_set(cache_key, result)
        return result

    matches = []
    any_to_ids = False
    for a in attrs[:_MISP_MAX_MATCHES]:
        ev = a.get("Event", {}) or {}
        to_ids = bool(a.get("to_ids", False))
        any_to_ids = any_to_ids or to_ids
        tags = []
        for src in ((a.get("Tag", []) or []), (ev.get("Tag", []) or [])):
            for t in src:
                name = t.get("name", "")
                if name and name not in tags:
                    tags.append(name)
        galaxies = []
        for g in (a.get("Galaxy", []) or []) + (ev.get("Galaxy", []) or []):
            gname = g.get("name", "")
            for cl in (g.get("GalaxyCluster", []) or []):
                gval = cl.get("value", "")
                if gval:
                    galaxies.append(f"{gname}: {gval}" if gname else gval)
        matches.append({
            "attribute_type": a.get("type", ""),
            "category": a.get("category", ""),
            "to_ids": to_ids,
            "comment": a.get("comment", ""),
            "event_id": ev.get("id", ""),
            "event_info": ev.get("info", ""),
            "event_uuid": ev.get("uuid", ""),
            "threat_level": _MISP_THREAT_LEVEL.get(
                str(ev.get("threat_level_id", "")), "Undefined"),
            "org": (ev.get("Orgc", {}) or {}).get("name", "")
                   or (ev.get("Org", {}) or {}).get("name", ""),
            "date": ev.get("date", ""),
            "tags": tags,
            "galaxies": galaxies,
        })

    result = {
        "status": "done",
        "found": True,
        "to_ids": any_to_ids,
        "match_count": len(attrs),
        "matches": matches,
    }
    db.cache_set(cache_key, result)
    return result


# --------------------------------------------------------------------------
# Agregación
# --------------------------------------------------------------------------

def _aggregate_verdict(vt: dict, abuse: dict, otx: dict, misp: dict) -> tuple[str, list[str]]:
    """Veredicto del observable + razones, SOLO sobre datos verificados."""
    reasons: list[str] = []
    level = 0   # 0 unknown/clean, 1 suspicious, 2 malicious
    has_data = False

    if vt.get("status") == "done" and vt.get("found"):
        has_data = True
        m = vt.get("malicious", 0)
        if m >= VT_MALICIOUS_MIN:
            level = max(level, 2)
            reasons.append(f"VirusTotal: {m} motores lo marcan malicioso")
        elif m >= VT_SUSPICIOUS_MIN:
            level = max(level, 1)
            reasons.append(f"VirusTotal: {m} motores lo marcan malicioso (umbral sospechoso)")
    if abuse.get("status") == "done":
        has_data = True
        score = abuse.get("abuse_confidence", 0)
        if score >= ABUSE_MALICIOUS_MIN:
            level = max(level, 2)
            reasons.append(f"AbuseIPDB: confianza de abuso {score}% "
                           f"({abuse.get('total_reports', 0)} reportes)")
        elif score >= ABUSE_SUSPICIOUS_MIN:
            level = max(level, 1)
            reasons.append(f"AbuseIPDB: confianza de abuso {score}%")
        if abuse.get("is_tor"):
            level = max(level, 1)
            reasons.append("AbuseIPDB: nodo de salida Tor")
    if otx.get("status") == "done":
        has_data = True
        pc = otx.get("pulse_count", 0)
        if pc >= OTX_PULSES_SUSPICIOUS:
            level = max(level, 1)
            reasons.append(f"OTX: presente en {pc} pulsos de la comunidad")
    # MISP: inteligencia propia curada. Pesa fuerte cuando hay hit.
    if misp.get("status") == "done" and misp.get("found"):
        has_data = True
        m0 = misp["matches"][0] if misp.get("matches") else {}
        ev_info = m0.get("event_info", "?")
        tl = m0.get("threat_level", "?")
        mtags = m0.get("tags", []) or []
        tagstr = f", tags: {', '.join(mtags[:4])}" if mtags else ""
        extra = (f" (+{misp['match_count'] - 1} match(es) más)"
                 if misp.get("match_count", 0) > 1 else "")
        if misp.get("to_ids"):
            level = max(level, 2)
            reasons.append(f"MISP: IOC conocido en '{ev_info}' "
                           f"(threat level {tl}{tagstr}){extra}")
        else:
            level = max(level, 1)
            reasons.append(f"MISP: presente en '{ev_info}' pero no marcado "
                           f"para detección (threat level {tl}{tagstr}){extra}")

    if not has_data:
        return "unknown", ["sin datos verificados de ninguna fuente"]
    return {0: "clean", 1: "suspicious", 2: "malicious"}[level], \
        reasons or ["sin señales negativas en las fuentes consultadas"]


def enrich(normalized: dict, routing: dict) -> dict:
    """
    Punto de entrada del agente. Enriquece los observables externos del
    routing y devuelve el bloque `enrichment` del contrato + actualiza
    el verdict/sources de cada observable en la estructura normalizada.
    """
    externals = routing.get("external_observables", [])
    if not externals:
        return {
            "status": "no_external_observables",
            "virustotal": {"status": "not_applicable"},
            "abuseipdb": {"status": "not_applicable"},
            "otx": {"status": "not_applicable"},
            "misp": {"status": "not_applicable"},
            "shodan": {"status": "not_configured"},
        }

    any_configured = any([config.VIRUSTOTAL_API_KEY, config.ABUSEIPDB_API_KEY,
                          config.OTX_API_KEY,
                          (config.MISP_URL and config.MISP_API_KEY)])
    if not any_configured:
        return {
            "status": "not_configured",
            "virustotal": {"status": "not_configured"},
            "abuseipdb": {"status": "not_configured"},
            "otx": {"status": "not_configured"},
            "misp": {"status": "not_configured"},
            "shodan": {"status": "not_configured"},
        }

    vt_all, abuse_all, otx_all, misp_all = {}, {}, {}, {}
    errors = 0
    for obs in externals:
        t, v = obs["type"], obs["value"]
        vt = query_virustotal(t, v)
        abuse = query_abuseipdb(t, v)
        otx = query_otx(t, v)
        misp = query_misp(t, v)
        vt_all[v], abuse_all[v], otx_all[v], misp_all[v] = vt, abuse, otx, misp
        errors += sum(1 for r in (vt, abuse, otx, misp) if r.get("status") == "error")

        verdict, reasons = _aggregate_verdict(vt, abuse, otx, misp)
        # Actualizar el observable en la estructura normalizada (por referencia)
        for o in normalized["observables"]:
            if o["type"] == t and o["value"] == v:
                o["verdict"] = verdict
                o["sources"] = {"virustotal": vt, "abuseipdb": abuse, "otx": otx,
                                "misp": misp, "reasons": reasons}

    if errors and config.ENRICH_FAIL_HARD:
        raise RuntimeError(f"enriquecimiento con {errors} errores y ENRICH_FAIL_HARD=true")

    return {
        "status": "partial" if errors else "done",
        "virustotal": vt_all,
        "abuseipdb": abuse_all,
        "otx": otx_all,
        "misp": misp_all,
        "shodan": {"status": "not_configured"},
    }

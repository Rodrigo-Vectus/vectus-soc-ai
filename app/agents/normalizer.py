"""
Agente 1 — Normalizador (brief §5).

Recibe el JSON crudo de Wazuh (cualquier agente, cualquier formato) y
produce la ESTRUCTURA INTERNA ESTÁNDAR sobre la que trabaja toda la
cadena. Es la base del contrato de salida estandarizado.

Responsabilidades:
- Desanidar `_source` (las alertas llegan envueltas por el índice de
  Elasticsearch/OpenSearch). Si el body ya es el _source pelado, se toma
  directo: soportamos ambos.
- Detectar la FAMILIA: network, windows_event (EventChannel `data.win.*`
  Y formato viejo WinEvtLog), syscheck_fim, rootcheck, apparmor, ossec,
  generic.
- Producir la abstracción "acción" común: {actor, operation, resource,
  outcome, detail} — permite razonar comportamiento interno sin IOCs.
- Extraer observables (IPs, hashes, dominios, URLs, CVEs, usuarios,
  procesos, archivos) con marca de público/privado y de IOC genérico.
- Extraer MITRE de rule.mitre, con mapa de fallback.
- Derivar el alert_id idempotente y la firma de comportamiento.
"""
import hashlib
import ipaddress
import json
import re

# IOCs genéricos: que dos alertas mencionen `root` NO las relaciona (brief §5,
# agente 5). Se extraen igual (todo se guarda) pero marcados para excluirlos
# de correlación y de key_observable.
GENERIC_IOCS = {
    "root", "admin", "administrator", "system", "nt authority\\system",
    "local service", "network service", "guest", "anonymous logon",
}

_RE_IPV4 = re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b")
_RE_SHA256 = re.compile(r"\b[a-fA-F0-9]{64}\b")
_RE_MD5 = re.compile(r"\b[a-fA-F0-9]{32}\b")
_RE_CVE = re.compile(r"\bCVE-\d{4}-\d{4,7}\b", re.IGNORECASE)
_RE_URL = re.compile(r"\bhttps?://[^\s\"']+", re.IGNORECASE)
_RE_APPARMOR = re.compile(
    r'apparmor="(?P<status>\w+)"\s+operation="(?P<operation>[^"]+)"'
    r'(?:\s+class="[^"]*")?\s+profile="(?P<profile>[^"]+)"\s+name="(?P<name>[^"]+)"'
    r'.*?comm="(?P<comm>[^"]+)"',
    re.DOTALL,
)

# Mapa de fallback MITRE cuando rule.mitre no viene (brief §5, agente 1).
# Conservador: solo técnicas con sustento directo en el tipo de evento.
# Veredicto firme apoyado en evidencia real — nunca inventado (§4.2).
MITRE_FALLBACK_BY_GROUP = {
    "authentication_failed": ["T1110"],      # Brute Force (intentos fallidos)
    "invalid_login": ["T1110"],
}
MITRE_FALLBACK_BY_RULE_ID = {
    "504": ["T1562.001"],   # Agent disconnected → posible Impair Defenses
}


def _is_public_ip(value: str) -> bool:
    try:
        ip = ipaddress.ip_address(value)
        return ip.is_global
    except ValueError:
        return False


def _walk_strings(obj) -> str:
    """Concatena todos los strings de un dict anidado (para regex globales)."""
    parts: list[str] = []
    if isinstance(obj, dict):
        for v in obj.values():
            parts.append(_walk_strings(v))
    elif isinstance(obj, list):
        for v in obj:
            parts.append(_walk_strings(v))
    elif isinstance(obj, str):
        parts.append(obj)
    return " ".join(p for p in parts if p)


# --------------------------------------------------------------------------
# Detección de familia
# --------------------------------------------------------------------------

_NETWORK_GROUP_HINTS = {
    "sshd", "firewall", "ids", "web", "attack", "web_scan", "recon",
    "authentication_failures", "invalid_login", "fortigate", "pfsense",
}


def detect_family(src: dict) -> str:
    """Orden de detección: lo más específico primero."""
    groups = set(src.get("rule", {}).get("groups", []) or [])
    location = src.get("location", "") or ""
    decoder = (src.get("decoder", {}) or {}).get("name", "") or ""
    data = src.get("data", {}) or {}

    if "syscheck" in src or location == "syscheck" or decoder.startswith("syscheck"):
        return "syscheck_fim"
    if "rootcheck" in groups or location == "rootcheck" or decoder == "rootcheck":
        return "rootcheck"
    if "apparmor" in groups:
        return "apparmor"
    if isinstance(data.get("win"), dict):
        return "windows_event"          # formato EventChannel (data.win.*)
    if decoder in ("windows", "windows_eventchannel") or \
            (src.get("predecoder", {}) or {}).get("program_name") == "WinEvtLog":
        return "windows_event"          # formato viejo WinEvtLog
    if data.get("srcip") or data.get("src_ip") or (groups & _NETWORK_GROUP_HINTS):
        return "network"
    if "ossec" in groups or location.startswith("wazuh-") or decoder == "ossec":
        return "ossec"
    return "generic"


# --------------------------------------------------------------------------
# Extracción por familia: acción + metadatos + observables específicos
# --------------------------------------------------------------------------

def _norm_windows(src: dict, out: dict) -> None:
    """Soporta EventChannel (data.win.*) y formato viejo (data.* plano)."""
    data = src.get("data", {}) or {}
    win = data.get("win")
    if isinstance(win, dict):                       # --- EventChannel ---
        system = win.get("system", {}) or {}
        eventdata = win.get("eventdata", {}) or {}
        event_id = str(system.get("eventID", ""))
        target_user = eventdata.get("targetUserName", "")
        subject_user = eventdata.get("subjectUserName", "")
        logon_type = str(eventdata.get("logonType", ""))
        computer = system.get("computer", "")
        out["win_meta"] = {
            "format": "eventchannel",
            "event_id": event_id,
            "logon_type": logon_type,
            "target_user": target_user,
            "subject_user": subject_user,
            "target_domain": eventdata.get("targetDomainName", ""),
            "computer": computer,
            "process_name": eventdata.get("processName", ""),
            "ip_address": eventdata.get("ipAddress", ""),
            "workstation": eventdata.get("workstationName", ""),
            "outcome": system.get("severityValue", ""),
        }
        actor = target_user or subject_user
        process = eventdata.get("processName", "")
    else:                                           # --- WinEvtLog viejo ---
        subject = data.get("subject", {}) or {}
        event_id = str(data.get("id", ""))
        target_user = data.get("dstuser", "") or subject.get("account_name", "")
        logon_type = str(data.get("logon_type", ""))
        computer = data.get("system_name", "")
        out["win_meta"] = {
            "format": "winevtlog",
            "event_id": event_id,
            "logon_type": logon_type,
            "target_user": target_user,
            "subject_user": subject.get("account_name", ""),
            "target_domain": subject.get("account_domain", ""),
            "computer": computer,
            "process_name": "",
            "ip_address": data.get("srcip", ""),
            "workstation": "",
            "outcome": data.get("status", ""),
        }
        actor = target_user
        process = ""

    op_map = {"4624": "logon", "4634": "logoff", "4647": "logoff",
              "4625": "logon_failed", "4672": "privileged_logon"}
    operation = op_map.get(event_id, f"win_event_{event_id}")
    outcome = "success" if "SUCCESS" in (out["win_meta"]["outcome"] or "").upper() else \
              ("failure" if event_id == "4625" else "observed")
    out["action"] = {
        "actor": actor,
        "operation": operation,
        "resource": computer or out["asset"],
        "outcome": outcome,
        "detail": f"event_id={event_id} logon_type={logon_type}".strip(),
    }
    if actor:
        out["observables"].append(_obs("user", actor))
    if process:
        out["observables"].append(_obs("process", process))
    src_ip = out["win_meta"].get("ip_address", "")
    if src_ip and src_ip not in ("-", "::1", "127.0.0.1"):
        out["observables"].append(_obs("ip", src_ip))

    # Observables de alto valor de eventos Sysmon/Windows (vienen en `data`).
    hashes = data.get("hashes", {}) or {}
    sha256 = hashes.get("sha256", "") or data.get("sha256", "")
    if sha256:
        out["observables"].append(_obs("hash_sha256", sha256, is_public=True))
    md5 = hashes.get("md5", "") or data.get("md5", "")
    if md5:
        out["observables"].append(_obs("hash_md5", md5, is_public=True))
    image = data.get("image", "")
    if image:
        out["observables"].append(_obs("file", image))
        out["win_meta"]["image"] = image
    parent_image = data.get("parent_image", "")
    if parent_image:
        out["observables"].append(_obs("file", parent_image))
    cmdline = data.get("command_line", "")
    if cmdline:
        out["observables"].append(_obs("process", cmdline))
        out["win_meta"]["command_line"] = cmdline
    task_name = data.get("task_name", "")
    if task_name:
        out["observables"].append(_obs("other", task_name))
        out["win_meta"]["task_name"] = task_name
    task_action = data.get("task_action", "")
    if task_action:
        out["observables"].append(_obs("process", task_action))


def _norm_fim(src: dict, out: dict) -> None:
    sc = src.get("syscheck", {}) or {}
    path = sc.get("path", "")
    event = sc.get("event", "")
    changed = sc.get("changed_attributes", []) or []
    out["fim_meta"] = {
        "path": path,
        "event": event,
        "mode": sc.get("mode", ""),
        "changed_attributes": changed,
        "uname_after": sc.get("uname_after", ""),
        "perm_after": sc.get("perm_after", ""),
        "size_after": sc.get("size_after", ""),
        "sha256_before": sc.get("sha256_before", ""),
        "sha256_after": sc.get("sha256_after", ""),
        "md5_after": sc.get("md5_after", ""),
        "inode_before": sc.get("inode_before", ""),
        "inode_after": sc.get("inode_after", ""),
        "content_changed": any(a in changed for a in ("sha256", "sha1", "md5", "size")),
    }
    out["action"] = {
        "actor": sc.get("uname_after", "") or "desconocido",
        "operation": f"file_{event or 'change'}",
        "resource": path,
        "outcome": "changed",
        "detail": "changed_attributes=" + ",".join(changed) if changed else event,
    }
    if path:
        out["observables"].append(_obs("file", path))
    # Para FIM se enriquece solo sha256_after (un hash) — brief §5, agente 3.
    if sc.get("sha256_after"):
        out["observables"].append(_obs("hash_sha256", sc["sha256_after"], is_public=True))


def _norm_rootcheck(src: dict, out: dict) -> None:
    data = src.get("data", {}) or {}
    file_ = data.get("file", "")
    title = data.get("title", "") or src.get("full_log", "")
    out["rootcheck_meta"] = {"file": file_, "title": title}
    out["action"] = {
        "actor": "rootcheck",
        "operation": "policy_anomaly",
        "resource": file_ or out["asset"],
        "outcome": "detected",
        "detail": title,
    }
    if file_:
        out["observables"].append(_obs("file", file_))


def _norm_apparmor(src: dict, out: dict) -> None:
    data = src.get("data", {}) or {}
    full_log = src.get("full_log", "") or ""
    m = _RE_APPARMOR.search(full_log)
    meta = {
        "status": data.get("status", ""),
        "operation": data.get("extra_data", ""),
        "profile": "", "name": "", "comm": "",
    }
    if m:
        meta.update({k: m.group(k) for k in ("status", "operation", "profile", "name", "comm")})
    out["apparmor_meta"] = meta
    out["action"] = {
        "actor": meta["comm"] or "desconocido",
        "operation": meta["operation"] or "apparmor_event",
        "resource": meta["name"] or out["asset"],
        "outcome": (meta["status"] or "").lower() or "observed",
        "detail": f"profile={meta['profile']}" if meta["profile"] else "",
    }
    if meta["comm"]:
        out["observables"].append(_obs("process", meta["comm"]))
    if meta["name"]:
        out["observables"].append(_obs("file", meta["name"]))


def _norm_ossec(src: dict, out: dict) -> None:
    full_log = src.get("full_log", "") or ""
    rule_desc = src.get("rule", {}).get("description", "")
    # Caso típico: "ossec: Agent disconnected: 'Forti-EMS-any'."
    m = re.search(r"Agent (\w+): '([^']+)'", full_log)
    status, target = (m.group(1).lower(), m.group(2)) if m else ("", "")
    out["ossec_meta"] = {"event": rule_desc, "target": target, "status": status}
    out["action"] = {
        "actor": "wazuh-manager",
        "operation": "agent_status" if "agent" in rule_desc.lower() else "ossec_event",
        "resource": target or out["asset"],
        "outcome": status or "observed",
        "detail": rule_desc,
    }


def _norm_network(src: dict, out: dict) -> None:
    data = src.get("data", {}) or {}
    srcip = data.get("srcip") or data.get("src_ip") or ""
    dstip = data.get("dstip") or data.get("dst_ip") or ""
    user = data.get("srcuser") or data.get("dstuser") or ""
    out["net_meta"] = {
        "srcip": srcip, "dstip": dstip, "srcport": data.get("srcport", ""),
        "dstport": data.get("dstport", ""), "protocol": data.get("protocol", ""),
        "user": user,
    }
    out["action"] = {
        "actor": srcip or user or "desconocido",
        "operation": src.get("rule", {}).get("description", "network_event"),
        "resource": dstip or out["asset"],
        "outcome": "observed",
        "detail": f"dstport={data.get('dstport', '')}" if data.get("dstport") else "",
    }
    for ip in (srcip, dstip):
        if ip:
            out["observables"].append(_obs("ip", ip))
    if user:
        out["observables"].append(_obs("user", user))


def _norm_generic(src: dict, out: dict) -> None:
    out["action"] = {
        "actor": "desconocido",
        "operation": src.get("rule", {}).get("description", "evento"),
        "resource": out["asset"],
        "outcome": "observed",
        "detail": (src.get("full_log", "") or "")[:300],
    }


_FAMILY_HANDLERS = {
    "windows_event": _norm_windows,
    "syscheck_fim": _norm_fim,
    "rootcheck": _norm_rootcheck,
    "apparmor": _norm_apparmor,
    "ossec": _norm_ossec,
    "network": _norm_network,
    "generic": _norm_generic,
}


# --------------------------------------------------------------------------
# Observables
# --------------------------------------------------------------------------

def _obs(type_: str, value: str, is_public: bool | None = None) -> dict:
    if is_public is None:
        is_public = _is_public_ip(value) if type_ == "ip" else False
    return {
        "type": type_,
        "value": value,
        "is_public": bool(is_public),
        "is_generic": value.strip().lower() in GENERIC_IOCS,
        "verdict": "unknown",
        "sources": {},
    }


def _dedup_observables(items: list[dict]) -> list[dict]:
    seen, result = set(), []
    for o in items:
        key = (o["type"], o["value"])
        if key not in seen:
            seen.add(key)
            result.append(o)
    return result


def _global_observables(src: dict, out: dict) -> None:
    """Barrido por regex sobre todos los strings: IPs públicas, CVEs, URLs.

    No se barren hashes globalmente para evitar falsos positivos (GUIDs,
    ids hex de OpenSearch): los hashes salen de campos estructurados (FIM).
    """
    blob = _walk_strings(src.get("data", {})) + " " + (src.get("full_log", "") or "")
    for ip in _RE_IPV4.findall(blob):
        if _is_public_ip(ip):
            out["observables"].append(_obs("ip", ip))
    for cve in _RE_CVE.findall(blob):
        out["observables"].append(_obs("cve", cve.upper()))
    for url in _RE_URL.findall(blob):
        out["observables"].append(_obs("url", url))


# --------------------------------------------------------------------------
# MITRE
# --------------------------------------------------------------------------

def _extract_mitre(src: dict) -> list[str]:
    rule = src.get("rule", {}) or {}
    mitre = rule.get("mitre") or {}
    ids = mitre.get("id") if isinstance(mitre, dict) else None
    if ids:
        return sorted({str(i) for i in ids})
    # Fallback conservador por grupos / rule id.
    techniques: set[str] = set()
    for g in rule.get("groups", []) or []:
        techniques.update(MITRE_FALLBACK_BY_GROUP.get(g, []))
    techniques.update(MITRE_FALLBACK_BY_RULE_ID.get(str(rule.get("id", "")), []))
    return sorted(techniques)


# --------------------------------------------------------------------------
# Identidad: alert_id idempotente + firma de comportamiento
# --------------------------------------------------------------------------

def derive_alert_id(src: dict, raw: dict) -> str:
    """
    Id único derivado de la alerta de Wazuh (brief §10, idempotencia):
    agent.id + id interno del manager. Si faltan, SHA-256 del JSON crudo.
    """
    wazuh_id = src.get("id", "")
    agent_id = (src.get("agent", {}) or {}).get("id", "")
    if wazuh_id:
        return f"{agent_id or 'na'}-{wazuh_id}"
    digest = hashlib.sha256(
        json.dumps(raw, sort_keys=True, ensure_ascii=False).encode()
    ).hexdigest()
    return f"hash-{digest[:24]}"


def behavior_signature(out: dict) -> str:
    """Firma de comportamiento: agente | regla | recurso de la acción.

    Es la unidad que cuenta el anti-ruido supervisado (Fase 3)."""
    return "|".join([
        out["asset"],
        str(out["rule"].get("id", "")),
        out["action"].get("resource", "") or "",
    ])


# --------------------------------------------------------------------------
# Entrada principal del agente
# --------------------------------------------------------------------------

def normalize(raw: dict) -> dict:
    """Punto de entrada del Agente 1. Devuelve la estructura interna estándar."""
    if not isinstance(raw, dict) or not raw:
        raise ValueError("la alerta debe ser un objeto JSON no vacío")

    src = raw.get("_source", raw)            # desanidar wrapper de OpenSearch
    if not isinstance(src, dict) or not src.get("rule"):
        raise ValueError("alerta sin estructura de Wazuh reconocible (falta 'rule')")

    rule = src.get("rule", {}) or {}
    agent = src.get("agent", {}) or {}
    family = detect_family(src)

    out: dict = {
        "alert_id": derive_alert_id(src, raw),
        "family": family,
        "asset": agent.get("name", "") or "desconocido",
        "agent": {"id": agent.get("id", ""), "name": agent.get("name", ""),
                  "ip": agent.get("ip", "")},
        "timestamp": src.get("timestamp", ""),
        "rule": {
            "id": str(rule.get("id", "")),
            "level": rule.get("level"),
            "description": rule.get("description", ""),
            "groups": rule.get("groups", []) or [],
            "firedtimes": rule.get("firedtimes"),
        },
        "full_log": src.get("full_log", "") or "",
        "action": {},
        "observables": [],
        "mitre": _extract_mitre(src),
        "raw_source": src,
    }

    _FAMILY_HANDLERS[family](src, out)
    _global_observables(src, out)
    out["observables"] = _dedup_observables(out["observables"])
    out["signature"] = behavior_signature(out)
    return out

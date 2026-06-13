"""
Reglas curadas — el veredicto básico de Fase 1 (brief §0 y §5.b).

Conocimiento de seguridad que no cambia y funciona el día 1 sin historial.
Cada regla evalúa la estructura normalizada y, si matchea, devuelve una
DECISIÓN: veredicto + confidence + factores + próximos pasos + MITRE.

Principios aplicados (brief §4 y §7):
- Veredicto firme SIEMPRE, acotado a la evidencia disponible.
- Sin "modo aprendizaje": cuando ninguna regla aplica y la línea base aún
  no existe (Fase 2), el default da un veredicto firme sobre lo que SÍ se
  observa, sin fingir un juicio de línea base que no tiene.
- 3 estados: informational | false_positive | true_positive.
  true_positive ⇒ create_case=True. Los otros dos no crean caso.
"""
from dataclasses import dataclass, field

from app import config


@dataclass
class Decision:
    verdict: str                    # informational | false_positive | needs_review | true_positive
    confidence: int                 # 0-100, certeza del motor sobre su veredicto
    rule_id: str                    # id interno de la regla curada
    rule_name: str
    rationale: str                  # explicación técnica (alimenta case_description)
    key_factors: list[str] = field(default_factory=list)
    next_steps: list[str] = field(default_factory=list)
    mitre: list[str] = field(default_factory=list)
    severity_override: str | None = None   # una regla puede ajustar severidad
    # final=True: la regla resuelve sola (ruido benigno identificado con
    # certeza, o evidencia absoluta en la propia alerta). final=False: el
    # veredicto es preliminar y la alerta sigue al análisis profundo
    # (enriquecimiento + línea base + correlación + analista GPT) en Fase 2.
    final: bool = True


def _is_machine_account(user: str) -> bool:
    """Cuenta de máquina AD (termina en $) o cuenta de sistema conocida."""
    u = (user or "").strip()
    return u.endswith("$") or u.upper() in ("SYSTEM", "LOCAL SERVICE", "NETWORK SERVICE")


# --------------------------------------------------------------------------
# Reglas. Se evalúan en orden; la primera que matchea decide.
# --------------------------------------------------------------------------

def r_win_service_logon(n: dict) -> Decision | None:
    """Logon tipo 5 + cuenta de máquina/sistema = arranque de servicio rutinario."""
    if n["family"] != "windows_event":
        return None
    w = n.get("win_meta", {})
    if w.get("event_id") == "4624" and w.get("logon_type") == "5" \
            and _is_machine_account(w.get("target_user", "")) \
            and "SUCCESS" in (w.get("outcome", "") or "").upper():
        return Decision(
            verdict="informational", confidence=92,
            rule_id="R-WIN-001", rule_name="Logon de servicio (tipo 5, cuenta de sistema)",
            rationale=(
                f"Evento 4624 con logon type 5 (Service) para la cuenta "
                f"'{w.get('target_user')}' iniciado por '{w.get('process_name') or 'SCM'}' "
                f"en {w.get('computer') or n['asset']}. El tipo 5 corresponde al arranque "
                "de un servicio por el Service Control Manager con credenciales locales; "
                "combinado con una cuenta de máquina/sistema es actividad rutinaria del SO."
            ),
            key_factors=[
                "Logon type 5 (Service): inicio de servicio, no sesión humana",
                f"Cuenta de sistema/máquina: {w.get('target_user')}",
                "Resultado AUDIT_SUCCESS sin origen de red",
            ],
            next_steps=[],
        )
    return None


def r_win_machine_logoff(n: dict) -> Decision | None:
    """Logoff (4634/4647) — cierre de sesión, valor forense pero no accionable."""
    if n["family"] != "windows_event":
        return None
    w = n.get("win_meta", {})
    if w.get("event_id") in ("4634", "4647"):
        machine = _is_machine_account(w.get("target_user", ""))
        return Decision(
            verdict="informational", confidence=90 if machine else 80,
            rule_id="R-WIN-002", rule_name="Logoff de sesión",
            rationale=(
                f"Evento {w.get('event_id')} (logoff) de la cuenta '{w.get('target_user')}' "
                f"(logon type {w.get('logon_type') or 'n/d'}) en {w.get('computer') or n['asset']}. "
                "Un cierre de sesión no es accionable por sí mismo: su valor es forense, "
                "para correlacionar con el 4624 de apertura vía Logon ID."
                + (" La cuenta es de máquina (sufijo $), consistente con sesiones de "
                   "red automáticas entre hosts del dominio." if machine else "")
            ),
            key_factors=[
                f"Evento {w.get('event_id')}: destrucción de sesión",
                f"Cuenta: {w.get('target_user')}" + (" (cuenta de máquina)" if machine else ""),
            ],
            next_steps=[],
        )
    return None


def r_agent_disconnected(n: dict) -> Decision | None:
    """Agente Wazuh desconectado: pérdida de visibilidad, no caso (acordado)."""
    if n["rule"]["id"] != "504":
        return None
    target = n.get("ossec_meta", {}).get("target", "") or n["asset"]
    return Decision(
        verdict="informational", confidence=70,
        rule_id="R-OSSEC-001", rule_name="Agente Wazuh desconectado",
        rationale=(
            f"El manager reporta la desconexión del agente '{target}'. Implica pérdida "
            "de visibilidad sobre ese host: puede ser mantenimiento, reinicio o problema "
            "de red, pero también la consecuencia de un atacante deteniendo el agente "
            "(T1562.001). Sin señales adicionales en esta alerta, se clasifica como "
            "informativa; la correlación (Fase 2) escalará desconexiones precedidas de "
            "actividad anómala en el mismo host."
        ),
        key_factors=[
            f"Agente desconectado: {target}",
            "Pérdida de visibilidad de monitoreo sobre el host",
        ],
        next_steps=[
            "Verificar si la desconexión corresponde a mantenimiento o reinicio planificado",
            "Confirmar que el host responde y que el servicio del agente vuelve a conectar",
            "Si la desconexión persiste sin causa operativa, revisar el host manualmente",
        ],
        mitre=["T1562.001"],
        final=False,   # la correlación/analista puede escalar una desconexión sospechosa
    )


def r_apparmor_pycache_noise(n: dict) -> Decision | None:
    """AppArmor DENIED mknod sobre __pycache__ = ruido conocido de Ubuntu Pro."""
    if n["family"] != "apparmor":
        return None
    a = n.get("apparmor_meta", {})
    if a.get("status", "").upper() == "DENIED" and a.get("operation") == "mknod" \
            and "__pycache__" in (a.get("name") or ""):
        return Decision(
            verdict="false_positive", confidence=93,
            rule_id="R-AA-001", rule_name="AppArmor: mknod denegado en __pycache__ (ruido conocido)",
            rationale=(
                f"AppArmor denegó una operación mknod de '{a.get('comm')}' (perfil "
                f"'{a.get('profile')}') sobre '{a.get('name')}'. Es el patrón conocido del "
                "cliente de Ubuntu Pro/ESM intentando escribir bytecode (.pyc) en "
                "__pycache__ dentro de un path confinado: el perfil lo bloquea por diseño "
                "y el servicio funciona igual. Comportamiento benigno, recurrente y "
                "documentado; no representa actividad maliciosa."
            ),
            key_factors=[
                f"Perfil AppArmor: {a.get('profile')} (confinamiento esperado)",
                "Recurso: caché de bytecode Python (__pycache__), sin valor para un atacante",
                "La denegación es el control funcionando, no un bypass",
            ],
            next_steps=[],
        )
    return None


def r_apparmor_denied_generic(n: dict) -> Decision | None:
    """Cualquier otra denegación de AppArmor: el control actuó; revisar contexto."""
    if n["family"] != "apparmor":
        return None
    a = n.get("apparmor_meta", {})
    if a.get("status", "").upper() == "DENIED":
        return Decision(
            verdict="informational", confidence=60,
            rule_id="R-AA-002", rule_name="AppArmor: operación denegada (genérico)",
            rationale=(
                f"AppArmor denegó la operación '{a.get('operation')}' del proceso "
                f"'{a.get('comm')}' sobre '{a.get('name')}' (perfil '{a.get('profile')}'). "
                "La denegación indica que el confinamiento actuó. Sin patrón de ruido "
                "conocido ni señales de explotación en la alerta, se registra como "
                "informativa para línea base y correlación."
            ),
            key_factors=[f"Operación denegada: {a.get('operation')} por perfil {a.get('profile')}"],
            next_steps=["Si la denegación se repite sobre recursos sensibles, revisar el perfil y el proceso"],
        )
    return None


def r_rootcheck_world_writable_key(n: dict) -> Decision | None:
    """Clave/cert privado world-writable = configuración insegura SIEMPRE → caso."""
    if n["family"] != "rootcheck":
        return None
    rc = n.get("rootcheck_meta", {})
    text = (rc.get("title", "") + " " + n["full_log"]).lower()
    file_ = rc.get("file", "") or ""
    is_world_writable = "written permissions to anyone" in text or "world-writable" in text
    is_key_material = any(t in file_.lower() for t in (".key", ".pem", "/ssl/", "/private", ".crt"))
    if is_world_writable and is_key_material:
        return Decision(
            verdict="true_positive", confidence=90,
            rule_id="R-RC-001", rule_name="Material criptográfico con permisos de escritura globales",
            rationale=(
                f"Rootcheck detectó que '{file_}' (material criptográfico: clave/certificado "
                "TLS) es propiedad de root pero tiene permisos de escritura para cualquier "
                "usuario del sistema. Es una configuración insegura en sí misma, sin "
                "depender de contexto: cualquier usuario local puede sustituir la clave "
                "privada del servicio (suplantación TLS, MitM) o leerla/exfiltrarla según "
                "permisos de lectura asociados. Requiere corrección inmediata de permisos "
                "y evaluación de rotación de la clave."
            ),
            key_factors=[
                f"Archivo afectado: {file_}",
                "Clave privada TLS escribible por cualquier usuario local",
                "Riesgo: sustitución/compromiso de la identidad TLS del servicio",
            ],
            next_steps=[
                f"Corregir permisos: chmod 600 {file_} (propietario root o el usuario del servicio)",
                "Auditar si el archivo fue modificado por un usuario no autorizado (mtime, auditd si existe)",
                "Evaluar rotación de la clave y reemisión del certificado si hay indicios de acceso",
                "Revisar el resto de /etc/apache2/ssl/ en busca del mismo patrón de permisos",
            ],
            mitre=["T1552.004"],   # Unsecured Credentials: Private Keys
        )
    return None


def r_rootcheck_generic(n: dict) -> Decision | None:
    """Otras anomalías de rootcheck: informativa firme sobre lo observado."""
    if n["family"] != "rootcheck":
        return None
    rc = n.get("rootcheck_meta", {})
    return Decision(
        verdict="informational", confidence=55,
        rule_id="R-RC-002", rule_name="Anomalía de rootcheck (genérico)",
        rationale=(
            f"Rootcheck reportó: {rc.get('title') or n['rule']['description']}. "
            "No coincide con un patrón curado de severidad confirmada; se registra "
            "como informativa con la evidencia observada."
        ),
        key_factors=[rc.get("title", "")] if rc.get("title") else [],
        next_steps=["Revisar el hallazgo de rootcheck en el host si se repite"],
        final=False,
    )


_SNAP_PATH_HINTS = ("/snap/", "snapd", "/etc/systemd/system/snap.", "/etc/systemd/system/snap-")


def r_fim_inode_only(n: dict) -> Decision | None:
    """FIM que cambia SOLO el inode = reemplazo atómico (deploy), no edición."""
    if n["family"] != "syscheck_fim":
        return None
    f = n.get("fim_meta", {})
    if f.get("event") == "modified" and f.get("changed_attributes") == ["inode"]:
        return Decision(
            verdict="informational", confidence=85,
            rule_id="R-FIM-001", rule_name="FIM: solo cambió el inode (reemplazo de archivo)",
            rationale=(
                f"Syscheck reportó '{f.get('path')}' como modificado, pero el único "
                "atributo que cambió es el inode (de "
                f"{f.get('inode_before')} a {f.get('inode_after')}): los hashes de "
                "contenido (md5/sha1/sha256), tamaño y permisos se mantienen. Ese patrón "
                "corresponde a un reemplazo atómico del archivo con contenido idéntico "
                "— típico de deploys, reinstalación de paquetes o herramientas de "
                "gestión de configuración — y no a una edición de contenido."
            ),
            key_factors=[
                f"Archivo: {f.get('path')}",
                "changed_attributes = [inode] únicamente; contenido idéntico (hashes sin cambio)",
                "Patrón consistente con deploy/reemplazo, no con edición",
            ],
            next_steps=[],
        )
    return None


def r_fim_snap_lifecycle(n: dict) -> Decision | None:
    """Cambios FIM en unidades/archivos de snapd = ciclo de vida de snaps."""
    if n["family"] != "syscheck_fim":
        return None
    f = n.get("fim_meta", {})
    path = (f.get("path") or "").lower()
    if any(h in path for h in _SNAP_PATH_HINTS):
        event = f.get("event", "cambio")
        return Decision(
            verdict="informational", confidence=80,
            rule_id="R-FIM-002", rule_name="FIM: ciclo de vida de snapd",
            rationale=(
                f"Syscheck reportó '{f.get('path')}' con evento '{event}'. El path "
                "corresponde a unidades systemd/artefactos generados y regenerados por "
                "snapd durante actualizaciones automáticas de snaps (refresh): creación "
                "y borrado de mounts versionados y sockets es parte de su operación "
                "normal. Se registra para línea base; sin señales de manipulación "
                "maliciosa en la alerta."
            ),
            key_factors=[
                f"Archivo: {f.get('path')} (artefacto de snapd)",
                f"Evento: {event}; patrón de actualización automática de snaps",
            ]
            + ([f"Contenido modificado (sha256 {f.get('sha256_before','')[:12]}… → "
                f"{f.get('sha256_after','')[:12]}…), consistente con regeneración de la unidad"]
               if f.get("content_changed") else []),
            next_steps=[
                "Si se requiere reducir este ruido, evaluar excluir paths de snapd en la config de syscheck",
            ],
        )
    return None


def r_fim_content_change(n: dict) -> Decision | None:
    """FIM con cambio real de contenido sin regla específica: firme sobre lo observado."""
    if n["family"] != "syscheck_fim":
        return None
    f = n.get("fim_meta", {})
    if f.get("content_changed"):
        return Decision(
            verdict="informational", confidence=55,
            rule_id="R-FIM-003", rule_name="FIM: cambio de contenido sin patrón curado",
            rationale=(
                f"Syscheck reportó cambio de contenido en '{f.get('path')}' "
                f"(atributos: {', '.join(f.get('changed_attributes', []))}). No coincide "
                "con un patrón curado y en esta fase no hay línea base histórica ni "
                "reputación del hash para contrastar. Sobre la evidencia disponible: "
                "modificación de archivo monitoreado, sin señales adicionales de "
                "compromiso en la propia alerta. Se registra y queda disponible para "
                "correlación; verificar contra ventana de cambios."
            ),
            key_factors=[
                f"Archivo: {f.get('path')}",
                f"sha256 posterior: {f.get('sha256_after', 'n/d')}",
            ],
            next_steps=[
                "Confirmar si el cambio corresponde a una tarea de administración o deploy conocido",
                "Si el archivo es de configuración de servicio, hacer diff contra la versión esperada",
            ],
            final=False,   # cambio de contenido sin explicación: análisis profundo
        )
    return None


def r_fim_other(n: dict) -> Decision | None:
    """FIM restante (deleted/added sin patrón): informativa con evidencia."""
    if n["family"] != "syscheck_fim":
        return None
    f = n.get("fim_meta", {})
    return Decision(
        verdict="informational", confidence=60,
        rule_id="R-FIM-004", rule_name="FIM: evento sin patrón curado",
        rationale=(
            f"Syscheck reportó el evento '{f.get('event')}' sobre '{f.get('path')}'. "
            "Sin patrón curado aplicable ni línea base en esta fase; se registra como "
            "informativa sobre la evidencia observada."
        ),
        key_factors=[f"Archivo: {f.get('path')}", f"Evento: {f.get('event')}"],
        next_steps=["Verificar si el cambio corresponde a operación administrativa conocida"],
    )


def r_default(n: dict) -> Decision:
    """
    Default cuando ninguna regla curada matchea (cold start, brief §7).

    PRINCIPIO (acordado con Rodrigo): el motor NUNCA emite true_positive
    sin evidencia real que lo sostenga. El nivel de la regla Wazuh no es
    evidencia propia: es la opinión de otra herramienta. Por lo tanto:

      - nivel >= REVIEW_MIN_LEVEL → needs_review: "no tengo regla curada
        ni evidencia suficiente, y la severidad de origen amerita ojos
        humanos". create_case=False (no abre caso automático); llega al
        analista por la branch de Shuffle sobre verdict == needs_review.
      - nivel menor → informational: severidad baja sin señales de
        compromiso observadas; queda en memoria para línea base.

    true_positive queda reservado para análisis real: regla curada sólida
    hoy, fuentes externas + línea base + IA en Fase 2.
    """
    level = n["rule"].get("level") or 0
    desc = n["rule"].get("description", "evento")
    if level >= config.REVIEW_MIN_LEVEL:
        return Decision(
            verdict="needs_review", confidence=50,
            rule_id="R-DEF-REVIEW", rule_name="Default: sin patrón curado, severidad de origen alta",
            rationale=(
                f"La regla {n['rule']['id']} de Wazuh ('{desc}', nivel {level}) no "
                "coincide con ningún patrón curado del motor, y en esta fase no hay "
                "enriquecimiento externo ni línea base para profundizar. El motor no "
                "tiene evidencia propia para afirmar un positivo, pero la severidad "
                "asignada por Wazuh y la ausencia de explicación benigna ameritan "
                "revisión humana. Veredicto deliberadamente no concluyente: se marca "
                "para revisión en lugar de fingir una certeza que no existe."
            ),
            key_factors=[
                f"Regla Wazuh nivel {level}: {desc}",
                "Sin patrón benigno curado aplicable",
                "Sin evidencia propia suficiente para un veredicto firme",
            ],
            next_steps=["Revisión manual del evento en el host afectado"],
            final=False,   # justamente el caso que el análisis profundo debe resolver
        )
    return Decision(
        verdict="informational", confidence=55,
        rule_id="R-DEF-INFO", rule_name="Default: sin patrón curado, severidad baja",
        rationale=(
            f"La alerta ('{desc}', nivel {level}) no coincide con ningún patrón curado. "
            "Sobre las señales disponibles no se observan indicadores de compromiso y "
            "la severidad de origen es baja; se registra como informativa y queda en "
            "memoria para línea base y correlación futura."
        ),
        key_factors=[f"Regla Wazuh nivel {level}: {desc}"],
        next_steps=[],
        final=False,   # sin patrón curado: si hay observables externos o GPT, que opinen
    )


# Orden de evaluación: específico → genérico dentro de cada familia.
RULES = [
    r_win_service_logon,
    r_win_machine_logoff,
    r_agent_disconnected,
    r_apparmor_pycache_noise,
    r_apparmor_denied_generic,
    r_rootcheck_world_writable_key,
    r_rootcheck_generic,
    r_fim_inode_only,
    r_fim_snap_lifecycle,
    r_fim_content_change,
    r_fim_other,
]


def evaluate(normalized: dict) -> Decision:
    """Evalúa las reglas curadas en orden; la primera que matchea decide."""
    for rule in RULES:
        decision = rule(normalized)
        if decision is not None:
            return decision
    return r_default(normalized)


# --------------------------------------------------------------------------
# Reglas post-enriquecimiento (Fase 2): evidencia de reputación verificada.
# Corren DESPUÉS del enricher; son la vía con evidencia real que puede
# producir true_positive incluso si el analista GPT no está disponible.
# --------------------------------------------------------------------------

def evaluate_post_enrichment(normalized: dict, prior: Decision) -> Decision | None:
    """Si la reputación verificada cambia la historia, emite nueva decisión."""
    malicious = [o for o in normalized["observables"] if o.get("verdict") == "malicious"]
    suspicious = [o for o in normalized["observables"] if o.get("verdict") == "suspicious"]

    if malicious:
        reasons: list[str] = []
        for o in malicious:
            reasons.extend(o.get("sources", {}).get("reasons", []))
        multi_source = len({r.split(":")[0] for r in reasons}) >= 2
        values = ", ".join(o["value"] for o in malicious)
        return Decision(
            verdict="true_positive",
            confidence=95 if multi_source else 85,
            rule_id="R-ENR-001",
            rule_name="Observable con reputación maliciosa verificada",
            rationale=(
                f"La reputación externa confirma actividad maliciosa asociada a: {values}. "
                f"Evidencia verificada: {'; '.join(reasons)}. La presencia de un indicador "
                "con reputación maliciosa confirmada interactuando con el activo "
                f"{normalized['asset']} sostiene un positivo con evidencia real, "
                "independientemente del nivel de la regla Wazuh de origen."
            ),
            key_factors=[f"Indicador malicioso confirmado: {values}"] + reasons[:5],
            next_steps=[
                f"Bloquear/contener los indicadores confirmados ({values}) en perímetro",
                f"Revisar en {normalized['asset']} actividad asociada a esos indicadores "
                "en la ventana del evento",
                "Buscar los mismos indicadores en el resto del parque (threat hunting)",
            ],
            mitre=prior.mitre,
            final=False,    # el analista puede refinar; sin analista, esta decisión queda
        )

    if suspicious and prior.verdict == "informational" and not prior.final:
        values = ", ".join(o["value"] for o in suspicious)
        reasons = []
        for o in suspicious:
            reasons.extend(o.get("sources", {}).get("reasons", []))
        return Decision(
            verdict="needs_review",
            confidence=55,
            rule_id="R-ENR-002",
            rule_name="Observable con reputación sospechosa (no concluyente)",
            rationale=(
                f"La reputación externa marca señales sospechosas pero no concluyentes "
                f"para: {values} ({'; '.join(reasons[:3])}). No alcanza para un positivo "
                "firme; se deriva a revisión con la evidencia adjunta."
            ),
            key_factors=[f"Indicador sospechoso: {values}"] + reasons[:3],
            next_steps=["Revisar el contexto del indicador sospechoso en el activo"],
            mitre=prior.mitre,
            final=False,
        )
    return None

"""
Reporter — construye el contrato de salida final (Fase 2).

Dos modos:
- Camino corto (regla curada final) o analista no disponible: el
  case_description sale de plantillas de prosa técnica determinísticas,
  describiendo honestamente qué fuentes operaron y cuáles no.
- Camino profundo con analista: el case_description lo redacta GPT con
  el dossier completo; el reporter solo ensambla el contrato y agrega
  el pie de trazabilidad.

El contrato (keys) es EXACTAMENTE el mismo en ambos modos y el mismo
de Fase 1: solo cambia el contenido de los bloques.
"""
from datetime import datetime, timezone

from app import config
from app.agents.rules import Decision
from app.contract import (AlertResult, Correlation, Enrichment,
                          InternalAnalysis, Observable, severity_from_level)

_FAMILY_LABEL = {
    "windows_event": "evento de Windows",
    "syscheck_fim": "integridad de archivos (FIM)",
    "rootcheck": "rootcheck",
    "apparmor": "AppArmor",
    "ossec": "evento del manager Wazuh",
    "network": "evento de red",
    "generic": "evento",
}

_VERDICT_LABEL = {
    "informational": "INFORMATIVA (no genera caso; queda en memoria para línea base y correlación)",
    "false_positive": "FALSO POSITIVO (ruido conocido; no genera caso, queda registrada)",
    "needs_review": "REQUIERE REVISIÓN (el motor no tiene evidencia suficiente para un "
                    "veredicto firme; no genera caso automático — derivar a revisión humana)",
    "true_positive": "POSITIVO CONFIRMADO (genera caso en TheHive)",
}

_SOURCE_LABEL = {
    "curated_rule": "regla curada",
    "evidence_rule": "regla con evidencia de reputación verificada",
    "analyst": "analista IA con dossier completo",
    "fallback": "degradación segura (analista no disponible)",
}


def _short_title(normalized: dict, decision: Decision) -> str:
    family = normalized["family"]
    asset = normalized["asset"]
    if family == "windows_event":
        w = normalized.get("win_meta", {})
        user = w.get("target_user", "")
        core = f"{normalized['rule']['description']} ({user})" if user else normalized["rule"]["description"]
    elif family == "syscheck_fim":
        f = normalized.get("fim_meta", {})
        core = f"FIM {f.get('event', 'cambio')}: {f.get('path', '')}"
    elif family == "rootcheck":
        core = f"Rootcheck: {normalized.get('rootcheck_meta', {}).get('file') or normalized['rule']['description']}"
    elif family == "apparmor":
        a = normalized.get("apparmor_meta", {})
        core = f"AppArmor {a.get('status', '').upper()} {a.get('operation', '')} ({a.get('comm', '')})"
    elif family == "ossec":
        core = normalized["rule"]["description"].rstrip(".")
    elif family == "network":
        n = normalized.get("net_meta", {})
        src = f" desde {n.get('srcip')}" if n.get("srcip") else ""
        core = f"{normalized['rule']['description']}{src}"
    else:
        core = normalized["rule"]["description"]
    return f"[Vectus SOC] {core} en {asset}"[:200]


def _pick_key_observable(normalized: dict) -> str:
    """Prioriza observables con veredicto malo; luego por tipo."""
    obs = [o for o in normalized["observables"] if not o["is_generic"]]
    for verdict in ("malicious", "suspicious"):
        for o in obs:
            if o.get("verdict") == verdict:
                return o["value"]
    for type_ in ("ip", "hash_sha256", "hash_md5", "url", "cve", "file", "user", "process"):
        for o in obs:
            if o["type"] != type_:
                continue
            if type_ == "ip" and not o["is_public"]:
                continue
            return o["value"]
    return ""


def _sources_paragraph(enrichment: dict, baseline_block: dict,
                       correlation: dict) -> str:
    """Estado honesto de cada fuente de análisis (nunca se inventa)."""
    parts: list[str] = []
    e_status = enrichment.get("status", "")
    e_map = {
        "done": "Reputación externa (VT/AbuseIPDB/OTX): consultada sin errores.",
        "partial": "Reputación externa: consultada con errores parciales en alguna fuente "
                   "(detalle en el bloque enrichment); solo se usó lo verificado.",
        "no_external_observables": "Reputación externa: no aplica (la alerta no contiene "
                                   "observables públicos enriquecibles).",
        "not_configured": "Reputación externa: no configurada (sin API keys); ninguna "
                          "afirmación de reputación en este veredicto.",
        "skipped_curated_rule": "Reputación externa: no consultada (la regla curada "
                                "resolvió sin necesitarla).",
    }
    parts.append(e_map.get(e_status, f"Reputación externa: {e_status}."))

    b = baseline_block.get("baseline", {})
    b_status = b.get("status", "")
    if b_status == "ok":
        r = baseline_block.get("rarity", {})
        parts.append(
            f"Línea base del activo: {b.get('asset_events')} eventos históricos; "
            f"similitud máxima con lo habitual {b.get('nearest_similarity')}; "
            f"rareza {r.get('score')}/100 ({r.get('label')})."
        )
    elif b_status == "cold_start":
        parts.append(
            f"Línea base: en cold start ({b.get('asset_events', 0)}/"
            f"{b.get('required')} eventos para este activo); sin juicio de "
            "normalidad — no se finge histórico."
        )
    elif b_status == "not_configured":
        parts.append("Línea base: no configurada (requiere OPENAI_API_KEY).")
    elif b_status == "skipped_curated_rule":
        parts.append("Línea base: no consultada (resuelto por regla curada).")
    else:
        parts.append(f"Línea base: {b_status}.")

    c_status = correlation.get("status", "")
    if c_status == "done":
        rc = correlation.get("related_count", 0)
        if rc:
            reasons = "; ".join(
                f"{r['alert_id']} ({r['reason']})" for r in correlation.get("related", [])[:3])
            parts.append(f"Correlación: {rc} alerta(s) relacionada(s) en la ventana "
                         f"de {config.CORRELATION_WINDOW_HOURS} h — {reasons}.")
        else:
            parts.append("Correlación: sin alertas relacionadas en la ventana temporal.")
    elif c_status == "skipped_curated_rule":
        parts.append("Correlación: no consultada (resuelto por regla curada).")
    else:
        parts.append(f"Correlación: {c_status}.")
    return " ".join(parts)


def _fmt_fecha(iso: str) -> str:
    """Convierte un timestamp ISO a un formato legible para el analista."""
    if not iso:
        return "fecha desconocida"
    try:
        dt = datetime.fromisoformat(iso.replace("Z", "+00:00"))
        return dt.strftime("%d/%m/%Y %H:%M UTC")
    except (ValueError, AttributeError):
        return iso


def build_correlation_summary(correlation: dict) -> str:
    """
    Genera un relato en lenguaje natural del patrón histórico, pensado
    para que el analista entienda de un vistazo si la alerta es un evento
    aislado o parte de algo recurrente. Siempre devuelve texto.
    Formato Markdown para que TheHive lo renderice prolijo.
    """
    status = correlation.get("status", "")
    if status == "skipped_curated_rule":
        return "Correlación no evaluada: la alerta se resolvió por una regla curada de certeza."
    if status != "done":
        return "Correlación no disponible para esta alerta."

    related = correlation.get("related", [])
    rc = correlation.get("related_count", len(related))

    if not rc:
        return ("**Evento aislado:** no se encontraron alertas relacionadas con este "
                "activo u observable en la ventana temporal analizada. No hay "
                "indicios de un patrón previo.")

    encabezado = (
        f"**⚠ PATRÓN RECURRENTE**: esta alerta NO es un evento aislado. "
        f"Se detectaron **{rc} alerta(s) relacionada(s)** en la ventana temporal:"
    )

    eventos = sorted(related, key=lambda x: x.get("created_at", ""))
    items = []
    for r in eventos[:5]:
        fecha = _fmt_fecha(r.get("created_at", ""))
        veredicto = r.get("verdict", "sin veredicto")
        motivo = r.get("reason", "")
        aid = r.get("alert_id", "—")
        items.append(f"- `{fecha}` — **{veredicto}** — `{aid}` ({motivo})")
    if len(eventos) > 5:
        items.append(f"- … y {len(eventos) - 5} más.")
    lista = "\n".join(items)

    veredictos_previos = [r.get("verdict") for r in related]
    tp_previos = veredictos_previos.count("true_positive")
    if tp_previos >= 2:
        interpretacion = (
            "**Interpretación:** la repetición de positivos confirmados sobre el mismo "
            "objetivo sugiere una campaña sostenida, no un intento puntual. Se "
            "recomienda priorizar la contención y revisar la cadena completa de eventos."
        )
    elif tp_previos == 1:
        interpretacion = (
            "**Interpretación:** ya hubo al menos un positivo confirmado relacionado. "
            "Conviene revisar si se trata de la misma actividad en curso."
        )
    else:
        interpretacion = (
            "**Interpretación:** hay actividad relacionada previa, aún sin confirmar como "
            "maliciosa. Útil como contexto para la investigación."
        )

    return encabezado + "\n\n" + lista + "\n\n" + interpretacion


def _build_description_template(normalized: dict, decision: Decision,
                                classification: str, signature_count: int,
                                enrichment: dict, baseline_block: dict,
                                correlation: dict) -> str:
    """Prosa técnica determinística (camino corto o analista ausente)."""
    rule = normalized["rule"]
    action = normalized["action"]
    sev = severity_from_level(rule.get("level"))
    p: list[str] = []
    p.append(
        f"Alerta de Wazuh ({_FAMILY_LABEL.get(normalized['family'], 'evento')}) en el "
        f"activo {normalized['asset']}"
        + (f" ({normalized['agent'].get('ip')})" if normalized['agent'].get('ip') else "")
        + f". Regla {rule['id']} nivel {rule.get('level')} ({sev}): "
        f"\"{rule.get('description', '')}\". Timestamp del evento: "
        f"{normalized.get('timestamp') or 'n/d'}. Componente de análisis: {classification}."
    )
    p.append(
        f"Comportamiento observado — actor: {action.get('actor') or 'n/d'}; operación: "
        f"{action.get('operation') or 'n/d'}; recurso: {action.get('resource') or 'n/d'}; "
        f"resultado: {action.get('outcome') or 'n/d'}"
        + (f"; detalle: {action.get('detail').rstrip('.')}." if action.get("detail") else ".")
    )
    p.append(f"Análisis [{decision.rule_id} · {decision.rule_name}]: {decision.rationale}")
    p.append(_sources_paragraph(enrichment, baseline_block, correlation))
    if signature_count > 1:
        p.append(
            f"La firma de comportamiento de esta alerta se observó {signature_count} "
            "veces desde el arranque del motor (conteo informativo; el silenciado es "
            "siempre supervisado, nunca automático)."
        )
    p.append(
        f"Conclusión: {_VERDICT_LABEL[decision.verdict]}. Confianza del motor en este "
        f"veredicto: {decision.confidence}/100."
    )
    return "\n\n".join(p)


def build_result(alert_id: str, normalized: dict, decision: Decision,
                 routing: dict, signature_count: int,
                 enrichment_block: dict, baseline_block: dict,
                 correlation_block: dict, analyst_meta: dict,
                 analyst_result: dict | None,
                 verdict_source: str) -> dict:
    """Ensambla el AlertResult completo (todas las keys, siempre)."""
    rule = normalized["rule"]
    severity = decision.severity_override or severity_from_level(rule.get("level"))

    if analyst_result is not None:
        # El analista emite el veredicto final y redacta la descripción.
        verdict = analyst_result["verdict"]
        confidence = analyst_result["confidence"]
        case_description = analyst_result["case_description"] + (
            f"\n\n— Veredicto emitido por: {_SOURCE_LABEL['analyst']}. "
            f"Regla curada previa: {decision.rule_id} ({decision.verdict}, "
            f"{decision.confidence}/100)."
        )
        key_factors = analyst_result["key_factors"]
        next_steps = analyst_result["next_steps"]
        mitre = sorted(set(normalized["mitre"]) | set(decision.mitre)
                       | set(analyst_result["mitre"]))
    else:
        verdict = decision.verdict
        confidence = decision.confidence
        case_description = _build_description_template(
            normalized, decision, routing["classification"], signature_count,
            enrichment_block, baseline_block, correlation_block)
        key_factors = decision.key_factors
        next_steps = decision.next_steps
        mitre = sorted(set(normalized["mitre"]) | set(decision.mitre))

    rules_applied = [{
        "rule_id": decision.rule_id,
        "rule_name": decision.rule_name,
        "verdict": decision.verdict,
        "confidence": decision.confidence,
    }]

    result = AlertResult(
        alert_id=alert_id,
        status="done",
        create_case=(verdict == "true_positive"),
        verdict=verdict,
        confidence=confidence,
        severity=severity,
        alert_class=normalized["family"],
        asset=normalized["asset"],
        title=_short_title(normalized, decision),
        case_description=case_description,
        correlation_summary=build_correlation_summary(correlation_block),
        key_observable=_pick_key_observable(normalized),
        key_factors=key_factors,
        next_steps=next_steps,
        mitre=mitre,
        is_informational=(verdict == "informational"),
        observables=[Observable(**o) for o in normalized["observables"]],
        enrichment=Enrichment(**enrichment_block),
        internal_analysis=InternalAnalysis(
            rules_applied=rules_applied,
            action=normalized["action"],
            baseline=baseline_block.get("baseline", {}),
            rarity=baseline_block.get("rarity", {}),
            signature_count=signature_count,
            verdict_source=verdict_source,
            analyst=analyst_meta,
        ),
        correlation=Correlation(**correlation_block),
        engine_version=config.APP_VERSION,
        processed_at=datetime.now(timezone.utc).isoformat(),
    )
    return result.model_dump()

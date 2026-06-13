"""
Agente 6 — Analista final (Fase 2, brief §5): GPT-4o-mini, temp 0.1.

EL agente que emite el veredicto definitivo. Recibe el dossier completo
(normalización + decisión de reglas + reputación externa + línea base +
correlación) y produce veredicto, confidence y el case_description que
el analista humano lee en TheHive.

Regla de oro (acordada): true_positive SOLO sale de acá o de las reglas
curadas de certeza absoluta. Y el analista solo puede afirmar lo que la
evidencia del dossier sostiene — el prompt lo instruye y el validador
lo controla.

Robustez:
- Salida JSON estricta (response_format json_object) + validación dura.
- Un reintento ante JSON inválido; si falla, la alerta cae a needs_review
  con el dossier adjunto. NUNCA un veredicto inventado por fallo técnico.
- Sin OPENAI_API_KEY → "not_configured" y la cadena degrada al veredicto
  de reglas (o post-enriquecimiento) sin romperse.
"""
import json
import logging

from app import config

logger = logging.getLogger("vectus.analyst")

VALID_VERDICTS = {"informational", "false_positive", "needs_review", "true_positive"}

_openai_client = None


def _get_openai():
    global _openai_client
    if _openai_client is None:
        from openai import OpenAI
        _openai_client = OpenAI(api_key=config.OPENAI_API_KEY)
    return _openai_client


def is_configured() -> bool:
    return bool(config.OPENAI_API_KEY)


_SYSTEM_PROMPT = """Sos el analista senior de un SOC. Recibís el dossier técnico completo de una alerta de Wazuh ya procesada por una cadena de agentes: normalización, reglas curadas, reputación externa verificada (VirusTotal/AbuseIPDB/OTX), línea base de comportamiento del entorno y correlación con alertas recientes.

Tu trabajo: emitir el veredicto final y redactar la descripción del caso para otro analista.

PRINCIPIOS OBLIGATORIOS:
1. Veredicto firme apoyado SOLO en la evidencia del dossier. Nunca inventes datos, reputación ni contexto que no esté en el dossier. Si una fuente dice "not_configured", "cold_start" o "error", esa fuente NO aporta evidencia: decilo y no la uses.
2. "true_positive" exige evidencia concreta de actividad maliciosa o configuración insegura verificable (reputación maliciosa confirmada, patrón de ataque en correlación, evidencia en la propia alerta). La severidad de la regla Wazuh por sí sola NO alcanza.
3. "false_positive" solo para ruido benigno identificable. "informational" para actividad legítima/rutinaria sin valor de caso. "needs_review" cuando la evidencia es insuficiente o contradictoria: es preferible derivar a humano antes que fingir certeza.
4. confidence (0-100) = tu certeza sobre TU veredicto según cuánta evidencia convergente hay. Evidencia de una sola fuente débil = confidence bajo.
5. La descripción es para un analista técnico: densa, accionable, en español. Estructura: qué llegó, qué se observó, qué dijo cada fuente (incluyendo las que no aportaron), conclusión razonada. Sin narrativa blanda.
6. next_steps: pasos concretos y ejecutables. Si el veredicto es informational/false_positive pueden ser vacíos.
7. mitre: solo técnicas ATT&CK con sustento directo en la evidencia (formato Txxxx o Txxxx.xxx).

Respondé ÚNICAMENTE con un objeto JSON con estas keys exactas:
{"verdict": "...", "confidence": 0-100, "case_description": "...", "key_factors": ["..."], "next_steps": ["..."], "mitre": ["..."]}"""


def _build_dossier(normalized: dict, decision, routing: dict, enrichment: dict,
                   baseline_block: dict, correlation: dict,
                   signature_count: int) -> dict:
    """Dossier compacto: todo lo que el analista necesita, nada de relleno."""
    return {
        "alerta": {
            "activo": normalized["asset"],
            "familia": normalized["family"],
            "regla_wazuh": normalized["rule"],
            "timestamp": normalized.get("timestamp", ""),
            "accion_observada": normalized["action"],
            "full_log": normalized.get("full_log", "")[:800],
            "clasificacion_router": routing["classification"],
            "repeticiones_firma": signature_count,
        },
        "observables": [
            {k: o[k] for k in ("type", "value", "is_public", "is_generic", "verdict")}
            | ({"razones_reputacion": o["sources"].get("reasons", [])}
               if o.get("sources") else {})
            for o in normalized["observables"]
        ],
        "regla_curada_aplicada": {
            "rule_id": decision.rule_id,
            "nombre": decision.rule_name,
            "veredicto_preliminar": decision.verdict,
            "confidence_preliminar": decision.confidence,
            "razonamiento": decision.rationale,
        },
        "reputacion_externa": {"status": enrichment.get("status")},
        "linea_base": baseline_block.get("baseline", {}),
        "rareza": baseline_block.get("rarity", {}),
        "correlacion": {
            "status": correlation.get("status"),
            "relacionadas": [
                {k: r[k] for k in ("alert_id", "verdict", "alert_class", "reason")}
                for r in correlation.get("related", [])
            ],
        },
    }


def _validate(payload: dict) -> dict | None:
    """Validación dura de la salida del modelo. None si no cumple."""
    try:
        verdict = payload["verdict"]
        confidence = int(payload["confidence"])
        desc = str(payload["case_description"]).strip()
        if verdict not in VALID_VERDICTS or not (0 <= confidence <= 100) or not desc:
            return None
        return {
            "verdict": verdict,
            "confidence": confidence,
            "case_description": desc,
            "key_factors": [str(x) for x in payload.get("key_factors", [])][:10],
            "next_steps": [str(x) for x in payload.get("next_steps", [])][:10],
            "mitre": [str(x) for x in payload.get("mitre", [])][:10],
        }
    except (KeyError, TypeError, ValueError):
        return None


def _call_model(dossier: dict) -> dict | None:
    client = _get_openai()
    resp = client.chat.completions.create(
        model=config.OPENAI_MODEL,
        temperature=config.ANALYST_TEMP,
        response_format={"type": "json_object"},
        messages=[
            {"role": "system", "content": _SYSTEM_PROMPT},
            {"role": "user", "content": json.dumps(dossier, ensure_ascii=False)},
        ],
    )
    text = resp.choices[0].message.content or ""
    try:
        return _validate(json.loads(text))
    except json.JSONDecodeError:
        return None


def analyze(normalized: dict, decision, routing: dict, enrichment: dict,
            baseline_block: dict, correlation: dict,
            signature_count: int) -> dict:
    """
    Devuelve {"status": "done"|"not_configured"|"error", "result": {...}|None}.
    Un reintento ante salida inválida; nunca inventa veredicto ante fallo.
    """
    if not is_configured():
        return {"status": "not_configured", "result": None}

    dossier = _build_dossier(normalized, decision, routing, enrichment,
                             baseline_block, correlation, signature_count)
    for attempt in (1, 2):
        try:
            result = _call_model(dossier)
        except Exception as exc:                              # noqa: BLE001
            logger.warning("analista GPT fallo (intento %d) para %s: %s",
                           attempt, normalized["alert_id"], exc)
            result = None
        if result is not None:
            return {"status": "done", "result": result}
    return {"status": "error", "result": None}

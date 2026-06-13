"""
Agente 2 — Clasificador / Router (brief §5).

Decide el camino de análisis: ¿la alerta tiene componente EXTERNA
(IPs/hashes/dominios públicos), INTERNA (comportamiento), o AMBAS?

En Fase 1 la clasificación queda registrada en el resultado (y en SQLite)
pero la rama externa todavía no enriquece: el Enricher llega en Fase 2.
Esto evita gastar VirusTotal en un logon, y línea base en una IP (cuando
existan), sin cambiar el contrato más adelante.
"""

EXTERNAL_TYPES = {"ip", "hash_sha256", "hash_md5", "domain", "url", "cve"}


def route(normalized: dict) -> dict:
    """Devuelve {'classification': 'externa'|'interna'|'ambas',
                 'external_observables': [...], 'internal_component': bool}."""
    external = [
        o for o in normalized["observables"]
        if o["type"] in EXTERNAL_TYPES and o["is_public"]
    ]
    # Toda alerta tiene componente interna (comportamiento observado en un
    # host propio); lo externo se suma cuando hay observables públicos.
    has_external = len(external) > 0

    classification = "ambas" if has_external else "interna"
    if has_external and normalized["family"] == "network" and \
            len(external) == len([o for o in normalized["observables"] if not o["is_generic"]]):
        classification = "externa"

    normalized["classification"] = classification
    return {
        "classification": classification,
        "external_observables": external,
        "internal_component": classification != "externa",
    }

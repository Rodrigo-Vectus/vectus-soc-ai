"""
Contrato de salida del motor (brief §8) — EL DIFERENCIAL.

Reglas del contrato:
- Las MISMAS keys para toda alerta, sin importar el agente de Wazuh de
  origen (aunque vengan vacías). Rodrigo mapea key → campo de TheHive
  UNA sola vez en Shuffle y no se toca más.
- Formato híbrido: lo crítico plano en primer nivel (mapeo directo en
  Shuffle), el detalle anidado (bloque/adjunto del caso).
- Estable desde Fase 1: `enrichment`, `internal_analysis` y `correlation`
  existen ya con estructura, marcadas como no disponibles, y se llenan en
  Fase 2 sin romper el mapeo.
"""
from pydantic import BaseModel, Field


class Observable(BaseModel):
    type: str                      # ip | hash_sha256 | hash_md5 | domain | url | cve | user | process | file
    value: str
    is_public: bool = False        # enriquecible externamente (Fase 2)
    is_generic: bool = False       # IOC genérico (root/admin/system...) — excluido de correlación
    verdict: str = "unknown"       # unknown | clean | suspicious | malicious (Fase 2)
    sources: dict = Field(default_factory=dict)  # VT/AbuseIPDB/OTX (Fase 2)


class Enrichment(BaseModel):
    """Detalle del enriquecimiento externo. En Fase 1 viaja vacío y marcado."""
    status: str = "not_available_phase1"   # done | partial | not_available_phase1 | not_configured
    virustotal: dict = Field(default_factory=lambda: {"status": "not_configured"})
    abuseipdb: dict = Field(default_factory=lambda: {"status": "not_configured"})
    otx: dict = Field(default_factory=lambda: {"status": "not_configured"})
    shodan: dict = Field(default_factory=lambda: {"status": "not_configured"})  # nunca se usa


class InternalAnalysis(BaseModel):
    """Detalle del análisis interno: reglas curadas + línea base + rareza."""
    rules_applied: list[dict] = Field(default_factory=list)   # [F1] reglas curadas que matchearon
    action: dict = Field(default_factory=dict)                 # [F1] abstracción {actor, operation, resource, outcome, detail}
    baseline: dict = Field(default_factory=lambda: {"status": "not_available_phase1"})  # RAG (Fase 2)
    rarity: dict = Field(default_factory=lambda: {"status": "not_available_phase1"})    # rareza (Fase 2)
    signature_count: int = 0                                   # [F1] repeticiones de la firma de comportamiento
    verdict_source: str = "curated_rule"                       # [F2] curated_rule | evidence_rule | analyst | fallback
    analyst: dict = Field(default_factory=lambda: {"status": "skipped"})  # [F2] estado del analista GPT


class Correlation(BaseModel):
    """Correlación temporal/semántica. Estructura presente desde Fase 1."""
    status: str = "not_available_phase1"
    related_count: int = 0
    related: list[dict] = Field(default_factory=list)
    chain: list[dict] = Field(default_factory=list)


class AlertResult(BaseModel):
    """El JSON completo que consume Shuffle (POST 200 / GET done)."""
    # --- nivel plano: mapeo directo en Shuffle -----------------------------
    alert_id: str
    status: str = "done"                 # done | processing | error
    create_case: bool = False            # key de la branch en Shuffle (solo true_positive)
    verdict: str = "informational"       # informational | false_positive | needs_review | true_positive
    confidence: int = 0                  # 0-100: certeza del motor sobre SU veredicto
    severity: str = "low"                # low | medium | high | critical (desde rule.level)
    alert_class: str = "generic"         # familia del normalizador
    asset: str = ""                      # agente/host afectado
    title: str = ""                      # título del caso en TheHive
    case_description: str = ""           # CAMPO CENTRAL: relato técnico del triage
    correlation_summary: str = ""        # relato humano del patrón histórico (para el analista)
    key_observable: str = ""             # el observable más relevante
    key_factors: list[str] = Field(default_factory=list)
    next_steps: list[str] = Field(default_factory=list)
    mitre: list[str] = Field(default_factory=list)
    is_informational: bool = True
    # --- detalle anidado ----------------------------------------------------
    observables: list[Observable] = Field(default_factory=list)
    enrichment: Enrichment = Field(default_factory=Enrichment)
    internal_analysis: InternalAnalysis = Field(default_factory=InternalAnalysis)
    correlation: Correlation = Field(default_factory=Correlation)
    # --- trazabilidad -------------------------------------------------------
    engine_version: str = ""
    processed_at: str = ""


# Mapeo estándar de rule.level de Wazuh a severidad del contrato.
def severity_from_level(level: int | None) -> str:
    if level is None:
        return "low"
    if level >= 15:
        return "critical"
    if level >= 12:
        return "high"
    if level >= 7:
        return "medium"
    return "low"

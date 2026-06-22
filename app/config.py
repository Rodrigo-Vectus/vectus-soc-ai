"""
Configuración central del motor Vectus SOC.

Todas las variables vienen del entorno (.env via docker compose).
En Fase 1 solo se usan las marcadas [F1]; el resto queda declarado
para que el contrato de configuración sea estable desde el día 1.
"""
import os


def _int(name: str, default: int) -> int:
    """Lee un entero del entorno con default seguro."""
    try:
        return int(os.getenv(name, str(default)))
    except (TypeError, ValueError):
        return default


def _float(name: str, default: float) -> float:
    try:
        return float(os.getenv(name, str(default)))
    except (TypeError, ValueError):
        return default


# --- Identidad / API -------------------------------------------------------
APP_NAME = "Vectus SOC Engine"
APP_VERSION = "3.0.0-fase3"
API_KEY = os.getenv("API_KEY", "")            # [F1] vacío = abierto (red interna)
INGEST_MAX_WAIT = _int("INGEST_MAX_WAIT", 25)  # [F1] segundos antes de responder 202
# Nivel de regla Wazuh a partir del cual una alerta SIN regla curada queda
# en needs_review (en vez de informational). Nunca produce true_positive:
# ese veredicto exige evidencia real (regla sólida ahora, fuentes+IA en F2).
REVIEW_MIN_LEVEL = _int("REVIEW_MIN_LEVEL", 7)

# --- Persistencia ----------------------------------------------------------
DATA_DIR = os.getenv("DATA_DIR", "/data")      # [F1] volumen docker
DB_PATH = os.path.join(DATA_DIR, "vectus.db")  # [F1] SQLite
CHROMA_DIR = os.path.join(DATA_DIR, "chroma")  # [F2] vectores de línea base

# --- IA (Fase 2) ------------------------------------------------------------
OPENAI_API_KEY = os.getenv("OPENAI_API_KEY", "")
OPENAI_MODEL = os.getenv("OPENAI_MODEL", "gpt-4o-mini")
ANALYST_TEMP = _float("ANALYST_TEMP", 0.1)
EMBEDDING_MODEL = os.getenv("EMBEDDING_MODEL", "text-embedding-3-small")

# --- Enriquecimiento externo (Fase 2) ---------------------------------------
VIRUSTOTAL_API_KEY = os.getenv("VIRUSTOTAL_API_KEY", "")
ABUSEIPDB_API_KEY = os.getenv("ABUSEIPDB_API_KEY", "")
OTX_API_KEY = os.getenv("OTX_API_KEY", "")
SHODAN_API_KEY = os.getenv("SHODAN_API_KEY", "")   # no se usa (tier free sin créditos)
ENRICH_FAIL_HARD = os.getenv("ENRICH_FAIL_HARD", "false").lower() == "true"
VT_MIN_INTERVAL = _int("VT_MIN_INTERVAL", 15)
ENRICH_CACHE_TTL_HOURS = _int("ENRICH_CACHE_TTL_HOURS", 24)   # [F2] caché reputación

# --- Correlación (Fase 2) ----------------------------------------------------
CORRELATION_WINDOW_HOURS = _int("CORRELATION_WINDOW_HOURS", 24)
CORRELATION_MAX_RELATED = _int("CORRELATION_MAX_RELATED", 10)

# --- Anti-ruido supervisado (Fase 3) ------------------------------------------
# Candidatas por TASA: >= NOISE_MIN_COUNT eventos en NOISE_WINDOW_HOURS.
NOISE_MIN_COUNT = _int("NOISE_MIN_COUNT", 20)
NOISE_WINDOW_HOURS = _int("NOISE_WINDOW_HOURS", 168)   # 7 días

# --- Endurecimiento operativo (Fase 3) -----------------------------------------
PROCESSING_TIMEOUT_MINUTES = _int("PROCESSING_TIMEOUT_MINUTES", 10)
MAX_PAYLOAD_KB = _int("MAX_PAYLOAD_KB", 512)
ENRICH_RETRIES = _int("ENRICH_RETRIES", 2)              # reintentos por fuente caída

# --- RAG / línea base (Fase 2) ----------------------------------------------
RAG_SIM_THRESHOLD = _float("RAG_SIM_THRESHOLD", 0.20)
RAG_WINDOW_DAYS = _int("RAG_WINDOW_DAYS", 90)
COLDSTART_MIN_BASELINE = _int("COLDSTART_MIN_BASELINE", 50)

# --- Anti-ruido (Fase 3) -----------------------------------------------------
NOISE_THRESHOLD = _int("NOISE_THRESHOLD", 100)
NOISE_WINDOW_DAYS = _int("NOISE_WINDOW_DAYS", 7)

# --- Retencion / limpieza automatica (Fase 4) -------------------------------
# El motor corre una limpieza periodica en background para no crecer sin limite.
# Todos los plazos son configurables por entorno; los defaults son los acordados.
CLEANUP_ENABLED = os.getenv("CLEANUP_ENABLED", "true").lower() == "true"
CLEANUP_INTERVAL_HOURS = _int("CLEANUP_INTERVAL_HOURS", 24)
RETAIN_RAW_DAYS = _int("RETAIN_RAW_DAYS", 30)
RETAIN_SIGNATURE_EVENTS_DAYS = _int("RETAIN_SIGNATURE_EVENTS_DAYS", 7)
RETAIN_CORRELATIONS_DAYS = _int("RETAIN_CORRELATIONS_DAYS", 90)
RETAIN_RESULT_HISTORY_VERSIONS = _int("RETAIN_RESULT_HISTORY_VERSIONS", 3)
RETAIN_VECTORS_DAYS = _int("RETAIN_VECTORS_DAYS", 90)

# --- MISP (inteligencia propia del SOC) -------------------------------------
MISP_URL = os.getenv("https://192.168.11.125/", "")
MISP_API_KEY = os.getenv("bTthdSWAJF2QMiN7kNP2fr5IMOp08kQp6Riw1cGx", "")
MISP_VERIFY_SSL = os.getenv("MISP_VERIFY_SSL", "false").lower() == "true"

# --- MISP (inteligencia propia del SOC) -------------------------------------
MISP_URL = os.getenv("MISP_URL", "")
MISP_API_KEY = os.getenv("MISP_API_KEY", "")
MISP_VERIFY_SSL = os.getenv("MISP_VERIFY_SSL", "false").lower() == "true"

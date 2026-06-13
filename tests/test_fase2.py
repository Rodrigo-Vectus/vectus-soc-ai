"""
Tests de Fase 2 — cadena profunda completa con MOCKS DETERMINISTAS de las
APIs externas (VirusTotal, AbuseIPDB, OTX, OpenAI). Los tests corren
offline, sin keys y sin gastar cuota; la validación en vivo se hace en el
servidor de Rodrigo con las keys reales.

NOTA sobre datos: las 12 alertas reales del set no contienen IPs públicas,
por lo que la rama de enriquecimiento se ejercita con UNA alerta de red
sintética construida sobre el formato real de Wazuh (sshd), usando la IP
de prueba del proyecto (185.220.101.5). Cuando Rodrigo aporte una alerta
de red orgánica, se suma al set.

Cubre:
- Camino corto: las reglas curadas siguen resolviendo sin tocar APIs.
- Camino profundo + enriquecimiento: observable malicioso → R-ENR-001
  true_positive con evidencia (sin GPT) y → veredicto del analista (con GPT).
- Caché de reputación (segunda consulta no llama a la API).
- Analista GPT: salida válida manda; salida corrupta → reintento → needs_review.
- Línea base: cold_start honesto y rareza con histórico.
- Correlación por host y por observable compartido.
- Bulk-load: carga, dedup y errores.
- Contrato: mismas keys de siempre en todos los caminos.
"""
import json
import os
import re
import tempfile

import pytest

_tmpdir = tempfile.mkdtemp(prefix="vectus-test-f2-")
os.environ["DATA_DIR"] = _tmpdir
os.environ["API_KEY"] = ""

from fastapi.testclient import TestClient   # noqa: E402

from app import config, db                   # noqa: E402
from app.agents import analyst, baseline, enricher  # noqa: E402
from app.main import app                     # noqa: E402
from tests.test_fase1 import CONTRACT_KEYS, load_real_alerts  # noqa: E402

ALERTS = load_real_alerts()

# IP de prueba del proyecto (nodo Tor conocido) — brief §13.
TEST_IP = "185.220.101.5"


def make_network_alert(alert_uid: str, srcip: str = TEST_IP) -> dict:
    """Alerta de red sintética sobre el formato real de Wazuh (sshd brute)."""
    return {
        "_source": {
            "agent": {"id": "010", "name": "web-01", "ip": "192.168.10.20"},
            "manager": {"name": "wazuh"},
            "data": {"srcip": srcip, "srcport": "51234", "dstuser": "ubuntu"},
            "rule": {
                "id": "5763", "level": 10, "firedtimes": 8,
                "description": "sshd: brute force trying to get access to the system.",
                "groups": ["syslog", "sshd", "authentication_failures"],
                "mitre": {"id": ["T1110"]},
            },
            "location": "/var/log/auth.log",
            "decoder": {"name": "sshd", "parent": "sshd"},
            "id": alert_uid,
            "full_log": f"sshd[1234]: Failed password for ubuntu from {srcip} port 51234 ssh2",
            "timestamp": "2026-06-10T12:00:00.000+0000",
        }
    }


# ---------------------------------------------------------------------------
# Mocks deterministas
# ---------------------------------------------------------------------------

def mock_vt_malicious(obs_type, value):
    return {"status": "done", "found": True, "malicious": 12, "suspicious": 2,
            "harmless": 50, "undetected": 10, "reputation": -40,
            "tags": ["tor"], "as_owner": "Example AS", "country": "DE"}


def mock_abuse_malicious(obs_type, value):
    if obs_type != "ip":
        return {"status": "not_applicable"}
    return {"status": "done", "abuse_confidence": 100, "total_reports": 842,
            "country": "DE", "isp": "Example ISP", "usage_type": "Data Center",
            "is_tor": True, "last_reported_at": "2026-06-10T10:00:00+00:00"}


def mock_otx_active(obs_type, value):
    return {"status": "done", "pulse_count": 21,
            "pulse_names": ["Tor exit nodes", "SSH brute force campaign"]}


def mock_clean(obs_type, value):
    return {"status": "done", "found": True, "malicious": 0, "suspicious": 0,
            "harmless": 70, "undetected": 12, "reputation": 0, "tags": [],
            "as_owner": "Clean AS", "country": "US"}


class FakeEmbeddings:
    """Embeddings deterministas por hash de tokens: documentos parecidos
    producen vectores parecidos, sin llamar a OpenAI."""
    DIM = 64

    @staticmethod
    def embed(texts):
        out = []
        for t in texts:
            vec = [0.0] * FakeEmbeddings.DIM
            for tok in t.lower().split():
                vec[hash(tok) % FakeEmbeddings.DIM] += 1.0
            norm = sum(v * v for v in vec) ** 0.5 or 1.0
            out.append([v / norm for v in vec])
        return out


def make_analyst_response(verdict="true_positive", confidence=93):
    return {
        "verdict": verdict, "confidence": confidence,
        "case_description": "Análisis del dossier completo redactado por el analista. "
                            "Evidencia convergente de reputación maliciosa y patrón de "
                            "fuerza bruta sobre sshd.",
        "key_factors": ["IP con reputación maliciosa en múltiples fuentes",
                        "Patrón de fuerza bruta sshd"],
        "next_steps": ["Bloquear la IP en el firewall", "Revisar accesos exitosos posteriores"],
        "mitre": ["T1110"],
    }


@pytest.fixture()
def client():
    with TestClient(app) as c:
        yield c


@pytest.fixture()
def keys_configured(monkeypatch):
    """Simula keys presentes (las llamadas reales están mockeadas)."""
    monkeypatch.setattr(config, "VIRUSTOTAL_API_KEY", "vt-test")
    monkeypatch.setattr(config, "ABUSEIPDB_API_KEY", "abuse-test")
    monkeypatch.setattr(config, "OTX_API_KEY", "otx-test")
    monkeypatch.setattr(config, "OPENAI_API_KEY", "openai-test")


# ---------------------------------------------------------------------------
# Camino corto: el ruido se sigue resolviendo sin tocar ninguna API
# ---------------------------------------------------------------------------

def test_camino_corto_no_llama_apis(client, monkeypatch, keys_configured):
    llamadas = {"n": 0}

    def contador(*a, **k):
        llamadas["n"] += 1
        raise AssertionError("el camino corto no debe llamar APIs externas")

    monkeypatch.setattr(enricher, "_http_get", contador)
    monkeypatch.setattr(analyst, "_call_model", contador)
    monkeypatch.setattr(baseline, "embed", FakeEmbeddings.embed)

    # AppArmor __pycache__: regla curada final (false_positive)
    r = client.post("/api/alert/ingest", json=ALERTS[6]).json()
    assert r["verdict"] == "false_positive"
    assert r["internal_analysis"]["verdict_source"] == "curated_rule"
    assert r["enrichment"]["status"] == "skipped_curated_rule"
    assert llamadas["n"] == 0


# ---------------------------------------------------------------------------
# Camino profundo: enriquecimiento con reputación maliciosa
# ---------------------------------------------------------------------------

def test_evidencia_maliciosa_sin_gpt_da_true_positive(client, monkeypatch):
    """Sin OPENAI_API_KEY pero con reputación verificada: R-ENR-001 sostiene
    el positivo con evidencia real (degradación con dignidad)."""
    monkeypatch.setattr(config, "VIRUSTOTAL_API_KEY", "vt-test")
    monkeypatch.setattr(config, "ABUSEIPDB_API_KEY", "abuse-test")
    monkeypatch.setattr(config, "OTX_API_KEY", "otx-test")
    monkeypatch.setattr(config, "OPENAI_API_KEY", "")
    monkeypatch.setattr(enricher, "query_virustotal", mock_vt_malicious)
    monkeypatch.setattr(enricher, "query_abuseipdb", mock_abuse_malicious)
    monkeypatch.setattr(enricher, "query_otx", mock_otx_active)

    r = client.post("/api/alert/ingest",
                    json=make_network_alert("2000000001.000001")).json()
    assert r["alert_class"] == "network"
    assert r["verdict"] == "true_positive"
    assert r["create_case"] is True
    assert r["confidence"] == 95                      # evidencia multi-fuente
    assert r["internal_analysis"]["verdict_source"] == "evidence_rule"
    assert r["key_observable"] == TEST_IP
    ip_obs = [o for o in r["observables"] if o["value"] == TEST_IP][0]
    assert ip_obs["verdict"] == "malicious"
    assert ip_obs["sources"]["virustotal"]["malicious"] == 12
    assert "T1110" in r["mitre"]                      # vino de rule.mitre de Wazuh
    assert set(r.keys()) == CONTRACT_KEYS             # contrato intacto


def test_analista_emite_el_veredicto_final(client, monkeypatch, keys_configured):
    monkeypatch.setattr(enricher, "query_virustotal", mock_vt_malicious)
    monkeypatch.setattr(enricher, "query_abuseipdb", mock_abuse_malicious)
    monkeypatch.setattr(enricher, "query_otx", mock_otx_active)
    monkeypatch.setattr(baseline, "embed", FakeEmbeddings.embed)
    monkeypatch.setattr(analyst, "_call_model",
                        lambda dossier: make_analyst_response("true_positive", 93))

    r = client.post("/api/alert/ingest",
                    json=make_network_alert("2000000002.000001")).json()
    assert r["verdict"] == "true_positive"
    assert r["confidence"] == 93                      # el del analista, no el de la regla
    assert r["internal_analysis"]["verdict_source"] == "analyst"
    assert r["internal_analysis"]["analyst"]["status"] == "done"
    assert "analista" in r["case_description"]        # pie de trazabilidad
    assert "Bloquear la IP" in " ".join(r["next_steps"])


def test_analista_corrupto_cae_a_needs_review(client, monkeypatch, keys_configured):
    """GPT devolviendo basura dos veces → needs_review, nunca veredicto inventado."""
    monkeypatch.setattr(enricher, "query_virustotal", mock_clean)
    monkeypatch.setattr(enricher, "query_abuseipdb",
                        lambda t, v: {"status": "done", "abuse_confidence": 0,
                                      "total_reports": 0, "is_tor": False})
    monkeypatch.setattr(enricher, "query_otx",
                        lambda t, v: {"status": "done", "pulse_count": 0, "pulse_names": []})
    monkeypatch.setattr(baseline, "embed", FakeEmbeddings.embed)
    monkeypatch.setattr(analyst, "_call_model", lambda dossier: None)   # inválido siempre

    r = client.post("/api/alert/ingest",
                    json=make_network_alert("2000000003.000001", srcip="8.8.8.8")).json()
    assert r["verdict"] == "needs_review"
    assert r["create_case"] is False
    assert r["internal_analysis"]["verdict_source"] == "fallback"
    assert r["internal_analysis"]["analyst"]["status"] == "error"
    assert r["internal_analysis"]["rules_applied"][0]["rule_id"] == "R-SYS-001"


def test_cache_de_reputacion(monkeypatch):
    """La segunda consulta del mismo observable sale del caché, no de la API."""
    db.init_db()
    monkeypatch.setattr(config, "VIRUSTOTAL_API_KEY", "vt-test")
    monkeypatch.setattr(config, "VT_MIN_INTERVAL", 0)
    llamadas = {"n": 0}

    def fake_http(url, headers, params=None):
        llamadas["n"] += 1
        return {"data": {"attributes": {"last_analysis_stats":
                {"malicious": 7, "suspicious": 0, "harmless": 60, "undetected": 5},
                "reputation": -10, "tags": [], "as_owner": "X", "country": "NL"}}}

    monkeypatch.setattr(enricher, "_http_get", fake_http)
    r1 = enricher.query_virustotal("ip", "203.0.113.99")
    r2 = enricher.query_virustotal("ip", "203.0.113.99")
    assert llamadas["n"] == 1
    assert r1["malicious"] == 7 and r2.get("from_cache") is True


def test_fuente_caida_degrada_sin_romper(client, monkeypatch):
    """VT con error de red: se sigue con AbuseIPDB/OTX; status partial."""
    monkeypatch.setattr(config, "VIRUSTOTAL_API_KEY", "vt-test")
    monkeypatch.setattr(config, "ABUSEIPDB_API_KEY", "abuse-test")
    monkeypatch.setattr(config, "OTX_API_KEY", "otx-test")
    monkeypatch.setattr(config, "OPENAI_API_KEY", "")
    monkeypatch.setattr(enricher, "query_virustotal",
                        lambda t, v: {"status": "error", "detail": "timeout"})
    monkeypatch.setattr(enricher, "query_abuseipdb", mock_abuse_malicious)
    monkeypatch.setattr(enricher, "query_otx", mock_otx_active)

    r = client.post("/api/alert/ingest",
                    json=make_network_alert("2000000004.000001")).json()
    assert r["status"] == "done"
    assert r["enrichment"]["status"] == "partial"
    assert r["verdict"] == "true_positive"            # AbuseIPDB 100% alcanza
    assert r["internal_analysis"]["verdict_source"] == "evidence_rule"


# ---------------------------------------------------------------------------
# Línea base y correlación
# ---------------------------------------------------------------------------

def test_linea_base_cold_start_honesto(client, monkeypatch, keys_configured):
    monkeypatch.setattr(enricher, "query_virustotal", mock_clean)
    monkeypatch.setattr(enricher, "query_abuseipdb",
                        lambda t, v: {"status": "done", "abuse_confidence": 0,
                                      "total_reports": 0, "is_tor": False})
    monkeypatch.setattr(enricher, "query_otx",
                        lambda t, v: {"status": "done", "pulse_count": 0, "pulse_names": []})
    monkeypatch.setattr(baseline, "embed", FakeEmbeddings.embed)
    monkeypatch.setattr(analyst, "_call_model",
                        lambda d: make_analyst_response("informational", 60))

    r = client.post("/api/alert/ingest",
                    json=make_network_alert("2000000005.000001", srcip="8.8.4.4")).json()
    assert r["internal_analysis"]["baseline"]["status"] == "cold_start"
    assert r["internal_analysis"]["rarity"]["status"] == "cold_start"


def test_linea_base_con_historico_y_bulk_load(client, monkeypatch, keys_configured):
    monkeypatch.setattr(baseline, "embed", FakeEmbeddings.embed)
    monkeypatch.setattr(config, "COLDSTART_MIN_BASELINE", 10)

    # Bulk-load: 60 variantes históricas de la misma conducta en web-01
    historico = []
    for i in range(60):
        a = make_network_alert(f"1900000000.{i:06d}", srcip="8.8.4.4")
        historico.append(a)
    resp = client.post("/api/rag/bulk-load", json={"alerts": historico})
    assert resp.status_code == 200
    body = resp.json()
    assert body["cargadas"] == 60 and body["errores"] == 0

    # Re-carga del mismo lote: todo duplicado
    again = client.post("/api/rag/bulk-load", json={"alerts": historico}).json()
    assert again["duplicadas"] == 60 and again["cargadas"] == 0

    # Una alerta nueva muy parecida al histórico → rareza baja (habitual)
    monkeypatch.setattr(enricher, "query_virustotal", mock_clean)
    monkeypatch.setattr(enricher, "query_abuseipdb",
                        lambda t, v: {"status": "done", "abuse_confidence": 0,
                                      "total_reports": 0, "is_tor": False})
    monkeypatch.setattr(enricher, "query_otx",
                        lambda t, v: {"status": "done", "pulse_count": 0, "pulse_names": []})
    monkeypatch.setattr(analyst, "_call_model",
                        lambda d: make_analyst_response("informational", 70))
    r = client.post("/api/alert/ingest",
                    json=make_network_alert("2000000006.000001", srcip="8.8.4.4")).json()
    b = r["internal_analysis"]["baseline"]
    assert b["status"] == "ok" and b["asset_events"] >= 60
    assert r["internal_analysis"]["rarity"]["label"] == "habitual"
    assert r["internal_analysis"]["rarity"]["score"] <= 20


def test_bulk_load_con_basura_reporta_errores(client, monkeypatch, keys_configured):
    monkeypatch.setattr(baseline, "embed", FakeEmbeddings.embed)
    lote = [make_network_alert("1900000099.000001"), {"sin": "rule"}, "no-es-dict"]
    body = client.post("/api/rag/bulk-load", json={"alerts": lote}).json()
    assert body["errores"] == 2 and body["cargadas"] >= 0
    assert body["detalle_errores"]


def test_correlacion_por_host_y_observable(client, monkeypatch, keys_configured):
    monkeypatch.setattr(enricher, "query_virustotal", mock_vt_malicious)
    monkeypatch.setattr(enricher, "query_abuseipdb", mock_abuse_malicious)
    monkeypatch.setattr(enricher, "query_otx", mock_otx_active)
    monkeypatch.setattr(baseline, "embed", FakeEmbeddings.embed)
    monkeypatch.setattr(analyst, "_call_model",
                        lambda d: make_analyst_response("true_positive", 90))

    a1 = client.post("/api/alert/ingest",
                     json=make_network_alert("2000000007.000001")).json()
    r = client.post("/api/alert/ingest",
                    json=make_network_alert("2000000008.000001")).json()
    corr = r["correlation"]
    assert corr["status"] == "done"
    assert corr["related_count"] >= 1
    ids = [x["alert_id"] for x in corr["related"]]
    assert a1["alert_id"] in ids
    razones = " ".join(x["reason"] for x in corr["related"])
    assert "web-01" in razones or TEST_IP in razones
    assert corr["chain"], "la cadena temporal debe estar presente cuando hay relacionadas"


# ---------------------------------------------------------------------------
# El dossier que recibe el analista declara lo no disponible
# ---------------------------------------------------------------------------

def test_benigno_curado_con_hash_limpio_no_llama_analista(client, monkeypatch, keys_configured):
    """FIM de snap (regla curada benigna) con hash verificado limpio: el hash
    se enriquece (podría dar vuelta el veredicto si fuera malicioso) pero el
    analista GPT NO corre — no se gastan tokens en ruido resuelto."""
    monkeypatch.setattr(enricher, "query_virustotal", mock_clean)
    monkeypatch.setattr(enricher, "query_abuseipdb", lambda t, v: {"status": "not_applicable"})
    monkeypatch.setattr(enricher, "query_otx",
                        lambda t, v: {"status": "done", "pulse_count": 0, "pulse_names": []})
    monkeypatch.setattr(baseline, "embed", FakeEmbeddings.embed)

    def no_llamar(dossier):
        raise AssertionError("el analista no debe correr para benigno curado + reputación limpia")

    monkeypatch.setattr(analyst, "_call_model", no_llamar)
    # Copia con id propio: la original ya fue ingerida por la suite de F1
    # (base compartida en la sesión) y la idempotencia devolvería lo viejo.
    alerta = json.loads(json.dumps(ALERTS[11]))
    alerta["_source"]["id"] = "2000000009.000001"
    r = client.post("/api/alert/ingest", json=alerta).json()   # FIM snap con hash
    assert r["verdict"] == "informational"
    assert r["internal_analysis"]["verdict_source"] == "curated_rule"
    assert r["internal_analysis"]["analyst"]["status"] == "skipped_clean_reputation"
    assert r["enrichment"]["status"] == "done"
    h = [o for o in r["observables"] if o["type"] == "hash_sha256"][0]
    assert h["verdict"] == "clean"


def test_dossier_es_honesto_con_fuentes_faltantes(monkeypatch):
    from app.agents.rules import Decision
    monkeypatch.setattr(config, "OPENAI_API_KEY", "openai-test")
    capturado = {}

    def capturar(dossier):
        capturado.update(dossier)
        return make_analyst_response("needs_review", 45)

    monkeypatch.setattr(analyst, "_call_model", capturar)
    normalized = {
        "alert_id": "x", "asset": "host-x", "family": "network",
        "rule": {"id": "1", "level": 10, "description": "d", "groups": []},
        "action": {}, "observables": [], "timestamp": "", "full_log": "",
    }
    decision = Decision(verdict="needs_review", confidence=50, rule_id="R-DEF-REVIEW",
                        rule_name="default", rationale="r", final=False)
    out = analyst.analyze(normalized, decision, {"classification": "interna"},
                          {"status": "not_configured"},
                          {"baseline": {"status": "not_configured"},
                           "rarity": {"status": "not_configured"}},
                          {"status": "done", "related": [], "related_count": 0},
                          1)
    assert out["status"] == "done"
    assert capturado["reputacion_externa"]["status"] == "not_configured"
    assert capturado["linea_base"]["status"] == "not_configured"

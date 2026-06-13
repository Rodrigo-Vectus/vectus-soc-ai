"""
Tests de Fase 1 — validación contra las 12 ALERTAS REALES de Wazuh
(tests/data/alertas-wazuh.txt), con TestClient de FastAPI (in-process).

Cubre:
- Parseo e ingesta de cada alerta real → 200 done con contrato completo.
- Familia detectada, veredicto, create_case y confidence esperados por alerta.
- Estabilidad del contrato: las MISMAS keys en toda respuesta.
- Observables clave (hashes FIM, archivos, usuarios) y exclusión de genéricos.
- Idempotencia: re-POST de la misma alerta no duplica ni reprocesa.
- Auth X-API-Key, 404, 422, health, raíz, bulk-load 501.
"""
import json
import os
import re
import tempfile

import pytest

# Aislar la base: cada corrida usa un SQLite temporal propio.
_tmpdir = tempfile.mkdtemp(prefix="vectus-test-")
os.environ["DATA_DIR"] = _tmpdir
os.environ["API_KEY"] = ""           # abierto por defecto; el test de auth lo ajusta

from fastapi.testclient import TestClient   # noqa: E402

from app import config, db                   # noqa: E402
from app.main import app                     # noqa: E402

DATA_FILE = os.path.join(os.path.dirname(__file__), "data", "alertas-wazuh.txt")

# Keys del contrato (§8) que DEBEN estar en toda respuesta done, siempre.
CONTRACT_KEYS = {
    "alert_id", "status", "create_case", "verdict", "confidence", "severity",
    "alert_class", "asset", "title", "case_description", "key_observable",
    "key_factors", "next_steps", "mitre", "is_informational", "observables",
    "enrichment", "internal_analysis", "correlation", "engine_version",
    "processed_at",
}


def load_real_alerts() -> list[dict]:
    """Parsea el archivo real: bloques separados por encabezados 'JSON N:'."""
    with open(DATA_FILE, encoding="utf-8") as fh:
        content = fh.read()
    blocks = re.split(r"^JSON \d+:\s*$", content, flags=re.MULTILINE)
    alerts = [json.loads(b) for b in blocks if b.strip()]
    assert len(alerts) == 12, f"se esperaban 12 alertas reales, hay {len(alerts)}"
    return alerts


ALERTS = load_real_alerts()

# Expectativas acordadas con Rodrigo para cada alerta real (índice 0-based).
# (familia, veredicto, create_case)
EXPECTED = [
    ("windows_event", "informational", False),   # 1  logoff 4634 ARCD-DC100$ (WinEvtLog viejo)
    ("windows_event", "informational", False),   # 2  logoff 4634 (WinEvtLog viejo)
    ("ossec",         "informational", False),   # 3  agente desconectado (Forti-EMS)
    ("windows_event", "informational", False),   # 4  logon 4624 type 5 SYSTEM (Forti-EMS)
    ("windows_event", "informational", False),   # 5  logon 4624 type 5 SYSTEM (VectusBckp)
    ("windows_event", "informational", False),   # 6  logon 4624 type 5 SYSTEM (VectusBckp)
    ("apparmor",      "false_positive", False),  # 7  AppArmor mknod __pycache__
    ("apparmor",      "false_positive", False),  # 8  AppArmor mknod __pycache__
    ("rootcheck",     "true_positive", True),    # 9  clave SSL world-writable → CASO
    ("syscheck_fim",  "informational", False),   # 10 FIM solo inode (conf Apache)
    ("syscheck_fim",  "informational", False),   # 11 FIM deleted snap mount (Passbolt)
    ("syscheck_fim",  "informational", False),   # 12 FIM cambio de hash snap socket (Passbolt)
]


@pytest.fixture(scope="module")
def client():
    with TestClient(app) as c:
        yield c


@pytest.fixture(scope="module")
def results(client) -> list[dict]:
    """Ingesta las 12 alertas reales una vez y comparte los resultados."""
    out = []
    for i, alert in enumerate(ALERTS):
        resp = client.post("/api/alert/ingest", json=alert)
        assert resp.status_code == 200, f"alerta {i+1}: {resp.status_code} {resp.text[:300]}"
        body = resp.json()
        assert body["status"] == "done", f"alerta {i+1} no terminó: {body}"
        out.append(body)
    return out


# --------------------------------------------------------------------------
# Infraestructura básica
# --------------------------------------------------------------------------

def test_root_y_health(client):
    assert client.get("/health").json()["status"] == "ok"
    root = client.get("/").json()
    assert root["version"] == config.APP_VERSION and root["phase"] == "2"


def test_bulk_load_sin_openai_503(client):
    # Sin OPENAI_API_KEY el RAG no puede embeber: 503 con mensaje claro.
    assert client.post("/api/rag/bulk-load", json=[{"x": 1}]).status_code == 503


def test_alerta_mal_formada_422(client):
    assert client.post("/api/alert/ingest", json={"hola": "mundo"}).status_code == 422
    assert client.post("/api/alert/ingest",
                       content=b"no-json",
                       headers={"Content-Type": "application/json"}).status_code == 422


def test_get_inexistente_404(client):
    assert client.get("/api/alert/no-existe").status_code == 404


def test_auth_api_key(client):
    config.API_KEY = "clave-secreta"
    try:
        assert client.get("/api/alert/x").status_code == 401
        assert client.post("/api/alert/ingest", json=ALERTS[0]).status_code == 401
        ok = client.post("/api/alert/ingest", json=ALERTS[0],
                         headers={"X-API-Key": "clave-secreta"})
        assert ok.status_code == 200
    finally:
        config.API_KEY = ""


# --------------------------------------------------------------------------
# Validación de la cadena contra las alertas reales
# --------------------------------------------------------------------------

def test_contrato_estable_en_todas(results):
    """Las MISMAS keys para toda alerta, sin importar el agente de origen."""
    for i, r in enumerate(results):
        assert set(r.keys()) == CONTRACT_KEYS, f"alerta {i+1}: keys del contrato difieren"
        assert r["verdict"] in ("informational", "false_positive",
                                "needs_review", "true_positive")
        assert 0 <= r["confidence"] <= 100
        assert r["severity"] in ("low", "medium", "high", "critical")
        assert r["case_description"].strip(), f"alerta {i+1} sin case_description"
        assert r["title"].startswith("[Vectus SOC]")
        # coherencia interna del contrato
        assert r["create_case"] == (r["verdict"] == "true_positive")
        assert r["is_informational"] == (r["verdict"] == "informational")
        # bloques anidados SIEMPRE presentes con estado declarado (contrato estable)
        assert r["enrichment"]["status"] in (
            "done", "partial", "no_external_observables", "not_configured",
            "skipped_curated_rule")
        assert r["correlation"]["status"] in ("done", "skipped_curated_rule", "error")
        assert isinstance(r["correlation"]["related_count"], int)
        assert r["internal_analysis"]["rules_applied"], f"alerta {i+1} sin regla aplicada"
        assert r["internal_analysis"]["verdict_source"] in (
            "curated_rule", "evidence_rule", "analyst", "fallback",
            "supervised_suppression")


def test_familias_y_veredictos_esperados(results):
    for i, (r, (family, verdict, create_case)) in enumerate(zip(results, EXPECTED)):
        assert r["alert_class"] == family, \
            f"alerta {i+1}: familia {r['alert_class']} != {family}"
        assert r["verdict"] == verdict, \
            f"alerta {i+1}: veredicto {r['verdict']} != {verdict} " \
            f"(regla {r['internal_analysis']['rules_applied']})"
        assert r["create_case"] is create_case, f"alerta {i+1}: create_case incorrecto"


def test_unico_caso_es_la_clave_ssl(results):
    """De las 12 reales, solo la clave SSL world-writable abre caso."""
    casos = [r for r in results if r["create_case"]]
    assert len(casos) == 1
    caso = casos[0]
    assert caso["asset"] == "Reverse-Proxy"
    assert "private_helpdesk_la.key" in caso["key_observable"]
    assert caso["severity"] == "medium"          # rule.level 7
    assert caso["confidence"] >= 85              # regla curada firme
    assert "T1552.004" in caso["mitre"]
    assert caso["next_steps"], "un caso confirmado debe traer próximos pasos"
    assert "chmod" in " ".join(caso["next_steps"])


def test_detalles_windows(results):
    # Formato viejo WinEvtLog (alerta 1) y EventChannel (alerta 4) normalizan parejo.
    viejo, nuevo = results[0], results[3]
    assert viejo["internal_analysis"]["action"]["operation"] == "logoff"
    assert nuevo["internal_analysis"]["action"]["operation"] == "logon"
    assert viejo["asset"] == "WServer2019" and nuevo["asset"] == "Forti-EMS"
    # La cuenta de máquina quedó como observable user
    users = [o["value"] for o in viejo["observables"] if o["type"] == "user"]
    assert "ARCD-DC100$" in users
    # SYSTEM se extrae pero queda marcado como IOC genérico (no correlaciona)
    sys_obs = [o for o in nuevo["observables"] if o["value"] == "SYSTEM"]
    assert sys_obs and sys_obs[0]["is_generic"] is True
    assert nuevo["key_observable"] != "SYSTEM"


def test_detalles_fim(results):
    inode_only, deleted, content = results[9], results[10], results[11]
    # Solo inode → regla de reemplazo/deploy
    assert inode_only["internal_analysis"]["rules_applied"][0]["rule_id"] == "R-FIM-001"
    assert "inode" in inode_only["case_description"]
    # El hash sha256_after del FIM con cambio real queda como observable público
    hashes = [o for o in content["observables"] if o["type"] == "hash_sha256"]
    assert hashes and hashes[0]["is_public"] is True
    assert hashes[0]["value"].startswith("03ba96ee")
    # Los artefactos snap matchean la regla de ciclo de vida de snapd
    assert deleted["internal_analysis"]["rules_applied"][0]["rule_id"] == "R-FIM-002"
    assert content["internal_analysis"]["rules_applied"][0]["rule_id"] == "R-FIM-002"


def test_detalles_apparmor_y_ossec(results):
    aa = results[6]
    assert aa["internal_analysis"]["rules_applied"][0]["rule_id"] == "R-AA-001"
    assert aa["internal_analysis"]["action"]["actor"] == "python3"
    assert "__pycache__" in aa["internal_analysis"]["action"]["resource"]
    disc = results[2]
    assert "T1562.001" in disc["mitre"]
    assert disc["next_steps"], "la desconexión de agente debe traer pasos de verificación"


def test_idempotencia_no_duplica(client, results):
    """Re-POST de una alerta ya procesada devuelve el MISMO resultado, sin reprocesar."""
    first = results[8]                      # la del caso (rootcheck)
    again = client.post("/api/alert/ingest", json=ALERTS[8])
    assert again.status_code == 200
    body = again.json()
    assert body["alert_id"] == first["alert_id"]
    assert body["processed_at"] == first["processed_at"]   # no se reprocesó
    # Y en la base hay UNA sola fila para ese alert_id
    conn = db.get_conn()
    n = conn.execute("SELECT COUNT(*) FROM alerts WHERE alert_id=?",
                     (first["alert_id"],)).fetchone()[0]
    assert n == 1


def test_get_devuelve_resultado_completo(client, results):
    alert_id = results[0]["alert_id"]
    resp = client.get(f"/api/alert/{alert_id}")
    assert resp.status_code == 200
    assert set(resp.json().keys()) == CONTRACT_KEYS


def test_input_sin_wrapper_source(client):
    """Shuffle puede mandar el _source pelado: se acepta igual (mismo id)."""
    pelada = ALERTS[1]["_source"]
    resp = client.post("/api/alert/ingest", json=pelada)
    assert resp.status_code == 200
    body = resp.json()
    assert body["alert_class"] == "windows_event"
    # mismo alert_id que la versión envuelta → idempotencia entre formatos
    envuelta = client.post("/api/alert/ingest", json=ALERTS[1]).json()
    assert body["alert_id"] == envuelta["alert_id"]


def test_alerta_lenta_202_y_get(client, monkeypatch):
    """Si el análisis supera INGEST_MAX_WAIT, el POST devuelve 202 y el
    resultado completo se recupera luego con GET (contrato §10)."""
    import time
    from app import pipeline as pl

    original = pl._process_sync

    def lento(alert_id, raw, normalized):
        time.sleep(0.5)                      # simula enriquecimiento lento (Fase 2)
        return original(alert_id, raw, normalized)

    monkeypatch.setattr(pl, "_process_sync", lento)

    # Alerta nueva (modificamos el id de Wazuh para no chocar con las ya ingestadas)
    alerta = json.loads(json.dumps(ALERTS[9]))
    alerta["_source"]["id"] = "9999999999.111"

    # POST con tope de espera artificialmente bajo:
    monkeypatch.setattr(config, "INGEST_MAX_WAIT", 0.05)
    resp = client.post("/api/alert/ingest", json=alerta)
    assert resp.status_code == 202
    body = resp.json()
    assert body["status"] == "processing" and body["alert_id"]

    # Mientras procesa, el GET devuelve 202; al terminar, 200 con contrato completo.
    deadline = time.time() + 5
    final = None
    while time.time() < deadline:
        g = client.get(f"/api/alert/{body['alert_id']}")
        if g.status_code == 200:
            final = g.json()
            break
        assert g.status_code == 202
        time.sleep(0.1)
    assert final is not None, "la alerta lenta nunca terminó"
    assert set(final.keys()) == CONTRACT_KEYS
    assert final["status"] == "done"


def test_default_needs_review_nunca_true_positive(client):
    """Alerta de nivel alto SIN regla curada → needs_review, NUNCA true_positive
    (principio: veredicto firme solo con evidencia). Alerta sintética porque el
    set real no ejercita este camino — cubre el comportamiento del default."""
    alerta = {
        "_source": {
            "agent": {"id": "099", "name": "host-x", "ip": "192.168.99.9"},
            "rule": {"id": "99999", "level": 12, "groups": ["custom"],
                     "description": "Evento de prueba de severidad alta sin patrón curado"},
            "id": "1799999999.000001",
            "full_log": "evento sintetico de prueba",
            "timestamp": "2026-06-10T00:00:00.000+0000",
        }
    }
    r = client.post("/api/alert/ingest", json=alerta)
    assert r.status_code == 200
    body = r.json()
    assert body["verdict"] == "needs_review"
    assert body["create_case"] is False          # no abre caso automático
    assert body["is_informational"] is False     # tampoco es descartable
    assert body["confidence"] == 50
    assert body["internal_analysis"]["rules_applied"][0]["rule_id"] == "R-DEF-REVIEW"
    assert "REQUIERE REVISIÓN" in body["case_description"]
    # Y la misma alerta con nivel bajo cae a informational
    alerta["_source"]["rule"]["level"] = 3
    alerta["_source"]["id"] = "1799999999.000002"
    low = client.post("/api/alert/ingest", json=alerta).json()
    assert low["verdict"] == "informational"
    assert low["internal_analysis"]["rules_applied"][0]["rule_id"] == "R-DEF-INFO"


def test_repeticiones_de_firma(client):
    """Las alertas AppArmor 7 y 8 comparten patrón pero son archivos distintos;
    el contador de firma cuenta por (agente|regla|recurso)."""
    sig_counts = [r["internal_analysis"]["signature_count"] for r in
                  [client.post("/api/alert/ingest", json=ALERTS[6]).json(),
                   client.post("/api/alert/ingest", json=ALERTS[7]).json()]]
    # Ya ingestadas antes (fixture), el re-POST no incrementa: idempotente.
    assert all(c >= 1 for c in sig_counts)

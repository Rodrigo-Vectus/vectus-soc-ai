"""
Tests de Fase 3 — anti-ruido supervisado, endurecimiento e idempotencia
robusta. Mismos mocks deterministas que Fase 2: corren offline sin keys.

Cubre:
- Candidatas por TASA (ventana 7 días configurable) con veredictos benignos
  consistentes; una firma con true_positive/needs_review NUNCA es candidata.
- Supresión con autoría obligatoria → la siguiente alerta de la firma
  resuelve como false_positive/supervised_suppression con auditoría.
- Válvula de seguridad: firma suprimida + observable malicioso → la
  supresión se IGNORA y la evidencia manda.
- Revocación auditada → la firma vuelve al análisis normal.
- Reproceso versionado: resultado nuevo + el anterior archivado.
- Huérfanas: alertas en 'processing' se reencolan al arrancar.
- Timeout de processing colgado → error recuperable.
- Reintentos con backoff en fuentes externas.
- Límite de payload (413) y /api/stats.
"""
import json
import os
import tempfile

import httpx
import pytest

_tmpdir = tempfile.mkdtemp(prefix="vectus-test-f3-")
os.environ["DATA_DIR"] = _tmpdir
os.environ["API_KEY"] = ""

from fastapi.testclient import TestClient   # noqa: E402

from app import config, db                   # noqa: E402
from app.agents import analyst, baseline, enricher  # noqa: E402
from app.main import app                     # noqa: E402
from tests.test_fase1 import CONTRACT_KEYS   # noqa: E402
from tests.test_fase2 import (FakeEmbeddings, make_network_alert,  # noqa: E402
                              mock_abuse_malicious, mock_otx_active,
                              mock_vt_malicious)


@pytest.fixture()
def client():
    with TestClient(app) as c:
        yield c


def make_benign_alert(uid: str, host: str = "srv-ruidoso") -> dict:
    """Logoff de cuenta de máquina: regla curada benigna, sin observables
    externos. La firma (asset|regla|recurso) se repite por host: cada test
    usa su PROPIO host para que la supresión de uno no contamine a otro."""
    return {
        "_source": {
            "agent": {"id": "020", "name": host, "ip": "192.168.50.5"},
            "rule": {"id": "60137", "level": 3,
                     "groups": ["windows", "windows_security"],
                     "description": "Windows logoff: An account was logged off."},
            "data": {"win": {"system": {"eventID": "4634", "channel": "Security"},
                             "eventdata": {"targetUserName": "SRV-RUIDOSO$",
                                           "logonType": "3"}}},
            "id": uid,
            "full_log": "logoff repetitivo",
            "timestamp": "2026-06-11T10:00:00.000+0000",
        }
    }


def _ingest_n_benignas(client, n: int, host: str, start: int = 0) -> str:
    """Ingresa n alertas benignas de la misma firma (host propio del test);
    devuelve la firma."""
    last_id = None
    for i in range(n):
        r = client.post("/api/alert/ingest",
                        json=make_benign_alert(f"1810000000.{start + i:06d}", host)).json()
        assert r["verdict"] == "informational"
        last_id = r["alert_id"]
    row = db.get_conn().execute(
        "SELECT signature FROM alerts WHERE alert_id = ?", (last_id,)).fetchone()
    assert row and row["signature"]
    return row["signature"]


# ---------------------------------------------------------------------------
# Candidatas por tasa
# ---------------------------------------------------------------------------

def test_candidatas_aparecen_por_tasa(client, monkeypatch):
    monkeypatch.setattr(config, "NOISE_MIN_COUNT", 5)
    sig = _ingest_n_benignas(client, 6, host="host-tasa")

    body = client.get("/api/noise/candidates").json()
    assert body["min_count"] == 5 and body["window_hours"] == config.NOISE_WINDOW_HOURS
    cands = {c["signature"]: c for c in body["candidates"]}
    assert sig in cands
    c = cands[sig]
    assert c["count_in_window"] >= 6
    assert set(c["verdicts"].keys()) <= {"informational", "false_positive"}
    assert len(c["sample_alert_ids"]) == 3


def test_firma_con_no_benignos_no_es_candidata(client, monkeypatch):
    """La IP maliciosa genera true_positive repetidos: su firma JAMÁS puede
    sugerirse como ruido, por más tasa que tenga."""
    monkeypatch.setattr(config, "NOISE_MIN_COUNT", 2)
    monkeypatch.setattr(config, "VIRUSTOTAL_API_KEY", "vt-test")
    monkeypatch.setattr(config, "ABUSEIPDB_API_KEY", "abuse-test")
    monkeypatch.setattr(config, "OTX_API_KEY", "otx-test")
    monkeypatch.setattr(config, "OPENAI_API_KEY", "")
    monkeypatch.setattr(enricher, "query_virustotal", mock_vt_malicious)
    monkeypatch.setattr(enricher, "query_abuseipdb", mock_abuse_malicious)
    monkeypatch.setattr(enricher, "query_otx", mock_otx_active)

    sigs = set()
    for i in range(3):
        r = client.post("/api/alert/ingest",
                        json=make_network_alert(f"1810000100.{i:06d}")).json()
        assert r["verdict"] == "true_positive"
    row = db.get_conn().execute(
        "SELECT signature FROM alerts WHERE alert_id LIKE '010-1810000100%' LIMIT 1"
    ).fetchone()
    sig_tp = row["signature"]

    body = client.get("/api/noise/candidates").json()
    assert sig_tp not in {c["signature"] for c in body["candidates"]}


# ---------------------------------------------------------------------------
# Supresión supervisada
# ---------------------------------------------------------------------------

def test_suprimir_requiere_autoria_y_firma_conocida(client):
    assert client.post("/api/noise/suppress",
                       json={"signature": "x|y|z"}).status_code == 422
    r = client.post("/api/noise/suppress",
                    json={"signature": "firma|inexistente|jamas-vista",
                          "approved_by": "rodrigo"})
    assert r.status_code == 409
    assert "desconocida" in r.json()["detail"]


def test_supresion_aplica_con_auditoria(client, monkeypatch):
    sig = _ingest_n_benignas(client, 2, host="host-supresion", start=200)
    r = client.post("/api/noise/suppress",
                    json={"signature": sig, "approved_by": "rodrigo",
                          "note": "logoffs de cuenta de máquina, validado"})
    assert r.status_code == 201
    supp_id = r.json()["id"]

    # Doble supresión de la misma firma → 409
    assert client.post("/api/noise/suppress",
                       json={"signature": sig, "approved_by": "otro"}).status_code == 409

    # La siguiente alerta de la firma resuelve por supresión, con auditoría
    out = client.post("/api/alert/ingest",
                      json=make_benign_alert("1810000300.000001",
                                             host="host-supresion")).json()
    assert out["verdict"] == "false_positive"
    assert out["create_case"] is False
    assert out["internal_analysis"]["verdict_source"] == "supervised_suppression"
    assert out["internal_analysis"]["rules_applied"][0]["rule_id"] == "R-SUP-001"
    assert "rodrigo" in out["case_description"]
    assert str(supp_id) in out["case_description"]
    assert set(out.keys()) == CONTRACT_KEYS          # contrato intacto

    # Queda registrada y consultable (no desaparece)
    got = client.get(f"/api/alert/{out['alert_id']}")
    assert got.status_code == 200 and got.json()["verdict"] == "false_positive"


def test_evidencia_pisa_la_supresion(client, monkeypatch):
    """Firma de red suprimida + IP con reputación maliciosa: la supresión se
    ignora y la evidencia manda. El silenciado jamás tapa evidencia real."""
    monkeypatch.setattr(config, "VIRUSTOTAL_API_KEY", "vt-test")
    monkeypatch.setattr(config, "ABUSEIPDB_API_KEY", "abuse-test")
    monkeypatch.setattr(config, "OTX_API_KEY", "otx-test")
    monkeypatch.setattr(config, "OPENAI_API_KEY", "")
    # Primera pasada con reputación LIMPIA para que exista la firma benigna
    monkeypatch.setattr(enricher, "query_virustotal",
                        lambda t, v: {"status": "done", "found": True, "malicious": 0,
                                      "suspicious": 0, "harmless": 70, "undetected": 10,
                                      "reputation": 0, "tags": [], "as_owner": "", "country": ""})
    monkeypatch.setattr(enricher, "query_abuseipdb",
                        lambda t, v: {"status": "done", "abuse_confidence": 0,
                                      "total_reports": 0, "is_tor": False})
    monkeypatch.setattr(enricher, "query_otx",
                        lambda t, v: {"status": "done", "pulse_count": 0, "pulse_names": []})

    a = make_network_alert("1810000400.000001", srcip="91.240.118.7")
    r1 = client.post("/api/alert/ingest", json=a).json()
    assert r1["verdict"] == "needs_review"   # sin GPT, default preliminar honesto
    sig = db.get_conn().execute(
        "SELECT signature FROM alerts WHERE alert_id=?",
        (r1["alert_id"],)).fetchone()["signature"]

    # Forzamos la supresión (decisión humana, aunque discutible) y luego la
    # MISMA conducta llega con la IP ahora reportada maliciosa.
    db.get_conn().execute("UPDATE alerts SET verdict='false_positive' WHERE alert_id=?",
                          (r1["alert_id"],))
    client.post("/api/noise/suppress",
                json={"signature": sig, "approved_by": "rodrigo"})

    monkeypatch.setattr(enricher, "query_virustotal", mock_vt_malicious)
    monkeypatch.setattr(enricher, "query_abuseipdb", mock_abuse_malicious)
    monkeypatch.setattr(enricher, "query_otx", mock_otx_active)
    r2 = client.post("/api/alert/ingest",
                     json=make_network_alert("1810000400.000002",
                                             srcip="91.240.118.7")).json()
    assert r2["verdict"] == "true_positive"
    assert r2["create_case"] is True
    assert r2["internal_analysis"]["verdict_source"] == "evidence_rule"
    assert any("ignorada" in f.lower() for f in r2["key_factors"])


def test_revocacion_auditada(client):
    sig = _ingest_n_benignas(client, 2, host="host-revoca", start=500)
    supp = client.post("/api/noise/suppress",
                       json={"signature": sig, "approved_by": "rodrigo"}).json()

    assert client.delete(f"/api/noise/suppress/{supp['id']}").status_code == 422
    assert client.delete(f"/api/noise/suppress/{supp['id']}?revoked_by=rodrigo"
                         ).status_code == 200
    assert client.delete(f"/api/noise/suppress/{supp['id']}?revoked_by=rodrigo"
                         ).status_code == 404   # ya no está activa

    # La firma vuelve al análisis normal
    out = client.post("/api/alert/ingest",
                      json=make_benign_alert("1810000600.000001",
                                             host="host-revoca")).json()
    assert out["internal_analysis"]["verdict_source"] == "curated_rule"
    assert out["verdict"] == "informational"

    # Auditoría completa: la fila revocada sigue visible
    listado = client.get("/api/noise/suppressions").json()["suppressions"]
    fila = [s for s in listado if s["id"] == supp["id"]][0]
    assert fila["active"] == 0 and fila["revoked_by"] == "rodrigo"


# ---------------------------------------------------------------------------
# Idempotencia robusta
# ---------------------------------------------------------------------------

def test_reproceso_versionado(client, monkeypatch):
    a = make_benign_alert("1810000700.000001", host="host-reproceso")
    r1 = client.post("/api/alert/ingest", json=a).json()
    assert r1["verdict"] == "informational"

    r2 = client.post(f"/api/alert/{r1['alert_id']}/reprocess").json()
    assert r2["verdict"] == "informational"
    assert set(r2.keys()) == CONTRACT_KEYS            # contrato puro, sin extras
    assert r2["processed_at"] != r1["processed_at"]   # reanálisis real

    hist = db.get_result_history(r1["alert_id"])
    assert [h["version"] for h in hist] == [1]
    client.post(f"/api/alert/{r1['alert_id']}/reprocess")
    assert [h["version"] for h in db.get_result_history(r1["alert_id"])] == [1, 2]

    assert client.post("/api/alert/000-noexiste/reprocess").status_code == 404


def test_huerfanas_se_reencolan_al_arrancar():
    """Una alerta que quedó en 'processing' por caída del contenedor se
    reencola y completa al siguiente arranque."""
    db.init_db()
    raw = make_benign_alert("1810000800.000001", host="host-huerfana")
    alert_id = "020-1810000800.000001"
    assert db.insert_alert_processing(alert_id, raw)   # simula la caída

    with TestClient(app) as c:                          # lifespan → requeue
        import time
        for _ in range(50):
            rec = db.get_alert(alert_id)
            if rec and rec["status"] == "done":
                break
            time.sleep(0.1)
        assert rec["status"] == "done"
        assert rec["result"]["verdict"] == "informational"
        got = c.get(f"/api/alert/{alert_id}")
        assert got.status_code == 200


def test_processing_colgado_expira_recuperable(client, monkeypatch):
    db.init_db()
    alert_id = "020-1810000900.000001"
    db.insert_alert_processing(alert_id, make_benign_alert("1810000900.000001", host="host-colgado"))
    # Sin tarea corriendo y con timeout 0: el GET lo marca error recuperable
    monkeypatch.setattr(config, "PROCESSING_TIMEOUT_MINUTES", 0)
    r = client.get(f"/api/alert/{alert_id}")
    assert r.status_code == 500
    assert "reprocess" in r.json()["detail"]
    # Y el reproceso lo recupera
    out = client.post(f"/api/alert/{alert_id}/reprocess").json()
    assert out["verdict"] == "informational"


# ---------------------------------------------------------------------------
# Endurecimiento
# ---------------------------------------------------------------------------

def test_reintentos_con_backoff(monkeypatch):
    """Dos fallos transitorios y luego éxito: el resultado llega igual."""
    db.init_db()
    monkeypatch.setattr(config, "VIRUSTOTAL_API_KEY", "vt-test")
    monkeypatch.setattr(config, "VT_MIN_INTERVAL", 0)
    dormido = {"total": 0.0}
    monkeypatch.setattr(enricher.time, "sleep", lambda s: dormido.__setitem__(
        "total", dormido["total"] + s))
    intentos = {"n": 0}

    def inestable(url, headers=None, params=None, timeout=None):
        intentos["n"] += 1
        if intentos["n"] <= 2:
            raise httpx.ConnectTimeout("transitorio")
        class R:
            status_code = 200
            def raise_for_status(self): pass
            def json(self):
                return {"data": {"attributes": {"last_analysis_stats":
                        {"malicious": 0, "suspicious": 0, "harmless": 70,
                         "undetected": 10}, "reputation": 0, "tags": [],
                        "as_owner": "", "country": ""}}}
        return R()

    monkeypatch.setattr(enricher.httpx, "get", inestable)
    r = enricher.query_virustotal("ip", "203.0.113.200")
    assert r["status"] == "done" and intentos["n"] == 3
    assert dormido["total"] == pytest.approx(0.5 + 1.5)

    # 4xx es definitivo: un solo intento
    intentos["n"] = 0
    def cliente_error(url, headers=None, params=None, timeout=None):
        intentos["n"] += 1
        resp = httpx.Response(429, request=httpx.Request("GET", url))
        raise httpx.HTTPStatusError("rate", request=resp.request, response=resp)
    monkeypatch.setattr(enricher.httpx, "get", cliente_error)
    r = enricher.query_virustotal("ip", "203.0.113.201")
    assert r["status"] == "error" and intentos["n"] == 1


def test_payload_excesivo_413(client, monkeypatch):
    monkeypatch.setattr(config, "MAX_PAYLOAD_KB", 1)
    gigante = make_benign_alert("1810001000.000001", host="host-payload")
    gigante["_source"]["full_log"] = "X" * 4096
    r = client.post("/api/alert/ingest", json=gigante)
    assert r.status_code == 413


def test_stats(client):
    body = client.get("/api/stats").json()
    for key in ("alerts_by_status", "alerts_by_verdict", "alerts_by_verdict_source",
                "alerts_last_24h", "enrichment_cache_entries",
                "behavior_signatures", "active_suppressions"):
        assert key in body
    assert body["alerts_by_status"].get("done", 0) >= 1
    assert "supervised_suppression" in body["alerts_by_verdict_source"]

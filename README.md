# Vectus SOC Engine — Fase 3

Motor de inteligencia para SOC: API REST pura, multi-agente, que recibe alertas crudas de Wazuh (vía Shuffle), las analiza por una cadena de agentes y devuelve un JSON estandarizado listo para crear casos en TheHive. El motor no orquesta, no crea casos ni habla con TheHive: recibe, analiza, devuelve.

**Estado: Fase 3 completa** — Fase 1 (API + normalizador + router + reglas curadas + contrato) + Fase 2 (reputación externa, línea base RAG, correlación, analista GPT) + Fase 3: **anti-ruido supervisado** (el motor cuenta y sugiere por tasa; el humano decide, todo auditado y reversible), **endurecimiento operativo** (reintentos con backoff, límite de payload, timeout de análisis colgado, `/api/stats`) e **idempotencia robusta** (huérfanas reencoladas al arrancar, reproceso versionado). **El contrato JSON no cambió: mismas keys desde Fase 1.**

## Despliegue (Ubuntu, Docker Compose v2)

```bash
cp .env.example .env        # cargar las API keys (ver sección Configuración)
docker compose up --build -d
curl http://localhost:8003/health
```

Puerto **8003**. SQLite y ChromaDB persisten en el volumen `vectus-data`.

## Configuración (.env)

| Variable | Uso |
|----------|-----|
| `API_KEY` | Protege los endpoints con header `X-API-Key` (vacío = abierto) |
| `OPENAI_API_KEY` | Analista final + embeddings de línea base. Sin ella, el motor degrada: reglas curadas + evidencia de reputación, línea base `not_configured` |
| `VIRUSTOTAL_API_KEY` / `ABUSEIPDB_API_KEY` / `OTX_API_KEY` | Reputación externa. Cada una es independiente: la que falte queda `not_configured` y se sigue con las demás |
| `SHODAN_API_KEY` | Declarada, nunca se usa (tier free sin créditos) |
| `VT_MIN_INTERVAL` (15) | Segundos entre llamadas reales a VT (tier free 4/min). Acá nacen los 202 |
| `ENRICH_CACHE_TTL_HOURS` (24) | Caché de reputación: el mismo observable no gasta cuota dos veces |
| `RAG_SIM_THRESHOLD` (0.20) / `RAG_WINDOW_DAYS` (90) / `COLDSTART_MIN_BASELINE` (50) | Línea base |
| `CORRELATION_WINDOW_HOURS` (24) / `CORRELATION_MAX_RELATED` (10) | Correlación |
| `REVIEW_MIN_LEVEL` (7) / `INGEST_MAX_WAIT` (25) | Heredadas de Fase 1 |
| `NOISE_MIN_COUNT` (20) / `NOISE_WINDOW_HOURS` (168) | Anti-ruido: candidata = firma con ≥ N eventos en la ventana (tasa, 7 días default) y veredictos consistentemente benignos |
| `PROCESSING_TIMEOUT_MINUTES` (10) / `MAX_PAYLOAD_KB` (512) / `ENRICH_RETRIES` (2) | Endurecimiento Fase 3 |

## La cadena de agentes

**Camino corto** (regla curada resuelve con certeza): Normalizador → Router → Reglas → Reporter. El ruido benigno identificado (logons de servicio, AppArmor `__pycache__`, FIM de snapd) se resuelve en milisegundos sin gastar tokens ni cuota. Si la alerta trae observables públicos (p.ej. el hash de un FIM), la reputación SÍ se consulta — un hash malicioso da vuelta cualquier veredicto benigno — pero si viene limpia, el analista GPT no corre (`analyst.status: skipped_clean_reputation`).

**Camino profundo** (decisión preliminar, observables con señales, o evidencia de reputación): → Enricher (VT/AbuseIPDB/OTX con caché y rate limit) → Reglas post-enriquecimiento → Línea base (rareza vs. histórico del activo) → Correlador (ventana temporal, mismo host u observables compartidos no genéricos) → **Analista GPT-4o-mini (temp 0.1)** que recibe el dossier completo y emite el veredicto final con el `case_description` redactado.

**Procedencia del veredicto** (`internal_analysis.verdict_source`): `curated_rule` | `evidence_rule` (reputación maliciosa verificada, p.ej. R-ENR-001) | `analyst` | `fallback` (analista caído sin evidencia firme → `needs_review`, nunca un veredicto inventado).

**Regla de oro:** `true_positive` solo sale de (a) reglas curadas de certeza absoluta (clave SSL world-writable), (b) evidencia de reputación verificada (R-ENR-001: multi-fuente conf 95, una fuente conf 85), o (c) el analista con el dossier. El nivel de la regla Wazuh por sí solo jamás lo produce.

**Degradación elegante:** fuente externa caída → su bloque queda `{"status": "error"}` y se sigue (status `partial`); GPT devuelve basura → un reintento → `needs_review` con dossier adjunto; sin ninguna key → comportamiento Fase 1. El `case_description` siempre declara qué fuentes operaron y cuáles no — el motor no inventa lo que no verificó.

## Endpoints

| Método | Ruta | Descripción |
|--------|------|-------------|
| GET | `/` · `/health` | Info / healthcheck |
| POST | `/api/alert/ingest` | Alerta cruda de Wazuh → 200 contrato completo, o 202 + GET |
| GET | `/api/alert/{id}` | Recupera resultado (alertas que excedieron `INGEST_MAX_WAIT`) |
| POST | `/api/rag/bulk-load` | Carga histórico a la línea base: array JSON de alertas crudas o `{"alerts": [...]}`, máx. 500 por request → `{cargadas, duplicadas, errores}`. Requiere `OPENAI_API_KEY` (503 si falta) |
| GET | `/api/noise/candidates` | Firmas candidatas a supresión por tasa, con evidencia (conteo, ventana, veredictos, muestras). El motor sugiere; el humano decide |
| POST | `/api/noise/suppress` | Aprueba una supresión: `{"signature", "approved_by", "note"?}` — autoría obligatoria, 409 si ya está suprimida o la firma jamás se vio |
| DELETE | `/api/noise/suppress/{id}?revoked_by=` | Revoca (auditada: la fila queda como registro) |
| GET | `/api/noise/suppressions` | Auditoría de supresiones (`?active=true` solo vigentes) |
| POST | `/api/alert/{id}/reprocess` | Reanaliza con reglas/keys/línea base actuales; el resultado previo se archiva versionado. Responde el contrato puro |
| GET | `/api/stats` | Métricas: veredictos, fuente del veredicto, caché, firmas, supresiones activas |

Con el rate limit de VT (15 s entre llamadas no cacheadas), una alerta con varios observables nuevos puede exceder los 25 s del POST: respuesta `202 {alert_id, status: processing}` y Shuffle recupera con el GET. Este es el camino 202 "real" anticipado en Fase 1.

## Contrato de salida

Idéntico en keys a Fase 1 (ver test `test_contrato_estable_en_todas`). Lo que antes viajaba `not_available_phase1` ahora se llena: `enrichment.{virustotal,abuseipdb,otx}` por observable, `observables[].verdict` (`unknown|clean|suspicious|malicious`) y `observables[].sources` con la evidencia, `internal_analysis.{baseline,rarity,verdict_source,analyst}`, `correlation.{related,chain}`.

Umbrales de reputación documentados (`enricher.py`): VT ≥5 motores = malicioso, ≥2 sospechoso; AbuseIPDB ≥80% = malicioso, ≥25% sospechoso, nodo Tor = sospechoso; OTX ≥3 pulsos = sospechoso.

## Línea base y cold start

Cada alerta se convierte en un documento de comportamiento (no de texto crudo) y se embebe (text-embedding-3-small) en ChromaDB. Las nuevas se comparan contra el histórico del MISMO activo → `rarity.score` 0-100 (`habitual` / `poco_frecuente` / `inusual`). Con menos de `COLDSTART_MIN_BASELINE` eventos para el activo, la línea base declara `cold_start` y no emite juicio — no finge histórico. El `bulk-load` con el export de OpenSearch acorta ese período.

## Tests

```bash
pip install -r requirements-dev.txt
python3 -m pytest tests/ -q          # 41 passed
```

`test_fase1.py` (17): todo lo de Fase 1, intacto — las 12 alertas reales conservan familia, veredicto y caso. `test_fase2.py` (12): cadena profunda con mocks deterministas (offline, sin cuota). `test_fase3.py` (12): candidatas por tasa, firma con no-benignos jamás candidata, supresión con auditoría, **evidencia pisa supresión**, revocación, reproceso versionado, huérfanas reencoladas, timeout recuperable, reintentos con backoff, payload 413, stats.

La rama de red se valida con una alerta sintética sobre formato Wazuh real (sshd + IP `185.220.101.5`) hasta contar con una orgánica del entorno.

## Anti-ruido supervisado: el flujo

1. El motor cuenta cada firma de comportamiento (`asset|regla|recurso`) desde Fase 1.
2. `GET /api/noise/candidates` lista las que superan la TASA configurada **y** tuvieron solo veredictos benignos en la ventana — una sola `true_positive`/`needs_review` la excluye.
3. El analista humano aprueba con `POST /api/noise/suppress` (autoría y timestamp registrados, reversible).
4. Las alertas de una firma suprimida resuelven como `false_positive` con `verdict_source: "supervised_suppression"`, citando quién y cuándo aprobó. Quedan registradas y consultables: dejan de hacer ruido, no desaparecen.
5. **Válvula de seguridad**: si una alerta suprimida trae observables externos, la reputación se verifica ANTES de aplicar la supresión; cualquier señal maliciosa/sospechosa la ignora y la alerta entra al camino profundo, con el override anotado en `key_factors`. El silenciado jamás tapa evidencia real.

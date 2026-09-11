# Review — feature 14 (nvd_enrichment)

**Veredicto:** APPROVED

## Resumen de verificación

- `./init.sh` ejecutado **3 veces** de forma independiente: exit 0 estable,
  0 `[FAIL]` en las tres corridas.
- `cargo test` (sin Docker): **115 tests unitarios**, todos `ok` (baseline
  feature 13 era 97 → +18: 9 en `config` para las 3 vars nuevas, 1 en `domain`
  para `VulnSource::Nvd`, 8 en `enrichment::nvd`).
- `cargo test -- --ignored` (con Docker real, `mongo:7` + `sshd`): **23 tests**,
  todos `ok` (baseline 18 → +5, exactamente los nuevos de `MongoNvdCache` en
  `tests/repository.rs`: put/get, miss, creación TTL, idempotencia, `collMod`).
  Desglose: `repository` 11, `scan_pipeline` 3, `scanner` 4, `ssh` 5.
- `cargo build`: sin warnings (verificado con `touch src/lib.rs` + rebuild).
- `cargo clippy --all-targets -- -D warnings`: limpio.
- `cargo fmt --check`: limpio.
- `RUSTDOCFLAGS="-D warnings" cargo doc --no-deps`: limpio, 0 warnings.
- `cargo tree -i native-tls` / `-i openssl-sys`: sin resultados — confirmado
  que `reqwest` con `default-features = false` + `rustls-tls` no arrastra
  OpenSSL/native-tls a la dependencia.

## Checkpoints (CHECKPOINTS.md)

- **C1**: [x] Archivos base y docs existen; `./init.sh` exit 0.
- **C2**: [x] Solo la feature 14 está en `in_progress` (13 en `done`, verificado
  con `jq`/Counter); `progress/current.md` describe la sesión activa vigente,
  sin basura de sesiones previas.
- **C3**: [x] `cargo doc --no-deps` sin warnings (todo ítem público documentado).
  Sin `println!`/`dbg!`/TODO sueltos en los archivos tocados (grep limpio). Sin
  `unwrap`/`expect`/`panic!` fuera de `#[cfg(test)]` (grep exhaustivo revisado
  línea por línea; todas las ocurrencias están dentro de módulos `tests`).
  Nota: la lista literal de módulos de C3 (`config, domain, ssh, scanner,
  parser, repository, messaging`) quedó desactualizada desde antes de esta
  feature (no incluye `enrichment`, `pipeline`, `wiring`, ya aprobados en
  features 10-13); no es una regresión introducida aquí.
- **C4**: [x] `tests/repository.rs` tiene los 5 tests de integración nuevos de
  `MongoNvdCache` contra Mongo real vía `testcontainers`, marcados `#[ignore]`.
  `cargo test` > 0 y todo verde. Clippy limpio.
- **C5**: [ ] `progress/history.md` todavía no tiene entrada de esta sesión —
  correcto por protocolo: eso lo hace el leader tras aprobar esta revisión, no
  el implementer. No es un motivo de rechazo.

## Los 14 criterios de `acceptance` (feature_list.json id 14)

1. **`NvdApiEnricher` implementa `VulnEnricher`, dedup CPEs, conversión 2.2→2.3,
   consulta `?cpeName=<cpe23>`** — [x] `src/enrichment/nvd.rs:204-233` (enrich:
   dedup con `HashSet`+`Vec` antes de tocar caché/API), `cpe22_to_cpe23`
   (líneas 248-265), `findings_for_cpe23` construye
   `client.get(&self.base_url).query(&[("cpeName", cpe23)])` (línea 167).

2. **Mapeo `VulnFinding{id, severity, description, references, source: Nvd}`**
   — [x] `finding_from_cve` (líneas 327-345): `id: Some(cve.id)`,
   `severity: severity_from_metrics(&cve.metrics)`, `description` (primero
   `lang == "en"`), `references` desde `cve.references`, `source: VulnSource::Nvd`.

3. **`MS_NMAP_NVD_ENRICHMENT_ENABLED` requerida sin default; en `false` no hay
   egress** — [x] `config.rs:171-174` (`parse_strict_bool`, sin default, falla
   con `MissingVar` si ausente/vacía, `InvalidValue` si no es exactamente
   `"true"`/`"false"`). **Verificado en el código real** (no solo tests):
   `wiring.rs:100-115` sólo entra al bloque que construye `NvdApiEnricher`
   (incluyendo `repo.nvd_cache_store(ttl)`, que sí toca red hacia Mongo pero
   nunca hacia NVD) dentro de `if config.nvd_enrichment_enabled { ... }`. Fuera
   de ese `if` no existe ninguna referencia a `NvdApiEnricher` en el módulo:
   `grep -n NvdApiEnricher src/wiring.rs` sólo devuelve el import y esa única
   construcción condicional. Cero posibilidad de llamada de red si es `false`.

4. **`MS_NMAP_NVD_API_KEY` opcional real** — [x] `optional_secret` (líneas
   267-272): ausente o vacía (tras `trim`) → `None`, sin error. Tests
   `empty_nvd_api_key_is_none` y `present_nvd_api_key_is_some` cubren ambos
   caminos explícitamente.

5. **`MS_NMAP_NVD_CACHE_TTL_SECS` condicional** — [x] `config.rs:176-180`:
   `Some(parse_timeout(...))` sólo si `nvd_enrichment_enabled`, si no `None`
   sin leer ni exigir la variable. Tests `nvd_enabled_without_cache_ttl_is_a_typed_error`
   (falla con `MissingVar`), `nvd_enabled_with_cache_ttl_loads_ok`, y
   `nvd_disabled_without_cache_ttl_or_api_key_loads_ok` (deshabilitado, sin
   TTL ni API key, carga bien) — los 3 caminos verificados.

6. **Conversión CPE 2.2→2.3 con el CPE real de nmap** — [x]
   `cpe22_to_cpe23_converts_the_real_fixture_cpe`: usa
   `cpe:/a:openbsd:openssh:9.9` (idéntico al de
   `tests/fixtures/open_ports_service_version.xml:25`) → produce
   `cpe:2.3:a:openbsd:openssh:9.9:*:*:*:*:*:*:*`, exactamente lo pedido.

7. **Mapeo de severidad CVSS v3.1/v3.0/v2, `Unknown` sin métricas** — [x]
   `severity_from_metrics` prioriza v3.1 > v3.0 > v2 (`.or()`); tests:
   `severity_prefers_v31_over_v30_and_v2` (v3.1 CRITICAL con v3.0 y v2
   presentes, gana v3.1), `severity_from_v2_uses_nvd_score_thresholds_when_no_base_severity`
   (v2 sin `baseSeverity`, umbrales exactos <4.0/4.0-6.9/>=7.0 verificados en
   los 3 bordes), `severity_is_unknown_without_any_metric` (sin métricas →
   `Unknown`). Los 3 caminos cubiertos con test explícito.

8. **Caché con `NvdCache` trait + `InMemoryNvdCache` + `MongoNvdCache` con TTL,
   cache hit evita llamada HTTP** — [x] Trait en `nvd.rs:42-57`,
   `InMemoryNvdCache` (líneas 63-92) con tests unitarios sin Docker,
   `MongoNvdCache` en `repository.rs:490-541` con índice TTL sobre `cached_at`
   (`ensure_nvd_cache_ttl_index`, líneas 555-583, idempotente con fallback
   `collMod` para cambios de TTL, cubierto por 5 tests de integración reales).
   Test `cache_hit_avoids_a_second_http_call` en `nvd.rs`: mock con
   `.expect(1)`, dos llamadas a `enrich` con el mismo CPE → wiremock verifica
   que solo llegó 1 solicitud HTTP (falla el test si llega una segunda).

9. **Dedup de CPEs repetidos entre puertos** — [x] `enrich` (líneas 207-215)
   usa `HashSet` para deduplicar antes de iterar; test
   `duplicated_cpe_across_ports_is_queried_once`: 2 puertos con el mismo CPE,
   mock con `.expect(1)`, `findings.len() == 1`.

10. **Rate limiting propio, sin dependencia externa** — [x]
    `wait_for_rate_limit` (líneas 146-155) con `tokio::sync::Mutex<Option<Instant>>`
    interno, sin crates de limitador. Constantes documentadas y razonables:
    `MIN_INTERVAL_WITHOUT_KEY = 6.5s` (NVD: 5 req/30s → 6.0s + margen),
    `MIN_INTERVAL_WITH_KEY = 0.7s` (NVD: 50 req/30s → 0.6s + margen). Los
    tests aceleran `min_interval` a 1ms solo para no correr lento (código de
    producción usa los valores reales).

11. **Best-effort real: fallo HTTP/parseo → `EnrichError::Backend` +
    `tracing::warn!`, escaneo sigue, nunca `Failed`; un CPE roto no aborta los
    demás** — [x] `findings_for_cpe23` mapea error de red (línea 175) y de
    JSON (línea 187) a `Backend`; `enrich` (líneas 223-230) captura el `Err`
    por CPE con `tracing::warn!` y sigue el `for`, nunca propaga. Tests
    `http_500_yields_backend_error_without_panicking_and_keeps_other_cpes`
    (un CPE falla con 500, el otro responde 200, sólo 1 finding, sin panic) y
    `unreachable_server_yields_ok_with_no_findings_never_panics` (servidor
    caído → `Ok(vec![])`, nunca error propagado). Además,
    `CompositeVulnEnricher::enrich` (mod.rs:82-96) nunca falla el pipeline
    completo aunque un enricher individual falle.

12. **Dedup final por CVE entre NmapNse/ExploitDb/Nvd** — [x]
    `pipeline.rs::merge_enrichment_findings` (líneas 280-294) es agnóstica a
    la fuente: deduplica por `id` (CVE) contra lo ya existente y entre los
    elementos de `extra` según se van insertando. Como `extra` es la
    concatenación de todos los `VulnEnricher` del composite (ExploitDb + Nvd,
    si está habilitado) y `existing` arranca con los hallazgos NSE de nmap, el
    dedup cruza las 3 fuentes correctamente. Sin cambios de comportamiento
    respecto a la feature 13 (mismo mecanismo, ahora alimentado también por
    NVD).

13. **`docs/security-scope.md` con sección explícita de egress NVD** — [x]
    Sección nueva "Enriquecimiento de vulnerabilidades desde la API NVD"
    (líneas 97-132): documenta el endpoint, egress opt-in y condición exacta
    (`MS_NMAP_NVD_ENRICHMENT_ENABLED=true`), el dato mínimo enviado (sólo CPE,
    "**Nunca** se envía la IP del objetivo, el `correlation_id`... ni
    `network_user`"), dónde viaja la API key (header `apiKey`, nunca al
    objetivo ni persistida junto a hallazgos), la caché con TTL y qué guarda
    (sólo CPE + `VulnFinding`, nunca datos del objetivo), rate limiting, y el
    contrato best-effort. Cumple sobradamente lo pedido.

14. **Tests con `wiremock`, cero llamadas reales a NVD** — [x] Suite completa
    en `nvd.rs::tests` usa `MockServer::start()` + `base_url` inyectada vía
    `NvdApiEnricher::with_base_url`. `grep -rn "services.nvd.nist.gov"` en todo
    el repo sólo devuelve 3 resultados, todos en comentarios/rustdoc/constante
    (`nvd.rs:2,24`, `config.rs:56`, `security-scope.md:100`) — ninguno dentro
    de un test o de código que se ejecute en la suite. `cargo build` sin
    warnings, `./init.sh` verde x3, clippy/fmt/doc limpios (ver arriba), sin
    regresión: los 97 tests unitarios y 18 de Docker de las features 1-13
    siguen presentes (reubicados a `enrichment::exploitdb`/`enrichment::mod`
    sin pérdida ni cambio de lógica) y en verde junto con los nuevos.

## Sección de seguridad / egress (verificación exhaustiva)

- **Punto 1 del encargo (opt-in real en código)**: confirmado línea por línea
  en `src/wiring.rs:100-115`. `grep -c "NvdApiEnricher" src/wiring.rs` = 2
  (import + la única construcción, dentro del `if`). No existe ningún otro
  punto del código de producción (`src/main.rs`, `src/lib.rs`) que construya
  `NvdApiEnricher` fuera de `wiring::service_ports_from_config`.
- **Punto 2 (solo CPE viaja a NVD)**: en `findings_for_cpe23` (nvd.rs:160-201)
  la única entrada de usuario/objetivo que toca la request es `cpe23`
  (`.query(&[("cpeName", cpe23)])`) y, opcionalmente, el header `apiKey`
  (`api_key.expose_secret()`, la propia credencial de NVD, no del objetivo).
  `PortFinding` no expone `ip`/`correlation_id`/`network_user`/credenciales SSH
  a esta función — sólo recibe `&[PortFinding]`, que en el dominio no contiene
  esos campos (son parte de `ScanRequest`/`ScanResult`, nunca pasados al
  enricher). No hay forma de que esos datos lleguen al request HTTP.
- **Punto 3 (API key opcional real)**: confirmado con test explícito,
  `MissingVar` nunca se dispara para `NVD_API_KEY_VAR`.
- **Punto 4 (TTL condicional)**: confirmado con tests para ambos caminos
  (habilitado exige TTL con error tipado si falta; deshabilitado no lo exige
  ni lo lee).
- **Caché Mongo**: sólo persiste `{_id: <cpe>, findings, cached_at}` — nunca
  IP/correlation_id/credenciales (`StoredNvdCacheEntry`, repository.rs:475-481).
- **Ningún egress real en tests**: confirmado (ver criterio 14).

## Observaciones menores (no bloqueantes)

- `nvd_cache_error`/`MongoNvdCache::get`/`put` propagan
  `mongodb::error::Error::to_string()` sin redactar explícitamente; es el
  mismo patrón ya usado y aprobado en `RepoError` para el resto del módulo
  (`repository.rs`) desde features anteriores, no es una regresión introducida
  por esta feature ni un vector de fuga de credenciales de objetivo (la URI de
  Mongo es configuración de despliegue, no dato del `ScanRequest`).
- La entrada de C3 en `CHECKPOINTS.md` que enumera los módulos esperados de
  `src/` está desactualizada desde antes de esta feature (no incluye
  `enrichment`, `pipeline`, `wiring`); no se penaliza aquí porque no es un
  cambio introducido por el implementador de la feature 14.

## Conclusión

Los 14 criterios de aceptación de la feature 14 se cumplen con evidencia
verificable en código y tests. El egress hacia NVD es genuinamente opt-in
(sin ninguna ruta de código alcanzable con `nvd_enrichment_enabled=false`), el
único dato enviado es el CPE, la caché y el rate limiting están implementados
correctamente, el contrato best-effort se mantiene, y no hay regresión ni
scope creep (ssh/scanner/main.rs intactos, sin adaptadores adicionales no
pedidos). `./init.sh` verde en 3 corridas, clippy/fmt/doc limpios.

**APPROVED.**

# Informe de implementación — feature 14: `nvd_enrichment`

## Resumen

Segundo adaptador de `VulnEnricher` (`NvdApiEnricher`, `src/enrichment/nvd.rs`),
que consulta la API NVD 2.0 por CPE, con caché persistente en Mongo (TTL) y
egress de red opt-in vía `MS_NMAP_NVD_ENRICHMENT_ENABLED`. `enrichment.rs` se
dividió en el submódulo `src/enrichment/{mod.rs, exploitdb.rs, nvd.rs}` porque
el archivo plano ya rondaba las 510 líneas antes de añadir NVD.

## Archivos tocados

- `src/domain.rs` — `VulnSource::Nvd` + test de serialización estable.
- `src/enrichment/mod.rs` (nuevo, antes `src/enrichment.rs`) — `EnrichError`,
  trait `VulnEnricher`, `CompositeVulnEnricher` y sus tests (sin cambios de
  comportamiento, sólo reubicados).
- `src/enrichment/exploitdb.rs` (nuevo) — `ExploitDbEnricher` tal cual estaba
  (movido, no reescrito).
- `src/enrichment/nvd.rs` (nuevo) — `NvdApiEnricher`, trait `NvdCache`,
  `InMemoryNvdCache`, conversión CPE 2.2→2.3, mapeo de severidad CVSS,
  rate limiting propio, tests con `wiremock`.
- `src/repository.rs` — colección `nvd_cache`, `MongoNvdCache` (implementa
  `NvdCache`), `MongoRepository::nvd_cache_store(ttl)` que asegura el índice
  TTL de forma idempotente (con fallback a `collMod` si el TTL cambió).
- `src/config.rs` — `NVD_ENRICHMENT_ENABLED_VAR`, `NVD_API_KEY_VAR`,
  `NVD_CACHE_TTL_VAR`, campos correspondientes en `Config` y su validación
  condicional, con 9 tests nuevos.
- `src/wiring.rs` — añade `NvdApiEnricher` al `CompositeVulnEnricher` sólo si
  `config.nvd_enrichment_enabled`; nuevo `WiringError::InvalidNvdConfig`
  (defensivo, no debería ocurrir nunca) y helper `clone_secret` (`SecretString`
  no es `Clone`).
- `src/pipeline.rs` — doc del campo `ServicePorts::enricher` actualizada.
- `Cargo.toml` — `reqwest` (rustls, sin OpenSSL) y `wiremock` (dev-dependency).
- `docs/security-scope.md` — nueva sección "Enriquecimiento de vulnerabilidades
  desde la API NVD" (egress opt-in, único dato enviado, caché, rate limiting,
  contrato best-effort).
- `docs/architecture.md` — tabla de puertos/adaptadores, capa `enrichment`,
  diagrama de flujo y sección "Despliegue" actualizados para reflejar el
  submódulo y el segundo adaptador.
- `README.md` — nuevas variables de entorno documentadas + ejemplo de
  `docker run` con NVD habilitado.
- `tests/repository.rs` — 5 tests de integración nuevos contra Mongo real
  (`#[ignore = "requiere Docker"]`): put/get, miss, creación del índice TTL con
  el `expireAfterSeconds` esperado, idempotencia y actualización vía `collMod`.

## Decisiones y desviaciones documentadas

1. **Split de módulo** (`enrichment.rs` → `enrichment/{mod,exploitdb,nvd}.rs`):
   decisión explícita para no dejar un archivo de >800 líneas: el trait
   compartido y el composite viven en `mod.rs`; cada adaptador en su propio
   archivo. Documentado en el rustdoc de `enrichment/mod.rs`.

2. **`cached_at` como `bson::DateTime`, no cadena RFC 3339** (desviación
   respecto al `acceptance`, que sugiere una cadena como en `scan_results`):
   el índice TTL de MongoDB **sólo funciona sobre un campo de tipo fecha
   BSON real**; con una cadena el documento nunca expiraría. Documentado en
   el rustdoc de `StoredNvdCacheEntry` en `src/repository.rs`.

3. **`MongoRepository::nvd_cache_store` es `async` y devuelve
   `Result<MongoNvdCache, RepoError>`** (el `acceptance` sugería una firma
   síncrona sin `Result`, en paralelo a `host_key_store()`): construir la
   caché implica asegurar el índice TTL, que es una operación de red contra
   Mongo y puede fallar. `host_key_store()` no tiene ese problema porque no
   crea ningún índice.

4. **`expireAfterSeconds` distinto al ya existente**: MongoDB no permite
   cambiarlo con `createIndexes`; se detecta el error
   `IndexOptionsConflict`/`IndexKeySpecsConflict` (códigos 85/86) y se hace
   fallback a `collMod`. Cubierto por el test de integración
   `nvd_cache_store_updates_the_ttl_via_collmod_when_the_ttl_changes`.

5. **Test de expiración real del TTL**: MongoDB corre el job de fondo de TTL
   cada ~60s por defecto; esperar el borrado real habría hecho el test lento
   y potencialmente flaky. En su lugar, los tests de integración verifican
   directamente contra el servidor (`list_indexes`) que el índice
   `expireAfterSeconds` sobre `cached_at` se creó/actualizó con el valor
   esperado. Documentado también en el propio test.

6. **`SecretString` no es `Clone`** (`secrecy` sólo implementa
   `CloneableSecret` para enteros, no para `str`): `wiring::clone_secret`
   reconstruye un nuevo `SecretString` a partir de `expose_secret()` en el
   único punto donde hace falta (no se pudo derivar `Clone` para `Config`
   completo).

7. **Rate limiting**: 6.5s sin `apiKey` (NVD documenta 5 req/30s → 6.0s
   exactos, se añade margen), 0.7s con `apiKey` (50 req/30s → 0.6s exactos,
   con margen). Implementado con un único `tokio::sync::Mutex<Option<Instant>>`
   interno por instancia de `NvdApiEnricher`, sin dependencias externas de
   limitador.

8. **Severidad desde CVSS v2**: la respuesta de NVD para `cvssMetricV2` no
   trae `baseSeverity` dentro de `cvssData` (a diferencia de v3.x); el modelo
   de deserialización sólo lee `cvssData.{baseScore,baseSeverity}` para las
   tres versiones, así que v2 siempre cae a los umbrales de NVD sobre
   `baseScore` (`<4.0` Low, `4.0..=6.9` Medium, `>=7.0` High), tal como pide
   el `acceptance`.

9. **Dependencias nuevas**: `reqwest` con `default-features = false` +
   `rustls-tls` (mismo TLS que ya usa `mongodb` en este crate, evita arrastrar
   OpenSSL/`native-tls`); `wiremock` sólo como dev-dependency, para no meter
   un servidor HTTP mock en el binario de producción.

## Verificación

- `cargo build`: sin warnings.
- `cargo test` (unit, sin Docker): **115 tests** pasan (todos los previos +
  todos los nuevos de `config`, `domain` y `enrichment::nvd`; los de
  `enrichment.rs` se reubicaron a los submódulos sin perder ninguno).
- `cargo test -- --ignored` (Docker): **23 tests** de integración pasan (18
  previos + 5 nuevos de `MongoNvdCache` en `tests/repository.rs`).
- `cargo clippy --all-targets -- -D warnings`: limpio.
- `cargo fmt --check`: limpio.
- `RUSTDOCFLAGS="-D warnings" cargo doc --no-deps`: limpio (se corrigió un
  intra-doc-link a constantes privadas en `nvd.rs`).
- `./init.sh` corrido en verde 3 veces seguidas, sin flakiness observada.
- Revisión manual: con `MS_NMAP_NVD_ENRICHMENT_ENABLED=false`,
  `wiring::service_ports_from_config` nunca entra al bloque que construye
  `NvdApiEnricher` (ni crea `reqwest::Client` para NVD ni llama a
  `repo.nvd_cache_store`), por lo que no hay ninguna ruta de código con
  posibilidad de egress hacia NVD.
- Sin `unwrap()`/`expect()`/`panic!()` fuera de tests en el código nuevo
  (verificado con `grep` excluyendo `#[cfg(test)]`).
- Sin regresión: los 97 tests unitarios y ~19 de Docker de las features 1-13
  se mantienen verdes (algunos reubicados de módulo, ninguno eliminado ni
  modificado en su lógica).

## Estado

Feature 14 implementada y verificada localmente. **No se marcó `done`**: queda
pendiente la revisión de un agente `reviewer` antes de cerrar, según el
protocolo del implementador.

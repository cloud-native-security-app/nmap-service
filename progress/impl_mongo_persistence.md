# Implementación feature 7 — `mongo_persistence`

- **Agente:** implementer
- **Fecha:** 2026-08-27
- **Estado:** implementada + `./init.sh` verde (incl. `cargo test -- --ignored` con Docker). Pendiente de review.

## Alcance cubierto

### A. `src/ssh.rs` — `HostKeyStore` pasa a async (decisión del usuario, parte de esta feature)

- Nuevo error público `HostKeyStoreError` (`thiserror`, variantes distintas):
  - `Unavailable(String)` — almacén de respaldo caído/inalcanzable; la conexión SSH se aborta.
  - `Corrupt(String)` — registro con formato inesperado (p. ej. hex de fingerprint que no mide 64).
  - Se eligió tipo propio (no variante de `SshError`) para que las impls del trait no dependan de `SshError`.
- `#[async_trait::async_trait] pub trait HostKeyStore: Send + Sync` (se añade `Sync`):
  - `async fn known_fingerprint(&self, host: &str) -> Result<Option<Fingerprint>, HostKeyStoreError>`
  - `async fn remember(&self, host: &str, fingerprint: Fingerprint) -> Result<(), HostKeyStoreError>` — **`&self`** (mutabilidad interior), ya no `&mut self`.
- Tipo compartido: `Arc<dyn HostKeyStore>` (se elimina el `Mutex` externo). Actualizados `Verifier`, `connect()`, `verify_fingerprint` (ahora `async fn verify_fingerprint(store: &dyn HostKeyStore, ...)`), y todos los tests unitarios de `src/ssh.rs` + `tests/ssh.rs` + `tests/scanner.rs` que usaban `Arc<Mutex<dyn HostKeyStore>>`.
- `InMemoryHostKeyStore`: pasa a `entries: std::sync::Mutex<HashMap<String, Fingerprint>>`. El guard se toma y suelta dentro de cada método, sin cruzar `.await`; sus `async fn` no hacen `.await` real y nunca devuelven `Err`. `#[derive(Debug, Default)]` sigue válido.
- Nueva variante `SshError::HostKeyStore(#[from] HostKeyStoreError)`: `connect()` la usa cuando `check_server_key` no pudo consultar/actualizar el trust store. `Verifier` comparte con `connect` un slot `Arc<Mutex<Option<HostKeyStoreError>>>` además del `Arc<AtomicBool>` de mismatch; en ambos casos `check_server_key` devuelve `Ok(false)` (nunca acepta una clave sin verificar).
- **Regresión features 4 y 5:** `tests/ssh.rs` (5) y `tests/scanner.rs` (4) siguen 100% verdes con Docker real; los 7 unit tests de `ssh.rs` (3 convertidos a `#[tokio::test]`) también.

### B. `src/repository.rs` — `MongoRepository` (struct concreto, NO trait)

- `async fn connect(uri: &str, db_name: &str) -> Result<Self, RepoError>`: crea el `Client`, hace `run_command({ping:1})` para fallar rápido, y guarda `Collection<StoredScan>` + `Collection<Document>`. Es `Clone` (comparte pool).
- `async fn save(&self, result: &ScanResult, correlation_id: &CorrelationId) -> Result<ScanId, RepoError>` — **firma ampliada** (documentada): `ScanResult` no tiene `correlation_id`, se pasa aparte y se guarda en el documento junto con `timestamp` (RFC3339 del instante de guardado).
- `async fn find_by_id(&self, id: &ScanId) -> Result<Option<ScanResult>, RepoError>` — id inexistente → `Ok(None)`. Un `ScanId` que no es `ObjectId` válido → `RepoError::Serialization` (distinto de "inexistente").
- `async fn find_by_correlation_id(&self, correlation_id: &CorrelationId) -> Result<Option<ScanResult>, RepoError>` — `find_one(...).sort({timestamp:-1})`; si hubiera re-escaneos, devuelve el más reciente.
- Documento (`StoredScan`): `{ _id, correlation_id, timestamp (rfc3339 string), result: <ScanResult> }`. El `ScanResult` va anidado bajo `result` (más simple y robusto que `#[serde(flatten)]` con BSON).
- `ScanId`: newtype `#[serde(transparent)]` sobre `String` (hex del `ObjectId`). `new`/`as_str`/`Display`/`FromStr` (infalible)/`From<ObjectId>`. Helper privado `to_object_id()`.
- `RepoError` (`thiserror`): `ConnectionFailed(String)` (ServerSelection / Io / DnsResolve / ConnectionPoolCleared), `Serialization(String)` (BsonSerialization/BsonDeserialization + ScanId inválido), `Backend(String)` (resto). `impl From<mongodb::error::Error>` con `match *err.kind`. Sin panics.
- `scanned_at` se persiste como **string RFC3339** (via el `#[serde(with = "time::serde::rfc3339")]` que ya tiene `ScanResult`), no `bson::DateTime`: consistente con el JSON al Broker y sin dep extra de `bson`. Trade-off documentado en el rustdoc del módulo: `scanned_at`/`timestamp` no son consultables como fecha en Mongo (no se hace en este servicio).

### C. `src/repository.rs` — `MongoHostKeyStore` implementa el `HostKeyStore` async

- Struct con una `mongodb::Collection<Document>` (colección `ssh_host_keys`). Se obtiene con `MongoRepository::host_key_store()`. `Clone`.
- `known_fingerprint`: `find_one({_id: host})` → reconstruye `Fingerprint` con `from_sha256_bytes` desde el hex (`fingerprint_from_hex`, valida longitud 64 y dígitos).
- `remember`: `update_one({_id: host}, { $set: {fingerprint_sha256_hex}, $setOnInsert: {first_seen} }).upsert(true)`. `$setOnInsert` para que `first_seen` sea de verdad "primera vez vista" y `remember` sea idempotente.
- Documento: `{ "_id": "<host>", "fingerprint_sha256_hex": "<64 hex>", "first_seen": "<rfc3339>" }` (no el `[u8;32]` crudo).
- Errores del driver → `HostKeyStoreError` (`host_key_store_error`): BSON → `Corrupt`, resto → `Unavailable`.

### D. `Cargo.toml`

- `mongodb = "3"` (3.8.2; defaults: rustls-tls + dns-resolver + bson-2). Driver oficial async exigido por `docs/architecture.md`.
- `async-trait = "0.1"` **movido a `[dependencies]`** (antes solo estaba en el árbol como dep transitiva dev de `testcontainers`): necesario para que `HostKeyStore` con `async fn` sea dyn-compatible (`Arc<dyn HostKeyStore>`).
- **`futures-util` NO se añadió**: `find_by_correlation_id` se resuelve con `find_one().sort()` (`FindOneOptions.sort` existe en mongodb 3.8) sin iterar cursores; añadir una dep sin uso iría contra `docs/conventions.md`. Desviación consciente respecto a la sugerencia de `progress/explore_mongo.md`.
- **`tokio` sin cambios**: no se añadió `"sync"` porque toda la sincronización interna usa `std::sync::Mutex` (guards que no cruzan `.await`).

## Tests

- **Unit (`src/repository.rs`, sin Docker):** `ScanId` round-trip string + serde + `From<ObjectId>` + rechazo de no-hex; `RepoError::from` mapea E/S de red → `ConnectionFailed` y fallo BSON → `Serialization`; `RepoError` Display sin términos de credencial; `fingerprint_to_hex`/`from_hex` round-trip y rechazo de longitud/dígitos inválidos.
  - `connect_to_unreachable_mongo_is_connection_failed` (`#[tokio::test]` normal, ~0.5 s, sin Docker): `connect` a `mongodb://127.0.0.1:1/?serverSelectionTimeoutMS=500` → `RepoError::ConnectionFailed` (cubre el caso real `ServerSelection`, que es `#[non_exhaustive]` y no se puede construir a mano).
- **Integración (`tests/repository.rs`, `#[tokio::test]` + `#[ignore = "requiere Docker"]`, contenedor `mongo:7`):**
  - `save` + `find_by_id`: comprueba `assert_eq!` del `ScanResult` completo y además puertos concretos (443 filtered), CVE, severidad, `scanned_at`.
  - `save` + `find_by_correlation_id`: recupera por correlation_id + correlation_id desconocido → `None`.
  - `find_by_id` de `ObjectId::new()` no guardado → `Ok(None)`.
  - `stored_document_carries_timestamp_and_correlation_id`: inspección con un `Client` raw — `correlation_id` string, `timestamp` RFC3339 dentro del rango de guardado, `result.scanned_at` string RFC3339.
  - `MongoHostKeyStore`: `remember` → `known_fingerprint` lo devuelve; host desconocido → `Ok(None)`; **persistencia entre "reinicios"** (nuevo `MongoRepository::connect` → `.host_key_store()` sobre la misma colección sigue viéndolo) + `remember` idempotente.
  - Solo contra el contenedor (base `db-nmap-test`), nunca producción.

## Verificación

`./init.sh` → EXIT 0:
- `cargo fmt --check` limpio.
- `cargo clippy --all-targets -- -D warnings` limpio.
- `cargo test` → 56 passed (config 8 + domain 7 + parser 11 + scanner 14 + ssh 7 + repository 9).
- `cargo test -- --ignored` → repository 6 + scanner 4 + ssh 5, todos verdes con Docker real.
- `cargo doc --no-deps` limpio (rustdoc en todo ítem público; `#![deny(missing_docs)]`).
- Sin `unwrap`/`expect`/`panic!` fuera de `#[cfg(test)]`.

## Archivos tocados

- `src/ssh.rs` — `HostKeyStore` async, `HostKeyStoreError`, `SshError::HostKeyStore`, `Verifier`/`connect`/`verify_fingerprint`, tests.
- `src/repository.rs` — implementación completa (era stub).
- `tests/repository.rs` — nuevo.
- `tests/ssh.rs`, `tests/scanner.rs` — adaptados a `Arc<dyn HostKeyStore>`.
- `Cargo.toml` — `mongodb`, `async-trait`.
- `feature_list.json` — feature 7 → `in_progress`.

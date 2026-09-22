# Review — feature 7 `mongo_persistence`

- **Revisor:** reviewer
- **Fecha:** 2026-08-27
- **Informe evaluado:** `progress/impl_mongo_persistence.md`
- **Investigación de referencia:** `progress/explore_mongo.md`

**Veredicto:** APPROVED

---

## Ejecución de `./init.sh` — VERDE (exit 0)

- `cargo fmt --check` → sin diferencias.
- `cargo clippy --all-targets -- -D warnings` → sin warnings (verificado también fuera de init.sh).
- `cargo test` (unit) → **56 passed / 0 failed** (`src/lib.rs`).
- `cargo test -- --ignored` (Docker real, testcontainers) → **15 passed / 0 failed**:
  - `tests/repository.rs`: 6/6 (contenedor `mongo:7`).
  - `tests/scanner.rs`: 4/4 (contenedor `sshd`).
  - `tests/ssh.rs`: 5/5 (contenedor `sshd`).
- `cargo doc --no-deps` → sin errores (`#![deny(missing_docs)]` activo, todo ítem público documentado).

Recuento total de tests: **56 unit + 15 integración (#[ignore]) = 71**, todos verdes.
Ningún test borrado, comentado ni marcado skip. Los 3 unit tests de `ssh.rs` afectados
por el cambio a async se convirtieron a `#[tokio::test]` (siguen cubriendo lo mismo) y
se añadieron 2 tests nuevos de `HostKeyStoreError`/hex.

---

## Checkpoints C1–C5

- **C1** — [x] 4 archivos base + 4 docs presentes; `./init.sh` exit 0.
- **C2** — [x] Solo la feature 7 en `in_progress`; no se marcó `done` (correcto, lo hace el leader).
  `progress/current.md` describe la sesión activa sin basura previa.
- **C3** — [x] `src/` mantiene solo los módulos previstos (`config`, `domain`, `ssh`, `scanner`,
  `parser`, `repository`, `messaging`). Dependencias nuevas justificadas (ver sección Cargo.toml).
  Sin `println!`/`dbg!`/`unwrap`/`panic!` fuera de `#[cfg(test)]`. `cargo doc` limpio.
- **C4** — [x] `tests/repository.rs` nuevo: integración real contra contenedor MongoDB oficial vía
  `testcontainers`, `#[ignore = "requiere Docker"]`, base `db-nmap-test` (nunca producción).
  Asserts sobre contenido concreto (puertos, CVE, severidad, timestamp), no solo "no Err".
  `cargo test` > 0 y verde; clippy sin warnings.
- **C5** — [x] Sin archivos basura (`*.tmp`, `target/` fuera de `.gitignore`). Untracked:
  `progress/explore_mongo.md`, `progress/impl_mongo_persistence.md`, `tests/repository.rs`
  (legítimos, a incluir en el commit de la feature). `progress/history.md` y el cambio de
  estado a `done` quedan para el cierre de sesión del leader (no bloquean la review).

---

## Criterios de `acceptance` de la feature 7 (uno a uno)

### 1. `save` con driver oficial `mongodb` async — [x]
`MongoRepository::save(&self, result: &ScanResult, correlation_id: &CorrelationId) -> Result<ScanId, RepoError>`
(`src/repository.rs:202`). Usa `mongodb` 3 async (`insert_one(&document).await`).
La ampliación de firma a `save(result, correlation_id)` está **documentada** en el
rustdoc de módulo (`src/repository.rs:10-16`) — `ScanResult` no lleva `correlation_id`
(vive en `ScanRequest`), misma clase de desviación que `connect` en features 4/5.
Razonable y aprobada por el usuario. NO se cuenta como incumplimiento.

### 2. `find_by_id` / `find_by_correlation_id` → `Result<Option<ScanResult>, RepoError>`, id inexistente → `Ok(None)` — [x]
- `find_by_id` (`:234`): `find_one(...).await?` → `Ok(found.map(|s| s.result))`; `None` → `Ok(None)`.
- `find_by_correlation_id` (`:249`): `find_one().sort({timestamp:-1})`; devuelve el más reciente.
- Un `ScanId` que no es `ObjectId` válido → `RepoError::Serialization` (distinto de "inexistente"): correcto.
- Tests: `find_by_id_of_unknown_id_returns_none` (`ObjectId::new()` no guardado → `Ok(None)`),
  `save_then_find_by_correlation_id_returns_the_scan_result` (incluye correlation_id desconocido → `None`).

### 3. Cada documento incluye `timestamp` y `correlation_id` — [x]
`StoredScan { _id, correlation_id, timestamp (RFC3339), result }` (`:142-150`).
`timestamp = OffsetDateTime::now_utc()` en el `save`. Test
`stored_document_carries_timestamp_and_correlation_id` inspecciona el documento crudo
con un `Client` raw: `correlation_id` string, `timestamp` RFC3339 dentro del rango de
guardado, `result.scanned_at` string RFC3339.

### 4. `MongoHostKeyStore` implementa `HostKeyStore` (async) respaldado por colección Mongo — [x]
`MongoHostKeyStore` (`:271`) con `Collection<Document>` sobre `ssh_host_keys`, obtenido
por `MongoRepository::host_key_store()`. `#[async_trait] impl HostKeyStore` (`:276`).
`remember` usa `update_one(...).upsert(true)` con `$setOnInsert` para `first_seen`
(idempotente). Persistencia verificada: `mongo_host_key_store_persists_across_new_instances`
crea un `MongoRepository::connect` nuevo (nuevo `Client`) sobre la misma colección y sigue
viendo el fingerprint; `remember` idempotente comprobado.

### 5. Fallos de conexión a Mongo → `RepoError` distinguible, no panic — [x]
`RepoError::ConnectionFailed(String)` (`:110`). `impl From<mongodb::error::Error>` (`:124`)
mapea `ServerSelection | Io | DnsResolve | ConnectionPoolCleared` → `ConnectionFailed`;
`BsonSerialization | BsonDeserialization` → `Serialization`; resto → `Backend`. Sin `panic`.
Tests: `repo_error_from_network_io_is_connection_failed` (unit, `ErrorKind::Io`),
`connect_to_unreachable_mongo_is_connection_failed` (`#[tokio::test]` sin Docker, puerto 1 →
`ServerSelection` real tras `serverSelectionTimeoutMS`) → `RepoError::ConnectionFailed`.
`connect` hace `ping` inmediato para fallar rápido.

### 6. Tests de integración contra contenedor MongoDB oficial vía testcontainers, `#[ignore]` — [x]
`tests/repository.rs`: `GenericImage::new("mongo","7")`, `#[ignore = "requiere Docker"]` en
los 6. Cubre: guardar/recuperar por id, por correlation_id, id inexistente → `None`,
guardar/recuperar fingerprint conocido + persistencia entre instancias + forma del documento.
Base `db-nmap-test`, solo el contenedor desechable — nunca producción.

---

## Regresión por el cambio de `HostKeyStore` a async (features 4 y 5)

### `src/ssh.rs` — coherencia del cambio — [x]
- Trait: `#[async_trait] pub trait HostKeyStore: Send + Sync` (se añadió `Sync`);
  `known_fingerprint(&self) -> Result<Option<Fingerprint>, HostKeyStoreError>`,
  `remember(&self, ...) -> Result<(), HostKeyStoreError>` (`&self`, ya no `&mut`).
- Tipo compartido `Arc<dyn HostKeyStore>` sin `Mutex` externo. `Verifier`, `connect()`
  (`store: &Arc<dyn HostKeyStore>`), `verify_fingerprint(store: &dyn HostKeyStore, ...)` async.
- Nuevo error propio `HostKeyStoreError` (`Unavailable` / `Corrupt`), variante
  `SshError::HostKeyStore(#[from] HostKeyStoreError)`.
- **TOFU intacto** (`verify_fingerprint`, `:392`): host desconocido → `remember` + `Ok(true)`;
  fingerprint registrado igual → `Ok(true)`; distinto → `Ok(false)` y **no** se sobrescribe;
  fallo del almacén → `Err`. `check_server_key` devuelve `Ok(false)` tanto en mismatch como en
  error de almacén — **nunca acepta una clave sin verificar**. `connect` traduce a
  `HostKeyMismatch` / `HostKeyStore` leyendo los slots compartidos tras el handshake.
- Verificación TOFU no debilitada: sigue rechazando y abortando, no "loggea y continúa".

### `InMemoryHostKeyStore` — sincronización interna — [x]
`entries: std::sync::Mutex<HashMap<..>>`. Guard obtenido vía helper `entries()` y usado
dentro de una sola expresión por método; **no cruza ningún `.await`** (los `async fn` no
tienen `.await` real). Poisoning tolerado (`into_inner`). Sigue `Send + Sync` (compila como
`Arc<dyn HostKeyStore>` con bound `Send + Sync` y los tests Docker lo ejercitan).

### `tests/ssh.rs` (5) y `tests/scanner.rs` (4) — [x] 100% verdes
Adaptados a `Arc<dyn HostKeyStore>` y `.await` en `known_fingerprint`/`remember`.
Ningún test borrado ni comentado. Ejecutados con Docker real:
`changed_host_key_is_rejected_with_host_key_mismatch`, `first_connection_stores_fingerprint_and_second_is_accepted`,
`connect_with_wrong_password_fails_with_auth_failed`, `connect_succeeds_and_runs_remote_command`,
`run_command_captures_stderr_and_nonzero_exit_code` → OK.
scanner: con/sin sudo, `ToolNotAvailable`, `InsufficientPrivileges` → OK.

---

## Otras verificaciones

- **`Cargo.toml`**: `mongodb = "3"` (exigido por `docs/architecture.md`), `async-trait = "0.1"`
  (necesario para trait async dyn-compatible `Arc<dyn HostKeyStore>`, antes solo dev-transitiva).
  `futures-util` **NO** añadido (no se iteran cursores: `find_one().sort()`) — correcto y
  documentado como desviación consciente de `explore_mongo.md`. `tokio` **sin** `"sync"`
  (toda la sincronización usa `std::sync::Mutex` sin cruzar `.await`) — correcto. Ninguna dep
  injustificada (C3 OK).
- **`scanned_at`**: persistido como string RFC3339 (vía `time::serde::rfc3339` que ya tiene
  `ScanResult`), no `bson::DateTime`. Trade-off documentado en rustdoc de módulo
  (`src/repository.rs:22-29`). Test lo verifica (`scanned_at.starts_with("2026-08-27T12:30:00")`).
- **`Fingerprint` en BSON**: hex-string de 64 chars (`fingerprint_sha256_hex`), no `[u8;32]` crudo.
  `fingerprint_from_hex` valida longitud y dígitos → `HostKeyStoreError::Corrupt`. Tests unit lo cubren.
- **security-scope**: `ScanResult` no lleva credenciales; `RepoError`/`HostKeyStoreError`/`SshError`
  no exponen material sensible (tests `*_display_never_mentions_credentials`). Trust store solo
  guarda fingerprints públicos + `first_seen`. Tests solo contra contenedor, nunca `db-nmap` prod.
- **Sin scope creep**: cambios acotados a `src/repository.rs`, `src/ssh.rs`, `tests/repository.rs`,
  `tests/ssh.rs`, `tests/scanner.rs`, `Cargo.toml`/`Cargo.lock`, `feature_list.json`, `progress/`.
  No se implementó `messaging`, ni `lib::run()`, ni se convirtió `repository` en trait (feature 11).
- **Rustdoc**: todo ítem público documentado (`cargo doc` limpio con `#![deny(missing_docs)]`).
  Sin `unwrap`/`expect`/`panic!` fuera de `#[cfg(test)]` (`now_rfc3339` usa `unwrap_or_default()`,
  admisible: formatear un `OffsetDateTime` válido como RFC3339 es infalible).

---

## Cambios requeridos

Ninguno. La feature cumple los 6 criterios de `acceptance`, la regresión de features 4 y 5
está contenida y verde, y `./init.sh` termina en verde.

## Nota para el leader (no bloqueante)

Al cerrar la sesión: mover el resumen a `progress/history.md`, marcar la feature 7 como
`done` en `feature_list.json`, e incluir `tests/repository.rs` y los `progress/*.md` nuevos
en el commit.

# Investigación feature 7 `mongo_persistence`

> Subagente Explore (2026-08-27), guardado por el leader. Verificar firmas
> exactas contra docs.rs de la versión que se fije al implementar.

## 0. Contexto del repo que condiciona el diseño

- `src/repository.rs`: solo stub. Dos responsabilidades: persistir `ScanResult` +
  respaldar el trust store TOFU.
- `src/domain.rs`: `ScanResult { host: IpAddr, ports, vulnerabilities, scanned_at:
  OffsetDateTime }` — **NO tiene `_id` ni `correlation_id`**. `scanned_at` usa
  `#[serde(with = "time::serde::rfc3339")]` → serde emite string RFC3339.
  `CorrelationId(String)` (`#[serde(transparent)]`) vive en `ScanRequest`.
- `src/ssh.rs`: `trait HostKeyStore: Send` **síncrono** — `known_fingerprint(&self, host) -> Option<Fingerprint>`,
  `remember(&mut self, host, Fingerprint)`. Usado como `Arc<Mutex<dyn HostKeyStore>>`
  (`std::sync::Mutex`) en `Verifier`, `connect()`, `fn verify_fingerprint(...)`.
  `Verifier::check_server_key` es async nativo pero llama a `verify_fingerprint`
  síncrono sin `.await` mientras el guard vive — ese invariante se rompe si el
  trait pasa a async.
- `Fingerprint { sha256: [u8; 32] }` deriva serde → array de 32 int32 en BSON
  (subóptimo). Mejor persistir hex-string y reconstruir con `from_sha256_bytes`.
- `Cargo.toml`: `tokio` con `["rt-multi-thread","macros","time","net"]` — **falta `"sync"`**.
- `Cargo.lock`: `async-trait 0.1.92` YA está pero **solo como dep de `testcontainers`
  (dev)** → no está en el build de release. `russh 0.63` NO lo arrastra.
- `docs/architecture.md`: `repository` = persistencia de `ScanResult` vía driver
  oficial `mongodb` (async). **`repository` NO es un trait todavía** (se reserva
  para `hexagonal_ports`, feature 11) → implementar como struct concreto.
  Error propio por módulo con `thiserror`. Prohibido bloquear el runtime async.

## 1. Driver `mongodb` (async)

- **`mongodb 3.8.2`** (2026-08-27). Serie 3.x. MSRV 1.88. **Solo tokio** (no hay
  feature `tokio-runtime` que activar). Defaults: `compat-3-0-0`, `compat-3-3-0`,
  `dns-resolver`, `rustls-tls`, `bson-2`. **rustls es default** (no native-tls).
- `Cargo.toml` sugerido:
  - `mongodb = "3"` (deja defaults; incluye `dns-resolver` para URIs
    `mongodb+srv://` de Atlas en prod) — **recomendado**.
  - o `mongodb = { version = "3", default-features = false, features = ["rustls-tls"] }`
    si se quiere minimizar árbol y no hay SRV.
- API 3.x = "action builder": los métodos devuelven un struct-acción `IntoFuture`;
  `.await` directo; opciones encadenadas antes del `.await` (ya no `Option<XxxOptions>`).

```rust
let client = mongodb::Client::with_uri_str(uri).await?;   // NO conecta; falla solo por URI inválido / DNS SRV
let db = client.database("db-nmap");
let coll = db.collection::<ScanResult>("scan_results");

let res = coll.insert_one(&scan_result).await?;           // InsertOneResult { inserted_id: Bson }
let id: mongodb::bson::Bson = res.inserted_id;            // Bson::ObjectId(_) si T no tiene _id

let found: Option<ScanResult> = coll.find_one(doc! { "_id": &id }).await?;  // id inexistente -> Ok(None)

use futures_util::stream::TryStreamExt;                   // necesita `futures-util` (o `futures`)
let mut cursor = coll.find(doc! { "correlation_id": cid }).await?;
while let Some(r) = cursor.try_next().await? { /* ... */ }

use mongodb::options::ReturnDocument;
coll.update_one(doc!{"_id": host}, doc!{"$set": {"fingerprint_sha256_hex": hex}})
    .upsert(true)
    .await?;
```

- `find_one` de id inexistente → **`Ok(None)`** (lo que exige el acceptance).
- `ObjectId` en `mongodb::bson::oid::ObjectId`: `ObjectId::new()`, `oid.to_hex()`,
  `ObjectId::parse_str(&str)`. Serde: en BSON nativo; en JSON `{ "$oid": "<hex>" }`
  (usar helper `hex_string_as_object_id` si se quiere string plano).
- `bson` se re-exporta como `mongodb::bson` — no añadir dep directa salvo que
  necesites una feature no propagada (p. ej. `time-0_3`).
- **Iterar cursor** requiere `TryStreamExt` en scope → añadir `futures-util = "0.3"`.

### (De)serialización de los tipos de dominio — gotchas

- `scanned_at: OffsetDateTime` con `#[serde(with = "time::serde::rfc3339")]` →
  **string RFC3339 en BSON**, no `bson::DateTime` nativa. Round-trip OK.
  **Recomendación: dejarlo así** (consistente con el JSON al Broker); NO forzar
  `bson::DateTime` (rompería el test `scan_result_serializes_timestamp_as_rfc3339`
  y añadiría dep `bson` con feature `time-0_3`). Documentar el trade-off.
- `host: IpAddr` → string. OK.
- `Option<String>` → `null` BSON explícito (campo presente). OK.
- Enums `#[serde(rename_all=...)]` → strings BSON. OK.
- `Fingerprint { sha256: [u8;32] }` → array de 32 int32 vía derive. **Preferir**
  persistir `{ "_id": "<host>", "fingerprint_sha256_hex": "<64 hex>", "first_seen": "<rfc3339>" }`
  y reconstruir con `Fingerprint::from_sha256_bytes`.
- `ScanResult` sin `_id`: Mongo autogenera `ObjectId` → `InsertOneResult.inserted_id`.

### Errores del driver

- `mongodb::error::Error` con campo público `kind: Box<ErrorKind>`. En 3.x **ya no
  hay `is_network_timeout()` / `is_server_selection_error()`** — hacer `match *e.kind`.
- `ErrorKind` (`#[non_exhaustive]`), variantes para "servidor no alcanzable":
  **`ServerSelection { .. }`** (la típica cuando el host no responde, tras
  `serverSelectionTimeoutMS`), `Io(Arc<io::Error>)`, `DnsResolve { .. }`,
  `ConnectionPoolCleared { .. }`, `InvalidArgument` (URI mal formado),
  `Authentication { .. }`, `Command(CommandError { code, code_name, message })`,
  `BsonSerialization`/`BsonDeserialization` (verificar nombres exactos con `cargo doc`).
- Mapeo sugerido:

```rust
#[derive(Debug, thiserror::Error)]
pub enum RepoError {
    #[error("no se pudo conectar con MongoDB: {0}")]
    ConnectionFailed(String),
    #[error("error de MongoDB: {0}")]
    Backend(String),
    #[error("documento inválido: {0}")]
    Serialization(String),
}

impl From<mongodb::error::Error> for RepoError {
    fn from(e: mongodb::error::Error) -> Self {
        use mongodb::error::ErrorKind;
        match *e.kind {
            ErrorKind::ServerSelection { .. }
            | ErrorKind::Io(_)
            | ErrorKind::DnsResolve { .. }
            | ErrorKind::ConnectionPoolCleared { .. } => Self::ConnectionFailed(e.to_string()),
            ErrorKind::BsonSerialization(_) | ErrorKind::BsonDeserialization(_) => Self::Serialization(e.to_string()),
            _ => Self::Backend(e.to_string()),
        }
    }
}
```

- **URI inalcanzable**: `with_uri_str` devuelve `Ok(Client)` (no conecta). La
  primera operación falla con `ServerSelection` tras `serverSelectionTimeoutMS`
  (**default 30 000 ms**). → configurar `?serverSelectionTimeoutMS=5000&connectTimeoutMS=5000`
  en el URI, y hacer `db.run_command(doc!{"ping": 1}).await` como health-check al arrancar.

## 2. `testcontainers` 0.24 — contenedor MongoDB

Imports idénticos a `tests/ssh.rs` / `tests/scanner.rs` (raíz, no `::core`):

```rust
use testcontainers::{
    core::{IntoContainerPort, WaitFor},
    runners::AsyncRunner,
    ContainerAsync, GenericImage, ImageExt,
};
```

```rust
const MONGO_IMAGE: &str = "mongo";
const MONGO_TAG: &str = "7";            // o pin exacto "7.0.14"
const MONGO_PORT: u16 = 27017;

GenericImage::new(MONGO_IMAGE, MONGO_TAG)
    .with_exposed_port(MONGO_PORT.tcp())
    .with_wait_for(WaitFor::message_on_stdout("Waiting for connections"))
    .with_startup_timeout(Duration::from_secs(180))
    .start().await
    .expect("contenedor mongo arranca");

let host = c.get_host().await?.to_string();
let port = c.get_host_port_ipv4(MONGO_PORT).await?;
let uri = format!("mongodb://{host}:{port}/?directConnection=true&serverSelectionTimeoutMS=5000");
```

- Imagen oficial `mongo`, tags reales: `6.0`, `7.0`, `8.0`, `mongo:7`, `mongo:8`.
- **Sin auth** (no poner `MONGO_INITDB_ROOT_*`). **Sin `--replSet`** (no hay
  transacciones). `directConnection=true` recomendado (mongod standalone).
- Mongo 6/7/8 loguean JSON a stdout; la línea de ready contiene `Waiting for connections`.
  NO usar `WaitFor::healthcheck()` (la imagen no define HEALTHCHECK).
- Mantener `GenericImage` directo (homogeneidad con los tests existentes); no
  añadir `testcontainers-modules`.

## 3. `HostKeyStore` async dyn-compatible — `async-trait`

- `async fn` en trait nativo **NO es dyn-compatible** (Rust 1.98). `HostKeyStore`
  se usa como `dyn` → necesita `#[async_trait]` (boxing por llamada, despreciable
  para un trust store consultado 1–2 veces por conexión).
- `async-trait = "0.1"` — proc-macro diminuto (deps ya en el árbol por
  `thiserror`/`serde_derive`). Pasa a `[dependencies]` (hoy solo dev vía testcontainers).
  Justificar en el informe.

```rust
#[async_trait::async_trait]
pub trait HostKeyStore: Send + Sync {
    async fn known_fingerprint(&self, host: &str) -> Result<Option<Fingerprint>, HostKeyStoreError>;
    async fn remember(&self, host: &str, fingerprint: Fingerprint) -> Result<(), HostKeyStoreError>;
}
```

Cambios de firma que arrastra a `src/ssh.rs` + tests:
- `remember`: `&mut self` → **`&self`** (interior mutability). `InMemoryHostKeyStore`
  pasa a `entries: std::sync::Mutex<HashMap<..>>` (un `Mutex` síncrono interno
  tomado y soltado **dentro** del método, sin cruzar `.await`, es correcto y `Send`).
- Métodos devuelven `Result` → propaga a `verify_fingerprint` (se vuelve `async`),
  `Verifier::check_server_key`, `connect`, y ~6 tests unitarios de `ssh.rs` +
  `tests/ssh.rs` / `tests/scanner.rs` (usan `Arc<Mutex<dyn HostKeyStore>>` explícito).
- Nuevo error `HostKeyStoreError` (`thiserror`) en `ssh.rs`, o variante en `SshError`.

### Tipo compartido: `Arc<dyn HostKeyStore>` (sin Mutex externo) — RECOMENDADO

Con `&self` en todos los métodos y sincronización interna por impl:
- `InMemoryHostKeyStore`: `Mutex<HashMap>` interno.
- `MongoHostKeyStore`: solo un `mongodb::Collection<Document>` (ya `Clone + Send + Sync`,
  sin mutex).
- `Verifier.store: Arc<dyn HostKeyStore>`; `connect(store: &Arc<dyn HostKeyStore>, ...)`;
  `async fn verify_fingerprint(store: &dyn HostKeyStore, ...)` con
  `store.known_fingerprint(host).await?` / `store.remember(...).await?`.
- `trait HostKeyStore: Send + Sync` (añadir `Sync`).
- Elimina la clase entera de bugs de poisoning/deadlock del `std::sync::Mutex`
  sostenido a través de `.await` (que además haría el future no-`Send` → no compila con russh).

Alternativa (peor): `tokio::sync::Mutex<dyn HostKeyStore>` (requiere feature
`"sync"` en tokio; guard `Send`; serializa todas las consultas). No usar salvo
necesidad.

## 4. `Cargo.toml` — cambios sugeridos

```toml
[dependencies]
mongodb = "3"                    # 3.8.2; rustls-tls + dns-resolver + bson-2 por defecto
async-trait = "0.1"             # HostKeyStore async dyn-compatible
futures-util = "0.3"            # TryStreamExt sobre Cursor
# tokio: añadir "sync" SOLO si InMemoryHostKeyStore usa tokio::sync::*
```

## 5. Puntos de diseño para el implementer

1. **`save` + `correlation_id`**: `ScanResult` no lo tiene. Opción elegida:
   **pasar `&CorrelationId` como parámetro a `save(...)`** y construir el documento
   con ese campo en la capa repo (NO añadir el campo al dominio). Firma:
   `save(result: &ScanResult, correlation_id: &CorrelationId) -> Result<ScanId, RepoError>`.
   Documentar la desviación (como se hizo con `connect` en feature 4).
2. `repository` = struct concreto `MongoRepository` (NO trait; eso es feature 11).
3. `HostKeyStore` async → tocar `src/ssh.rs` + sus tests (regresión: features 4 y 5
   deben seguir verdes).
4. `scanned_at` = string RFC3339 en Mongo (no `bson::DateTime`). Documentar.
5. `serverSelectionTimeoutMS` bajo (~5 s) + `ping` al conectar → `RepoError::ConnectionFailed` rápido.
6. `Fingerprint` en BSON = hex-string, no `[u8;32]` crudo. Documento del trust store:
   `{ "_id": "<host>", "fingerprint_sha256_hex": "<64 hex>", "first_seen": "<rfc3339>" }`.

## Fuentes

- https://docs.rs/mongodb/latest/mongodb/ · https://docs.rs/crate/mongodb/latest/features
- https://docs.rs/mongodb/latest/mongodb/struct.Collection.html
- https://docs.rs/mongodb/latest/mongodb/error/enum.ErrorKind.html
- https://www.mongodb.com/docs/drivers/rust/current/fundamentals/serialization/
- https://www.mongodb.com/docs/drivers/rust/current/connection-troubleshooting/
- https://rust.testcontainers.org/features/wait_strategies/
- https://crates.io/crates/async-trait

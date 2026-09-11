//! Persistencia y consulta del [`ScanResult`] en MongoDB (`db-nmap`) y respaldo
//! persistente del almacén de host keys SSH (TOFU) que define `ssh`.
//!
//! [`MongoRepository`] es el adaptador de producción del puerto
//! [`ScanResultRepository`] (feature `hexagonal_ports`): implementa el trait
//! delegando en sus propios métodos inherentes, que se conservan porque los
//! tests de integración los usan directamente. [`MongoHostKeyStore`] implementa
//! el trait `ssh::HostKeyStore` (otro puerto) contra una colección de MongoDB,
//! de modo que el trust store sobreviva reinicios y se comparta entre réplicas
//! del servicio.
//!
//! ## Desviaciones respecto al `acceptance` de la feature (documentadas)
//!
//! - **`save`**: el `acceptance` describe `save(result: &ScanResult)`. La firma
//!   real es `save(result: &ScanResult, correlation_id: &CorrelationId)` porque
//!   [`ScanResult`] no lleva `correlation_id` (vive en `ScanRequest`, ver
//!   `domain`); se pasa como parámetro y se guarda en el documento. Misma clase
//!   de desviación que `connect` en las features 4 y 5.
//! - **`connect`**: constructor `async fn connect(uri, db_name)` (no en el
//!   `acceptance`, que no fija cómo se obtiene el repositorio). Hace un `ping`
//!   para fallar rápido con [`RepoError::ConnectionFailed`] si Mongo no está
//!   accesible, en vez de diferir el fallo a la primera operación real.
//!
//! ## Trade-off de serialización de `scanned_at`
//!
//! [`ScanResult::scanned_at`] se persiste como **string RFC 3339**, no como
//! `bson::DateTime` nativa: es el mismo encoding que viaja hacia el Broker
//! (consistencia de contrato) y evita forzar una dependencia extra de `bson`.
//! Contrapartida: ese campo no es consultable como fecha en Mongo (no se hacen
//! rangos temporales sobre `scanned_at` en este servicio). El `timestamp` de
//! guardado que añade el repositorio sigue el mismo criterio.

use std::fmt;
use std::str::FromStr;
use std::time::Duration;

use mongodb::bson::{self, doc, oid::ObjectId, Bson, DateTime as BsonDateTime, Document};
use mongodb::error::ErrorKind;
use mongodb::options::IndexOptions;
use mongodb::{Client, Collection, Database, IndexModel};
use serde::{Deserialize, Serialize};
use time::format_description::well_known::Rfc3339;
use time::OffsetDateTime;

use crate::domain::{CorrelationId, ScanResult, VulnFinding};
use crate::enrichment::{EnrichError, NvdCache};
use crate::ssh::{Fingerprint, HostKeyStore, HostKeyStoreError};

/// Colección donde se guardan los [`ScanResult`].
const SCAN_RESULTS_COLLECTION: &str = "scan_results";

/// Colección donde [`MongoHostKeyStore`] guarda los fingerprints de host (TOFU).
const HOST_KEYS_COLLECTION: &str = "ssh_host_keys";

/// Colección donde [`MongoNvdCache`] cachea los hallazgos de NVD por CPE 2.3.
const NVD_CACHE_COLLECTION: &str = "nvd_cache";

/// Nombre del índice TTL (`expireAfterSeconds`) sobre `cached_at` en
/// [`NVD_CACHE_COLLECTION`].
const NVD_CACHE_TTL_INDEX_NAME: &str = "nvd_cache_ttl";

/// Identificador de un [`ScanResult`] persistido: la representación hexadecimal
/// (24 caracteres) del `ObjectId` que MongoDB asigna al documento.
///
/// Se (de)serializa como una cadena simple y convierte a/desde `&str` vía
/// [`ScanId::as_str`] / [`ScanId::new`] / [`FromStr`] / [`fmt::Display`].
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(transparent)]
pub struct ScanId(String);

impl ScanId {
    /// Construye un identificador a partir de su representación hexadecimal.
    pub fn new(hex: impl Into<String>) -> Self {
        Self(hex.into())
    }

    /// Devuelve la representación hexadecimal del identificador.
    pub fn as_str(&self) -> &str {
        &self.0
    }

    fn to_object_id(&self) -> Result<ObjectId, RepoError> {
        ObjectId::parse_str(&self.0).map_err(|err| {
            RepoError::Serialization(format!(
                "ScanId {:?} no es un ObjectId válido: {err}",
                self.0
            ))
        })
    }
}

impl fmt::Display for ScanId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

impl FromStr for ScanId {
    type Err = std::convert::Infallible;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        Ok(Self(s.to_owned()))
    }
}

impl From<ObjectId> for ScanId {
    fn from(oid: ObjectId) -> Self {
        Self(oid.to_hex())
    }
}

/// Error de una operación del repositorio de MongoDB.
///
/// Cada modo de fallo relevante es una variante distinta; nunca se hace `panic`.
/// Ningún mensaje incluye credenciales (aquí no se manejan: el `ScanResult` no
/// lleva credenciales y el trust store solo guarda fingerprints públicos).
#[derive(Debug, thiserror::Error)]
pub enum RepoError {
    /// No se pudo establecer o mantener la conexión con MongoDB (servidor no
    /// seleccionable, E/S de red, resolución DNS, pool de conexiones purgado).
    /// Distinguible de un fallo de comando del servidor.
    #[error("no se pudo conectar con MongoDB: {0}")]
    ConnectionFailed(String),

    /// El documento no se pudo serializar hacia BSON o deserializar desde BSON
    /// (estructura inesperada, tipo incompatible, `ScanId` mal formado).
    #[error("documento inválido: {0}")]
    Serialization(String),

    /// Cualquier otro fallo devuelto por el driver o el servidor de MongoDB
    /// (error de comando, argumento inválido, autenticación, etc.).
    #[error("error de MongoDB: {0}")]
    Backend(String),
}

impl From<mongodb::error::Error> for RepoError {
    fn from(err: mongodb::error::Error) -> Self {
        match *err.kind {
            ErrorKind::ServerSelection { .. }
            | ErrorKind::Io(_)
            | ErrorKind::DnsResolve { .. }
            | ErrorKind::ConnectionPoolCleared { .. } => Self::ConnectionFailed(err.to_string()),
            ErrorKind::BsonSerialization(_) | ErrorKind::BsonDeserialization(_) => {
                Self::Serialization(err.to_string())
            }
            _ => Self::Backend(err.to_string()),
        }
    }
}

/// Documento tal como se guarda en la colección `scan_results`: el
/// [`ScanResult`] más los metadatos que añade el repositorio
/// (`correlation_id` de la solicitud original y `timestamp` de guardado).
#[derive(Debug, Serialize, Deserialize)]
struct StoredScan {
    #[serde(rename = "_id", skip_serializing_if = "Option::is_none")]
    id: Option<ObjectId>,
    correlation_id: CorrelationId,
    #[serde(with = "time::serde::rfc3339")]
    timestamp: OffsetDateTime,
    result: ScanResult,
}

/// Repositorio de resultados de escaneo respaldado por MongoDB (`db-nmap`).
///
/// Se construye una vez al arrancar con [`MongoRepository::connect`]. Es barato
/// de clonar (comparte el pool de conexiones del `Client` interno).
#[derive(Debug, Clone)]
pub struct MongoRepository {
    database: Database,
    scans: Collection<StoredScan>,
    host_keys: Collection<Document>,
    nvd_cache: Collection<Document>,
}

impl MongoRepository {
    /// Conecta con MongoDB en `uri` y selecciona la base `db_name`.
    ///
    /// Ejecuta un `ping` inmediato: si el servidor no está accesible, falla ya
    /// con [`RepoError::ConnectionFailed`] en vez de diferir el error a la
    /// primera operación.
    ///
    /// # Errores
    ///
    /// - [`RepoError::ConnectionFailed`] si la URI no resuelve, no hay servidor
    ///   seleccionable o el `ping` falla por red.
    /// - [`RepoError::Backend`] para otros fallos del driver (URI mal formada,
    ///   autenticación, etc.).
    pub async fn connect(uri: &str, db_name: &str) -> Result<Self, RepoError> {
        let client = Client::with_uri_str(uri).await?;
        let database = client.database(db_name);
        database.run_command(doc! { "ping": 1 }).await?;
        Ok(Self {
            scans: database.collection(SCAN_RESULTS_COLLECTION),
            host_keys: database.collection(HOST_KEYS_COLLECTION),
            nvd_cache: database.collection(NVD_CACHE_COLLECTION),
            database,
        })
    }

    /// Devuelve el [`HostKeyStore`] persistente respaldado por la colección
    /// `ssh_host_keys` de esta misma base.
    pub fn host_key_store(&self) -> MongoHostKeyStore {
        MongoHostKeyStore {
            collection: self.host_keys.clone(),
        }
    }

    /// Devuelve el [`NvdCache`] persistente respaldado por la colección
    /// `nvd_cache` de esta misma base, asegurando de forma idempotente el
    /// índice TTL (`expireAfterSeconds`) sobre `cached_at` con el valor `ttl`.
    ///
    /// Sólo se llama cuando el enriquecimiento NVD está habilitado (ver
    /// [`crate::config::Config::nvd_enrichment_enabled`] y
    /// [`crate::wiring::service_ports_from_config`]).
    ///
    /// # Errores
    ///
    /// [`RepoError`] si no se pudo crear o actualizar el índice TTL.
    pub async fn nvd_cache_store(&self, ttl: Duration) -> Result<MongoNvdCache, RepoError> {
        ensure_nvd_cache_ttl_index(&self.database, ttl).await?;
        Ok(MongoNvdCache {
            collection: self.nvd_cache.clone(),
            ttl,
        })
    }

    /// Persiste `result` junto con `correlation_id` y una marca temporal de
    /// guardado, y devuelve el [`ScanId`] asignado.
    ///
    /// # Errores
    ///
    /// - [`RepoError::ConnectionFailed`] si Mongo no está accesible.
    /// - [`RepoError::Serialization`] si el documento no se puede serializar, o
    ///   si el `_id` devuelto no es un `ObjectId`.
    /// - [`RepoError::Backend`] para otros fallos del servidor.
    pub async fn save(
        &self,
        result: &ScanResult,
        correlation_id: &CorrelationId,
    ) -> Result<ScanId, RepoError> {
        let document = StoredScan {
            id: None,
            correlation_id: correlation_id.clone(),
            timestamp: OffsetDateTime::now_utc(),
            result: result.clone(),
        };

        let inserted = self.scans.insert_one(&document).await?;

        match inserted.inserted_id {
            Bson::ObjectId(oid) => Ok(ScanId::from(oid)),
            other => Err(RepoError::Serialization(format!(
                "MongoDB devolvió un _id que no es ObjectId: {other:?}"
            ))),
        }
    }

    /// Recupera el [`ScanResult`] con identificador `id`.
    ///
    /// Un `id` que no existe devuelve `Ok(None)`, no un error.
    ///
    /// # Errores
    ///
    /// - [`RepoError::Serialization`] si `id` no es un `ObjectId` válido o el
    ///   documento almacenado no se puede deserializar.
    /// - [`RepoError::ConnectionFailed`] / [`RepoError::Backend`] según el fallo
    ///   del driver.
    pub async fn find_by_id(&self, id: &ScanId) -> Result<Option<ScanResult>, RepoError> {
        let oid = id.to_object_id()?;
        let found = self.scans.find_one(doc! { "_id": oid }).await?;
        Ok(found.map(|stored| stored.result))
    }

    /// Recupera el [`ScanResult`] asociado a `correlation_id`. Si hubiera varios
    /// (re-escaneos de la misma solicitud), devuelve el guardado más
    /// recientemente. Sin coincidencias devuelve `Ok(None)`.
    ///
    /// # Errores
    ///
    /// - [`RepoError::Serialization`] si el documento no se puede deserializar.
    /// - [`RepoError::ConnectionFailed`] / [`RepoError::Backend`] según el fallo
    ///   del driver.
    pub async fn find_by_correlation_id(
        &self,
        correlation_id: &CorrelationId,
    ) -> Result<Option<ScanResult>, RepoError> {
        let found = self
            .scans
            .find_one(doc! { "correlation_id": correlation_id.as_str() })
            .sort(doc! { "timestamp": -1 })
            .await?;
        Ok(found.map(|stored| stored.result))
    }
}

/// Puerto (hexagonal) para persistir y consultar [`ScanResult`].
///
/// Abstrae [`MongoRepository`] tras un trait dyn-compatible
/// (`Arc<dyn ScanResultRepository>`) para poder inyectar el adaptador real o un
/// doble en tests. Las firmas coinciden con los métodos inherentes de
/// [`MongoRepository`].
#[async_trait::async_trait]
pub trait ScanResultRepository: Send + Sync {
    /// Persiste `result` junto con `correlation_id` y una marca temporal, y
    /// devuelve el [`ScanId`] asignado.
    ///
    /// # Errores
    ///
    /// Ver [`RepoError`] (conexión, serialización, backend).
    async fn save(
        &self,
        result: &ScanResult,
        correlation_id: &CorrelationId,
    ) -> Result<ScanId, RepoError>;

    /// Recupera el [`ScanResult`] con identificador `id`; `Ok(None)` si no
    /// existe.
    ///
    /// # Errores
    ///
    /// Ver [`RepoError`].
    async fn find_by_id(&self, id: &ScanId) -> Result<Option<ScanResult>, RepoError>;

    /// Recupera el [`ScanResult`] asociado a `correlation_id` (el más reciente si
    /// hubiera varios); `Ok(None)` si no hay coincidencias.
    ///
    /// # Errores
    ///
    /// Ver [`RepoError`].
    async fn find_by_correlation_id(
        &self,
        correlation_id: &CorrelationId,
    ) -> Result<Option<ScanResult>, RepoError>;
}

#[async_trait::async_trait]
impl ScanResultRepository for MongoRepository {
    async fn save(
        &self,
        result: &ScanResult,
        correlation_id: &CorrelationId,
    ) -> Result<ScanId, RepoError> {
        MongoRepository::save(self, result, correlation_id).await
    }

    async fn find_by_id(&self, id: &ScanId) -> Result<Option<ScanResult>, RepoError> {
        MongoRepository::find_by_id(self, id).await
    }

    async fn find_by_correlation_id(
        &self,
        correlation_id: &CorrelationId,
    ) -> Result<Option<ScanResult>, RepoError> {
        MongoRepository::find_by_correlation_id(self, correlation_id).await
    }
}

/// Implementación de [`HostKeyStore`] respaldada por la colección `ssh_host_keys`
/// de MongoDB, para que el trust store TOFU sobreviva reinicios y se comparta
/// entre réplicas del servicio.
///
/// Cada host es un documento
/// `{ "_id": "<host>", "fingerprint_sha256_hex": "<64 hex>", "first_seen": "<rfc3339>" }`.
/// Se guarda el digest en hexadecimal (no el `[u8; 32]` crudo) para que el
/// documento sea legible y estable. Es barato de clonar.
#[derive(Debug, Clone)]
pub struct MongoHostKeyStore {
    collection: Collection<Document>,
}

#[async_trait::async_trait]
impl HostKeyStore for MongoHostKeyStore {
    async fn known_fingerprint(
        &self,
        host: &str,
    ) -> Result<Option<Fingerprint>, HostKeyStoreError> {
        let document = self
            .collection
            .find_one(doc! { "_id": host })
            .await
            .map_err(host_key_store_error)?;

        let Some(document) = document else {
            return Ok(None);
        };

        let hex = document.get_str("fingerprint_sha256_hex").map_err(|err| {
            HostKeyStoreError::Corrupt(format!(
                "el registro de {host} no tiene un fingerprint_sha256_hex de texto: {err}"
            ))
        })?;

        Ok(Some(fingerprint_from_hex(hex)?))
    }

    async fn remember(
        &self,
        host: &str,
        fingerprint: Fingerprint,
    ) -> Result<(), HostKeyStoreError> {
        self.collection
            .update_one(
                doc! { "_id": host },
                doc! {
                    "$set": { "fingerprint_sha256_hex": fingerprint_to_hex(&fingerprint) },
                    "$setOnInsert": { "first_seen": now_rfc3339() },
                },
            )
            .upsert(true)
            .await
            .map_err(host_key_store_error)?;
        Ok(())
    }
}

fn host_key_store_error(err: mongodb::error::Error) -> HostKeyStoreError {
    match *err.kind {
        ErrorKind::BsonSerialization(_) | ErrorKind::BsonDeserialization(_) => {
            HostKeyStoreError::Corrupt(err.to_string())
        }
        _ => HostKeyStoreError::Unavailable(err.to_string()),
    }
}

fn fingerprint_to_hex(fingerprint: &Fingerprint) -> String {
    fingerprint
        .as_bytes()
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect()
}

fn fingerprint_from_hex(hex: &str) -> Result<Fingerprint, HostKeyStoreError> {
    if hex.len() != 64 {
        return Err(HostKeyStoreError::Corrupt(format!(
            "se esperaban 64 caracteres hexadecimales en el fingerprint, hay {}",
            hex.len()
        )));
    }

    let (pairs, _rest) = hex.as_bytes().as_chunks::<2>();
    let mut bytes = [0u8; 32];
    for (index, pair) in pairs.iter().enumerate() {
        let pair = std::str::from_utf8(pair)
            .map_err(|_| HostKeyStoreError::Corrupt("el fingerprint no es UTF-8".to_owned()))?;
        bytes[index] = u8::from_str_radix(pair, 16).map_err(|err| {
            HostKeyStoreError::Corrupt(format!(
                "dígito hexadecimal inválido en el fingerprint: {err}"
            ))
        })?;
    }
    Ok(Fingerprint::from_sha256_bytes(bytes))
}

fn now_rfc3339() -> String {
    OffsetDateTime::now_utc()
        .format(&Rfc3339)
        .unwrap_or_default()
}

/// Documento tal como se guarda en la colección `nvd_cache`:
/// `{ "_id": "<cpe23>", "findings": [...], "cached_at": <fecha BSON> }`.
///
/// ## Desviación respecto al `acceptance` de la feature (documentada)
///
/// El `acceptance` describe `cached_at` como una cadena RFC 3339 (mismo
/// criterio que [`ScanResult::scanned_at`] o el `timestamp` de
/// `scan_results`). Aquí se usa deliberadamente [`BsonDateTime`] (una fecha
/// BSON nativa) en su lugar: el índice TTL de MongoDB (`expireAfterSeconds`)
/// **sólo funciona sobre campos de tipo fecha BSON**, nunca sobre cadenas — con
/// una cadena el documento nunca expiraría y la caché crecería sin límite. Es
/// la misma clase de desviación pragmática que ya documenta este módulo para
/// `save`/`connect`.
#[derive(Debug, Serialize, Deserialize)]
struct StoredNvdCacheEntry {
    #[serde(rename = "_id")]
    id: String,
    findings: Vec<VulnFinding>,
    cached_at: BsonDateTime,
}

/// Implementación de [`NvdCache`] respaldada por la colección `nvd_cache` de
/// MongoDB, con un índice TTL sobre `cached_at` para expirar automáticamente
/// las entradas tras `ttl`.
///
/// Se construye con [`MongoRepository::nvd_cache_store`], que asegura el
/// índice antes de devolver la instancia. Es barato de clonar.
#[derive(Debug, Clone)]
pub struct MongoNvdCache {
    collection: Collection<Document>,
    ttl: Duration,
}

impl MongoNvdCache {
    /// TTL configurado para esta caché (el mismo que se usó para construir su
    /// índice `expireAfterSeconds`).
    pub fn ttl(&self) -> Duration {
        self.ttl
    }
}

#[async_trait::async_trait]
impl NvdCache for MongoNvdCache {
    async fn get(&self, cpe: &str) -> Result<Option<Vec<VulnFinding>>, EnrichError> {
        let document = self
            .collection
            .find_one(doc! { "_id": cpe })
            .await
            .map_err(nvd_cache_error)?;

        let Some(document) = document else {
            return Ok(None);
        };

        let stored: StoredNvdCacheEntry = bson::from_document(document).map_err(|err| {
            EnrichError::Backend(format!("documento de caché NVD inválido para {cpe}: {err}"))
        })?;
        Ok(Some(stored.findings))
    }

    async fn put(&self, cpe: &str, findings: &[VulnFinding]) -> Result<(), EnrichError> {
        let entry = StoredNvdCacheEntry {
            id: cpe.to_owned(),
            findings: findings.to_vec(),
            cached_at: BsonDateTime::now(),
        };
        let document = bson::to_document(&entry).map_err(|err| {
            EnrichError::Backend(format!(
                "no se pudo serializar la entrada de caché NVD para {cpe}: {err}"
            ))
        })?;

        self.collection
            .replace_one(doc! { "_id": cpe }, document)
            .upsert(true)
            .await
            .map_err(nvd_cache_error)?;
        Ok(())
    }
}

fn nvd_cache_error(err: mongodb::error::Error) -> EnrichError {
    EnrichError::Backend(err.to_string())
}

/// Crea (de forma idempotente) el índice TTL de [`NVD_CACHE_COLLECTION`] sobre
/// `cached_at`, con `expireAfterSeconds = ttl`.
///
/// Si el índice ya existe con **el mismo** `ttl`, `create_index` no falla (es
/// idempotente). Si ya existe con **otro** `ttl`, MongoDB rechaza
/// `createIndexes` (error `IndexOptionsConflict`/`IndexKeySpecsConflict`):
/// `collMod` es la única forma soportada de cambiar el `expireAfterSeconds` de
/// un índice existente sin borrarlo primero, así que se usa como fallback.
async fn ensure_nvd_cache_ttl_index(database: &Database, ttl: Duration) -> Result<(), RepoError> {
    let collection: Collection<Document> = database.collection(NVD_CACHE_COLLECTION);
    let index = IndexModel::builder()
        .keys(doc! { "cached_at": 1 })
        .options(
            IndexOptions::builder()
                .name(NVD_CACHE_TTL_INDEX_NAME.to_owned())
                .expire_after(ttl)
                .build(),
        )
        .build();

    match collection.create_index(index).await {
        Ok(_) => Ok(()),
        Err(err) if is_index_options_conflict(&err) => {
            database
                .run_command(doc! {
                    "collMod": NVD_CACHE_COLLECTION,
                    "index": {
                        "keyPattern": { "cached_at": 1 },
                        "expireAfterSeconds": ttl.as_secs() as i64,
                    }
                })
                .await?;
            Ok(())
        }
        Err(err) => Err(RepoError::from(err)),
    }
}

/// `true` si `err` es el error de MongoDB `IndexOptionsConflict` (código 85) o
/// `IndexKeySpecsConflict` (código 86): el índice pedido ya existe con otras
/// opciones (aquí, otro `expireAfterSeconds`).
fn is_index_options_conflict(err: &mongodb::error::Error) -> bool {
    matches!(&*err.kind, ErrorKind::Command(command) if command.code == 85 || command.code == 86)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn scan_id_round_trips_through_string() {
        let hex = "507f1f77bcf86cd799439011";

        let id = ScanId::new(hex);
        assert_eq!(id.as_str(), hex);
        assert_eq!(id.to_string(), hex);

        let parsed: ScanId = hex.parse().expect("ScanId::from_str es infalible");
        assert_eq!(parsed, id);

        let json = serde_json::to_string(&id).expect("serializa");
        assert_eq!(json, format!("\"{hex}\""));
        let back: ScanId = serde_json::from_str(&json).expect("deserializa");
        assert_eq!(back, id);
    }

    #[test]
    fn scan_id_from_object_id_uses_hex_representation() {
        let oid = ObjectId::parse_str("507f191e810c19729de860ea").expect("ObjectId válido");
        assert_eq!(ScanId::from(oid).as_str(), "507f191e810c19729de860ea");
    }

    #[test]
    fn scan_id_to_object_id_rejects_non_hex() {
        let err = ScanId::new("no-es-un-objectid")
            .to_object_id()
            .expect_err("un ScanId no hexadecimal no es un ObjectId");
        assert!(matches!(err, RepoError::Serialization(_)), "{err:?}");
    }

    #[test]
    fn repo_error_from_network_io_is_connection_failed() {
        // Las variantes de `ErrorKind` para "servidor no alcanzable" son
        // `#[non_exhaustive]` y no se pueden construir fuera del crate `mongodb`;
        // `ErrorKind::Io` sí, vía `From<std::io::Error>`. El caso
        // `ServerSelection` real se cubre en
        // `connect_to_unreachable_mongo_is_connection_failed` (test async).
        let io = mongodb::error::Error::from(std::io::Error::new(
            std::io::ErrorKind::ConnectionRefused,
            "connection refused",
        ));
        assert!(
            matches!(RepoError::from(io), RepoError::ConnectionFailed(_)),
            "un error de E/S de red debe mapear a ConnectionFailed"
        );
    }

    #[test]
    fn repo_error_from_bson_failure_is_serialization() {
        let bson_err =
            mongodb::bson::to_document(&42_i32).expect_err("un i32 no es un documento BSON");
        assert!(
            matches!(
                RepoError::from(mongodb::error::Error::from(bson_err)),
                RepoError::Serialization(_)
            ),
            "un fallo de (de)serialización BSON debe mapear a Serialization"
        );
    }

    #[tokio::test]
    async fn connect_to_unreachable_mongo_is_connection_failed() {
        // Puerto 1: nada escucha -> el `ping` de `connect` falla por
        // ServerSelection tras `serverSelectionTimeoutMS`. NO requiere Docker.
        let err = MongoRepository::connect(
            "mongodb://127.0.0.1:1/?serverSelectionTimeoutMS=500&connectTimeoutMS=500",
            "db-nmap-test",
        )
        .await
        .expect_err("no hay MongoDB en 127.0.0.1:1");

        assert!(
            matches!(err, RepoError::ConnectionFailed(_)),
            "se esperaba ConnectionFailed, se obtuvo {err:?}"
        );
    }

    #[test]
    fn repo_error_display_never_mentions_credentials() {
        let rendered = [
            RepoError::ConnectionFailed("connection refused".to_owned()).to_string(),
            RepoError::Serialization("missing field host".to_owned()).to_string(),
            RepoError::Backend("command failed".to_owned()).to_string(),
        ]
        .join(" | ");

        for banned in [
            "password",
            "contraseña",
            "secret",
            "credential",
            "credencial",
        ] {
            assert!(
                !rendered.to_lowercase().contains(banned),
                "el mensaje no debe mencionar {banned}: {rendered}"
            );
        }
    }

    #[test]
    fn fingerprint_hex_round_trips() {
        let bytes = [
            0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21, 22, 23,
            24, 25, 26, 27, 28, 29, 30, 255,
        ];
        let fingerprint = Fingerprint::from_sha256_bytes(bytes);

        let hex = fingerprint_to_hex(&fingerprint);
        assert_eq!(hex.len(), 64);
        assert!(hex.ends_with("ff"));

        assert_eq!(fingerprint_from_hex(&hex).expect("hex válido"), fingerprint);
    }

    #[test]
    fn fingerprint_from_hex_rejects_wrong_length_and_bad_digits() {
        assert!(matches!(
            fingerprint_from_hex("abcd"),
            Err(HostKeyStoreError::Corrupt(_))
        ));
        let sixty_four_non_hex = "z".repeat(64);
        assert!(matches!(
            fingerprint_from_hex(&sixty_four_non_hex),
            Err(HostKeyStoreError::Corrupt(_))
        ));
    }
}

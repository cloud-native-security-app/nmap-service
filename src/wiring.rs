//! Composition root: construye los adaptadores **reales** de cada puerto
//! hexagonal a partir de la [`Config`] y los agrupa en un [`ServicePorts`] listo
//! para [`crate::run`].
//!
//! Aquí -y sólo aquí, junto con `src/main.rs`- se decide qué implementación
//! concreta cumple cada puerto:
//!
//! - [`RemoteExecutor`] -> [`RusshExecutor`] (cliente `russh`).
//! - [`NmapScanner`] -> [`NmapCliScanner`] (invoca el binario `nmap` remoto).
//! - [`ScanResultRepository`] -> [`MongoRepository`].
//! - [`HostKeyStore`] -> el respaldado por Mongo
//!   ([`crate::repository::MongoHostKeyStore`]), para que la verificación TOFU
//!   sobreviva reinicios y se comparta entre réplicas.
//!
//! # Hueco pendiente: adaptador de broker
//!
//! La tecnología concreta de cola de mensajes aún no está decidida (ver
//! `docs/architecture.md`). No existe todavía un adaptador real de
//! [`ScanRequestSource`](crate::messaging::consumer::ScanRequestSource) ni de
//! [`ScanResultSink`]: el `sink` que se cablea aquí es el stub en memoria
//! ([`InMemoryScanResultSink`]) y `src/main.rs` llama a [`crate::run`] con
//! `source == None`. Cuando exista el adaptador de broker se construirá en esta
//! función y se pasará su `source` a [`crate::run`].

use std::sync::Arc;

use crate::config::Config;
use crate::messaging::publisher::{InMemoryScanResultSink, ScanResultSink};
use crate::repository::{MongoRepository, RepoError, ScanResultRepository};
use crate::scanner::{NmapCliScanner, NmapScanner};
use crate::ssh::{HostKeyStore, RemoteExecutor, RusshExecutor};
use crate::ServicePorts;

/// Error al construir los adaptadores reales del servicio.
#[derive(Debug, thiserror::Error)]
pub enum WiringError {
    /// No se pudo conectar con MongoDB (`db-nmap`) al inicializar el
    /// repositorio y el almacén de host keys.
    #[error("no se pudo conectar con MongoDB: {0}")]
    Mongo(#[from] RepoError),
}

/// Construye los [`ServicePorts`] con los adaptadores de producción a partir de
/// `config`.
///
/// Conecta con MongoDB (falla rápido si no está accesible) y deriva de esa
/// conexión tanto el [`ScanResultRepository`] como el [`HostKeyStore`]
/// persistente. El resto de adaptadores son unit-structs sin estado.
///
/// # Errores
///
/// [`WiringError::Mongo`] si no se puede establecer la conexión con MongoDB.
pub async fn service_ports_from_config(config: &Config) -> Result<ServicePorts, WiringError> {
    let repo = MongoRepository::connect(&config.mongo_uri, &config.mongo_db).await?;

    let host_key_store: Arc<dyn HostKeyStore> = Arc::new(repo.host_key_store());
    let repository: Arc<dyn ScanResultRepository> = Arc::new(repo);
    let executor: Arc<dyn RemoteExecutor> = Arc::new(RusshExecutor);
    let scanner: Arc<dyn NmapScanner> = Arc::new(NmapCliScanner);
    // Sin adaptador real de broker todavía (ver el módulo): stub en memoria.
    let sink: Arc<dyn ScanResultSink> = Arc::new(InMemoryScanResultSink::new());

    Ok(ServicePorts {
        executor,
        scanner,
        repository,
        host_key_store,
        sink,
    })
}

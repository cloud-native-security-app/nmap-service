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
//! - [`VulnEnricher`] -> [`CompositeVulnEnricher`] con [`ExploitDbEnricher`]
//!   (siempre) y, sólo si `config.nvd_enrichment_enabled`, también
//!   [`NvdApiEnricher`] (egress de red opt-in, ver `docs/security-scope.md`). Si
//!   está deshabilitado, este módulo no construye `NvdApiEnricher` en absoluto:
//!   no hay ninguna posibilidad de llamada de red hacia NVD.
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

use secrecy::{ExposeSecret, SecretString};

use crate::config::Config;
use crate::enrichment::{
    CompositeVulnEnricher, EnrichError, ExploitDbEnricher, NvdApiEnricher, NvdCache, VulnEnricher,
};
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

    /// No se pudo cargar el CSV de Exploit-DB para el enriquecimiento offline
    /// ([`crate::config::EXPLOITDB_CSV_VAR`]). Fallar al arrancar es correcto: el
    /// enriquecimiento es una capacidad obligatoria del servicio.
    #[error("no se pudo cargar el CSV de Exploit-DB: {0}")]
    Enrichment(#[from] EnrichError),

    /// `Config` llegó con `nvd_enrichment_enabled=true` pero sin
    /// `nvd_cache_ttl`. No debería ocurrir nunca: [`crate::config::Config`]
    /// valida esa invariante al construirse. Se reporta como error tipado (en
    /// vez de `panic!`) por si esa invariante se rompiera en el futuro.
    #[error("configuración NVD inconsistente: {0}")]
    InvalidNvdConfig(String),
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
/// - [`WiringError::Mongo`] si no se puede establecer la conexión con MongoDB,
///   o si el índice TTL de la caché de NVD no se pudo crear/actualizar.
/// - [`WiringError::Enrichment`] si el CSV de Exploit-DB no se pudo cargar.
/// - [`WiringError::InvalidNvdConfig`] si `config` llegó con
///   `nvd_enrichment_enabled=true` sin `nvd_cache_ttl` (no debería ocurrir:
///   ver [`crate::config::Config`]).
pub async fn service_ports_from_config(config: &Config) -> Result<ServicePorts, WiringError> {
    let repo = MongoRepository::connect(&config.mongo_uri, &config.mongo_db).await?;

    let host_key_store: Arc<dyn HostKeyStore> = Arc::new(repo.host_key_store());
    let executor: Arc<dyn RemoteExecutor> = Arc::new(RusshExecutor);
    let scanner: Arc<dyn NmapScanner> = Arc::new(NmapCliScanner);

    // Enriquecimiento: el adaptador offline de Exploit-DB siempre se añade (el
    // CSV se carga aquí; si no está disponible, el servicio no arranca, la
    // feature lo exige). El adaptador NVD es egress de red opt-in: sólo se
    // construye -y por tanto sólo existe la posibilidad de llamarlo- si
    // `config.nvd_enrichment_enabled` es `true` (ver `docs/security-scope.md`).
    // Ambos se construyen aquí, ANTES de mover `repo` al `Arc<dyn
    // ScanResultRepository>` de abajo, porque `NvdApiEnricher` necesita
    // `repo.nvd_cache_store(..)` (toma `&repo`).
    let exploitdb = ExploitDbEnricher::from_csv_path(&config.exploitdb_csv).await?;
    let mut enrichers: Vec<Arc<dyn VulnEnricher>> =
        vec![Arc::new(exploitdb) as Arc<dyn VulnEnricher>];

    if config.nvd_enrichment_enabled {
        // `Config::from_env` garantiza `nvd_cache_ttl == Some(_)` cuando
        // `nvd_enrichment_enabled` es `true` (ver `config.rs`). Si esa
        // invariante estuviera rota, es un error de programación, no de
        // entorno; se reporta como [`WiringError::InvalidNvdConfig`] en vez de
        // `panic!` (ver `docs/architecture.md`: ninguna etapa hace panic).
        let ttl = config.nvd_cache_ttl.ok_or_else(|| {
            WiringError::InvalidNvdConfig(
                "nvd_enrichment_enabled=true pero nvd_cache_ttl es None".to_owned(),
            )
        })?;
        let cache: Arc<dyn NvdCache> = Arc::new(repo.nvd_cache_store(ttl).await?);
        let api_key = clone_secret(&config.nvd_api_key);
        let nvd = NvdApiEnricher::new(api_key, cache);
        enrichers.push(Arc::new(nvd) as Arc<dyn VulnEnricher>);
    }

    let enricher: Arc<dyn VulnEnricher> = Arc::new(CompositeVulnEnricher::new(enrichers));
    let repository: Arc<dyn ScanResultRepository> = Arc::new(repo);

    // Sin adaptador real de broker todavía (ver el módulo): stub en memoria.
    let sink: Arc<dyn ScanResultSink> = Arc::new(InMemoryScanResultSink::new());

    Ok(ServicePorts {
        executor,
        scanner,
        repository,
        enricher,
        host_key_store,
        sink,
    })
}

/// Copia el contenido de `secret` a un nuevo [`SecretString`].
///
/// [`SecretString`] no implementa `Clone` (su contenido, `str`, no es
/// `CloneableSecret` en `secrecy`), así que no se puede clonar `Config`
/// directamente. `service_ports_from_config` sólo recibe `&Config`, así que
/// para construir [`NvdApiEnricher::new`] (que necesita ser dueño de su copia
/// de la API key) hace falta reconstruir el secreto explícitamente en este
/// único punto, en vez de derivar `Clone` para `Config` completo.
fn clone_secret(secret: &Option<SecretString>) -> Option<SecretString> {
    secret
        .as_ref()
        .map(|s| SecretString::from(s.expose_secret().to_owned()))
}

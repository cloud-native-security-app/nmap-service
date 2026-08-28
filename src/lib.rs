//! Crate `ms-nmap`: recibe una solicitud de escaneo desde el Broker, se conecta
//! por SSH al objetivo, ejecuta `nmap`, interpreta el resultado, lo persiste en
//! MongoDB y lo publica de vuelta hacia el Broker.
//!
//! `src/lib.rs` declara las capas del servicio como módulos públicos para que
//! los tests de integración de `tests/` (que compilan como crate externo)
//! puedan verlas. `src/main.rs` es solo un envoltorio delgado sobre [`run`].

#![deny(missing_docs)]

use std::sync::Arc;

pub mod config;
pub mod domain;
pub mod messaging;
pub mod parser;
pub mod pipeline;
pub mod repository;
pub mod scanner;
pub mod ssh;

use crate::config::Config;
use crate::messaging::publisher::{InMemoryScanResultSink, ScanResultSink};
use crate::pipeline::ScanPipeline;
use crate::repository::MongoRepository;
use crate::scanner::ScanOptions;
use crate::ssh::{HostKeyStore, SshTimeouts};

/// Arranca el servicio (composition root): carga la configuración, conecta con
/// MongoDB y construye el [`ScanPipeline`] que orquesta
/// `consumer -> ssh -> scanner -> parser -> repository -> publisher`.
///
/// El almacén de host keys (TOFU) que se inyecta es el respaldado por Mongo
/// ([`repository::MongoHostKeyStore`]), no el de memoria de los tests aislados de
/// `ssh`.
///
/// # Estado del wiring del broker
///
/// La tecnología concreta de cola de mensajes aún no está decidida (ver
/// `docs/architecture.md`), así que todavía no existe un adaptador real de
/// [`ScanRequestSource`](messaging::consumer::ScanRequestSource) ni de
/// [`ScanResultSink`] — sólo los stubs en
/// memoria. Esta función valida la configuración, comprueba que MongoDB es
/// accesible y deja el pipeline construido; cuando exista el adaptador de
/// broker se le pasará su `source` a [`ScanPipeline::run`]. Conectar ese
/// adaptador queda fuera del alcance de la feature `scan_pipeline_wiring`.
///
/// Nunca hace `panic`: un fallo de configuración o de conexión a MongoDB se
/// registra con `tracing::error!` y la función retorna de forma limpia.
pub async fn run() {
    let config = match Config::from_env() {
        Ok(config) => config,
        Err(err) => {
            tracing::error!(error = %err, "configuración inválida; ms-nmap no puede arrancar");
            return;
        }
    };

    let repo = match MongoRepository::connect(&config.mongo_uri, &config.mongo_db).await {
        Ok(repo) => repo,
        Err(err) => {
            tracing::error!(
                error = %err,
                "no se pudo conectar con MongoDB; ms-nmap no puede arrancar"
            );
            return;
        }
    };

    let host_key_store: Arc<dyn HostKeyStore> = Arc::new(repo.host_key_store());
    let sink: Arc<dyn ScanResultSink> = Arc::new(InMemoryScanResultSink::new());

    let _pipeline = ScanPipeline::new(
        repo,
        host_key_store,
        sink,
        config.ssh_port,
        SshTimeouts {
            connect: config.ssh_connect_timeout,
            command: config.ssh_command_timeout,
        },
        ScanOptions::default(),
    );

    tracing::warn!(
        "ms-nmap arrancó: configuración validada y MongoDB accesible. El adaptador de \
         broker (ScanRequestSource real) aún no existe; el pipeline no consumirá \
         solicitudes hasta que se implemente (fuera del alcance de scan_pipeline_wiring)."
    );
}

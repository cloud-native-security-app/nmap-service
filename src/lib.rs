//! Crate `ms-nmap`: recibe una solicitud de escaneo desde una cola SQS, se
//! conecta por SSH al objetivo, ejecuta `nmap`, interpreta el resultado, lo
//! persiste en MongoDB y lo publica de vuelta en el topic SNS `scan-outcomes`.
//!
//! `src/lib.rs` declara las capas del servicio como módulos públicos para que
//! los tests de integración de `tests/` (que compilan como crate externo)
//! puedan verlas. `src/main.rs` es solo un envoltorio delgado sobre [`run`].

#![deny(missing_docs)]

use std::sync::Arc;
use std::time::Duration;

use tokio_util::sync::CancellationToken;

pub mod config;
pub mod domain;
pub mod enrichment;
pub mod messaging;
pub mod parser;
pub mod pipeline;
pub mod repository;
pub mod scanner;
pub mod ssh;
pub mod wiring;

use crate::messaging::consumer::{
    InMemoryScanCancellationSource, ScanCancellationSource, ScanRequestSource,
};
use crate::pipeline::ScanPipeline;

pub use crate::pipeline::{PipelineConfig, ServicePorts};

/// Tiempo máximo que, tras la señal de apagado, se espera a los escaneos en
/// vuelo antes de abortarlos (sus mensajes reaparecen en la cola al vencer la
/// visibilidad, así que no se pierden). Queda por debajo de los 30 s que ECS da
/// por defecto entre `SIGTERM` y `SIGKILL` (`stopTimeout`); un escaneo típico
/// dura más, por lo que casi siempre se aborta y se reentrega.
pub const SHUTDOWN_DRAIN_TIMEOUT: Duration = Duration::from_secs(25);

/// Arranca el pipeline de escaneo con los puertos ya inyectados (composition
/// root en [`wiring`] + `src/main.rs`).
///
/// Construye el [`ScanPipeline`] a partir de `ports` y `config` y:
///
/// - si `source` es `Some`, consume solicitudes de esa
///   [`ScanRequestSource`] con [`ScanPipeline::run_until_shutdown`] hasta que
///   se cierre o `shutdown` se cancele. `cancellations` viaja junto a `source`:
///   si es `Some`, el pipeline también consume esa [`ScanCancellationSource`]
///   en su segundo bucle concurrente (feature `scan_cancellation`); si es
///   `None`, se usa una fuente en memoria vacía
///   ([`InMemoryScanCancellationSource::default`]) que no cancela nada, para no
///   exigirle un adaptador real a los usos de la librería que no lo necesitan;
/// - si `source` es `None`, deja constancia con `tracing::warn!` y retorna.
///   `src/main.rs` siempre pasa `Some` en producción (el adaptador real es
///   [`crate::messaging::sqs::SqsScanRequestSource`]); `None` sigue existiendo
///   para tests/usos de la librería que no necesitan consumir de la cola (p. ej.
///   un pipeline armado a mano con [`ScanPipeline::process_one`] directamente).
///
/// ## Apagado ordenado
///
/// Al cancelarse `shutdown` (`src/main.rs` lo hace con `SIGTERM`/`Ctrl-C`, ver
/// [`shutdown_signal`]) se deja de pedir mensajes de inmediato (el long poll
/// SQS en curso se descarta), se espera hasta [`SHUTDOWN_DRAIN_TIMEOUT`] a que
/// terminen los escaneos en vuelo (cada uno se borra de la cola solo tras su
/// desenlace terminal) y se abortan los que sigan corriendo: sus mensajes
/// reaparecen al vencer el `VisibilityTimeout` y se reprocesan. Las
/// cancelaciones recibidas durante ese drenado no se aplican.
///
/// Nunca hace `panic`.
pub async fn run(
    ports: ServicePorts,
    config: PipelineConfig,
    source: Option<Arc<dyn ScanRequestSource>>,
    cancellations: Option<Arc<dyn ScanCancellationSource>>,
    shutdown: CancellationToken,
) {
    let pipeline = ScanPipeline::new(ports, config);

    match source {
        Some(source) => {
            let cancellations: Arc<dyn ScanCancellationSource> = cancellations
                .unwrap_or_else(|| Arc::new(InMemoryScanCancellationSource::default()));
            pipeline
                .run_until_shutdown(source, cancellations, shutdown, SHUTDOWN_DRAIN_TIMEOUT)
                .await;
        }
        None => tracing::warn!(
            "ms-nmap arrancó: configuración validada y MongoDB accesible, pero no hay \
             ScanRequestSource; el pipeline no consumirá solicitudes."
        ),
    }
}

/// Se completa al recibir `Ctrl-C` (`SIGINT`) o, en Unix, `SIGTERM` (la señal
/// con la que ECS detiene una tarea). Si no se puede instalar un manejador se
/// registra el error y ese camino queda inactivo (el otro sigue vigente).
pub async fn shutdown_signal() {
    let ctrl_c = async {
        if let Err(err) = tokio::signal::ctrl_c().await {
            tracing::error!(error = %err, "no se pudo instalar el manejador de Ctrl-C");
            std::future::pending::<()>().await;
        }
    };

    #[cfg(unix)]
    let terminate = async {
        match tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate()) {
            Ok(mut sigterm) => {
                sigterm.recv().await;
            }
            Err(err) => {
                tracing::error!(error = %err, "no se pudo instalar el manejador de SIGTERM");
                std::future::pending::<()>().await;
            }
        }
    };
    #[cfg(not(unix))]
    let terminate = std::future::pending::<()>();

    tokio::select! {
        () = ctrl_c => {}
        () = terminate => {}
    }
}

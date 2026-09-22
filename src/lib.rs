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

/// Arranca el pipeline de escaneo con los puertos ya inyectados (composition
/// root en [`wiring`] + `src/main.rs`).
///
/// Construye el [`ScanPipeline`] a partir de `ports` y `config` y:
///
/// - si `source` es `Some`, consume solicitudes de esa
///   [`ScanRequestSource`] llamando a [`ScanPipeline::run`] hasta que se cierre.
///   `cancellations` viaja junto a `source`: si es `Some`, el pipeline también
///   consume esa [`ScanCancellationSource`] en su segundo bucle concurrente
///   (features `scan_cancellation` y `broker_adapter`); si es `None`, se usa
///   una fuente en memoria vacía ([`InMemoryScanCancellationSource::default`])
///   que no cancela nada, para no exigirle un adaptador real a los usos de la
///   librería que no lo necesitan;
/// - si `source` es `None`, deja constancia con `tracing::warn!` y retorna.
///   `src/main.rs` siempre pasa `Some` en producción (el adaptador real es
///   [`crate::messaging::rabbitmq::RabbitMqScanRequestSource`], feature
///   `broker_adapter`); `None` sigue existiendo para tests/usos de la librería
///   que no necesitan consumir del Broker (p. ej. un pipeline armado a mano
///   con [`ScanPipeline::process_one`] directamente).
///
/// Nunca hace `panic`.
pub async fn run(
    ports: ServicePorts,
    config: PipelineConfig,
    source: Option<Arc<dyn ScanRequestSource>>,
    cancellations: Option<Arc<dyn ScanCancellationSource>>,
) {
    let pipeline = ScanPipeline::new(ports, config);

    match source {
        Some(source) => {
            let cancellations: Arc<dyn ScanCancellationSource> = cancellations
                .unwrap_or_else(|| Arc::new(InMemoryScanCancellationSource::default()));
            pipeline.run(source, cancellations).await;
        }
        None => tracing::warn!(
            "ms-nmap arrancó: configuración validada y MongoDB accesible. El adaptador de \
             broker (ScanRequestSource real) aún no existe; el pipeline no consumirá \
             solicitudes hasta que se implemente."
        ),
    }
}

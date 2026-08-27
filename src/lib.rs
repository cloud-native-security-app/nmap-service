//! Crate `ms-nmap`: recibe una solicitud de escaneo desde el Broker, se conecta
//! por SSH al objetivo, ejecuta `nmap`, interpreta el resultado, lo persiste en
//! MongoDB y lo publica de vuelta hacia el Broker.
//!
//! `src/lib.rs` declara las capas del servicio como módulos públicos para que
//! los tests de integración de `tests/` (que compilan como crate externo)
//! puedan verlas. `src/main.rs` es solo un envoltorio delgado sobre [`run`].

#![deny(missing_docs)]

pub mod config;
pub mod domain;
pub mod messaging;
pub mod parser;
pub mod repository;
pub mod scanner;
pub mod ssh;

/// Arranca el servicio: conecta el pipeline
/// `consumer -> ssh -> scanner -> parser -> repository -> publisher`.
///
/// Por ahora es un stub del scaffolding (feature 1): registra que el servicio
/// arrancó y retorna. La orquestación real se implementa en la feature
/// `scan_pipeline_wiring`.
pub async fn run() {
    tracing::info!("ms-nmap iniciado (scaffolding: pipeline aún no implementado)");
}

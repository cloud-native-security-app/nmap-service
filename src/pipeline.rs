//! Orquestación end-to-end del pipeline de escaneo: conecta
//! `consumer -> ssh -> scanner -> parser -> repository -> publisher`
//! (ver `docs/architecture.md`, §"Flujo de datos").
//!
//! [`ScanPipeline::process_one`] ejecuta **una** solicitud por todas las etapas.
//! Un fallo en cualquiera de ellas (SSH, `nmap`, parseo, Mongo) **no** se
//! propaga ni provoca un `panic`: se convierte en un [`ScanOutcome::Failed`]
//! publicado hacia el Broker (§"Manejo de errores"). [`ScanPipeline::run`]
//! consume solicitudes de un [`ScanRequestSource`] y
//! despacha varias de forma concurrente con `tokio::spawn`; no hay llamadas
//! bloqueantes (`russh` y `mongodb` son nativamente async).
//!
//! # Seguridad
//!
//! El `reason` de un desenlace de fallo es `err.to_string()` de la etapa que
//! falló. Los `Display` de `SshError`, `ScanError`, `ParseError` y `RepoError`
//! ya redactan cualquier credencial, y el logging de este módulo sólo emite
//! `correlation_id`, IP objetivo y estado — nunca `ssh_credentials_ref` (ver
//! `docs/security-scope.md`).

use std::sync::Arc;

use tokio::task::JoinSet;

use crate::domain::{ScanRequest, ScanResult};
use crate::messaging::consumer::{ConsumeError, ScanRequestSource};
use crate::messaging::publisher::{ScanOutcome, ScanResultSink};
use crate::parser;
use crate::repository::MongoRepository;
use crate::scanner::{self, ScanOptions};
use crate::ssh::{self, HostKeyStore, SshTimeouts};

/// Dependencias ya construidas del pipeline de escaneo.
///
/// Es barato de clonar: `MongoRepository` comparte el pool de conexiones de su
/// `Client` interno y el resto de campos son `Arc` / `Copy` / colecciones
/// pequeñas. [`run`](Self::run) clona una copia por cada solicitud que despacha
/// a una tarea concurrente.
#[derive(Clone)]
pub struct ScanPipeline {
    repo: MongoRepository,
    host_key_store: Arc<dyn HostKeyStore>,
    sink: Arc<dyn ScanResultSink>,
    ssh_port: u16,
    ssh_timeouts: SshTimeouts,
    scan_options: ScanOptions,
}

impl ScanPipeline {
    /// Construye el pipeline con sus dependencias ya inicializadas.
    ///
    /// `ssh_port` es el puerto SSH del objetivo: el [`ScanRequest`] no lo
    /// transporta, proviene de la configuración del despliegue (ver
    /// [`crate::config::Config::ssh_port`]). `host_key_store` debe ser la
    /// implementación persistente respaldada por Mongo
    /// ([`crate::repository::MongoHostKeyStore`]) en producción, para que la
    /// verificación TOFU sobreviva reinicios y se comparta entre réplicas.
    pub fn new(
        repo: MongoRepository,
        host_key_store: Arc<dyn HostKeyStore>,
        sink: Arc<dyn ScanResultSink>,
        ssh_port: u16,
        ssh_timeouts: SshTimeouts,
        scan_options: ScanOptions,
    ) -> Self {
        Self {
            repo,
            host_key_store,
            sink,
            ssh_port,
            ssh_timeouts,
            scan_options,
        }
    }

    /// Procesa **una** solicitud por todas las etapas del pipeline y publica el
    /// desenlace (éxito o fallo) hacia el Broker.
    ///
    /// Nunca propaga un error ni hace `panic`: cualquier fallo de etapa se
    /// publica como [`ScanOutcome::Failed`] con el `correlation_id` de la
    /// solicitud. Si la propia publicación falla, se registra con
    /// `tracing::error!` y se termina (sin reintentos).
    pub async fn process_one(&self, request: ScanRequest) {
        let correlation_id = request.correlation_id.clone();
        tracing::info!(
            correlation_id = %correlation_id,
            target_ip = %request.ip,
            "pipeline de escaneo iniciado"
        );

        let outcome = match self.run_stages(&request).await {
            Ok(result) => ScanOutcome::completed(correlation_id.clone(), result),
            Err(reason) => {
                tracing::warn!(
                    correlation_id = %correlation_id,
                    reason = %reason,
                    "una etapa del pipeline falló; se publicará un desenlace de error"
                );
                ScanOutcome::failed(correlation_id.clone(), reason)
            }
        };

        let status = outcome.status_label();
        match self.sink.publish(&outcome).await {
            Ok(()) => tracing::info!(
                correlation_id = %correlation_id,
                status,
                "pipeline de escaneo finalizado; desenlace publicado"
            ),
            Err(err) => tracing::error!(
                correlation_id = %correlation_id,
                error = %err,
                "no se pudo publicar el desenlace del escaneo; se descarta"
            ),
        }
    }

    /// Ejecuta las etapas SSH -> `nmap` -> parseo -> persistencia. Devuelve el
    /// [`ScanResult`] o, ante el primer `Err`, el `reason` legible ya
    /// formateado (`err.to_string()` de la etapa, sin credenciales).
    async fn run_stages(&self, request: &ScanRequest) -> Result<ScanResult, String> {
        let session = ssh::connect(
            &request.ip.to_string(),
            self.ssh_port,
            &request.network_user,
            &request.ssh_credentials_ref,
            &self.host_key_store,
            self.ssh_timeouts,
        )
        .await
        .map_err(|err| err.to_string())?;

        let xml =
            scanner::run_scan_with(&session, request.ip, request.has_sudo, &self.scan_options)
                .await
                .map_err(|err| err.to_string())?;

        let result = parser::parse(&xml).map_err(|err| err.to_string())?;

        self.repo
            .save(&result, &request.correlation_id)
            .await
            .map_err(|err| err.to_string())?;

        Ok(result)
    }

    /// Consume solicitudes de `source` y las procesa de forma concurrente
    /// (`tokio::spawn` por solicitud, con el pipeline clonado).
    ///
    /// El bucle termina cuando:
    ///
    /// - la fuente devuelve `Ok(None)` (cierre ordenado), o
    /// - la fuente devuelve `Err(ConsumeError::Transport(_))`: sin transporte no
    ///   hay nada que consumir. La reconexión / backoff es responsabilidad del
    ///   adaptador de broker concreto (aún sin decidir, ver
    ///   `docs/architecture.md`), no de este bucle.
    ///
    /// Un `Err(ConsumeError::MalformedPayload | InvalidSchema)` se registra con
    /// `tracing::warn!` y **no** interrumpe el consumo (contrato de
    /// [`ScanRequestSource`]).
    ///
    /// Antes de retornar, espera a que terminen las tareas de escaneo en vuelo.
    pub async fn run(&self, source: Arc<dyn ScanRequestSource>) {
        let mut tasks: JoinSet<()> = JoinSet::new();

        while let Some(request) = next_valid_request(source.as_ref()).await {
            let pipeline = self.clone();
            tasks.spawn(async move { pipeline.process_one(request).await });
        }

        while let Some(joined) = tasks.join_next().await {
            if let Err(err) = joined {
                tracing::error!(error = %err, "una tarea de escaneo no terminó limpiamente");
            }
        }
    }
}

/// Bloquea hasta obtener la siguiente solicitud válida de `source`, o `None` si
/// la fuente se cerró (`Ok(None)`) o sufrió un fallo de transporte
/// ([`ConsumeError::Transport`]).
///
/// Los mensajes malformados o con esquema inválido se descartan con
/// `tracing::warn!` y no interrumpen el consumo.
async fn next_valid_request(source: &dyn ScanRequestSource) -> Option<ScanRequest> {
    loop {
        match source.next_request().await {
            Ok(Some(incoming)) => return Some(incoming.request),
            Ok(None) => return None,
            Err(err @ (ConsumeError::MalformedPayload(_) | ConsumeError::InvalidSchema(_))) => {
                tracing::warn!(error = %err, "solicitud del Broker descartada; se continúa");
            }
            Err(err @ ConsumeError::Transport(_)) => {
                tracing::error!(
                    error = %err,
                    "fallo de transporte con el Broker; se detiene el consumo"
                );
                return None;
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use std::sync::Mutex;

    use super::*;
    use crate::domain::CorrelationId;
    use crate::messaging::consumer::{InMemoryScanRequestSource, IncomingScanRequest};
    use crate::parser::ParseError;
    use crate::repository::RepoError;
    use crate::scanner::ScanError;
    use crate::ssh::SshError;

    const SECRET: &str = "hunter2-super-secret-token";

    fn request_json(correlation_id: &str) -> Vec<u8> {
        format!(
            r#"{{
                "correlation_id": "{correlation_id}",
                "ip": "198.51.100.7",
                "network_user": "netops",
                "ssh_credentials_ref": "{SECRET}",
                "has_sudo": false,
                "requested_by": "analyst@example.test"
            }}"#
        )
        .into_bytes()
    }

    #[tokio::test]
    async fn next_valid_request_skips_poison_messages_and_ends_on_none() {
        let source = InMemoryScanRequestSource::from_raw_messages([
            request_json("corr-1"),
            b"{ not json".to_vec(),
            request_json("corr-2"),
        ]);

        let first = next_valid_request(&source).await.expect("primera válida");
        assert_eq!(first.correlation_id.as_str(), "corr-1");

        // El mensaje envenenado se descarta y se entrega la siguiente válida.
        let second = next_valid_request(&source).await.expect("segunda válida");
        assert_eq!(second.correlation_id.as_str(), "corr-2");

        assert!(next_valid_request(&source).await.is_none());
    }

    struct TransportFailingSource {
        remaining: Mutex<usize>,
    }

    #[async_trait::async_trait]
    impl ScanRequestSource for TransportFailingSource {
        async fn next_request(&self) -> Result<Option<IncomingScanRequest>, ConsumeError> {
            let mut remaining = self.remaining.lock().expect("lock");
            if *remaining == 0 {
                return Ok(None);
            }
            *remaining -= 1;
            Err(ConsumeError::Transport(
                "conexión con el Broker caída".to_owned(),
            ))
        }
    }

    #[tokio::test]
    async fn next_valid_request_stops_on_transport_error() {
        let source = TransportFailingSource {
            remaining: Mutex::new(3),
        };

        assert!(
            next_valid_request(&source).await.is_none(),
            "un fallo de transporte detiene el consumo en la primera vuelta"
        );
        // No consumió las 3: paró en la primera.
        assert_eq!(*source.remaining.lock().unwrap(), 2);
    }

    #[test]
    fn stage_error_strings_become_failed_outcomes_without_leaking_credentials() {
        // Reproduce la transformación que hace `run_stages`: `err.to_string()`
        // de cada etapa como `reason` del `ScanOutcome::Failed`.
        let reasons = [
            SshError::AuthFailed.to_string(),
            ScanError::ToolNotAvailable.to_string(),
            ParseError::MalformedXml("línea 1: se esperaba '>'".to_owned()).to_string(),
            RepoError::ConnectionFailed("connection refused".to_owned()).to_string(),
        ];

        for reason in reasons {
            let outcome = ScanOutcome::failed(CorrelationId::from("corr-42"), reason.clone());
            match outcome {
                ScanOutcome::Failed {
                    correlation_id,
                    reason: stored,
                } => {
                    assert_eq!(correlation_id.as_str(), "corr-42");
                    assert_eq!(stored, reason);
                    assert!(
                        !stored.contains(SECRET),
                        "el reason no debe contener la credencial: {stored}"
                    );
                }
                other => panic!("se esperaba Failed, se obtuvo {other:?}"),
            }
        }
    }
}

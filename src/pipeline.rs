//! Orquestación end-to-end del pipeline de escaneo: conecta
//! `consumer -> ssh -> scanner -> parser -> repository -> publisher`
//! (ver `docs/architecture.md`, §"Flujo de datos").
//!
//! [`ScanPipeline::process_one`] ejecuta **una** solicitud por todas las etapas.
//! Antes de la primera (`ssh::connect`) publica un [`ScanOutcome::Started`]
//! best-effort, para que el Gateway sepa que la solicitud pasó a EN_PROGRESO
//! (feature `scan_started_event`). Un fallo en cualquiera de las etapas
//! siguientes (SSH, `nmap`, parseo, Mongo) **no** se propaga ni provoca un
//! `panic`: se convierte en un [`ScanOutcome::Failed`] publicado hacia el
//! Broker (§"Manejo de errores"). [`ScanPipeline::run`] consume solicitudes de
//! un [`ScanRequestSource`] y despacha varias de forma concurrente con
//! `tokio::spawn`; no hay llamadas bloqueantes (`russh` y `mongodb` son
//! nativamente async).
//!
//! # Cancelación (feature `scan_cancellation`)
//!
//! [`ScanPipeline::run`] también consume un [`ScanCancellationSource`] en un
//! segundo bucle concurrente (mismo `JoinSet`). Cada tarea en vuelo se
//! registra en un registro interno de tokens por su `correlation_id` al
//! arrancar [`ScanPipeline::process_one`] y se desregistra al terminar, para que una
//! cancelación tardía sobre una tarea ya finalizada sea un no-op seguro. Una
//! cancelación que llega mientras la tarea corre interrumpe `run_stages` en su
//! próximo punto de espera async (vía `tokio::select!`) y publica
//! [`ScanOutcome::Failed`] con un motivo que deja constancia explícita de que
//! fue una cancelación, no un fallo técnico.
//!
//! # Seguridad
//!
//! El `reason` de un desenlace de fallo es `err.to_string()` de la etapa que
//! falló. Los `Display` de `SshError`, `ScanError`, `ParseError` y `RepoError`
//! ya redactan cualquier credencial, y el logging de este módulo sólo emite
//! `correlation_id`, IP objetivo y estado — nunca `ssh_credentials_ref` (ver
//! `docs/security-scope.md`). [`ScanCancellation`] no lleva IP ni credenciales
//! del escaneo original.

use std::collections::HashMap;
use std::sync::{Arc, Mutex};

use tokio::task::JoinSet;
use tokio_util::sync::CancellationToken;

use crate::domain::{CorrelationId, ScanCancellation, ScanRequest, ScanResult, VulnFinding};
use crate::enrichment::VulnEnricher;
use crate::messaging::consumer::{ConsumeError, ScanCancellationSource, ScanRequestSource};
use crate::messaging::publisher::{ScanOutcome, ScanResultSink};
use crate::parser;
use crate::repository::ScanResultRepository;
use crate::scanner::{NmapScanner, ScanOptions};
use crate::ssh::{HostKeyStore, RemoteExecutor, SshTimeouts};

/// Motivo publicado en [`ScanOutcome::Failed`] cuando un escaneo se detuvo por
/// una cancelación explícita (en vez de un fallo técnico de alguna etapa).
const CANCELLATION_REASON: &str = "escaneo cancelado por solicitud explícita";

/// Registro de [`CancellationToken`] por `correlation_id` de las tareas de
/// escaneo en vuelo.
///
/// [`ScanPipeline::process_one`] registra un token al arrancar y lo
/// desregistra al terminar (éxito, fallo o cancelación). Ambas operaciones
/// toman el mismo `Mutex`, así que una cancelación tardía sobre una tarea ya
/// desregistrada nunca encuentra el token: es un no-op seguro, no una
/// condición de carrera.
#[derive(Clone, Default)]
struct CancellationRegistry {
    tokens: Arc<Mutex<HashMap<CorrelationId, CancellationToken>>>,
}

impl CancellationRegistry {
    /// Registra una nueva tarea y devuelve su token de cancelación.
    fn register(&self, correlation_id: CorrelationId) -> CancellationToken {
        let token = CancellationToken::new();
        let mut guard = match self.tokens.lock() {
            Ok(guard) => guard,
            Err(poisoned) => poisoned.into_inner(),
        };
        guard.insert(correlation_id, token.clone());
        token
    }

    /// Retira el registro de una tarea que ya terminó (éxito, fallo o
    /// cancelación).
    fn unregister(&self, correlation_id: &CorrelationId) {
        let mut guard = match self.tokens.lock() {
            Ok(guard) => guard,
            Err(poisoned) => poisoned.into_inner(),
        };
        guard.remove(correlation_id);
    }

    /// Cancela la tarea con `correlation_id`, si sigue registrada. Devuelve
    /// `true` si se encontró y canceló, `false` si el `correlation_id` es
    /// desconocido o ya se desregistró (no-op seguro, nunca un error).
    fn cancel(&self, correlation_id: &CorrelationId) -> bool {
        let guard = match self.tokens.lock() {
            Ok(guard) => guard,
            Err(poisoned) => poisoned.into_inner(),
        };
        match guard.get(correlation_id) {
            Some(token) => {
                token.cancel();
                true
            }
            None => false,
        }
    }
}

/// Adaptadores de los puertos hexagonales que necesita el pipeline, ya
/// construidos (inyección de dependencias).
///
/// La elección de la implementación concreta de cada puerto vive en el
/// composition root ([`crate::wiring`] + `src/main.rs`), nunca en esta capa.
/// Todos los campos son `Arc<dyn _>`: baratos de clonar y compartir entre las
/// tareas concurrentes que despacha [`ScanPipeline::run`].
#[derive(Clone)]
pub struct ServicePorts {
    /// Puerto SSH: establece la sesión con el objetivo (adaptador real
    /// [`crate::ssh::RusshExecutor`]).
    pub executor: Arc<dyn RemoteExecutor>,
    /// Puerto de escaneo: ejecuta `nmap` sobre la sesión (adaptador real
    /// [`crate::scanner::NmapCliScanner`]).
    pub scanner: Arc<dyn NmapScanner>,
    /// Puerto de persistencia del [`ScanResult`] (adaptador real
    /// [`crate::repository::MongoRepository`]).
    pub repository: Arc<dyn ScanResultRepository>,
    /// Puerto de enriquecimiento de vulnerabilidades: se ejecuta entre `parser`
    /// y `repository` (adaptador real
    /// [`crate::enrichment::CompositeVulnEnricher`] con
    /// [`crate::enrichment::ExploitDbEnricher`] siempre, y
    /// [`crate::enrichment::NvdApiEnricher`] sólo si el enriquecimiento NVD
    /// está habilitado, ver `docs/security-scope.md`).
    pub enricher: Arc<dyn VulnEnricher>,
    /// Almacén de host keys TOFU. En producción es el respaldado por Mongo
    /// ([`crate::repository::MongoHostKeyStore`]), para que sobreviva reinicios
    /// y se comparta entre réplicas.
    pub host_key_store: Arc<dyn HostKeyStore>,
    /// Destino de los desenlaces de escaneo hacia el Broker.
    pub sink: Arc<dyn ScanResultSink>,
}

/// Parámetros de despliegue del pipeline que no son puertos ni viajan en el
/// [`ScanRequest`]: provienen de [`crate::config::Config`].
#[derive(Clone)]
pub struct PipelineConfig {
    /// Puerto SSH del objetivo (todos los objetivos de un entorno escuchan en el
    /// mismo puerto; ver [`crate::config::Config::ssh_port`]).
    pub ssh_port: u16,
    /// Tiempos máximos de conexión y de comando SSH.
    pub ssh_timeouts: SshTimeouts,
    /// Opciones con las que se construye la línea de comandos de `nmap`.
    pub scan_options: ScanOptions,
}

/// Dependencias ya construidas del pipeline de escaneo.
///
/// Es barato de clonar: cada puerto es un `Arc` y el resto de campos son `Copy`
/// o colecciones pequeñas. [`run`](Self::run) clona una copia por cada solicitud
/// que despacha a una tarea concurrente.
#[derive(Clone)]
pub struct ScanPipeline {
    executor: Arc<dyn RemoteExecutor>,
    scanner: Arc<dyn NmapScanner>,
    repository: Arc<dyn ScanResultRepository>,
    enricher: Arc<dyn VulnEnricher>,
    host_key_store: Arc<dyn HostKeyStore>,
    sink: Arc<dyn ScanResultSink>,
    config: PipelineConfig,
    cancellations: CancellationRegistry,
}

impl ScanPipeline {
    /// Construye el pipeline a partir de los [`ServicePorts`] inyectados y la
    /// [`PipelineConfig`] del despliegue.
    ///
    /// El `host_key_store` de `ports` debe ser la implementación persistente
    /// respaldada por Mongo ([`crate::repository::MongoHostKeyStore`]) en
    /// producción, para que la verificación TOFU sobreviva reinicios y se
    /// comparta entre réplicas.
    pub fn new(ports: ServicePorts, config: PipelineConfig) -> Self {
        Self {
            executor: ports.executor,
            scanner: ports.scanner,
            repository: ports.repository,
            enricher: ports.enricher,
            host_key_store: ports.host_key_store,
            sink: ports.sink,
            config,
            cancellations: CancellationRegistry::default(),
        }
    }

    /// Procesa **una** solicitud por todas las etapas del pipeline y publica el
    /// desenlace (éxito o fallo) hacia el Broker.
    ///
    /// Antes de tocar el objetivo (`ssh::connect`/`scanner::run_scan`) publica
    /// exactamente un [`ScanOutcome::Started`], para que el Gateway sepa que la
    /// solicitud pasó de PENDIENTE a EN_PROGRESO (RF-07/RF-08). Esa publicación
    /// es best-effort: si `sink.publish` falla, se registra con
    /// `tracing::warn!` (sin credenciales) y el pipeline sigue igual con las
    /// etapas del escaneo — nunca se aborta por esto.
    ///
    /// Nunca propaga un error ni hace `panic`: cualquier fallo de etapa se
    /// publica como [`ScanOutcome::Failed`] con el `correlation_id` de la
    /// solicitud. Si la propia publicación del desenlace terminal falla, se
    /// registra con `tracing::error!` y se termina (sin reintentos).
    ///
    /// Registra un [`CancellationToken`] bajo el `correlation_id` de la
    /// solicitud **al arrancar**, antes de publicar
    /// [`ScanOutcome::Started`] (no después): así una cancelación que llegue
    /// mientras esa publicación todavía está en curso encuentra el token ya
    /// registrado y puede cancelar la tarea, en vez de descartarse como un
    /// `correlation_id` desconocido. Lo desregistra siempre al terminar
    /// (éxito, fallo o cancelación), para que una cancelación tardía sobre
    /// esta tarea ya finalizada sea un no-op seguro. Si llega una cancelación
    /// mientras las etapas siguen en curso, `tokio::select!` interrumpe el
    /// trabajo en el próximo punto de espera async y se publica
    /// [`ScanOutcome::Failed`] con un motivo que da constancia explícita de
    /// la cancelación, en vez del desenlace normal.
    pub async fn process_one(&self, request: ScanRequest) {
        let correlation_id = request.correlation_id.clone();
        tracing::info!(
            correlation_id = %correlation_id,
            target_ip = %request.ip,
            "pipeline de escaneo iniciado"
        );

        let token = self.cancellations.register(correlation_id.clone());

        if let Err(err) = self
            .sink
            .publish(&ScanOutcome::started(correlation_id.clone()))
            .await
        {
            tracing::warn!(
                correlation_id = %correlation_id,
                error = %err,
                "no se pudo publicar el evento de arranque del escaneo; se continúa igual"
            );
        }

        let outcome = tokio::select! {
            result = self.run_stages(&request) => match result {
                Ok(result) => ScanOutcome::completed(correlation_id.clone(), result),
                Err(reason) => {
                    tracing::warn!(
                        correlation_id = %correlation_id,
                        reason = %reason,
                        "una etapa del pipeline falló; se publicará un desenlace de error"
                    );
                    ScanOutcome::failed(correlation_id.clone(), reason)
                }
            },
            () = token.cancelled() => {
                tracing::warn!(
                    correlation_id = %correlation_id,
                    "escaneo cancelado por solicitud explícita; se detiene antes de completarse"
                );
                ScanOutcome::failed(correlation_id.clone(), CANCELLATION_REASON)
            }
        };

        self.cancellations.unregister(&correlation_id);

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
        let session = self
            .executor
            .connect(
                &request.ip.to_string(),
                self.config.ssh_port,
                &request.network_user,
                &request.ssh_credentials_ref,
                &self.host_key_store,
                self.config.ssh_timeouts,
            )
            .await
            .map_err(|err| err.to_string())?;

        let xml = self
            .scanner
            .run_scan(
                session.as_ref(),
                request.ip,
                request.has_sudo,
                &self.config.scan_options,
            )
            .await
            .map_err(|err| err.to_string())?;

        let mut result = parser::parse(&xml).map_err(|err| err.to_string())?;

        // Enriquecimiento best-effort: un fallo aquí NUNCA convierte el escaneo
        // en `ScanOutcome::Failed`; se registra y se continúa con los hallazgos
        // de `nmap` (ver `docs/architecture.md`, capa `enrichment`).
        let extra = self
            .enricher
            .enrich(&result.ports)
            .await
            .unwrap_or_else(|err| {
                tracing::warn!(
                    error = %err,
                    correlation_id = %request.correlation_id,
                    "enriquecimiento de vulnerabilidades falló; se continúa con los hallazgos de nmap"
                );
                Vec::new()
            });
        merge_enrichment_findings(&mut result.vulnerabilities, extra);

        self.repository
            .save(&result, &request.correlation_id)
            .await
            .map_err(|err| err.to_string())?;

        Ok(result)
    }

    /// Consume solicitudes de `source` y las procesa de forma concurrente
    /// (`tokio::spawn` por solicitud, con el pipeline clonado), mientras un
    /// segundo bucle -en el mismo `JoinSet`- consume cancelaciones de
    /// `cancellations` y aborta la tarea en curso cuyo `correlation_id`
    /// coincide, si existe.
    ///
    /// El bucle de solicitudes termina cuando:
    ///
    /// - la fuente devuelve `Ok(None)` (cierre ordenado), o
    /// - la fuente devuelve `Err(ConsumeError::Transport(_))`: sin transporte no
    ///   hay nada que consumir. La reconexión / backoff es responsabilidad del
    ///   adaptador de broker concreto (aún sin decidir, ver
    ///   `docs/architecture.md`), no de este bucle.
    ///
    /// El bucle de cancelaciones termina con el mismo criterio, aplicado a
    /// `cancellations`. Una cancelación para un `correlation_id` desconocido o
    /// ya finalizado es un no-op loggeado, nunca un error.
    ///
    /// Un `Err(ConsumeError::MalformedPayload | InvalidSchema)` en cualquiera de
    /// las dos fuentes se registra con `tracing::warn!` y **no** interrumpe su
    /// consumo (contrato de [`ScanRequestSource`]/[`ScanCancellationSource`]).
    ///
    /// Antes de retornar, espera a que terminen ambos bucles y todas las tareas
    /// de escaneo en vuelo.
    pub async fn run(
        &self,
        source: Arc<dyn ScanRequestSource>,
        cancellations: Arc<dyn ScanCancellationSource>,
    ) {
        let mut tasks: JoinSet<()> = JoinSet::new();

        let pipeline_for_cancellations = self.clone();
        tasks.spawn(async move {
            while let Some(cancellation) = next_valid_cancellation(cancellations.as_ref()).await {
                pipeline_for_cancellations.apply_cancellation(&cancellation);
            }
        });

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

    /// Aplica una [`ScanCancellation`] recibida: cancela la tarea en curso con
    /// el mismo `correlation_id`, si existe. Un `correlation_id` desconocido o
    /// ya finalizado es un no-op, sólo se registra con `tracing::info!`.
    fn apply_cancellation(&self, cancellation: &ScanCancellation) {
        if self.cancellations.cancel(&cancellation.correlation_id) {
            tracing::info!(
                correlation_id = %cancellation.correlation_id,
                requested_by = %cancellation.requested_by,
                "cancelación aplicada a un escaneo en curso"
            );
        } else {
            tracing::info!(
                correlation_id = %cancellation.correlation_id,
                requested_by = %cancellation.requested_by,
                "cancelación recibida para un escaneo desconocido o ya finalizado; no-op"
            );
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

/// Bloquea hasta obtener la siguiente cancelación válida de `source`, o `None`
/// si la fuente se cerró (`Ok(None)`) o sufrió un fallo de transporte
/// ([`ConsumeError::Transport`]).
///
/// Los mensajes malformados o con esquema inválido se descartan con
/// `tracing::warn!` y no interrumpen el consumo (mismo contrato que
/// [`next_valid_request`]).
async fn next_valid_cancellation(source: &dyn ScanCancellationSource) -> Option<ScanCancellation> {
    loop {
        match source.next_cancellation().await {
            Ok(Some(cancellation)) => return Some(cancellation),
            Ok(None) => return None,
            Err(err @ (ConsumeError::MalformedPayload(_) | ConsumeError::InvalidSchema(_))) => {
                tracing::warn!(error = %err, "cancelación del Broker descartada; se continúa");
            }
            Err(err @ ConsumeError::Transport(_)) => {
                tracing::error!(
                    error = %err,
                    "fallo de transporte con el Broker; se detiene el consumo de cancelaciones"
                );
                return None;
            }
        }
    }
}

/// Fusiona los hallazgos del enriquecimiento (`extra`) sobre los que ya trajo
/// `nmap` (`existing`), sin duplicar.
///
/// Un hallazgo de `extra` se descarta si:
///
/// - tiene `id` (CVE) y ese `id` ya está en `existing` (contando los que se van
///   añadiendo, así también se deduplican dos filas de Exploit-DB con el mismo
///   CVE), o
/// - no tiene `id` y ya hay en `existing` otro sin `id` con la misma
///   `description`.
fn merge_enrichment_findings(existing: &mut Vec<VulnFinding>, extra: Vec<VulnFinding>) {
    for finding in extra {
        let is_duplicate = match &finding.id {
            Some(id) => existing
                .iter()
                .any(|v| v.id.as_deref() == Some(id.as_str())),
            None => existing
                .iter()
                .any(|v| v.id.is_none() && v.description == finding.description),
        };
        if !is_duplicate {
            existing.push(finding);
        }
    }
}

#[cfg(test)]
mod tests {
    use std::net::IpAddr;
    use std::sync::Mutex;
    use std::time::Duration;

    use secrecy::SecretString;
    use tokio::sync::Notify;

    use super::*;
    use crate::domain::{CorrelationId, PortFinding, Severity, SshCredentialsRef, VulnSource};
    use crate::enrichment::EnrichError;
    use crate::messaging::consumer::{
        InMemoryScanCancellationSource, InMemoryScanRequestSource, IncomingScanRequest,
        ScanCancellationSource,
    };
    use crate::messaging::publisher::InMemoryScanResultSink;
    use crate::parser::ParseError;
    use crate::repository::{RepoError, ScanId};
    use crate::scanner::ScanError;
    use crate::ssh::{InMemoryHostKeyStore, RemoteSession, SshError};

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

    fn cancellation_json(correlation_id: &str) -> Vec<u8> {
        format!(
            r#"{{
                "correlation_id": "{correlation_id}",
                "requested_by": "analyst@example.test"
            }}"#
        )
        .into_bytes()
    }

    #[tokio::test]
    async fn next_valid_cancellation_skips_poison_messages_and_ends_on_none() {
        let source = InMemoryScanCancellationSource::from_raw_messages([
            cancellation_json("corr-1"),
            b"{ not json".to_vec(),
            cancellation_json("corr-2"),
        ]);

        let first = next_valid_cancellation(&source)
            .await
            .expect("primera válida");
        assert_eq!(first.correlation_id.as_str(), "corr-1");

        let second = next_valid_cancellation(&source)
            .await
            .expect("segunda válida");
        assert_eq!(second.correlation_id.as_str(), "corr-2");

        assert!(next_valid_cancellation(&source).await.is_none());
    }

    struct TransportFailingCancellationSource {
        remaining: Mutex<usize>,
    }

    #[async_trait::async_trait]
    impl ScanCancellationSource for TransportFailingCancellationSource {
        async fn next_cancellation(&self) -> Result<Option<ScanCancellation>, ConsumeError> {
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
    async fn next_valid_cancellation_stops_on_transport_error() {
        let source = TransportFailingCancellationSource {
            remaining: Mutex::new(3),
        };

        assert!(
            next_valid_cancellation(&source).await.is_none(),
            "un fallo de transporte detiene el consumo en la primera vuelta"
        );
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

    /// Doble de [`VulnEnricher`] que devuelve una lista fija de hallazgos.
    struct StubEnricher(Vec<VulnFinding>);

    #[async_trait::async_trait]
    impl VulnEnricher for StubEnricher {
        async fn enrich(&self, _ports: &[PortFinding]) -> Result<Vec<VulnFinding>, EnrichError> {
            Ok(self.0.clone())
        }
    }

    fn vuln(id: Option<&str>, description: &str, source: VulnSource) -> VulnFinding {
        VulnFinding {
            id: id.map(str::to_owned),
            severity: Severity::Unknown,
            description: description.to_owned(),
            nse_script: String::new(),
            source,
            references: Vec::new(),
        }
    }

    #[test]
    fn merge_enrichment_adds_new_cves_and_skips_ones_nmap_already_found() {
        let mut existing = vec![vuln(
            Some("CVE-2011-2523"),
            "vsFTPd backdoor (nmap)",
            VulnSource::NmapNse,
        )];
        let extra = vec![
            // Ya lo trajo nmap -> se descarta.
            vuln(
                Some("CVE-2011-2523"),
                "vsftpd 2.3.4 - Backdoor (Exploit-DB 49757)",
                VulnSource::ExploitDb,
            ),
            // Nuevo -> se añade.
            vuln(
                Some("CVE-2010-2075"),
                "UnrealIRCd 3.2.8.1 - Backdoor (Exploit-DB 16922)",
                VulnSource::ExploitDb,
            ),
            // Otra fila de Exploit-DB con el mismo CVE nuevo -> se deduplica.
            vuln(
                Some("CVE-2010-2075"),
                "UnrealIRCd 3.2.8.1 - Downloader (Exploit-DB 13853)",
                VulnSource::ExploitDb,
            ),
        ];

        merge_enrichment_findings(&mut existing, extra);

        assert_eq!(existing.len(), 2);
        assert_eq!(
            existing
                .iter()
                .filter(|v| v.id.as_deref() == Some("CVE-2010-2075"))
                .count(),
            1
        );
        assert!(
            existing
                .iter()
                .any(|v| v.id.as_deref() == Some("CVE-2010-2075")
                    && v.source == VulnSource::ExploitDb)
        );
    }

    #[test]
    fn merge_enrichment_dedups_findings_without_id_by_description() {
        let mut existing = vec![vuln(None, "misconfig X", VulnSource::NmapNse)];
        let extra = vec![
            vuln(None, "misconfig X", VulnSource::ExploitDb),
            vuln(None, "misconfig Y", VulnSource::ExploitDb),
        ];

        merge_enrichment_findings(&mut existing, extra);

        assert_eq!(existing.len(), 2);
        assert!(existing.iter().any(|v| v.description == "misconfig Y"));
    }

    /// Adaptador falso de [`RemoteExecutor`] que siempre falla la conexión.
    struct FailingExecutor;

    #[async_trait::async_trait]
    impl RemoteExecutor for FailingExecutor {
        async fn connect(
            &self,
            _host: &str,
            _port: u16,
            _user: &str,
            _credentials: &SshCredentialsRef,
            _store: &Arc<dyn HostKeyStore>,
            _timeouts: SshTimeouts,
        ) -> Result<Box<dyn RemoteSession>, SshError> {
            Err(SshError::AuthFailed)
        }
    }

    /// Puertos que no deben invocarse cuando una etapa previa falla.
    struct UnusedScanner;

    #[async_trait::async_trait]
    impl NmapScanner for UnusedScanner {
        async fn run_scan(
            &self,
            _session: &dyn RemoteSession,
            _target_ip: IpAddr,
            _has_sudo: bool,
            _options: &ScanOptions,
        ) -> Result<String, ScanError> {
            unreachable!("scanner no debe llamarse si la etapa SSH falló")
        }
    }

    struct UnusedRepository;

    #[async_trait::async_trait]
    impl ScanResultRepository for UnusedRepository {
        async fn save(
            &self,
            _result: &ScanResult,
            _correlation_id: &CorrelationId,
        ) -> Result<ScanId, RepoError> {
            unreachable!("repository no debe llamarse si la etapa SSH falló")
        }

        async fn find_by_id(&self, _id: &ScanId) -> Result<Option<ScanResult>, RepoError> {
            unreachable!()
        }

        async fn find_by_correlation_id(
            &self,
            _correlation_id: &CorrelationId,
        ) -> Result<Option<ScanResult>, RepoError> {
            unreachable!()
        }
    }

    fn test_request(correlation_id: &str) -> ScanRequest {
        ScanRequest {
            correlation_id: CorrelationId::from(correlation_id),
            ip: "198.51.100.7".parse().expect("IP de prueba válida"),
            network_user: "netops".to_owned(),
            ssh_credentials_ref: SshCredentialsRef::new(SecretString::from(SECRET.to_owned())),
            has_sudo: false,
            requested_by: "analyst@example.test".to_owned(),
        }
    }

    fn test_config() -> PipelineConfig {
        PipelineConfig {
            ssh_port: 22,
            ssh_timeouts: SshTimeouts {
                connect: Duration::from_secs(1),
                command: Duration::from_secs(1),
            },
            scan_options: ScanOptions::default(),
        }
    }

    #[tokio::test]
    async fn ssh_stage_failure_is_published_as_failed_outcome_without_docker() {
        let sink = Arc::new(InMemoryScanResultSink::new());
        let ports = ServicePorts {
            executor: Arc::new(FailingExecutor),
            scanner: Arc::new(UnusedScanner),
            repository: Arc::new(UnusedRepository),
            enricher: Arc::new(StubEnricher(Vec::new())),
            host_key_store: Arc::new(InMemoryHostKeyStore::new()),
            sink: sink.clone(),
        };
        let pipeline = ScanPipeline::new(ports, test_config());

        pipeline.process_one(test_request("corr-ssh-fail")).await;

        // Exactamente 2 desenlaces por invocación: Started primero, luego el
        // terminal (Failed en este caso), ambos con el mismo correlation_id.
        let published = sink.published();
        assert_eq!(
            published.len(),
            2,
            "debe publicarse el evento started y el desenlace terminal"
        );
        match &published[0] {
            ScanOutcome::Started { correlation_id } => {
                assert_eq!(correlation_id.as_str(), "corr-ssh-fail");
            }
            other => panic!("se esperaba Started primero, se obtuvo {other:?}"),
        }
        match &published[1] {
            ScanOutcome::Failed {
                correlation_id,
                reason,
            } => {
                assert_eq!(correlation_id.as_str(), "corr-ssh-fail");
                assert_eq!(reason, &SshError::AuthFailed.to_string());
                assert!(
                    !reason.contains(SECRET),
                    "el reason no debe filtrar la credencial: {reason}"
                );
            }
            other => panic!("se esperaba Failed, se obtuvo {other:?}"),
        }
    }

    /// [`ScanResultSink`] cuyas primeras `fail_first_n` llamadas a `publish`
    /// fallan con [`PublishError::Transport`]; el resto se delega a un
    /// [`InMemoryScanResultSink`] interno. Simula que publicar el evento
    /// `started` falla, para comprobar el contrato best-effort de
    /// `process_one`.
    struct FlakySink {
        fail_first_n: Mutex<usize>,
        inner: InMemoryScanResultSink,
    }

    impl FlakySink {
        fn failing_once() -> Self {
            Self {
                fail_first_n: Mutex::new(1),
                inner: InMemoryScanResultSink::new(),
            }
        }
    }

    #[async_trait::async_trait]
    impl ScanResultSink for FlakySink {
        async fn publish(
            &self,
            outcome: &ScanOutcome,
        ) -> Result<(), crate::messaging::publisher::PublishError> {
            let should_fail = {
                let mut remaining = self.fail_first_n.lock().expect("lock");
                if *remaining > 0 {
                    *remaining -= 1;
                    true
                } else {
                    false
                }
            };
            if should_fail {
                return Err(crate::messaging::publisher::PublishError::Transport(
                    "fallo simulado de transporte".to_owned(),
                ));
            }
            self.inner.publish(outcome).await
        }
    }

    #[tokio::test]
    async fn started_publish_failure_is_best_effort_and_does_not_abort_the_scan() {
        let sink = Arc::new(FlakySink::failing_once());
        let ports = ServicePorts {
            executor: Arc::new(FailingExecutor),
            scanner: Arc::new(UnusedScanner),
            repository: Arc::new(UnusedRepository),
            enricher: Arc::new(StubEnricher(Vec::new())),
            host_key_store: Arc::new(InMemoryHostKeyStore::new()),
            sink: sink.clone(),
        };
        let pipeline = ScanPipeline::new(ports, test_config());

        pipeline
            .process_one(test_request("corr-started-flaky"))
            .await;

        // La publicación de `started` falló (silenciosamente, sólo warn!) pero
        // el pipeline siguió con `run_stages` y publicó igual el desenlace
        // terminal.
        let published = sink.inner.published();
        assert_eq!(
            published.len(),
            1,
            "started falló al publicar; sólo debe quedar registrado el terminal"
        );
        assert!(matches!(published[0], ScanOutcome::Failed { .. }));
        assert_eq!(published[0].correlation_id().as_str(), "corr-started-flaky");
    }

    // --- feature `scan_cancellation`: registro de tokens sin Docker ---

    #[test]
    fn cancellation_registry_cancel_after_register_marks_the_token_cancelled() {
        let registry = CancellationRegistry::default();
        let id = CorrelationId::from("corr-cancel-1");
        let token = registry.register(id.clone());

        assert!(!token.is_cancelled());
        assert!(registry.cancel(&id), "debe encontrar el token registrado");
        assert!(token.is_cancelled());
    }

    #[test]
    fn cancellation_registry_cancel_unknown_id_is_a_safe_noop() {
        let registry = CancellationRegistry::default();

        assert!(!registry.cancel(&CorrelationId::from("corr-unknown")));
    }

    #[test]
    fn cancellation_registry_unregister_prevents_late_cancellation_from_finding_the_token() {
        let registry = CancellationRegistry::default();
        let id = CorrelationId::from("corr-finished");
        let token = registry.register(id.clone());

        registry.unregister(&id);

        assert!(
            !registry.cancel(&id),
            "una cancelación tardía sobre una tarea ya finalizada debe ser un no-op"
        );
        assert!(
            !token.is_cancelled(),
            "el token de una tarea ya finalizada nunca debe marcarse cancelado por una \
             cancelación tardía"
        );
    }

    /// Adaptador falso de [`RemoteExecutor`] que avisa (`started`) en cuanto
    /// entra a `connect` y luego se queda esperando indefinidamente. Permite
    /// que un test cancele `process_one` con certeza de que la tarea ya se
    /// registró y está detenida en su primer punto de espera async, sin
    /// depender de `sleep`s arbitrarios.
    struct SlowExecutor {
        started: Arc<Notify>,
    }

    #[async_trait::async_trait]
    impl RemoteExecutor for SlowExecutor {
        async fn connect(
            &self,
            _host: &str,
            _port: u16,
            _user: &str,
            _credentials: &SshCredentialsRef,
            _store: &Arc<dyn HostKeyStore>,
            _timeouts: SshTimeouts,
        ) -> Result<Box<dyn RemoteSession>, SshError> {
            self.started.notify_one();
            std::future::pending::<()>().await;
            unreachable!("esta rama nunca se alcanza: el test cancela antes de que resuelva")
        }
    }

    #[tokio::test]
    async fn cancellation_mid_flight_stops_process_one_and_publishes_cancellation_failed_outcome() {
        let started = Arc::new(Notify::new());
        let sink = Arc::new(InMemoryScanResultSink::new());
        let ports = ServicePorts {
            executor: Arc::new(SlowExecutor {
                started: started.clone(),
            }),
            scanner: Arc::new(UnusedScanner),
            repository: Arc::new(UnusedRepository),
            enricher: Arc::new(StubEnricher(Vec::new())),
            host_key_store: Arc::new(InMemoryHostKeyStore::new()),
            sink: sink.clone(),
        };
        let pipeline = ScanPipeline::new(ports, test_config());
        let correlation_id = CorrelationId::from("corr-cancel-mid-flight");

        let pipeline_for_task = pipeline.clone();
        let request = test_request(correlation_id.as_str());
        let handle = tokio::spawn(async move { pipeline_for_task.process_one(request).await });

        // Espera a que la tarea entre a `run_stages` (registrada en el
        // registro de cancelación) antes de cancelarla.
        started.notified().await;
        assert!(
            pipeline.cancellations.cancel(&correlation_id),
            "la tarea debe estar registrada en cuanto el executor avisó `started`"
        );

        handle
            .await
            .expect("process_one no debe entrar en panic al cancelarse");

        let published = sink.published();
        assert_eq!(
            published.len(),
            2,
            "debe publicarse el evento started y el desenlace de cancelación"
        );
        match &published[1] {
            ScanOutcome::Failed {
                correlation_id: id,
                reason,
            } => {
                assert_eq!(id, &correlation_id);
                assert_eq!(reason, CANCELLATION_REASON);
            }
            other => panic!("se esperaba Failed por cancelación, se obtuvo {other:?}"),
        }
    }

    /// [`ScanResultSink`] cuya publicación del evento `Started` se queda
    /// esperando (`entered_publish.notify_one()` + espera indefinida) hasta
    /// que el test la libere. Permite comprobar que el registro de
    /// cancelación ocurre ANTES de publicar `Started`, no después: un test
    /// puede cancelar la tarea mientras esa publicación sigue en curso y
    /// comprobar que el token ya está registrado (no se trata como un
    /// `correlation_id` desconocido).
    struct SlowStartedSink {
        entered_publish: Arc<Notify>,
        release: Arc<Notify>,
        inner: InMemoryScanResultSink,
    }

    #[async_trait::async_trait]
    impl ScanResultSink for SlowStartedSink {
        async fn publish(
            &self,
            outcome: &ScanOutcome,
        ) -> Result<(), crate::messaging::publisher::PublishError> {
            if matches!(outcome, ScanOutcome::Started { .. }) {
                self.entered_publish.notify_one();
                self.release.notified().await;
            }
            self.inner.publish(outcome).await
        }
    }

    #[tokio::test]
    async fn cancellation_while_started_publish_is_in_flight_finds_the_token_and_cancels() {
        let entered_publish = Arc::new(Notify::new());
        let release = Arc::new(Notify::new());
        let sink = Arc::new(SlowStartedSink {
            entered_publish: entered_publish.clone(),
            release: release.clone(),
            inner: InMemoryScanResultSink::new(),
        });
        // El executor nunca resuelve por sí mismo: así, si el token NO
        // estuviera registrado a tiempo (regresión del bug corregido), la
        // tarea seguiría corriendo indefinidamente en vez de cancelarse, y
        // `handle.await` de abajo colgaría el test en vez de pasar
        // silenciosamente.
        let ports = ServicePorts {
            executor: Arc::new(SlowExecutor {
                started: Arc::new(Notify::new()),
            }),
            scanner: Arc::new(UnusedScanner),
            repository: Arc::new(UnusedRepository),
            enricher: Arc::new(StubEnricher(Vec::new())),
            host_key_store: Arc::new(InMemoryHostKeyStore::new()),
            sink: sink.clone(),
        };
        let pipeline = ScanPipeline::new(ports, test_config());
        let correlation_id = CorrelationId::from("corr-cancel-during-started-publish");

        let pipeline_for_task = pipeline.clone();
        let request = test_request(correlation_id.as_str());
        let handle = tokio::spawn(async move { pipeline_for_task.process_one(request).await });

        // La publicación de `Started` está en curso (bloqueada en
        // `release.notified()`): en este punto el token YA debe estar
        // registrado, porque el registro ocurre antes de publicar.
        entered_publish.notified().await;
        assert!(
            pipeline.cancellations.cancel(&correlation_id),
            "el token debe estar registrado mientras sink.publish(Started) sigue en curso, \
             no sólo después de que termine"
        );
        // Libera la publicación de `Started`; `process_one` sigue con
        // `tokio::select!`, donde el token ya cancelado gana de inmediato
        // (el `SlowExecutor` nunca resuelve por sí mismo).
        release.notify_one();

        handle
            .await
            .expect("process_one no debe entrar en panic al cancelarse");

        let published = sink.inner.published();
        assert_eq!(
            published.len(),
            2,
            "debe publicarse el evento started y el desenlace de cancelación"
        );
        match &published[1] {
            ScanOutcome::Failed {
                correlation_id: id,
                reason,
            } => {
                assert_eq!(id, &correlation_id);
                assert_eq!(reason, CANCELLATION_REASON);
            }
            other => panic!("se esperaba Failed por cancelación, se obtuvo {other:?}"),
        }
    }

    #[tokio::test]
    async fn cancellation_after_process_one_finished_is_a_safe_noop() {
        let sink = Arc::new(InMemoryScanResultSink::new());
        let ports = ServicePorts {
            executor: Arc::new(FailingExecutor),
            scanner: Arc::new(UnusedScanner),
            repository: Arc::new(UnusedRepository),
            enricher: Arc::new(StubEnricher(Vec::new())),
            host_key_store: Arc::new(InMemoryHostKeyStore::new()),
            sink: sink.clone(),
        };
        let pipeline = ScanPipeline::new(ports, test_config());
        let correlation_id = CorrelationId::from("corr-cancel-late");

        pipeline
            .process_one(test_request(correlation_id.as_str()))
            .await;

        assert!(
            !pipeline.cancellations.cancel(&correlation_id),
            "una cancelación tardía sobre una tarea ya finalizada debe ser un no-op"
        );

        // El desenlace sigue siendo el fallo normal de la etapa SSH -la
        // cancelación llegó después de terminar, así que no debe alterar nada.
        let published = sink.published();
        match &published[1] {
            ScanOutcome::Failed { reason, .. } => {
                assert_eq!(reason, &SshError::AuthFailed.to_string())
            }
            other => panic!("se esperaba Failed, se obtuvo {other:?}"),
        }
    }

    #[tokio::test]
    async fn run_consumes_both_sources_and_a_cancellation_for_an_unknown_id_is_harmless() {
        let sink = Arc::new(InMemoryScanResultSink::new());
        let ports = ServicePorts {
            executor: Arc::new(FailingExecutor),
            scanner: Arc::new(UnusedScanner),
            repository: Arc::new(UnusedRepository),
            enricher: Arc::new(StubEnricher(Vec::new())),
            host_key_store: Arc::new(InMemoryHostKeyStore::new()),
            sink: sink.clone(),
        };
        let pipeline = ScanPipeline::new(ports, test_config());

        let source = Arc::new(InMemoryScanRequestSource::from_requests([test_request(
            "corr-run-with-cancellations",
        )]));
        let cancellations: Arc<dyn ScanCancellationSource> =
            Arc::new(InMemoryScanCancellationSource::from_cancellations([
                ScanCancellation {
                    correlation_id: CorrelationId::from("corr-unknown"),
                    requested_by: "analyst@example.test".to_owned(),
                },
            ]));

        pipeline.run(source, cancellations).await;

        let published = sink.published();
        assert_eq!(
            published.len(),
            2,
            "la solicitud se procesó igual (started + terminal) y la cancelación \
             desconocida no afectó nada"
        );
        assert_eq!(
            published[1].correlation_id().as_str(),
            "corr-run-with-cancellations"
        );
    }
}

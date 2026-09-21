//! Adaptador real de mensajería: cliente `lapin` sobre AMQPS contra el Broker
//! RabbitMQ (feature `broker_adapter`).
//!
//! Implementa los tres puertos hexagonales de mensajería que hasta ahora solo
//! tenían stubs en memoria (feature `broker_consumer`/`broker_publisher`):
//! [`RabbitMqScanRequestSource`] ([`ScanRequestSource`]),
//! [`RabbitMqScanCancellationSource`] ([`ScanCancellationSource`]) y
//! [`RabbitMqScanResultSink`] ([`ScanResultSink`]). El resto del servicio
//! (`pipeline`, `wiring`) sigue sin conocer que la tecnología es RabbitMQ: solo
//! depende de esos traits, definidos en [`crate::messaging::consumer`]/
//! [`crate::messaging::publisher`].
//!
//! # Patrón seguido: `gateway::broker`, no uno nuevo
//!
//! El repo hermano `gateway` ya resolvió `lapin` 2.x + AMQPS + TLS de
//! producción vs. laboratorio + `testcontainers` para este mismo runtime
//! `tokio` (`gateway/src/broker.rs`,
//! `gateway/progress/explore_lapin_publish.md`,
//! `gateway/progress/explore_lapin_testcontainers.md`). Este módulo reutiliza
//! ese patrón tal cual, no uno reinventado:
//!
//! - **`ConnectionProperties` con `tokio-executor-trait`/`tokio-reactor-trait`**:
//!   para que `lapin` use el runtime `tokio` ya en uso por el resto del
//!   servicio (`russh`, `mongodb`), en vez de su propio
//!   `async-global-executor` por defecto.
//! - **TLS vía `OwnedTLSConfig`**: `OwnedTLSConfig::default()` (almacén de
//!   certificados nativo del proceso) en producción
//!   ([`crate::wiring::service_ports_from_config`]); `OwnedTLSConfig` con
//!   `cert_chain: Some(ca_pem)` (CA de laboratorio) en los tests de
//!   integración (`tests/broker_adapter.rs`).
//! - **`confirm_select` en el canal del publicador** (no en los de consumo,
//!   irrelevante ahí): [`RabbitMqScanResultSink`] espera el ack/nack real del
//!   Broker antes de reportar éxito, igual que
//!   `gateway::broker::BrokerPublisher`.
//! - **No se declara topología**: el usuario RabbitMQ `ms-nmap` (definido en
//!   `broker/rabbitmq/definitions.json`) tiene `configure: "^$"` — ninguna
//!   función de este módulo llama a `exchange_declare`/`queue_declare`/
//!   `queue_bind`, solo a `basic_consume`/`basic_publish` (ver
//!   `docs/architecture.md`, §"Qué NO hacer").
//!
//! # `ack`/`nack` (criterios de aceptación de `broker_adapter`)
//!
//! [`RabbitMqScanRequestSource::next_request`] y
//! [`RabbitMqScanCancellationSource::next_cancellation`] comparten el mismo
//! contrato: por cada entrega (`Delivery`),
//!
//! 1. si el cuerpo no parsea (`parse_scan_request`/`parse_scan_cancellation`,
//!    ya existentes en [`crate::messaging::consumer`]) -> `nack(requeue:
//!    false)` (dead-letter inmediato hacia la `.dlq` ya aprovisionada por
//!    `broker/rabbitmq/definitions.json`, con `x-delivery-limit: 3`) y se
//!    sigue esperando la próxima entrega: **no** es fatal para el consumo, ni
//!    se propaga como `Err` al llamador (mismo criterio que ya aplica
//!    [`crate::pipeline::ScanPipeline::run`] a un `ConsumeError` de
//!    esquema/parseo, ver `next_valid_request`/`next_valid_cancellation`);
//! 2. si parsea, se hace `ack` **antes** de devolver `Ok(Some(_))`/`Ok(Some(_))`
//!    al llamador y **nunca** antes. Esto cumple "ack solo tras encolarlo con
//!    éxito en el pipeline": [`crate::pipeline::ScanPipeline::run`] no tiene
//!    ningún punto de espera async entre recibir el valor de
//!    `next_request()`/`next_cancellation()` y pasarlo a `tokio::spawn`/al
//!    registro de cancelación (ver `src/pipeline.rs`) — devolver `Ok(Some(_))`
//!    desde aquí es, en la práctica, el mismo instante en que la solicitud
//!    queda encolada en el pipeline, así que no hace falta un canal
//!    intermedio adicional para separar ambos momentos.
//!
//! Un fallo de transporte al leer el stream de entregas, o al hacer `ack`, se
//! traduce a `Err(ConsumeError::Transport(_))`: el llamador decide si detiene
//! el consumo (ver `next_valid_request`/`next_valid_cancellation`), nunca
//! `panic!`.
//!
//! # Seguridad
//!
//! Ninguna credencial (contraseña AMQPS) aparece en los mensajes de
//! [`BrokerError`], [`ConsumeError`] ni [`PublishError`]: todos envuelven el
//! `Display`/`to_string()` de `lapin::Error`, que nunca incluye la URI de
//! conexión completa (solo códigos/razones de protocolo AMQP e IO). La
//! contraseña en sí viaja como [`secrecy::SecretString`]
//! ([`crate::config::Config::broker_credential`]) y solo se usa una vez, al
//! construir la URI de conexión dentro de `connect_channel` (función privada
//! de este módulo) — nunca se formatea con `Debug`/`tracing` en este módulo.

use futures_util::StreamExt;
use lapin::options::{
    BasicAckOptions, BasicConsumeOptions, BasicNackOptions, BasicPublishOptions,
    ConfirmSelectOptions,
};
use lapin::protocol::BasicProperties;
use lapin::tcp::OwnedTLSConfig;
use lapin::types::FieldTable;
use lapin::{Channel, Connection, ConnectionProperties, Consumer};
use secrecy::{ExposeSecret, SecretString};
use tokio::sync::Mutex as AsyncMutex;

use crate::domain::ScanCancellation;
use crate::messaging::consumer::{
    log_cancellation_received, log_request_received, parse_scan_cancellation, parse_scan_request,
    ConsumeError, IncomingScanRequest, ScanCancellationSource, ScanRequestSource,
};
use crate::messaging::publisher::{
    encode_outcome, log_outcome_published, PublishError, ScanOutcome, ScanResultSink,
};

/// Exchange donde el Gateway publica cada [`crate::domain::ScanRequest`]
/// (topic, ya declarado por `broker/rabbitmq/definitions.json` — no se
/// redeclara aquí).
pub const EXCHANGE_SCAN_REQUESTS: &str = "scan.requests";

/// Routing key con la que el Gateway publica cada
/// [`crate::domain::ScanRequest`].
pub const ROUTING_KEY_SCAN_REQUEST: &str = "scan.request";

/// Cola de la que `ms-nmap` consume cada [`crate::domain::ScanRequest`]
/// (bindeada a [`ROUTING_KEY_SCAN_REQUEST`] en `broker/rabbitmq/definitions.json`).
pub const QUEUE_SCAN_REQUESTS: &str = "ms-nmap.scan-requests";

/// Exchange donde el Gateway publica cada
/// [`crate::domain::ScanCancellation`] (topic, ya declarado por
/// `broker/rabbitmq/definitions.json` — no se redeclara aquí).
pub const EXCHANGE_SCAN_CANCELLATIONS: &str = "scan.cancellations";

/// Routing key con la que el Gateway publica cada
/// [`crate::domain::ScanCancellation`].
pub const ROUTING_KEY_SCAN_CANCELLATION: &str = "scan.cancellation";

/// Cola de la que `ms-nmap` consume cada [`crate::domain::ScanCancellation`]
/// (bindeada a [`ROUTING_KEY_SCAN_CANCELLATION`] en
/// `broker/rabbitmq/definitions.json`).
pub const QUEUE_SCAN_CANCELLATIONS: &str = "ms-nmap.scan-cancellations";

/// Exchange donde `ms-nmap` publica cada [`ScanOutcome`] (topic, ya declarado
/// por `broker/rabbitmq/definitions.json` — no se redeclara aquí).
pub const EXCHANGE_SCAN_OUTCOMES: &str = "scan.outcomes";

/// Routing key de [`ScanOutcome::Started`].
pub const ROUTING_KEY_SCAN_OUTCOME_STARTED: &str = "scan.outcome.started";

/// Routing key de [`ScanOutcome::Completed`].
pub const ROUTING_KEY_SCAN_OUTCOME_COMPLETED: &str = "scan.outcome.completed";

/// Routing key de [`ScanOutcome::Failed`].
pub const ROUTING_KEY_SCAN_OUTCOME_FAILED: &str = "scan.outcome.failed";

/// Usuario RabbitMQ con el que este servicio se autentica contra el Broker.
///
/// Fijado por la topología del Broker (`broker/rabbitmq/definitions.json`,
/// único usuario con permiso `read` sobre [`QUEUE_SCAN_REQUESTS`]/
/// [`QUEUE_SCAN_CANCELLATIONS`] y `write` sobre [`EXCHANGE_SCAN_OUTCOMES`]) —
/// igual que los nombres de exchange/cola de este módulo, es parte del
/// contrato de mensajería, no un dato de despliegue ni una credencial (la
/// contraseña sí lo es, y viaja por separado en
/// [`crate::config::Config::broker_credential`], nunca hardcodeada).
const BROKER_USER: &str = "ms-nmap";

/// Identificador (`consumer_tag`) con el que este servicio se registra como
/// consumidor de [`QUEUE_SCAN_REQUESTS`].
const CONSUMER_TAG_SCAN_REQUESTS: &str = "ms-nmap-scan-requests";

/// Identificador (`consumer_tag`) con el que este servicio se registra como
/// consumidor de [`QUEUE_SCAN_CANCELLATIONS`].
const CONSUMER_TAG_SCAN_CANCELLATIONS: &str = "ms-nmap-scan-cancellations";

/// Errores al establecer o preparar la conexión AMQPS con el Broker
/// (fase de arranque, en [`crate::wiring::service_ports_from_config`] o en
/// los tests de integración).
///
/// Distinto de [`ConsumeError`]/[`PublishError`], que gobiernan el flujo en
/// caliente de cada puerto una vez la conexión ya está establecida. Ninguna
/// variante incluye la credencial AMQPS (ver la nota de seguridad del
/// módulo).
#[derive(Debug, thiserror::Error)]
pub enum BrokerError {
    /// No se pudo conectar (o crear canal) contra el Broker por AMQPS.
    #[error("no se pudo conectar al Broker (AMQPS)")]
    ConnectionFailed(#[source] lapin::Error),

    /// No se pudo iniciar el consumo de la cola indicada (`basic_consume`), o
    /// activar `confirm_select` en el canal del publicador.
    #[error("no se pudo preparar el canal AMQPS para '{context}'")]
    SetupFailed {
        /// Qué se intentaba preparar (nombre de cola, o "confirms del
        /// publicador").
        context: &'static str,
        /// Error original de `lapin`.
        #[source]
        source: lapin::Error,
    },
}

/// Conecta contra `amqps_url` (URI AMQPS completa, con usuario y contraseña
/// ya incluidos) y crea un canal nuevo sobre esa conexión — lógica de
/// conexión compartida entre los tres adaptadores de este módulo (la única
/// diferencia entre ellos es qué hacen con el canal después: `basic_consume`
/// o `confirm_select` + `basic_publish`).
async fn connect_channel(
    amqps_url: &str,
    tls_config: OwnedTLSConfig,
) -> Result<(Connection, Channel), BrokerError> {
    let options = ConnectionProperties::default()
        .with_executor(tokio_executor_trait::Tokio::current())
        .with_reactor(tokio_reactor_trait::Tokio);

    let connection = Connection::connect_with_config(amqps_url, options, tls_config)
        .await
        .map_err(BrokerError::ConnectionFailed)?;
    let channel = connection
        .create_channel()
        .await
        .map_err(BrokerError::ConnectionFailed)?;

    Ok((connection, channel))
}

/// Construye la URI AMQPS completa que espera `lapin::Connection::connect*`
/// a partir de las piezas ya validadas por [`crate::config::Config`]:
/// `endpoint` (`esquema://host:puerto`, sin userinfo ni vhost — ver
/// [`crate::config::Config::broker_endpoint`]), `user` ([`BROKER_USER`]),
/// `password` y `vhost`.
///
/// Siempre construye un esquema `amqps://`, sin importar el esquema recibido
/// en `endpoint` (que se descarta): este servicio nunca habla AMQP en claro
/// con el Broker, ni en producción ni en los tests de integración (que usan
/// el puerto AMQPS del contenedor de prueba con la CA de laboratorio, ver
/// `tests/broker_adapter.rs`).
fn build_amqps_uri(endpoint: &str, user: &str, password: &str, vhost: &str) -> String {
    let host_and_port = strip_scheme(endpoint).trim_end_matches('/');
    format!("amqps://{user}:{password}@{host_and_port}/{vhost}")
}

/// Quita el prefijo `esquema://` de `endpoint`, si tiene uno.
fn strip_scheme(endpoint: &str) -> &str {
    match endpoint.split_once("://") {
        Some((_, rest)) => rest,
        None => endpoint,
    }
}

/// Adaptador real de [`ScanRequestSource`]: consume [`QUEUE_SCAN_REQUESTS`]
/// vía `lapin` sobre AMQPS.
pub struct RabbitMqScanRequestSource {
    // Se conserva únicamente para mantener viva la conexión mientras exista
    // el canal (el `Consumer` deja de recibir entregas si su `Connection` se
    // destruye).
    _connection: Connection,
    consumer: AsyncMutex<Consumer>,
}

impl RabbitMqScanRequestSource {
    /// Conecta contra `amqps_url`/`vhost` con el almacén de certificados
    /// nativo del proceso (producción) y empieza a consumir
    /// [`QUEUE_SCAN_REQUESTS`].
    pub async fn connect(
        endpoint: &str,
        credential: &SecretString,
        vhost: &str,
    ) -> Result<Self, BrokerError> {
        Self::connect_with_tls_config(endpoint, credential, vhost, OwnedTLSConfig::default()).await
    }

    /// Igual que [`Self::connect`], pero confiando además en la CA de
    /// laboratorio (`ca_pem`) indicada — para los tests de integración contra
    /// un Broker de prueba con certificado autofirmado.
    pub async fn connect_with_ca_pem(
        endpoint: &str,
        credential: &SecretString,
        vhost: &str,
        ca_pem: String,
    ) -> Result<Self, BrokerError> {
        Self::connect_with_tls_config(
            endpoint,
            credential,
            vhost,
            OwnedTLSConfig {
                identity: None,
                cert_chain: Some(ca_pem),
            },
        )
        .await
    }

    async fn connect_with_tls_config(
        endpoint: &str,
        credential: &SecretString,
        vhost: &str,
        tls_config: OwnedTLSConfig,
    ) -> Result<Self, BrokerError> {
        let uri = build_amqps_uri(endpoint, BROKER_USER, credential.expose_secret(), vhost);
        let (connection, channel) = connect_channel(&uri, tls_config).await?;

        let consumer = channel
            .basic_consume(
                QUEUE_SCAN_REQUESTS,
                CONSUMER_TAG_SCAN_REQUESTS,
                BasicConsumeOptions::default(),
                FieldTable::default(),
            )
            .await
            .map_err(|source| BrokerError::SetupFailed {
                context: QUEUE_SCAN_REQUESTS,
                source,
            })?;

        Ok(Self {
            _connection: connection,
            consumer: AsyncMutex::new(consumer),
        })
    }
}

#[async_trait::async_trait]
impl ScanRequestSource for RabbitMqScanRequestSource {
    async fn next_request(&self) -> Result<Option<IncomingScanRequest>, ConsumeError> {
        let mut consumer = self.consumer.lock().await;
        loop {
            let delivery = match consumer.next().await {
                None => return Ok(None),
                Some(Err(err)) => return Err(ConsumeError::Transport(err.to_string())),
                Some(Ok(delivery)) => delivery,
            };

            match parse_scan_request(&delivery.data) {
                Ok(request) => {
                    delivery
                        .ack(BasicAckOptions::default())
                        .await
                        .map_err(|err| ConsumeError::Transport(err.to_string()))?;
                    log_request_received(&request);
                    return Ok(Some(IncomingScanRequest::new(request)));
                }
                Err(parse_err) => {
                    if let Err(nack_err) = delivery
                        .nack(BasicNackOptions {
                            multiple: false,
                            requeue: false,
                        })
                        .await
                    {
                        tracing::error!(
                            error = %nack_err,
                            "no se pudo descartar (nack) un ScanRequest malformado"
                        );
                    }
                    tracing::warn!(
                        error = %parse_err,
                        routing_key = %delivery.routing_key.as_str(),
                        payload_len = delivery.data.len(),
                        "ScanRequest malformado descartado (dead-lettered)"
                    );
                }
            }
        }
    }
}

/// Adaptador real de [`ScanCancellationSource`]: consume
/// [`QUEUE_SCAN_CANCELLATIONS`] vía `lapin` sobre AMQPS.
pub struct RabbitMqScanCancellationSource {
    // Igual que en `RabbitMqScanRequestSource`: se conserva únicamente para
    // mantener viva la conexión mientras exista el canal.
    _connection: Connection,
    consumer: AsyncMutex<Consumer>,
}

impl RabbitMqScanCancellationSource {
    /// Conecta contra `amqps_url`/`vhost` con el almacén de certificados
    /// nativo del proceso (producción) y empieza a consumir
    /// [`QUEUE_SCAN_CANCELLATIONS`].
    pub async fn connect(
        endpoint: &str,
        credential: &SecretString,
        vhost: &str,
    ) -> Result<Self, BrokerError> {
        Self::connect_with_tls_config(endpoint, credential, vhost, OwnedTLSConfig::default()).await
    }

    /// Igual que [`Self::connect`], pero confiando además en la CA de
    /// laboratorio (`ca_pem`) indicada — para los tests de integración.
    pub async fn connect_with_ca_pem(
        endpoint: &str,
        credential: &SecretString,
        vhost: &str,
        ca_pem: String,
    ) -> Result<Self, BrokerError> {
        Self::connect_with_tls_config(
            endpoint,
            credential,
            vhost,
            OwnedTLSConfig {
                identity: None,
                cert_chain: Some(ca_pem),
            },
        )
        .await
    }

    async fn connect_with_tls_config(
        endpoint: &str,
        credential: &SecretString,
        vhost: &str,
        tls_config: OwnedTLSConfig,
    ) -> Result<Self, BrokerError> {
        let uri = build_amqps_uri(endpoint, BROKER_USER, credential.expose_secret(), vhost);
        let (connection, channel) = connect_channel(&uri, tls_config).await?;

        let consumer = channel
            .basic_consume(
                QUEUE_SCAN_CANCELLATIONS,
                CONSUMER_TAG_SCAN_CANCELLATIONS,
                BasicConsumeOptions::default(),
                FieldTable::default(),
            )
            .await
            .map_err(|source| BrokerError::SetupFailed {
                context: QUEUE_SCAN_CANCELLATIONS,
                source,
            })?;

        Ok(Self {
            _connection: connection,
            consumer: AsyncMutex::new(consumer),
        })
    }
}

#[async_trait::async_trait]
impl ScanCancellationSource for RabbitMqScanCancellationSource {
    async fn next_cancellation(&self) -> Result<Option<ScanCancellation>, ConsumeError> {
        let mut consumer = self.consumer.lock().await;
        loop {
            let delivery = match consumer.next().await {
                None => return Ok(None),
                Some(Err(err)) => return Err(ConsumeError::Transport(err.to_string())),
                Some(Ok(delivery)) => delivery,
            };

            match parse_scan_cancellation(&delivery.data) {
                Ok(cancellation) => {
                    delivery
                        .ack(BasicAckOptions::default())
                        .await
                        .map_err(|err| ConsumeError::Transport(err.to_string()))?;
                    log_cancellation_received(&cancellation);
                    return Ok(Some(cancellation));
                }
                Err(parse_err) => {
                    if let Err(nack_err) = delivery
                        .nack(BasicNackOptions {
                            multiple: false,
                            requeue: false,
                        })
                        .await
                    {
                        tracing::error!(
                            error = %nack_err,
                            "no se pudo descartar (nack) una ScanCancellation malformada"
                        );
                    }
                    tracing::warn!(
                        error = %parse_err,
                        routing_key = %delivery.routing_key.as_str(),
                        payload_len = delivery.data.len(),
                        "ScanCancellation malformada descartada (dead-lettered)"
                    );
                }
            }
        }
    }
}

/// Adaptador real de [`ScanResultSink`]: publica cada [`ScanOutcome`] en
/// [`EXCHANGE_SCAN_OUTCOMES`] vía `lapin` sobre AMQPS, con `confirm_select`
/// activado (ver la nota de diseño al inicio del módulo).
pub struct RabbitMqScanResultSink {
    // Igual que en los otros dos adaptadores: se conserva únicamente para
    // mantener viva la conexión mientras exista el canal.
    _connection: Connection,
    channel: Channel,
}

impl RabbitMqScanResultSink {
    /// Conecta contra `amqps_url`/`vhost` con el almacén de certificados
    /// nativo del proceso (producción) y activa `confirm_select` en el
    /// canal.
    pub async fn connect(
        endpoint: &str,
        credential: &SecretString,
        vhost: &str,
    ) -> Result<Self, BrokerError> {
        Self::connect_with_tls_config(endpoint, credential, vhost, OwnedTLSConfig::default()).await
    }

    /// Igual que [`Self::connect`], pero confiando además en la CA de
    /// laboratorio (`ca_pem`) indicada — para los tests de integración.
    pub async fn connect_with_ca_pem(
        endpoint: &str,
        credential: &SecretString,
        vhost: &str,
        ca_pem: String,
    ) -> Result<Self, BrokerError> {
        Self::connect_with_tls_config(
            endpoint,
            credential,
            vhost,
            OwnedTLSConfig {
                identity: None,
                cert_chain: Some(ca_pem),
            },
        )
        .await
    }

    async fn connect_with_tls_config(
        endpoint: &str,
        credential: &SecretString,
        vhost: &str,
        tls_config: OwnedTLSConfig,
    ) -> Result<Self, BrokerError> {
        let uri = build_amqps_uri(endpoint, BROKER_USER, credential.expose_secret(), vhost);
        let (connection, channel) = connect_channel(&uri, tls_config).await?;

        channel
            .confirm_select(ConfirmSelectOptions::default())
            .await
            .map_err(|source| BrokerError::SetupFailed {
                context: "confirms del publicador",
                source,
            })?;

        Ok(Self {
            _connection: connection,
            channel,
        })
    }
}

/// Devuelve la routing key de [`EXCHANGE_SCAN_OUTCOMES`] que corresponde al
/// `status` de `outcome`. Exhaustivo sobre las variantes de [`ScanOutcome`]
/// (sin rama comodín): si se añadiera una variante nueva, este `match` deja
/// de compilar en vez de enrutarla silenciosamente mal.
fn routing_key_for(outcome: &ScanOutcome) -> &'static str {
    match outcome {
        ScanOutcome::Started { .. } => ROUTING_KEY_SCAN_OUTCOME_STARTED,
        ScanOutcome::Completed { .. } => ROUTING_KEY_SCAN_OUTCOME_COMPLETED,
        ScanOutcome::Failed { .. } => ROUTING_KEY_SCAN_OUTCOME_FAILED,
    }
}

#[async_trait::async_trait]
impl ScanResultSink for RabbitMqScanResultSink {
    async fn publish(&self, outcome: &ScanOutcome) -> Result<(), PublishError> {
        let routing_key = routing_key_for(outcome);
        let payload = encode_outcome(outcome)?;

        let publisher_confirm = self
            .channel
            .basic_publish(
                EXCHANGE_SCAN_OUTCOMES,
                routing_key,
                BasicPublishOptions::default(),
                &payload,
                BasicProperties::default().with_content_type("application/json".into()),
            )
            .await
            .map_err(|err| PublishError::Transport(err.to_string()))?;

        let confirmation = publisher_confirm
            .await
            .map_err(|err| PublishError::Transport(err.to_string()))?;

        if !confirmation.is_ack() {
            return Err(PublishError::NotAcknowledged {
                exchange: EXCHANGE_SCAN_OUTCOMES,
            });
        }

        log_outcome_published(outcome);
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn build_amqps_uri_combines_stripped_endpoint_user_password_and_vhost() {
        assert_eq!(
            build_amqps_uri(
                "amqp://broker.lab:5672",
                "ms-nmap",
                "s3cr3t",
                "security-app"
            ),
            "amqps://ms-nmap:s3cr3t@broker.lab:5672/security-app"
        );
    }

    #[test]
    fn build_amqps_uri_always_uses_amqps_scheme_even_if_endpoint_already_has_one() {
        assert_eq!(
            build_amqps_uri(
                "amqps://broker.lab:5671",
                "ms-nmap",
                "s3cr3t",
                "security-app"
            ),
            "amqps://ms-nmap:s3cr3t@broker.lab:5671/security-app"
        );
    }

    #[test]
    fn build_amqps_uri_tolerates_endpoint_without_scheme() {
        assert_eq!(
            build_amqps_uri("broker.lab:5671", "ms-nmap", "s3cr3t", "security-app"),
            "amqps://ms-nmap:s3cr3t@broker.lab:5671/security-app"
        );
    }

    #[test]
    fn build_amqps_uri_tolerates_trailing_slash_in_endpoint() {
        assert_eq!(
            build_amqps_uri(
                "amqps://broker.lab:5671/",
                "ms-nmap",
                "s3cr3t",
                "security-app"
            ),
            "amqps://ms-nmap:s3cr3t@broker.lab:5671/security-app"
        );
    }

    #[test]
    fn build_amqps_uri_never_leaks_only_the_endpoint_without_the_password() {
        // No es un test de fuga de credenciales (la URI SIEMPRE lleva la
        // contraseña, ese es su propósito) sino una comprobación de forma: la
        // contraseña aparece exactamente una vez, en la posición de userinfo,
        // nunca duplicada ni en el vhost.
        let uri = build_amqps_uri(
            "amqps://broker.lab:5671",
            "ms-nmap",
            "s3cr3t",
            "security-app",
        );
        assert_eq!(uri.matches("s3cr3t").count(), 1);
    }

    #[test]
    fn routing_key_for_maps_each_status_to_its_exact_contract_routing_key() {
        use crate::domain::{CorrelationId, ScanResult};
        use time::macros::datetime;

        let result = ScanResult {
            host: "192.0.2.10".parse().expect("IP de prueba válida"),
            ports: Vec::new(),
            vulnerabilities: Vec::new(),
            scanned_at: datetime!(2026-08-27 12:30:00 UTC),
        };

        assert_eq!(
            routing_key_for(&ScanOutcome::started(CorrelationId::from("c1"))),
            ROUTING_KEY_SCAN_OUTCOME_STARTED
        );
        assert_eq!(
            routing_key_for(&ScanOutcome::completed(CorrelationId::from("c2"), result)),
            ROUTING_KEY_SCAN_OUTCOME_COMPLETED
        );
        assert_eq!(
            routing_key_for(&ScanOutcome::failed(CorrelationId::from("c3"), "x")),
            ROUTING_KEY_SCAN_OUTCOME_FAILED
        );
    }
}

//! Consumo de solicitudes de escaneo desde el Broker y su conversión a
//! [`ScanRequest`].
//!
//! La tecnología concreta de cola de mensajes (RabbitMQ / NATS / Kafka / Redis
//! Streams / ...) todavía no está decidida (ver `docs/architecture.md`,
//! §"Decisiones de diseño"). Por eso el resto del servicio depende sólo del
//! trait [`ScanRequestSource`] y nunca de un cliente de broker concreto. Este
//! módulo aporta además:
//!
//! - [`parse_scan_request`]: deserializa el cuerpo de un mensaje a
//!   [`ScanRequest`], rechazando payloads malformados o incompletos con un
//!   [`ConsumeError`] tipado en vez de entrar en pánico.
//! - [`InMemoryScanRequestSource`]: implementación de [`ScanRequestSource`] para
//!   desarrollo, tests y el pipeline end-to-end (feature `scan_pipeline_wiring`)
//!   mientras el broker real no esté decidido.
//! - [`log_request_received`]: traza de recepción identificada por
//!   `correlation_id`.
//!
//! # Seguridad
//!
//! `ScanRequest` transporta `ssh_credentials_ref`. Ni el logging de este módulo
//! ni los mensajes de [`ConsumeError`] incluyen el cuerpo crudo del mensaje ni
//! el valor de la credencial (ver `docs/security-scope.md`).

use std::collections::VecDeque;
use std::sync::Mutex;

use crate::domain::ScanRequest;

/// Motivo por el que no se pudo obtener o interpretar una solicitud del Broker.
///
/// Cada variante es distinguible para que el llamador reaccione distinto:
/// descartar un mensaje envenenado (nack sin requeue) frente a reintentar ante
/// un corte de transporte. Ninguna hace que el proceso muera.
///
/// # Seguridad
///
/// Ningún mensaje de error incluye el cuerpo crudo del mensaje: sólo la
/// descripción estructural que aporta `serde` (posición del fallo de sintaxis,
/// nombre del campo ausente). Además [`parse_scan_request`] borra el valor de
/// `ssh_credentials_ref` de la descripción de `serde` por si el payload lo
/// codificó con un tipo inesperado (ver `docs/security-scope.md`).
#[derive(Debug, thiserror::Error)]
pub enum ConsumeError {
    /// El cuerpo del mensaje no es JSON sintácticamente válido.
    #[error("el mensaje del Broker no es JSON válido: {0}")]
    MalformedPayload(String),

    /// El cuerpo es JSON válido pero no encaja con el esquema de
    /// [`ScanRequest`]: falta un campo obligatorio o alguno tiene un tipo
    /// incorrecto.
    #[error("el mensaje del Broker no tiene la forma de un ScanRequest: {0}")]
    InvalidSchema(String),

    /// Fallo al comunicarse con el broker: conexión caída, suscripción
    /// cancelada, ack/nack rechazado, etc.
    #[error("fallo de transporte con el Broker: {0}")]
    Transport(String),
}

/// Deserializa el cuerpo crudo de un mensaje del Broker a un [`ScanRequest`].
///
/// Trabaja en dos etapas para poder distinguir un JSON roto de un JSON válido
/// con esquema incorrecto:
///
/// 1. `raw` -> [`serde_json::Value`]; si falla ->
///    [`ConsumeError::MalformedPayload`].
/// 2. `Value` -> [`ScanRequest`]; si falla (campo ausente o tipo incorrecto) ->
///    [`ConsumeError::InvalidSchema`].
///
/// Nunca hace `panic`/`unwrap`: cualquier entrada, incluida basura binaria,
/// produce un `Err` tipado.
///
/// # Seguridad
///
/// El mensaje de error nunca contiene el cuerpo crudo. En la etapa 2, si el
/// payload trajo `ssh_credentials_ref` con un tipo inesperado y `serde` incluyó
/// su valor en la descripción del fallo, ese valor se sustituye por
/// `[REDACTED]` antes de construir el error.
pub fn parse_scan_request(raw: &[u8]) -> Result<ScanRequest, ConsumeError> {
    let payload: serde_json::Value = serde_json::from_slice(raw)
        .map_err(|err| ConsumeError::MalformedPayload(err.to_string()))?;

    match serde_json::from_value::<ScanRequest>(payload.clone()) {
        Ok(request) => Ok(request),
        Err(err) => Err(ConsumeError::InvalidSchema(redact_credential(
            err.to_string(),
            &payload,
        ))),
    }
}

// Borra el valor de `ssh_credentials_ref` de un mensaje de error de `serde`.
// Necesario porque un payload podría codificar la credencial con un tipo
// inesperado (p. ej. un número) y `serde` la incluiría literalmente en su
// descripción "invalid type: ...". Ver `docs/security-scope.md`.
fn redact_credential(message: String, payload: &serde_json::Value) -> String {
    let Some(field) = payload.get("ssh_credentials_ref") else {
        return message;
    };
    let secret = match field {
        serde_json::Value::String(value) => value.clone(),
        other => other.to_string(),
    };
    if secret.is_empty() {
        return message;
    }
    message.replace(&secret, "[REDACTED]")
}

/// Registra en `tracing` (nivel `INFO`) la recepción de una solicitud,
/// identificándola por su `correlation_id`.
///
/// Los adaptadores concretos de [`ScanRequestSource`] deben llamarla al entregar
/// cada solicitud (la implementación de este módulo ya lo hace).
///
/// # Seguridad
///
/// Sólo emite campos no sensibles (`correlation_id`, `network_user`, IP objetivo
/// y `has_sudo`). Nunca registra `ssh_credentials_ref` ni el cuerpo crudo del
/// mensaje (ver `docs/security-scope.md`).
pub fn log_request_received(request: &ScanRequest) {
    tracing::info!(
        correlation_id = %request.correlation_id,
        network_user = %request.network_user,
        target_ip = %request.ip,
        has_sudo = request.has_sudo,
        "solicitud de escaneo recibida del Broker"
    );
}

/// Solicitud de escaneo recibida del Broker, lista para entrar al pipeline.
///
/// Hoy es un envoltorio fino sobre [`ScanRequest`]. Existe como punto de
/// extensión: cuando se decida la tecnología de broker y ésta necesite confirmar
/// (`ack`) o rechazar (`nack`) el mensaje, el token opaco requerido se añadirá
/// aquí sin cambiar la firma de [`ScanRequestSource::next_request`]. Por eso es
/// `#[non_exhaustive]`.
#[derive(Debug)]
#[non_exhaustive]
pub struct IncomingScanRequest {
    /// La solicitud ya deserializada y validada.
    pub request: ScanRequest,
}

impl IncomingScanRequest {
    /// Envuelve una solicitud ya validada.
    pub fn new(request: ScanRequest) -> Self {
        Self { request }
    }
}

/// Fuente de solicitudes de escaneo entrantes, independiente de la tecnología
/// concreta del broker.
///
/// Un adaptador concreto (RabbitMQ, NATS, ...) implementará este trait; el
/// pipeline (feature `scan_pipeline_wiring`) consume solicitudes a través de él
/// sin conocer el transporte. Es dyn-compatible: se comparte como
/// `Arc<dyn ScanRequestSource>`.
#[async_trait::async_trait]
pub trait ScanRequestSource: Send + Sync {
    /// Devuelve la siguiente solicitud disponible.
    ///
    /// - `Ok(Some(_))`: se recibió y validó una solicitud.
    /// - `Ok(None)`: la fuente se cerró de forma ordenada; no habrá más
    ///   solicitudes.
    /// - `Err(ConsumeError::MalformedPayload | InvalidSchema)`: llegó un mensaje
    ///   que no se pudo interpretar. El llamador debería descartarlo y seguir;
    ///   **no** es fatal.
    /// - `Err(ConsumeError::Transport)`: fallo de comunicación con el broker; el
    ///   llamador decide si reintenta.
    async fn next_request(&self) -> Result<Option<IncomingScanRequest>, ConsumeError>;
}

/// Implementación de [`ScanRequestSource`] respaldada por una cola en memoria.
///
/// Entrega los elementos en orden FIFO y, una vez agotada, devuelve `Ok(None)`
/// de forma indefinida. Se usa en los tests unitarios de este crate y como
/// fuente del pipeline end-to-end mientras la tecnología real de broker no esté
/// decidida.
///
/// - [`from_requests`](Self::from_requests): entrega solicitudes ya validadas.
/// - [`from_raw_messages`](Self::from_raw_messages): aplica [`parse_scan_request`]
///   a cada cuerpo al construir; un mensaje inválido se entrega como
///   `Err(ConsumeError)` en su turno y **no** interrumpe la entrega de los
///   siguientes (mismo contrato que un broker real entregando un mensaje
///   envenenado). Es decir: el parseo es responsabilidad de la fuente, no del
///   llamador.
pub struct InMemoryScanRequestSource {
    queue: Mutex<VecDeque<Result<ScanRequest, ConsumeError>>>,
}

impl InMemoryScanRequestSource {
    /// Crea una fuente que entregará las solicitudes dadas, ya validadas, en
    /// orden.
    pub fn from_requests<I>(requests: I) -> Self
    where
        I: IntoIterator<Item = ScanRequest>,
    {
        Self {
            queue: Mutex::new(requests.into_iter().map(Ok).collect()),
        }
    }

    /// Crea una fuente a partir de cuerpos de mensaje crudos. Cada uno se parsea
    /// con [`parse_scan_request`] al construir; el resultado (éxito o
    /// [`ConsumeError`]) se entrega en su turno por
    /// [`next_request`](ScanRequestSource::next_request).
    pub fn from_raw_messages<I>(messages: I) -> Self
    where
        I: IntoIterator,
        I::Item: AsRef<[u8]>,
    {
        Self {
            queue: Mutex::new(
                messages
                    .into_iter()
                    .map(|raw| parse_scan_request(raw.as_ref()))
                    .collect(),
            ),
        }
    }

    fn dequeue(&self) -> Option<Result<ScanRequest, ConsumeError>> {
        match self.queue.lock() {
            Ok(mut guard) => guard.pop_front(),
            Err(poisoned) => poisoned.into_inner().pop_front(),
        }
    }
}

#[async_trait::async_trait]
impl ScanRequestSource for InMemoryScanRequestSource {
    async fn next_request(&self) -> Result<Option<IncomingScanRequest>, ConsumeError> {
        match self.dequeue() {
            None => Ok(None),
            Some(Err(err)) => Err(err),
            Some(Ok(request)) => {
                log_request_received(&request);
                Ok(Some(IncomingScanRequest::new(request)))
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use std::io::Write;
    use std::net::IpAddr;
    use std::sync::{Arc, Mutex};

    use tracing_subscriber::fmt::MakeWriter;

    use super::*;
    use crate::domain::CorrelationId;

    const SECRET: &str = "TOP-SECRET-SSH-TOKEN-42";

    fn valid_message(secret: &str) -> Vec<u8> {
        format!(
            r#"{{
                "correlation_id": "corr-42",
                "ip": "203.0.113.7",
                "network_user": "netops",
                "ssh_credentials_ref": "{secret}",
                "has_sudo": true,
                "requested_by": "analyst@example.test"
            }}"#
        )
        .into_bytes()
    }

    #[test]
    fn valid_message_parses_into_scan_request() {
        let request = parse_scan_request(&valid_message(SECRET)).expect("debe parsear");

        assert_eq!(request.correlation_id.as_str(), "corr-42");
        assert_eq!(request.ip, "203.0.113.7".parse::<IpAddr>().unwrap());
        assert!(request.has_sudo);
        assert_eq!(request.network_user, "netops");
        assert_eq!(request.requested_by, "analyst@example.test");
        assert_eq!(request.ssh_credentials_ref.expose(), SECRET);
    }

    #[test]
    fn syntactically_broken_json_is_malformed_payload() {
        let err = parse_scan_request(br#"{ "correlation_id": "corr-1", "ip": "#)
            .expect_err("JSON roto debe fallar");

        assert!(matches!(err, ConsumeError::MalformedPayload(_)));
    }

    #[test]
    fn non_utf8_garbage_is_rejected_without_panic() {
        let err = parse_scan_request(&[0xff, 0xfe, 0x00, 0x42]).expect_err("basura debe fallar");

        assert!(matches!(err, ConsumeError::MalformedPayload(_)));
    }

    #[test]
    fn missing_required_field_is_invalid_schema() {
        let raw = br#"{
            "correlation_id": "corr-1",
            "network_user": "netops",
            "ssh_credentials_ref": "x",
            "has_sudo": false,
            "requested_by": "a@b.test"
        }"#;

        let err = parse_scan_request(raw).expect_err("falta 'ip', debe fallar");

        match err {
            ConsumeError::InvalidSchema(detail) => {
                assert!(detail.contains("ip"), "detalle: {detail}")
            }
            other => panic!("se esperaba InvalidSchema, se obtuvo {other:?}"),
        }
    }

    #[test]
    fn malformed_payload_error_does_not_echo_body() {
        let raw = format!(r#"{{ "ssh_credentials_ref": "{SECRET}" y roto"#).into_bytes();

        let err = parse_scan_request(&raw).expect_err("debe fallar");

        assert!(matches!(err, ConsumeError::MalformedPayload(_)));
        assert!(
            !err.to_string().contains(SECRET),
            "la credencial no debe filtrarse en el error: {err}"
        );
    }

    #[test]
    fn invalid_schema_error_redacts_credential_with_unexpected_type() {
        // La credencial llega como número: serde la incluiría en "invalid type".
        let raw = br#"{
            "correlation_id": "corr-1",
            "ip": "203.0.113.7",
            "network_user": "netops",
            "ssh_credentials_ref": 9081726354,
            "has_sudo": false,
            "requested_by": "a@b.test"
        }"#;

        let err = parse_scan_request(raw).expect_err("tipo incorrecto debe fallar");

        assert!(matches!(err, ConsumeError::InvalidSchema(_)));
        assert!(
            !err.to_string().contains("9081726354"),
            "la credencial no debe filtrarse en el error: {err}"
        );
    }

    #[tokio::test]
    async fn in_memory_source_delivers_in_order_then_none() {
        let first = parse_scan_request(&valid_message("s1")).unwrap();
        let mut second = parse_scan_request(&valid_message("s2")).unwrap();
        second.correlation_id = CorrelationId::from("corr-second");

        let source = InMemoryScanRequestSource::from_requests([first, second]);

        assert_eq!(
            source
                .next_request()
                .await
                .unwrap()
                .unwrap()
                .request
                .correlation_id
                .as_str(),
            "corr-42"
        );
        assert_eq!(
            source
                .next_request()
                .await
                .unwrap()
                .unwrap()
                .request
                .correlation_id
                .as_str(),
            "corr-second"
        );
        assert!(source.next_request().await.unwrap().is_none());
        assert!(source.next_request().await.unwrap().is_none());
    }

    #[tokio::test]
    async fn in_memory_source_from_raw_yields_error_then_continues() {
        let source = InMemoryScanRequestSource::from_raw_messages([
            valid_message("s1"),
            b"{ roto".to_vec(),
            valid_message("s2"),
        ]);

        assert!(source.next_request().await.unwrap().is_some());

        let err = source
            .next_request()
            .await
            .expect_err("el mensaje inválido se entrega como Err");
        assert!(matches!(err, ConsumeError::MalformedPayload(_)));

        assert!(
            source.next_request().await.unwrap().is_some(),
            "un mensaje envenenado no debe interrumpir la entrega"
        );
        assert!(source.next_request().await.unwrap().is_none());
    }

    #[derive(Clone, Default)]
    struct SharedBuffer(Arc<Mutex<Vec<u8>>>);

    impl SharedBuffer {
        fn contents(&self) -> String {
            String::from_utf8(self.0.lock().unwrap().clone()).unwrap()
        }
    }

    impl Write for SharedBuffer {
        fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
            self.0.lock().unwrap().extend_from_slice(buf);
            Ok(buf.len())
        }

        fn flush(&mut self) -> std::io::Result<()> {
            Ok(())
        }
    }

    impl<'a> MakeWriter<'a> for SharedBuffer {
        type Writer = SharedBuffer;

        fn make_writer(&'a self) -> Self::Writer {
            self.clone()
        }
    }

    #[test]
    fn log_request_received_records_correlation_id_without_credential() {
        let buffer = SharedBuffer::default();
        let subscriber = tracing_subscriber::fmt()
            .with_writer(buffer.clone())
            .with_ansi(false)
            .finish();

        let request = parse_scan_request(&valid_message(SECRET)).unwrap();
        tracing::subscriber::with_default(subscriber, || {
            log_request_received(&request);
        });

        let logged = buffer.contents();
        assert!(
            logged.contains("corr-42"),
            "la traza debe llevar el correlation_id: {logged}"
        );
        assert!(
            !logged.contains(SECRET),
            "la traza no debe contener la credencial: {logged}"
        );
        assert!(
            !logged.contains("REDACTED"),
            "no se debería ni siquiera intentar imprimir la credencial: {logged}"
        );
    }
}

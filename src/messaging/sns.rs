//! Adaptador SNS del puerto [`ScanResultSink`] (tarea MSG-NM-03).
//!
//! Publica cada [`ScanOutcome`] en el topic SNS `scan-outcomes`. El cuerpo es
//! exactamente [`encode_outcome`] (el mismo JSON que el adaptador AMQP) y la
//! routing key viaja como atributo de mensaje `String` llamado
//! [`ROUTING_KEY_ATTRIBUTE`] (`scan.outcome.started|completed|failed`), para
//! que las colas SQS suscritas (con `RawMessageDelivery=true`) filtren por él.
//!
//! Las credenciales salen de la cadena de proveedores por defecto de AWS (rol
//! de la tarea ECS); nunca hay claves estáticas en código.
//!
//! # Guarda de tamaño
//!
//! SNS limita el mensaje (cuerpo + atributos) a 256 KB y sólo
//! [`ScanOutcome::Completed`] puede crecer. Si su cuerpo supera
//! [`MAX_OUTCOME_BODY_BYTES`], se publica en su lugar un
//! [`ScanOutcome::Failed`] con el mismo `correlation_id` y el motivo fijo
//! [`RESULT_TOO_LARGE_REASON`] (decisión Q2 del broker), y se registra un
//! `warn` con el `correlation_id` y el tamaño en bytes únicamente.
//!
//! # Seguridad
//!
//! Los cuerpos nunca se loggean: un resultado de escaneo es información
//! sensible.

use aws_sdk_sns::error::DisplayErrorContext;
use aws_sdk_sns::types::MessageAttributeValue;
use aws_sdk_sns::Client;

use crate::messaging::publisher::{
    encode_outcome, log_outcome_published, routing_key_for, PublishError, ScanOutcome,
    ScanResultSink,
};

/// Nombre del atributo de mensaje SNS que transporta la routing key.
pub const ROUTING_KEY_ATTRIBUTE: &str = "routing_key";

/// Tamaño máximo (bytes) del cuerpo de un desenlace: 250 KiB. El límite de SNS
/// es 256 KiB para cuerpo + atributos, así que quedan ~6 KiB de margen para el
/// atributo `routing_key` y la sobrecarga del envelope.
pub const MAX_OUTCOME_BODY_BYTES: usize = 250 * 1024;

/// Motivo fijo (sin datos sensibles) del [`ScanOutcome::Failed`] que sustituye
/// a un [`ScanOutcome::Completed`] demasiado grande para SNS.
pub const RESULT_TOO_LARGE_REASON: &str =
    "el resultado del escaneo es demasiado grande para publicarse";

/// Devuelve el [`ScanOutcome::Failed`] que debe publicarse en lugar de
/// `outcome` si éste es un [`ScanOutcome::Completed`] cuyo cuerpo (`body_len`
/// bytes) supera `max_bytes`; `None` si se publica tal cual. `Started` y
/// `Failed` nunca se sustituyen. Función pura.
fn replacement_if_oversized(
    outcome: &ScanOutcome,
    body_len: usize,
    max_bytes: usize,
) -> Option<ScanOutcome> {
    match outcome {
        ScanOutcome::Completed { correlation_id, .. } if body_len > max_bytes => Some(
            ScanOutcome::failed(correlation_id.clone(), RESULT_TOO_LARGE_REASON),
        ),
        _ => None,
    }
}

/// Destino de desenlaces de escaneo sobre SNS.
#[derive(Debug, Clone)]
pub struct SnsScanResultSink {
    client: Client,
    topic_arn: String,
}

impl SnsScanResultSink {
    /// Construye el sink sobre un `client` ya configurado (los tests inyectan
    /// uno apuntando a LocalStack).
    pub fn from_client(client: Client, topic_arn: String) -> Self {
        Self { client, topic_arn }
    }

    /// Construye el sink con la cadena de credenciales por defecto de AWS, la
    /// `region` indicada y, opcionalmente, un `endpoint_url` (sólo LocalStack).
    pub async fn connect(region: &str, endpoint_url: Option<&str>, topic_arn: String) -> Self {
        let mut loader = aws_config::defaults(aws_config::BehaviorVersion::latest())
            .region(aws_config::Region::new(region.to_string()));
        if let Some(url) = endpoint_url {
            loader = loader.endpoint_url(url);
        }
        let shared = loader.load().await;
        Self::from_client(Client::new(&shared), topic_arn)
    }
}

/// Atributo `String` de SNS con la routing key `value`.
fn routing_key_attribute(value: &str) -> MessageAttributeValue {
    MessageAttributeValue::builder()
        .data_type("String")
        .string_value(value)
        .build()
        .expect("data_type está presente")
}

#[async_trait::async_trait]
impl ScanResultSink for SnsScanResultSink {
    async fn publish(&self, outcome: &ScanOutcome) -> Result<(), PublishError> {
        let mut effective = outcome;
        let mut body = encode_outcome(outcome)?;
        let replacement = replacement_if_oversized(outcome, body.len(), MAX_OUTCOME_BODY_BYTES);
        if let Some(failed) = &replacement {
            tracing::warn!(
                correlation_id = %outcome.correlation_id(),
                body_bytes = body.len(),
                max_bytes = MAX_OUTCOME_BODY_BYTES,
                "desenlace demasiado grande para SNS; se publica Failed en su lugar"
            );
            body = encode_outcome(failed)?;
            effective = failed;
        }
        let body =
            String::from_utf8(body).map_err(|err| PublishError::Serialization(err.to_string()))?;

        self.client
            .publish()
            .topic_arn(&self.topic_arn)
            .message(body)
            .message_attributes(
                ROUTING_KEY_ATTRIBUTE,
                routing_key_attribute(routing_key_for(effective)),
            )
            .send()
            .await
            .map_err(|source| {
                tracing::warn!(
                    correlation_id = %effective.correlation_id(),
                    detail = %DisplayErrorContext(&source),
                    "fallo al publicar el desenlace en SNS"
                );
                PublishError::Sns {
                    topic: self.topic_arn.clone(),
                    source: Box::new(source),
                }
            })?;

        log_outcome_published(effective);
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use std::error::Error as _;

    use time::macros::datetime;

    use super::*;
    use crate::domain::{CorrelationId, ScanResult};
    use crate::messaging::publisher::PublishError;

    fn empty_result() -> ScanResult {
        ScanResult {
            host: "192.0.2.10".parse().expect("IP de prueba válida"),
            ports: Vec::new(),
            vulnerabilities: Vec::new(),
            scanned_at: datetime!(2026-08-27 12:30:00 UTC),
        }
    }

    #[test]
    fn small_completed_outcome_passes_through_unchanged() {
        let outcome = ScanOutcome::completed(CorrelationId::from("c1"), empty_result());
        let body = encode_outcome(&outcome).expect("serializa");

        assert_eq!(
            replacement_if_oversized(&outcome, body.len(), MAX_OUTCOME_BODY_BYTES),
            None
        );
    }

    #[test]
    fn oversized_completed_becomes_failed_with_fixed_reason_and_same_correlation_id() {
        let outcome = ScanOutcome::completed(CorrelationId::from("c2"), empty_result());

        let replacement =
            replacement_if_oversized(&outcome, MAX_OUTCOME_BODY_BYTES + 1, MAX_OUTCOME_BODY_BYTES)
                .expect("un Completed por encima del umbral se reemplaza");

        assert_eq!(
            replacement,
            ScanOutcome::failed(CorrelationId::from("c2"), RESULT_TOO_LARGE_REASON)
        );
    }

    #[test]
    fn body_exactly_at_the_threshold_is_not_replaced() {
        let outcome = ScanOutcome::completed(CorrelationId::from("c3"), empty_result());

        assert_eq!(
            replacement_if_oversized(&outcome, MAX_OUTCOME_BODY_BYTES, MAX_OUTCOME_BODY_BYTES),
            None
        );
    }

    #[test]
    fn started_and_failed_are_never_replaced_even_if_huge() {
        let started = ScanOutcome::started(CorrelationId::from("c4"));
        let failed = ScanOutcome::failed(CorrelationId::from("c5"), "x");

        assert_eq!(replacement_if_oversized(&started, usize::MAX, 10), None);
        assert_eq!(replacement_if_oversized(&failed, usize::MAX, 10), None);
    }

    #[test]
    fn threshold_leaves_room_for_attributes_under_the_sns_limit() {
        const { assert!(MAX_OUTCOME_BODY_BYTES < 256 * 1024) };
        const { assert!(MAX_OUTCOME_BODY_BYTES >= 240 * 1024) };
    }

    #[test]
    fn the_too_large_reason_is_fixed_non_empty_and_in_spanish() {
        assert!(RESULT_TOO_LARGE_REASON.contains("demasiado grande"));
    }

    #[test]
    fn sns_publish_error_displays_topic_and_exposes_the_source_chain() {
        let source = std::io::Error::other("conexión rechazada");
        let err = PublishError::Sns {
            topic: "arn:aws:sns:us-east-1:000000000000:scan-outcomes".to_owned(),
            source: Box::new(source),
        };

        let shown = err.to_string();
        assert!(shown.contains("scan-outcomes"), "{shown}");
        let src = err.source().expect("la causa original se conserva");
        assert_eq!(src.to_string(), "conexión rechazada");
    }
}

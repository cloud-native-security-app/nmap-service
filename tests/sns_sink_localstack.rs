//! Tests de integración de `nmap_service::messaging::sns::SnsScanResultSink`
//! contra un LocalStack real (`localstack/localstack:4.4`) levantado con
//! `testcontainers`: sin mocks y sin cuenta AWS (MSG-NM-03).
//!
//! Se crea el topic `scan-outcomes` y una cola suscrita con
//! `RawMessageDelivery=true` y la política de filtro real del Gateway
//! (`routing_key` con prefijo `scan.outcome.`). El filtro de `ms-analisis`
//! queda diferido hasta que exista su cola (broker `sqs-sns-migration`, Q7).
//!
//! Requieren Docker y están marcados `#[ignore = "requiere Docker"]`:
//! `cargo test --test sns_sink_localstack -- --ignored` los ejecuta.

use std::time::Duration;

use serde_json::{json, Value};
use time::macros::datetime;

use nmap_service::domain::{CorrelationId, PortFinding, PortState, Protocol, ScanResult};
use nmap_service::messaging::publisher::{
    ScanOutcome, ScanResultSink, ROUTING_KEY_SCAN_OUTCOME_COMPLETED,
    ROUTING_KEY_SCAN_OUTCOME_FAILED, ROUTING_KEY_SCAN_OUTCOME_STARTED,
};
use nmap_service::messaging::sns::{
    SnsScanResultSink, MAX_OUTCOME_BODY_BYTES, RESULT_TOO_LARGE_REASON,
};

mod common;
use common::{LocalStack, REGION};

const TOPIC: &str = "scan-outcomes";
/// Política de filtro real del Gateway sobre `scan-outcomes`.
const GATEWAY_FILTER: &str = r#"{"routing_key":[{"prefix":"scan.outcome."}]}"#;

struct Fixture {
    ls: LocalStack,
    queue_url: String,
    sink: SnsScanResultSink,
}

impl Fixture {
    async fn start() -> Self {
        let ls = LocalStack::start().await;
        let (topic_arn, queue_url) = ls
            .topic_with_raw_queue(TOPIC, "gateway-scan-outcomes", Some(GATEWAY_FILTER))
            .await;
        let sink = SnsScanResultSink::from_client(ls.sns.clone(), topic_arn);
        Self {
            ls,
            queue_url,
            sink,
        }
    }

    async fn receive_one(&self) -> aws_sdk_sqs::types::Message {
        for _ in 0..10 {
            let out = self
                .ls
                .sqs
                .receive_message()
                .queue_url(&self.queue_url)
                .message_attribute_names("All")
                .wait_time_seconds(2)
                .max_number_of_messages(1)
                .send()
                .await
                .expect("recibir de la cola");
            if let Some(message) = out.messages.and_then(|m| m.into_iter().next()) {
                return message;
            }
            tokio::time::sleep(Duration::from_millis(200)).await;
        }
        panic!("no llegó ningún mensaje a la cola de salida");
    }
}

fn routing_key_of(message: &aws_sdk_sqs::types::Message) -> String {
    message
        .message_attributes()
        .and_then(|attrs| attrs.get("routing_key"))
        .and_then(|value| value.string_value())
        .expect("el mensaje debe traer el atributo routing_key")
        .to_string()
}

fn body_of(message: &aws_sdk_sqs::types::Message) -> Value {
    serde_json::from_str(message.body().expect("body")).expect("el cuerpo es JSON")
}

fn small_result() -> ScanResult {
    ScanResult {
        host: "192.0.2.10".parse().expect("IP de prueba válida"),
        ports: vec![PortFinding {
            port: 22,
            protocol: Protocol::Tcp,
            state: PortState::Open,
            service: Some("ssh".to_owned()),
            version: None,
            cpes: Vec::new(),
        }],
        vulnerabilities: Vec::new(),
        scanned_at: datetime!(2026-08-27 12:30:00 UTC),
    }
}

#[tokio::test]
#[ignore = "requiere Docker"]
async fn publishes_started_completed_and_failed_with_exact_body_and_routing_key() {
    let fx = Fixture::start().await;
    let completed = ScanOutcome::completed(CorrelationId::from("corr-2"), small_result());
    let expected_completed = serde_json::to_value(&completed).expect("JSON");

    for outcome in [
        ScanOutcome::started(CorrelationId::from("corr-1")),
        completed,
        ScanOutcome::failed(CorrelationId::from("corr-3"), "etapa SSH: tiempo agotado"),
    ] {
        fx.sink
            .publish(&outcome)
            .await
            .expect("publicar el desenlace");
    }

    // SNS -> SQS estándar no garantiza orden: se indexa por routing key.
    let mut by_key = std::collections::HashMap::new();
    for _ in 0..3 {
        let message = fx.receive_one().await;
        by_key.insert(routing_key_of(&message), body_of(&message));
        fx.ls
            .sqs
            .delete_message()
            .queue_url(&fx.queue_url)
            .receipt_handle(message.receipt_handle().expect("handle"))
            .send()
            .await
            .expect("borrar");
    }

    assert_eq!(
        by_key[ROUTING_KEY_SCAN_OUTCOME_STARTED],
        json!({"status": "started", "correlation_id": "corr-1"})
    );
    assert_eq!(
        by_key[ROUTING_KEY_SCAN_OUTCOME_COMPLETED],
        expected_completed
    );
    assert_eq!(
        by_key[ROUTING_KEY_SCAN_OUTCOME_FAILED],
        json!({
            "status": "failed",
            "correlation_id": "corr-3",
            "reason": "etapa SSH: tiempo agotado"
        })
    );
}

#[tokio::test]
#[ignore = "requiere Docker"]
async fn oversized_completed_arrives_as_failed_with_the_fixed_reason() {
    let fx = Fixture::start().await;
    let mut result = small_result();
    result.ports[0].version = Some("x".repeat(MAX_OUTCOME_BODY_BYTES + 1));
    let outcome = ScanOutcome::completed(CorrelationId::from("corr-big"), result);

    fx.sink
        .publish(&outcome)
        .await
        .expect("el sink degrada a Failed en vez de fallar");

    let message = fx.receive_one().await;
    assert_eq!(routing_key_of(&message), ROUTING_KEY_SCAN_OUTCOME_FAILED);
    assert_eq!(
        body_of(&message),
        json!({
            "status": "failed",
            "correlation_id": "corr-big",
            "reason": RESULT_TOO_LARGE_REASON
        })
    );
}

#[tokio::test]
#[ignore = "requiere Docker"]
async fn publishing_to_a_missing_topic_yields_a_sns_error() {
    let fx = Fixture::start().await;
    let sink = SnsScanResultSink::from_client(
        fx.ls.sns.clone(),
        format!("arn:aws:sns:{REGION}:000000000000:no-existe"),
    );

    let err = sink
        .publish(&ScanOutcome::started(CorrelationId::from("c")))
        .await
        .expect_err("el topic no existe");

    assert!(
        matches!(
            err,
            nmap_service::messaging::publisher::PublishError::Sns { .. }
        ),
        "{err:?}"
    );
}

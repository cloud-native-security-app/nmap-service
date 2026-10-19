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

use std::sync::Once;
use std::time::Duration;

use aws_sdk_sns::config::{BehaviorVersion, Credentials, Region};
use serde_json::{json, Value};
use testcontainers::core::{IntoContainerPort, WaitFor};
use testcontainers::runners::AsyncRunner;
use testcontainers::{ContainerAsync, GenericImage, ImageExt};
use time::macros::datetime;

use nmap_service::domain::{CorrelationId, PortFinding, PortState, Protocol, ScanResult};
use nmap_service::messaging::publisher::{
    ScanOutcome, ScanResultSink, ROUTING_KEY_SCAN_OUTCOME_COMPLETED,
    ROUTING_KEY_SCAN_OUTCOME_FAILED, ROUTING_KEY_SCAN_OUTCOME_STARTED,
};
use nmap_service::messaging::sns::{
    SnsScanResultSink, MAX_OUTCOME_BODY_BYTES, RESULT_TOO_LARGE_REASON,
};

const LOCALSTACK_TAG: &str = "4.4";
const REGION: &str = "us-east-1";
const TOPIC: &str = "scan-outcomes";
/// Política de filtro real del Gateway sobre `scan-outcomes`.
const GATEWAY_FILTER: &str = r#"{"routing_key":[{"prefix":"scan.outcome."}]}"#;

static CRYPTO_PROVIDER_INIT: Once = Once::new();

/// Mismo guard defensivo de proveedor criptográfico que
/// `tests/sqs_sources_localstack.rs` (LocalStack va por HTTP plano).
fn install_crypto_provider_once() {
    CRYPTO_PROVIDER_INIT.call_once(|| {
        let _ = rustls::crypto::ring::default_provider().install_default();
    });
}

struct Fixture {
    _container: ContainerAsync<GenericImage>,
    sqs: aws_sdk_sqs::Client,
    queue_url: String,
    sink: SnsScanResultSink,
}

impl Fixture {
    async fn start() -> Self {
        install_crypto_provider_once();
        let container = GenericImage::new("localstack/localstack", LOCALSTACK_TAG)
            .with_exposed_port(4566.tcp())
            .with_wait_for(WaitFor::message_on_stdout("Ready."))
            .with_startup_timeout(Duration::from_secs(180))
            .start()
            .await
            .expect("el contenedor LocalStack de test debe arrancar");
        let port = container
            .get_host_port_ipv4(4566.tcp())
            .await
            .expect("LocalStack debe publicar el puerto 4566");
        let endpoint = format!("http://127.0.0.1:{port}");
        let credentials = || Credentials::new("test", "test", None, None, "localstack-test");

        let sns = aws_sdk_sns::Client::from_conf(
            aws_sdk_sns::Config::builder()
                .behavior_version(BehaviorVersion::latest())
                .region(Region::new(REGION))
                .endpoint_url(&endpoint)
                .credentials_provider(credentials())
                .build(),
        );
        let sqs = aws_sdk_sqs::Client::from_conf(
            aws_sdk_sqs::Config::builder()
                .behavior_version(BehaviorVersion::latest())
                .region(Region::new(REGION))
                .endpoint_url(&endpoint)
                .credentials_provider(credentials())
                .build(),
        );

        let topic_arn = sns
            .create_topic()
            .name(TOPIC)
            .send()
            .await
            .expect("crear topic")
            .topic_arn
            .expect("topic arn");
        let queue_url = sqs
            .create_queue()
            .queue_name("gateway-scan-outcomes")
            .send()
            .await
            .expect("crear cola")
            .queue_url
            .expect("queue url");
        let queue_arn = sqs
            .get_queue_attributes()
            .queue_url(&queue_url)
            .attribute_names(aws_sdk_sqs::types::QueueAttributeName::QueueArn)
            .send()
            .await
            .expect("atributos de la cola")
            .attributes
            .expect("atributos")
            .remove(&aws_sdk_sqs::types::QueueAttributeName::QueueArn)
            .expect("arn de la cola");
        sns.subscribe()
            .topic_arn(&topic_arn)
            .protocol("sqs")
            .endpoint(&queue_arn)
            .attributes("RawMessageDelivery", "true")
            .attributes("FilterPolicy", GATEWAY_FILTER)
            .send()
            .await
            .expect("suscribir la cola al topic");

        Self {
            _container: container,
            sqs,
            queue_url,
            sink: SnsScanResultSink::from_client(sns, topic_arn),
        }
    }

    async fn receive_one(&self) -> aws_sdk_sqs::types::Message {
        for _ in 0..10 {
            let out = self
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
        fx.sqs
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
        aws_sdk_sns::Client::from_conf(
            aws_sdk_sns::Config::builder()
                .behavior_version(BehaviorVersion::latest())
                .region(Region::new(REGION))
                .endpoint_url(
                    // reutiliza el mismo LocalStack a través del cliente del fixture
                    fx_endpoint(&fx).await,
                )
                .credentials_provider(Credentials::new("test", "test", None, None, "t"))
                .build(),
        ),
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

async fn fx_endpoint(fx: &Fixture) -> String {
    let port = fx
        ._container
        .get_host_port_ipv4(4566.tcp())
        .await
        .expect("puerto");
    format!("http://127.0.0.1:{port}")
}

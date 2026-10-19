//! Tests de integración de `nmap_service::messaging::sqs` contra un LocalStack
//! real (`localstack/localstack:4.4`) levantado con `testcontainers`: sin
//! mocks y sin cuenta AWS (MSG-NM-02).
//!
//! Todos requieren Docker y están marcados `#[ignore = "requiere Docker"]`:
//! `cargo test` los omite; `cargo test --test sqs_sources_localstack -- --ignored`
//! los ejecuta. Cada test levanta su propio contenedor, así que los nombres de
//! colas nunca colisionan. Las colas usan visibilidad corta (2 s) para que los
//! tests de reentrega sean rápidos; en AWS el valor lo fija Terraform.

use std::sync::Once;
use std::time::Duration;

use aws_sdk_sqs::config::{BehaviorVersion, Credentials, Region};
use aws_sdk_sqs::types::{Message, MessageAttributeValue, QueueAttributeName};
use aws_sdk_sqs::Client;
use serde_json::{json, Value};
use testcontainers::core::{IntoContainerPort, WaitFor};
use testcontainers::runners::AsyncRunner;
use testcontainers::{ContainerAsync, GenericImage, ImageExt};

use nmap_service::messaging::consumer::{ConsumeError, ScanCancellationSource, ScanRequestSource};
use nmap_service::messaging::sqs::{SqsScanCancellationSource, SqsScanRequestSource};

const LOCALSTACK_TAG: &str = "4.4";
const REGION: &str = "us-east-1";
const VISIBILITY_SECONDS: &str = "2";

static CRYPTO_PROVIDER_INIT: Once = Once::new();

/// `Cargo.lock` trae `ring` y `aws-lc-rs` como proveedores candidatos de
/// `rustls` 0.23 (`russh`/`reqwest` -> `ring`; `mongodb`/`testcontainers` ->
/// `aws-lc-rs`; el SDK de AWS usa `aws-lc-rs` explícitamente). Se fija `ring`
/// como proveedor de proceso, igual que en `tests/broker_adapter.rs`, para
/// evitar el cuelgue de doble proveedor ante cualquier cliente TLS de los
/// tests (LocalStack va por HTTP plano, pero el contenedor de Docker no).
fn install_crypto_provider_once() {
    CRYPTO_PROVIDER_INIT.call_once(|| {
        let _ = rustls::crypto::ring::default_provider().install_default();
    });
}

struct LocalStack {
    _container: ContainerAsync<GenericImage>,
    sqs: Client,
}

impl LocalStack {
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
        let sqs = Client::from_conf(
            aws_sdk_sqs::Config::builder()
                .behavior_version(BehaviorVersion::latest())
                .region(Region::new(REGION))
                .endpoint_url(format!("http://127.0.0.1:{port}"))
                .credentials_provider(Credentials::new(
                    "test",
                    "test",
                    None,
                    None,
                    "localstack-test",
                ))
                .build(),
        );
        Self {
            _container: container,
            sqs,
        }
    }

    async fn queue_arn(&self, queue_url: &str) -> String {
        self.sqs
            .get_queue_attributes()
            .queue_url(queue_url)
            .attribute_names(QueueAttributeName::QueueArn)
            .send()
            .await
            .expect("atributos de la cola")
            .attributes
            .expect("atributos")
            .remove(&QueueAttributeName::QueueArn)
            .expect("arn de la cola")
    }

    async fn create_queue(&self, name: &str) -> String {
        self.sqs
            .create_queue()
            .queue_name(name)
            .send()
            .await
            .expect("crear cola")
            .queue_url
            .expect("url de la cola")
    }

    /// Crea `name` (visibilidad corta, `RedrivePolicy` con `maxReceiveCount: 3`
    /// hacia `<name>-redrive-dlq`) y su DLQ explícita de malformados
    /// `<name>-dlq`; devuelve `(queue_url, malformed_dlq_url, redrive_dlq_url)`.
    async fn queue_with_dlqs(&self, name: &str) -> (String, String, String) {
        let malformed_dlq = self.create_queue(&format!("{name}-dlq")).await;
        let redrive_dlq = self.create_queue(&format!("{name}-redrive-dlq")).await;
        let redrive_arn = self.queue_arn(&redrive_dlq).await;
        let queue = self
            .sqs
            .create_queue()
            .queue_name(name)
            .attributes(QueueAttributeName::VisibilityTimeout, VISIBILITY_SECONDS)
            .attributes(
                QueueAttributeName::RedrivePolicy,
                format!(r#"{{"deadLetterTargetArn":"{redrive_arn}","maxReceiveCount":3}}"#),
            )
            .send()
            .await
            .expect("crear cola")
            .queue_url
            .expect("url de la cola");
        (queue, malformed_dlq, redrive_dlq)
    }

    async fn send(&self, queue_url: &str, body: &str, attributes: &[(&str, &str)]) {
        let mut request = self
            .sqs
            .send_message()
            .queue_url(queue_url)
            .message_body(body);
        for (name, value) in attributes {
            request = request.message_attributes(
                *name,
                MessageAttributeValue::builder()
                    .data_type("String")
                    .string_value(*value)
                    .build()
                    .expect("data_type presente"),
            );
        }
        request.send().await.expect("enviar mensaje");
    }

    /// Recibe (y borra) un mensaje de `queue_url` esperando hasta `wait`
    /// segundos en total; `None` si no llega ninguno.
    async fn receive_and_delete(&self, queue_url: &str, wait: u64) -> Option<Message> {
        let deadline = std::time::Instant::now() + Duration::from_secs(wait);
        while std::time::Instant::now() < deadline {
            let out = self
                .sqs
                .receive_message()
                .queue_url(queue_url)
                .message_attribute_names("All")
                .wait_time_seconds(1)
                .max_number_of_messages(1)
                .send()
                .await
                .expect("recibir de la cola");
            if let Some(message) = out.messages.and_then(|m| m.into_iter().next()) {
                if let Some(handle) = message.receipt_handle() {
                    let _ = self
                        .sqs
                        .delete_message()
                        .queue_url(queue_url)
                        .receipt_handle(handle)
                        .send()
                        .await;
                }
                return Some(message);
            }
        }
        None
    }

    /// `true` si la cola no tiene mensajes visibles, en vuelo ni demorados.
    async fn is_empty(&self, queue_url: &str) -> bool {
        let attributes = self
            .sqs
            .get_queue_attributes()
            .queue_url(queue_url)
            .attribute_names(QueueAttributeName::All)
            .send()
            .await
            .expect("atributos de la cola")
            .attributes
            .expect("atributos");
        [
            QueueAttributeName::ApproximateNumberOfMessages,
            QueueAttributeName::ApproximateNumberOfMessagesNotVisible,
            QueueAttributeName::ApproximateNumberOfMessagesDelayed,
        ]
        .iter()
        .all(|name| attributes.get(name).map(String::as_str) == Some("0"))
    }
}

fn scan_request_payload(correlation_id: &str) -> Value {
    json!({
        "correlation_id": correlation_id,
        "ip": "192.0.2.10",
        "network_user": "netuser-lab",
        "ssh_credentials_ref": "lab-only-not-a-real-secret",
        "has_sudo": true,
        "requested_by": "analyst@example.test",
    })
}

fn scan_cancellation_payload(correlation_id: &str) -> Value {
    json!({
        "correlation_id": correlation_id,
        "requested_by": "analyst@example.test",
    })
}

async fn within<T>(seconds: u64, future: impl std::future::Future<Output = T>) -> T {
    tokio::time::timeout(Duration::from_secs(seconds), future)
        .await
        .expect("la operación debe completarse a tiempo")
}

#[tokio::test]
#[ignore = "requiere Docker"]
async fn request_source_delivers_and_parses_a_scan_request() {
    let ls = LocalStack::start().await;
    let (queue, dlq, _redrive) = ls.queue_with_dlqs("ms-nmap-scan-requests").await;
    ls.send(&queue, &scan_request_payload("corr-sqs-1").to_string(), &[])
        .await;
    let source = SqsScanRequestSource::from_client(ls.sqs.clone(), queue, dlq);

    let incoming = within(30, source.next_request())
        .await
        .expect("sin error")
        .expect("hay una solicitud");

    assert_eq!(incoming.request.correlation_id.as_str(), "corr-sqs-1");
    assert_eq!(incoming.request.network_user, "netuser-lab");
    assert!(incoming.request.has_sudo);
}

#[tokio::test]
#[ignore = "requiere Docker"]
async fn malformed_request_goes_to_the_dlq_with_body_and_attributes_and_leaves_the_queue() {
    let ls = LocalStack::start().await;
    let (queue, dlq, _redrive) = ls.queue_with_dlqs("ms-nmap-scan-requests").await;
    ls.send(&queue, "{ not json", &[("trace", "abc-123")]).await;
    let source = SqsScanRequestSource::from_client(ls.sqs.clone(), queue.clone(), dlq.clone());

    let err = within(30, source.next_request())
        .await
        .expect_err("un cuerpo malformado es un error no fatal");
    assert!(
        matches!(err, ConsumeError::MalformedPayload(_)),
        "se esperaba MalformedPayload, se obtuvo {err:?}"
    );

    let dead = ls
        .receive_and_delete(&dlq, 15)
        .await
        .expect("el mensaje malformado debe estar en la DLQ");
    assert_eq!(dead.body(), Some("{ not json"));
    let trace = dead
        .message_attributes()
        .and_then(|attrs| attrs.get("trace"))
        .and_then(|value| value.string_value());
    assert_eq!(trace, Some("abc-123"), "los atributos se conservan");

    // Pasada la visibilidad, la cola origen debe seguir vacía (se borró).
    tokio::time::sleep(Duration::from_secs(3)).await;
    assert!(
        ls.is_empty(&queue).await,
        "el malformado se borró del origen"
    );
}

#[tokio::test]
#[ignore = "requiere Docker"]
async fn request_is_not_deleted_until_acked_and_reappears_after_the_visibility_timeout() {
    let ls = LocalStack::start().await;
    let (queue, dlq, _redrive) = ls.queue_with_dlqs("ms-nmap-scan-requests").await;
    ls.send(
        &queue,
        &scan_request_payload("corr-no-ack").to_string(),
        &[],
    )
    .await;
    let source = SqsScanRequestSource::from_client(ls.sqs.clone(), queue.clone(), dlq);

    let incoming = within(30, source.next_request())
        .await
        .expect("sin error")
        .expect("hay una solicitud");
    assert_eq!(incoming.request.correlation_id.as_str(), "corr-no-ack");
    // Sin `ack`: tras la visibilidad (2 s) el mensaje vuelve a ser visible.

    let again = ls
        .receive_and_delete(&queue, 15)
        .await
        .expect("sin ack el mensaje debe reaparecer");
    let body: Value = serde_json::from_str(again.body().expect("cuerpo")).expect("json");
    assert_eq!(body["correlation_id"], "corr-no-ack");
}

#[tokio::test]
#[ignore = "requiere Docker"]
async fn ack_deletes_the_request_message() {
    let ls = LocalStack::start().await;
    let (queue, dlq, _redrive) = ls.queue_with_dlqs("ms-nmap-scan-requests").await;
    ls.send(&queue, &scan_request_payload("corr-ack").to_string(), &[])
        .await;
    let source = SqsScanRequestSource::from_client(ls.sqs.clone(), queue.clone(), dlq);

    let incoming = within(30, source.next_request())
        .await
        .expect("sin error")
        .expect("hay una solicitud");
    incoming.ack().await.expect("el ack borra el mensaje");

    tokio::time::sleep(Duration::from_secs(3)).await;
    assert!(ls.is_empty(&queue).await, "tras el ack no queda nada");
    assert!(ls.receive_and_delete(&queue, 3).await.is_none());
}

#[tokio::test]
#[ignore = "requiere Docker"]
async fn unacked_request_is_redriven_to_the_dlq_after_three_receives() {
    let ls = LocalStack::start().await;
    let (queue, dlq, redrive_dlq) = ls.queue_with_dlqs("ms-nmap-scan-requests").await;
    ls.send(
        &queue,
        &scan_request_payload("corr-redrive").to_string(),
        &[],
    )
    .await;
    let source = SqsScanRequestSource::from_client(ls.sqs.clone(), queue, dlq);

    for attempt in 1..=3 {
        let incoming = within(40, source.next_request())
            .await
            .expect("sin error")
            .unwrap_or_else(|| panic!("recepción {attempt}: debe llegar la solicitud"));
        assert_eq!(incoming.request.correlation_id.as_str(), "corr-redrive");
        // Nunca se confirma (el escaneo "falla"): se reentrega al vencer.
    }

    // Una cuarta recepción ya no la ve: la RedrivePolicy la movió a la DLQ.
    let fourth = tokio::time::timeout(Duration::from_secs(6), source.next_request()).await;
    assert!(fourth.is_err(), "no debe haber una cuarta entrega");
    let dead = ls
        .receive_and_delete(&redrive_dlq, 20)
        .await
        .expect("tras 3 recepciones el mensaje debe estar en la DLQ de redrive");
    let body: Value = serde_json::from_str(dead.body().expect("cuerpo")).expect("json");
    assert_eq!(body["correlation_id"], "corr-redrive");
}

#[tokio::test]
#[ignore = "requiere Docker"]
async fn cancellation_source_delivers_and_deletes_after_it_was_applied() {
    let ls = LocalStack::start().await;
    let (queue, dlq, _redrive) = ls.queue_with_dlqs("ms-nmap-scan-cancellations").await;
    ls.send(
        &queue,
        &scan_cancellation_payload("corr-cancel").to_string(),
        &[],
    )
    .await;
    let source = SqsScanCancellationSource::from_client(ls.sqs.clone(), queue.clone(), dlq);

    let cancellation = within(30, source.next_cancellation())
        .await
        .expect("sin error")
        .expect("hay una cancelación");
    assert_eq!(cancellation.correlation_id.as_str(), "corr-cancel");

    // El pipeline aplica la cancelación y vuelve a pedir la siguiente: ahí la
    // fuente borra la anterior y se queda en long poll (no hay más).
    let next = tokio::time::timeout(Duration::from_secs(4), source.next_cancellation()).await;
    assert!(next.is_err(), "no hay más cancelaciones");

    tokio::time::sleep(Duration::from_secs(3)).await;
    assert!(
        ls.is_empty(&queue).await,
        "la cancelación aplicada se borró"
    );
}

#[tokio::test]
#[ignore = "requiere Docker"]
async fn malformed_cancellation_goes_to_the_dlq() {
    let ls = LocalStack::start().await;
    let (queue, dlq, _redrive) = ls.queue_with_dlqs("ms-nmap-scan-cancellations").await;
    ls.send(&queue, r#"{"unexpected": true}"#, &[]).await;
    let source = SqsScanCancellationSource::from_client(ls.sqs.clone(), queue.clone(), dlq.clone());

    let err = within(30, source.next_cancellation())
        .await
        .expect_err("esquema inválido");
    assert!(matches!(err, ConsumeError::InvalidSchema(_)), "{err:?}");

    let dead = ls
        .receive_and_delete(&dlq, 15)
        .await
        .expect("debe estar en la DLQ");
    assert_eq!(dead.body(), Some(r#"{"unexpected": true}"#));
    tokio::time::sleep(Duration::from_secs(3)).await;
    assert!(ls.is_empty(&queue).await);
}

#[tokio::test]
#[ignore = "requiere Docker"]
async fn receive_errors_back_off_without_ending_the_stream() {
    let ls = LocalStack::start().await;
    let (queue, dlq, _redrive) = ls.queue_with_dlqs("ms-nmap-scan-requests").await;
    // La cola desaparece: cada ReceiveMessage falla (QueueDoesNotExist).
    ls.sqs
        .delete_queue()
        .queue_url(&queue)
        .send()
        .await
        .expect("borrar la cola");
    let source = SqsScanRequestSource::from_client(ls.sqs.clone(), queue.clone(), dlq)
        .with_backoff(Duration::from_millis(200), Duration::from_millis(800));

    let waiting = tokio::spawn(async move { source.next_request().await });
    tokio::time::sleep(Duration::from_secs(2)).await;
    assert!(
        !waiting.is_finished(),
        "los errores de recepción no deben llegar al pipeline como fatales"
    );

    // La cola reaparece (mismo nombre, misma URL) y llega un mensaje.
    let recreated = ls.create_queue("ms-nmap-scan-requests").await;
    assert_eq!(recreated, queue);
    ls.send(
        &queue,
        &scan_request_payload("corr-recovered").to_string(),
        &[],
    )
    .await;

    let incoming = within(60, waiting)
        .await
        .expect("la tarea no entra en pánico")
        .expect("sin error")
        .expect("hay una solicitud");
    assert_eq!(incoming.request.correlation_id.as_str(), "corr-recovered");
}

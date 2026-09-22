//! Tests de integración de la feature `broker_adapter`: los tres adaptadores
//! reales de `lapin` (`RabbitMqScanRequestSource`,
//! `RabbitMqScanCancellationSource`, `RabbitMqScanResultSink`) contra un
//! RabbitMQ real levantado con `testcontainers`, con la topología real de
//! `broker/rabbitmq/definitions.json` (copiada literalmente a
//! `rabbitmq/definitions.json` de este repo, mismo patrón que ya usó
//! `gateway`, ver `gateway/tests/scan_submission.rs`).
//!
//! Todos requieren Docker y están marcados `#[ignore = "requiere Docker"]`:
//! `cargo test` los omite; `cargo test -- --ignored` los ejecuta.

use std::net::{IpAddr, Ipv4Addr};
use std::path::PathBuf;
use std::sync::{Arc, Once};
use std::time::Duration;

use futures_util::StreamExt;
use lapin::options::{
    BasicAckOptions, BasicConsumeOptions, BasicPublishOptions, QueueBindOptions,
    QueueDeclareOptions,
};
use lapin::protocol::BasicProperties;
use lapin::tcp::OwnedTLSConfig;
use lapin::types::FieldTable;
use lapin::{Connection, ConnectionProperties};
use secrecy::SecretString;
use serde_json::{json, Value};
use testcontainers::core::{CmdWaitFor, ExecCommand, IntoContainerPort, WaitFor};
use testcontainers::runners::AsyncRunner;
use testcontainers::{ContainerAsync, GenericImage, ImageExt};

use nmap_service::domain::{CorrelationId, ScanResult};
use nmap_service::enrichment::{CompositeVulnEnricher, ExploitDbEnricher, VulnEnricher};
use nmap_service::messaging::consumer::{ScanCancellationSource, ScanRequestSource};
use nmap_service::messaging::publisher::{ScanOutcome, ScanResultSink};
use nmap_service::messaging::rabbitmq::{
    RabbitMqScanCancellationSource, RabbitMqScanRequestSource, RabbitMqScanResultSink,
    EXCHANGE_SCAN_CANCELLATIONS, EXCHANGE_SCAN_OUTCOMES, EXCHANGE_SCAN_REQUESTS,
    QUEUE_SCAN_REQUESTS, ROUTING_KEY_SCAN_CANCELLATION, ROUTING_KEY_SCAN_OUTCOME_COMPLETED,
    ROUTING_KEY_SCAN_OUTCOME_FAILED, ROUTING_KEY_SCAN_OUTCOME_STARTED, ROUTING_KEY_SCAN_REQUEST,
};
use nmap_service::pipeline::{PipelineConfig, ScanPipeline, ServicePorts};
use nmap_service::repository::{MongoRepository, ScanResultRepository};
use nmap_service::scanner::{NmapCliScanner, NmapScanner, ScanOptions};
use nmap_service::ssh::{HostKeyStore, RemoteExecutor, RusshExecutor, SshTimeouts};

const VHOST: &str = "security-app";

/// Credenciales de laboratorio del usuario RabbitMQ `ms-nmap`, copiadas de
/// `broker/rabbitmq/README.md` (tabla "Credenciales de laboratorio") — el
/// mismo usuario ya definido en `rabbitmq/definitions.json` (copia literal de
/// `broker/rabbitmq/definitions.json`), con permiso `read` sobre
/// `ms-nmap.scan-requests`/`ms-nmap.scan-cancellations` y `write` sobre
/// `scan.outcomes`.
const MS_NMAP_RABBITMQ_PASSWORD: &str = "lab-only-not-a-real-secret-ms-nmap";

/// Credenciales de laboratorio del usuario administrador de RabbitMQ, único
/// con permiso para declarar/bindear colas de verificación ad-hoc en estos
/// tests (el usuario `ms-nmap` tiene `configure: "^$"`, no puede declarar
/// nada — mismo motivo documentado en
/// `gateway/progress/explore_lapin_testcontainers.md` §3).
const ADMIN_RABBITMQ_USER: &str = "lab-admin";
const ADMIN_RABBITMQ_PASSWORD: &str = "lab-only-not-a-real-secret";

fn fixture_path(relative: &str) -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join(relative)
}

static CRYPTO_PROVIDER_INIT: Once = Once::new();

/// Instalación defensiva (aquí, verificada como **necesaria**: `Cargo.lock`
/// de este repo trae tanto `ring` como `aws-lc-rs` como proveedores
/// criptográficos candidatos de `rustls` 0.23 — `bollard`/`testcontainers`
/// arrastran `aws-lc-rs` vía las features por defecto de `rustls`, mientras
/// que `lapin`/`mongodb`/`russh` resuelven a `ring`) del backend `ring` antes
/// de la primera conexión AMQPS del proceso de test. Sin esto, la primera
/// conexión no falla: se cuelga indefinidamente (ver
/// `gateway/progress/explore_lapin_testcontainers.md` §4, el mismo gotcha
/// documentado por el repo hermano `broker`).
fn install_crypto_provider_once() {
    CRYPTO_PROVIDER_INIT.call_once(|| {
        let _ = rustls::crypto::ring::default_provider().install_default();
    });
}

/// Levanta un `rabbitmq:4.3.5-management` real vía `testcontainers`, con la
/// topología copiada literalmente de `broker/rabbitmq/definitions.json`
/// (`rabbitmq/definitions.json` de este repo) y TLS con los certificados de
/// laboratorio también copiados de `broker/rabbitmq/tls/`.
async fn start_rabbitmq() -> ContainerAsync<GenericImage> {
    install_crypto_provider_once();

    let definitions =
        std::fs::read(fixture_path("rabbitmq/definitions.json")).expect("leer definitions.json");
    let conf = std::fs::read(fixture_path("rabbitmq/rabbitmq.conf")).expect("leer rabbitmq.conf");
    let ca = std::fs::read(fixture_path("rabbitmq/tls/ca_certificate.pem")).expect("leer CA");
    let server_cert = std::fs::read(fixture_path("rabbitmq/tls/server_certificate.pem"))
        .expect("leer server cert");
    let server_key =
        std::fs::read(fixture_path("rabbitmq/tls/server_key.pem")).expect("leer server key");

    GenericImage::new("rabbitmq", "4.3.5-management")
        .with_exposed_port(5672.tcp())
        .with_exposed_port(5671.tcp())
        .with_exposed_port(15672.tcp())
        .with_wait_for(WaitFor::message_on_stdout("Server startup complete"))
        .with_startup_timeout(Duration::from_secs(120))
        .with_copy_to("/etc/rabbitmq/definitions.json", definitions)
        .with_copy_to("/etc/rabbitmq/rabbitmq.conf", conf)
        .with_copy_to("/etc/rabbitmq/tls/ca_certificate.pem", ca)
        .with_copy_to("/etc/rabbitmq/tls/server_certificate.pem", server_cert)
        .with_copy_to("/etc/rabbitmq/tls/server_key.pem", server_key)
        .start()
        .await
        .expect("el contenedor RabbitMQ de test debe arrancar")
}

fn ca_pem() -> String {
    std::fs::read_to_string(fixture_path("rabbitmq/tls/ca_certificate.pem"))
        .expect("debe poder leer la CA de laboratorio")
}

async fn amqps_endpoint(container: &ContainerAsync<GenericImage>) -> (String, u16) {
    let host = container
        .get_host()
        .await
        .expect("host del contenedor de prueba")
        .to_string();
    let port = container
        .get_host_port_ipv4(5671.tcp())
        .await
        .expect("puerto AMQPS publicado del contenedor de prueba");
    (host, port)
}

/// Conexión AMQPS "a mano" (sin pasar por `messaging::rabbitmq`, que solo
/// expone los tres adaptadores de producción) usada por los tests para
/// publicar mensajes "externos" (como lo haría el Gateway) y para
/// preparar/leer colas de verificación con el usuario `lab-admin` (el
/// usuario `ms-nmap` tiene `configure: "^$"`, no puede declarar nada).
async fn connect_lapin_as(user: &str, password: &str, host: &str, port: u16) -> Connection {
    let uri = format!("amqps://{user}:{password}@{host}:{port}/{VHOST}");
    let options = ConnectionProperties::default()
        .with_executor(tokio_executor_trait::Tokio::current())
        .with_reactor(tokio_reactor_trait::Tokio);
    let tls_config = OwnedTLSConfig {
        identity: None,
        cert_chain: Some(ca_pem()),
    };

    Connection::connect_with_config(&uri, options, tls_config)
        .await
        .expect("la conexión AMQPS de prueba debe completarse")
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

#[tokio::test]
#[ignore = "requiere Docker"]
async fn scan_request_source_delivers_a_scan_request_published_by_the_gateway() {
    let container = start_rabbitmq().await;
    let (host, amqps_port) = amqps_endpoint(&container).await;

    // Publicador de prueba: simula al Gateway, publicando directamente en el
    // exchange real del contrato con el usuario `lab-admin` (write ".*").
    let publisher_connection = connect_lapin_as(
        ADMIN_RABBITMQ_USER,
        ADMIN_RABBITMQ_PASSWORD,
        &host,
        amqps_port,
    )
    .await;
    let publisher_channel = publisher_connection
        .create_channel()
        .await
        .expect("canal de publicación de prueba");

    let payload = scan_request_payload("corr-broker-adapter-1");
    publisher_channel
        .basic_publish(
            EXCHANGE_SCAN_REQUESTS,
            ROUTING_KEY_SCAN_REQUEST,
            BasicPublishOptions::default(),
            serde_json::to_vec(&payload).expect("serializa").as_slice(),
            BasicProperties::default(),
        )
        .await
        .expect("publish debe aceptarse")
        .await
        .expect("el broker debe confirmar el frame");

    // Código de producción bajo prueba: se conecta como `ms-nmap`.
    let source = RabbitMqScanRequestSource::connect_with_ca_pem(
        &format!("amqps://{host}:{amqps_port}"),
        &SecretString::from(MS_NMAP_RABBITMQ_PASSWORD.to_string()),
        VHOST,
        ca_pem(),
    )
    .await
    .expect("RabbitMqScanRequestSource debe poder conectar");

    let incoming = tokio::time::timeout(Duration::from_secs(10), source.next_request())
        .await
        .expect("no debe hacer timeout")
        .expect("no debe fallar")
        .expect("debe entregar la solicitud publicada");

    assert_eq!(
        incoming.request.correlation_id.as_str(),
        "corr-broker-adapter-1"
    );
    assert_eq!(incoming.request.network_user, "netuser-lab");
    assert!(incoming.request.has_sudo);
}

#[tokio::test]
#[ignore = "requiere Docker"]
async fn scan_request_source_dead_letters_a_malformed_message_and_keeps_consuming() {
    let container = start_rabbitmq().await;
    let (host, amqps_port) = amqps_endpoint(&container).await;

    let publisher_connection = connect_lapin_as(
        ADMIN_RABBITMQ_USER,
        ADMIN_RABBITMQ_PASSWORD,
        &host,
        amqps_port,
    )
    .await;
    let publisher_channel = publisher_connection
        .create_channel()
        .await
        .expect("canal de publicación de prueba");

    // Cola de verificación de la DLQ, ya declarada por `definitions.json`
    // real (no la declara este test): basta con consumirla como `lab-admin`.
    let dlq_consumer_connection = connect_lapin_as(
        ADMIN_RABBITMQ_USER,
        ADMIN_RABBITMQ_PASSWORD,
        &host,
        amqps_port,
    )
    .await;
    let dlq_channel = dlq_consumer_connection
        .create_channel()
        .await
        .expect("canal de verificación de la DLQ");
    let dlq_name = format!("{QUEUE_SCAN_REQUESTS}.dlq");
    let mut dlq_consumer = dlq_channel
        .basic_consume(
            &dlq_name,
            "test-dlq-consumer",
            BasicConsumeOptions::default(),
            FieldTable::default(),
        )
        .await
        .expect("consumir la DLQ de verificación");

    // Mensaje envenenado: JSON válido pero sin los campos de ScanRequest.
    publisher_channel
        .basic_publish(
            EXCHANGE_SCAN_REQUESTS,
            ROUTING_KEY_SCAN_REQUEST,
            BasicPublishOptions::default(),
            br#"{"not_a_scan_request": true}"#,
            BasicProperties::default(),
        )
        .await
        .expect("publish debe aceptarse")
        .await
        .expect("el broker debe confirmar el frame");

    let payload = scan_request_payload("corr-broker-adapter-after-poison");
    publisher_channel
        .basic_publish(
            EXCHANGE_SCAN_REQUESTS,
            ROUTING_KEY_SCAN_REQUEST,
            BasicPublishOptions::default(),
            serde_json::to_vec(&payload).expect("serializa").as_slice(),
            BasicProperties::default(),
        )
        .await
        .expect("publish debe aceptarse")
        .await
        .expect("el broker debe confirmar el frame");

    let source = RabbitMqScanRequestSource::connect_with_ca_pem(
        &format!("amqps://{host}:{amqps_port}"),
        &SecretString::from(MS_NMAP_RABBITMQ_PASSWORD.to_string()),
        VHOST,
        ca_pem(),
    )
    .await
    .expect("RabbitMqScanRequestSource debe poder conectar");

    // El mensaje envenenado no se entrega: next_request() salta directo al
    // siguiente mensaje válido.
    let incoming = tokio::time::timeout(Duration::from_secs(10), source.next_request())
        .await
        .expect("no debe hacer timeout")
        .expect("no debe fallar")
        .expect("debe entregar la solicitud válida, saltando la envenenada");
    assert_eq!(
        incoming.request.correlation_id.as_str(),
        "corr-broker-adapter-after-poison"
    );

    // El mensaje envenenado terminó en la DLQ (dead-lettered, no perdido).
    let dead_letter = tokio::time::timeout(Duration::from_secs(10), dlq_consumer.next())
        .await
        .expect("no debe hacer timeout esperando el dead-letter")
        .expect("debe llegar un mensaje a la DLQ")
        .expect("sin error de protocolo AMQP");
    assert_eq!(dead_letter.data, br#"{"not_a_scan_request": true}"#);
    dead_letter
        .ack(BasicAckOptions::default())
        .await
        .expect("ack de verificación");
}

#[tokio::test]
#[ignore = "requiere Docker"]
async fn scan_cancellation_source_delivers_a_cancellation_published_by_the_gateway() {
    let container = start_rabbitmq().await;
    let (host, amqps_port) = amqps_endpoint(&container).await;

    let publisher_connection = connect_lapin_as(
        ADMIN_RABBITMQ_USER,
        ADMIN_RABBITMQ_PASSWORD,
        &host,
        amqps_port,
    )
    .await;
    let publisher_channel = publisher_connection
        .create_channel()
        .await
        .expect("canal de publicación de prueba");

    let payload = scan_cancellation_payload("corr-cancel-broker-adapter-1");
    publisher_channel
        .basic_publish(
            EXCHANGE_SCAN_CANCELLATIONS,
            ROUTING_KEY_SCAN_CANCELLATION,
            BasicPublishOptions::default(),
            serde_json::to_vec(&payload).expect("serializa").as_slice(),
            BasicProperties::default(),
        )
        .await
        .expect("publish debe aceptarse")
        .await
        .expect("el broker debe confirmar el frame");

    let source = RabbitMqScanCancellationSource::connect_with_ca_pem(
        &format!("amqps://{host}:{amqps_port}"),
        &SecretString::from(MS_NMAP_RABBITMQ_PASSWORD.to_string()),
        VHOST,
        ca_pem(),
    )
    .await
    .expect("RabbitMqScanCancellationSource debe poder conectar");

    let cancellation = tokio::time::timeout(Duration::from_secs(10), source.next_cancellation())
        .await
        .expect("no debe hacer timeout")
        .expect("no debe fallar")
        .expect("debe entregar la cancelación publicada");

    assert_eq!(
        cancellation.correlation_id.as_str(),
        "corr-cancel-broker-adapter-1"
    );
    assert_eq!(cancellation.requested_by, "analyst@example.test");
}

/// Declara (como `lab-admin`) una cola de verificación ad-hoc bindeada a
/// `scan.outcomes`/`routing_key`, exclusiva de este test.
async fn declare_outcome_verification_queue(
    host: &str,
    amqps_port: u16,
    queue_name: &str,
    routing_key: &str,
) -> (Connection, lapin::Consumer) {
    let connection = connect_lapin_as(
        ADMIN_RABBITMQ_USER,
        ADMIN_RABBITMQ_PASSWORD,
        host,
        amqps_port,
    )
    .await;
    let channel = connection
        .create_channel()
        .await
        .expect("canal de administración de prueba");

    channel
        .queue_declare(
            queue_name,
            QueueDeclareOptions {
                durable: false,
                exclusive: true,
                auto_delete: true,
                ..Default::default()
            },
            FieldTable::default(),
        )
        .await
        .expect("declarar la cola de verificación de prueba");

    channel
        .queue_bind(
            queue_name,
            EXCHANGE_SCAN_OUTCOMES,
            routing_key,
            QueueBindOptions::default(),
            FieldTable::default(),
        )
        .await
        .expect("bindear la cola de verificación de prueba");

    let consumer = channel
        .basic_consume(
            queue_name,
            "test-outcome-consumer",
            BasicConsumeOptions::default(),
            FieldTable::default(),
        )
        .await
        .expect("consumir la cola de verificación de prueba");

    (connection, consumer)
}

#[tokio::test]
#[ignore = "requiere Docker"]
async fn scan_result_sink_publishes_each_status_with_its_exact_contract_routing_key() {
    let container = start_rabbitmq().await;
    let (host, amqps_port) = amqps_endpoint(&container).await;

    let (_started_conn, mut started_consumer) = declare_outcome_verification_queue(
        &host,
        amqps_port,
        "test.outcomes-started-verify",
        ROUTING_KEY_SCAN_OUTCOME_STARTED,
    )
    .await;
    let (_completed_conn, mut completed_consumer) = declare_outcome_verification_queue(
        &host,
        amqps_port,
        "test.outcomes-completed-verify",
        ROUTING_KEY_SCAN_OUTCOME_COMPLETED,
    )
    .await;
    let (_failed_conn, mut failed_consumer) = declare_outcome_verification_queue(
        &host,
        amqps_port,
        "test.outcomes-failed-verify",
        ROUTING_KEY_SCAN_OUTCOME_FAILED,
    )
    .await;

    let sink = RabbitMqScanResultSink::connect_with_ca_pem(
        &format!("amqps://{host}:{amqps_port}"),
        &SecretString::from(MS_NMAP_RABBITMQ_PASSWORD.to_string()),
        VHOST,
        ca_pem(),
    )
    .await
    .expect("RabbitMqScanResultSink debe poder conectar");

    sink.publish(&ScanOutcome::started(CorrelationId::from(
        "corr-sink-started",
    )))
    .await
    .expect("publica started");

    sink.publish(&ScanOutcome::completed(
        CorrelationId::from("corr-sink-completed"),
        sample_scan_result(),
    ))
    .await
    .expect("publica completed");

    sink.publish(&ScanOutcome::failed(
        CorrelationId::from("corr-sink-failed"),
        "etapa SSH: tiempo de espera agotado",
    ))
    .await
    .expect("publica failed");

    let started_delivery = tokio::time::timeout(Duration::from_secs(10), started_consumer.next())
        .await
        .expect("no debe hacer timeout")
        .expect("debe llegar el mensaje started")
        .expect("sin error de protocolo");
    let started_json: Value = serde_json::from_slice(&started_delivery.data).expect("JSON válido");
    assert_eq!(started_json["status"], "started");
    assert_eq!(started_json["correlation_id"], "corr-sink-started");
    assert_eq!(
        started_delivery.routing_key.as_str(),
        ROUTING_KEY_SCAN_OUTCOME_STARTED
    );

    let completed_delivery =
        tokio::time::timeout(Duration::from_secs(10), completed_consumer.next())
            .await
            .expect("no debe hacer timeout")
            .expect("debe llegar el mensaje completed")
            .expect("sin error de protocolo");
    let completed_json: Value =
        serde_json::from_slice(&completed_delivery.data).expect("JSON válido");
    assert_eq!(completed_json["status"], "completed");
    assert_eq!(completed_json["correlation_id"], "corr-sink-completed");
    assert_eq!(completed_json["result"]["host"], "192.0.2.10");
    assert_eq!(
        completed_delivery.routing_key.as_str(),
        ROUTING_KEY_SCAN_OUTCOME_COMPLETED
    );

    let failed_delivery = tokio::time::timeout(Duration::from_secs(10), failed_consumer.next())
        .await
        .expect("no debe hacer timeout")
        .expect("debe llegar el mensaje failed")
        .expect("sin error de protocolo");
    let failed_json: Value = serde_json::from_slice(&failed_delivery.data).expect("JSON válido");
    assert_eq!(failed_json["status"], "failed");
    assert_eq!(failed_json["correlation_id"], "corr-sink-failed");
    assert_eq!(failed_json["reason"], "etapa SSH: tiempo de espera agotado");
    assert_eq!(
        failed_delivery.routing_key.as_str(),
        ROUTING_KEY_SCAN_OUTCOME_FAILED
    );
}

fn sample_scan_result() -> ScanResult {
    use time::macros::datetime;

    ScanResult {
        host: "192.0.2.10".parse().expect("IP de prueba válida"),
        ports: Vec::new(),
        vulnerabilities: Vec::new(),
        scanned_at: datetime!(2026-08-27 12:30:00 UTC),
    }
}

// ---------------------------------------------------------------------------
// Smoke test end-to-end con los tres adaptadores reales (criterio de
// aceptación "opcional pero deseable" de `broker_adapter`): un ScanRequest
// publicado "externamente" (como lo haría el Gateway) recorre el pipeline
// completo —SSH al objetivo, `nmap` (stub), parseo, enrichment, persistencia
// en Mongo— y termina en un ScanOutcome publicado en `scan.outcomes`, sin
// pasar por ninguno de los stubs en memoria. El patrón de contenedores
// ssd/Mongo es el mismo de `tests/scan_pipeline.rs`.
// ---------------------------------------------------------------------------

const SSHD_IMAGE: &str = "lscr.io/linuxserver/openssh-server";
const SSHD_TAG: &str = "version-9.9_p2-r0";
const SSH_PORT: u16 = 2222;
const SSH_USER: &str = "scanuser";
const SSH_PASS: &str = "s3cr3t-test";
const NMAP_PATH: &str = "/usr/local/bin/nmap";

const MONGO_IMAGE: &str = "mongo";
const MONGO_TAG: &str = "7";
const MONGO_PORT: u16 = 27017;
const TEST_DB: &str = "db-nmap-test";

/// XML de `nmap` fijo que escupe el stub (mismo fixture que
/// `tests/scan_pipeline.rs`): puertos 21 y 6667 abiertos y dos hallazgos NSE.
const STUB_XML: &str = include_str!("fixtures/vuln_findings.xml");

/// CSV fixture con filas reales de Exploit-DB (mismo que `tests/scan_pipeline.rs`).
const EXPLOITDB_SAMPLE_CSV: &str = concat!(
    env!("CARGO_MANIFEST_DIR"),
    "/tests/fixtures/exploitdb_sample.csv"
);

/// Stub de `nmap`: ignora las flags y vuelca `STUB_XML` por `stdout` con 0.
fn fake_nmap() -> Vec<u8> {
    format!("#!/bin/sh\ncat <<'NMAP_STUB_EOF'\n{STUB_XML}\nNMAP_STUB_EOF\n").into_bytes()
}

async fn start_target(files: &[(&'static str, Vec<u8>)]) -> ContainerAsync<GenericImage> {
    let mut request = GenericImage::new(SSHD_IMAGE, SSHD_TAG)
        .with_exposed_port(SSH_PORT.tcp())
        .with_wait_for(WaitFor::message_on_stdout("[ls.io-init] done."))
        .with_startup_timeout(Duration::from_secs(180))
        .with_env_var("PUID", "1000")
        .with_env_var("PGID", "1000")
        .with_env_var("TZ", "Etc/UTC")
        .with_env_var("USER_NAME", SSH_USER)
        .with_env_var("USER_PASSWORD", SSH_PASS)
        .with_env_var("PASSWORD_ACCESS", "true")
        .with_env_var("SUDO_ACCESS", "true")
        .with_env_var("LOG_STDOUT", "true");

    for (path, contents) in files {
        request = request.with_copy_to(path.to_string(), contents.clone());
    }

    let container = request
        .start()
        .await
        .expect("el contenedor sshd (objetivo) debe arrancar");

    for (path, _) in files {
        container
            .exec(
                ExecCommand::new(["chmod", "0755", *path])
                    .with_cmd_ready_condition(CmdWaitFor::exit_code(0)),
            )
            .await
            .expect("chmod del stub de nmap");
    }

    container
}

async fn start_mongo() -> ContainerAsync<GenericImage> {
    GenericImage::new(MONGO_IMAGE, MONGO_TAG)
        .with_exposed_port(MONGO_PORT.tcp())
        .with_wait_for(WaitFor::message_on_stdout("Waiting for connections"))
        .with_startup_timeout(Duration::from_secs(180))
        .start()
        .await
        .expect("el contenedor mongo debe arrancar")
}

async fn mongo_uri(container: &ContainerAsync<GenericImage>) -> String {
    let host = container
        .get_host()
        .await
        .expect("host del contenedor")
        .to_string();
    let port = container
        .get_host_port_ipv4(MONGO_PORT)
        .await
        .expect("puerto mapeado");
    format!("mongodb://{host}:{port}/?directConnection=true&serverSelectionTimeoutMS=5000")
}

async fn sshd_endpoint(container: &ContainerAsync<GenericImage>) -> (IpAddr, u16) {
    let host = container
        .get_host()
        .await
        .expect("host del contenedor")
        .to_string();
    let ip = host.parse().unwrap_or(IpAddr::V4(Ipv4Addr::LOCALHOST));
    let port = container
        .get_host_port_ipv4(SSH_PORT)
        .await
        .expect("puerto mapeado");
    (ip, port)
}

async fn sample_enricher() -> Arc<dyn VulnEnricher> {
    let exploitdb = ExploitDbEnricher::from_csv_path(EXPLOITDB_SAMPLE_CSV)
        .await
        .expect("el CSV fixture de Exploit-DB debe cargar");
    Arc::new(CompositeVulnEnricher::new(vec![
        Arc::new(exploitdb) as Arc<dyn VulnEnricher>
    ]))
}

fn timeouts() -> SshTimeouts {
    SshTimeouts {
        connect: Duration::from_secs(20),
        command: Duration::from_secs(40),
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[ignore = "requiere Docker"]
async fn published_scan_request_ends_in_a_published_completed_outcome_through_real_adapters() {
    let rabbit = start_rabbitmq().await;
    let (host, amqps_port) = amqps_endpoint(&rabbit).await;
    let target = start_target(&[(NMAP_PATH, fake_nmap())]).await;
    let mongo = start_mongo().await;
    let (ip, ssh_port) = sshd_endpoint(&target).await;

    // Repos y adaptadores de broker reales: nada de stubs en memoria.
    let repo = MongoRepository::connect(&mongo_uri(&mongo).await, TEST_DB)
        .await
        .expect("debe conectar con el contenedor mongo");

    let endpoint = format!("amqps://{host}:{amqps_port}");
    let credential = SecretString::from(MS_NMAP_RABBITMQ_PASSWORD.to_string());
    let source: Arc<dyn ScanRequestSource> = Arc::new(
        RabbitMqScanRequestSource::connect_with_ca_pem(&endpoint, &credential, VHOST, ca_pem())
            .await
            .expect("RabbitMqScanRequestSource debe conectar"),
    );
    let cancellations: Arc<dyn ScanCancellationSource> = Arc::new(
        RabbitMqScanCancellationSource::connect_with_ca_pem(
            &endpoint,
            &credential,
            VHOST,
            ca_pem(),
        )
        .await
        .expect("RabbitMqScanCancellationSource debe conectar"),
    );
    let sink: Arc<dyn ScanResultSink> = Arc::new(
        RabbitMqScanResultSink::connect_with_ca_pem(&endpoint, &credential, VHOST, ca_pem())
            .await
            .expect("RabbitMqScanResultSink debe conectar"),
    );

    let ports = ServicePorts {
        executor: Arc::new(RusshExecutor) as Arc<dyn RemoteExecutor>,
        scanner: Arc::new(NmapCliScanner) as Arc<dyn NmapScanner>,
        repository: Arc::new(repo.clone()) as Arc<dyn ScanResultRepository>,
        enricher: sample_enricher().await,
        host_key_store: Arc::new(repo.host_key_store()) as Arc<dyn HostKeyStore>,
        sink,
    };
    let pipeline = Arc::new(ScanPipeline::new(
        ports,
        PipelineConfig {
            ssh_port,
            ssh_timeouts: timeouts(),
            scan_options: ScanOptions::default(),
        },
    ));

    // Cola de verificación externa en `scan.outcomes` para el desenlace
    // completed, declarada con el usuario `lab-admin` (el usuario `ms-nmap`
    // tiene `configure: "^$"` y no puede declarar nada — mismo patrón que el
    // resto de tests de este archivo).
    let (_verify_conn, mut outcomes_consumer) = declare_outcome_verification_queue(
        &host,
        amqps_port,
        "test.e2e-outcomes-completed-verify",
        ROUTING_KEY_SCAN_OUTCOME_COMPLETED,
    )
    .await;

    // Publica el ScanRequest como lo haría el Gateway (usuario `lab-admin`,
    // exchange/routing key reales del contrato). La IP del objetivo es la del
    // contenedor sshd de prueba y la credencial SSH, la del usuario `scanuser`.
    let correlation_id = "corr-e2e-broker-smoke";
    let publisher_connection = connect_lapin_as(
        ADMIN_RABBITMQ_USER,
        ADMIN_RABBITMQ_PASSWORD,
        &host,
        amqps_port,
    )
    .await;
    let publisher_channel = publisher_connection
        .create_channel()
        .await
        .expect("canal de publicación de prueba");
    let payload = json!({
        "correlation_id": correlation_id,
        "ip": ip.to_string(),
        "network_user": SSH_USER,
        "ssh_credentials_ref": SSH_PASS,
        "has_sudo": false,
        "requested_by": "analyst@example.test",
    });
    publisher_channel
        .basic_publish(
            EXCHANGE_SCAN_REQUESTS,
            ROUTING_KEY_SCAN_REQUEST,
            BasicPublishOptions::default(),
            serde_json::to_vec(&payload).expect("serializa").as_slice(),
            BasicProperties::default(),
        )
        .await
        .expect("publish debe aceptarse")
        .await
        .expect("el broker debe confirmar el frame");

    // Los consumers de RabbitMQ nunca devuelven `None`, así que `run` consume
    // indefinidamente: corre en su propia tarea y el test la aborta al
    // terminar (los contenedores se destruyen al salir del scope).
    let run_task = {
        let pipeline = pipeline.clone();
        tokio::spawn(async move { pipeline.run(source, cancellations).await })
    };

    let outcome_delivery = tokio::time::timeout(Duration::from_secs(60), outcomes_consumer.next())
        .await
        .expect("el ScanOutcome completed debe llegar antes de 60s")
        .expect("sin error de protocolo AMQP")
        .expect("debe llegar el desenlace a la cola de verificación");

    let outcome_json: Value = serde_json::from_slice(&outcome_delivery.data).expect("JSON válido");
    assert_eq!(outcome_json["status"], "completed");
    assert_eq!(outcome_json["correlation_id"], correlation_id);
    assert_eq!(
        outcome_delivery.routing_key.as_str(),
        ROUTING_KEY_SCAN_OUTCOME_COMPLETED
    );
    assert_eq!(
        outcome_json["result"]["ports"].as_array().map(Vec::len),
        Some(2),
        "el ScanResult publicado debe incluir los 2 puertos del stub: {outcome_json}"
    );

    // El pipeline usó el repo real: el ScanResult quedó persistido en Mongo.
    let persisted = repo
        .find_by_correlation_id(&CorrelationId::from(correlation_id))
        .await
        .expect("consulta a mongo")
        .expect("el ScanResult debe estar persistido");
    assert_eq!(persisted.ports.len(), 2);

    run_task.abort();
}

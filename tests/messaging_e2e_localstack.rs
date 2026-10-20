//! Prueba de punta a punta del servicio con los adaptadores **reales** de SQS
//! y SNS (MSG-NM-04), sin ningún stub en memoria: una solicitud puesta en la
//! cola SQS "como la pondría el Gateway" recorre el cableado de producción
//! (`wiring::service_ports_from_config`) -> SSH a un sshd real con un `nmap`
//! falso -> parseo -> enriquecimiento -> persistencia en un Mongo real ->
//! publicación en el topic SNS `scan-outcomes`. El desenlace `Completed` se
//! observa en una cola suscrita en bruto (`RawMessageDelivery=true`), la
//! solicitud desaparece de su cola (borrado tras publicar) y, al pedir el
//! apagado, `run` vuelve de inmediato aunque el long poll siga en curso.
//!
//! Hereda el patrón de contenedores sshd/Mongo del antiguo smoke test AMQP.
//! Requiere Docker (`localstack/localstack:4.4`, `mongo:7`, sshd) y está
//! marcado `#[ignore = "requiere Docker"]`:
//! `cargo test --test messaging_e2e_localstack -- --ignored`.

use std::net::{IpAddr, Ipv4Addr};
use std::sync::Once;
use std::time::{Duration, Instant};

use serde_json::{json, Value};
use testcontainers::core::{CmdWaitFor, ExecCommand, IntoContainerPort, WaitFor};
use testcontainers::runners::AsyncRunner;
use testcontainers::{ContainerAsync, GenericImage, ImageExt};
use tokio_util::sync::CancellationToken;

use nmap_service::config::Config;
use nmap_service::domain::CorrelationId;
use nmap_service::repository::MongoRepository;
use nmap_service::scanner::{ScanOptions, Timing};
use nmap_service::ssh::SshTimeouts;
use nmap_service::{run, wiring, PipelineConfig};

mod common;
use common::{LocalStack, REGION};

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

/// XML de `nmap` fijo que escupe el stub: puertos 21 y 6667 abiertos y dos
/// hallazgos NSE (mismo fixture que `tests/scan_pipeline.rs`).
const STUB_XML: &str = include_str!("fixtures/vuln_findings.xml");

/// CSV fixture con filas reales de Exploit-DB.
const EXPLOITDB_SAMPLE_CSV: &str = concat!(
    env!("CARGO_MANIFEST_DIR"),
    "/tests/fixtures/exploitdb_sample.csv"
);

static AWS_ENV_INIT: Once = Once::new();

/// Credenciales ficticias para la cadena por defecto del SDK (LocalStack no las
/// valida) y sin consulta al servicio de metadatos de EC2.
fn set_aws_test_env() {
    AWS_ENV_INIT.call_once(|| {
        std::env::set_var("AWS_ACCESS_KEY_ID", "test");
        std::env::set_var("AWS_SECRET_ACCESS_KEY", "test");
        std::env::set_var("AWS_EC2_METADATA_DISABLED", "true");
    });
}

/// Stub de `nmap`: ignora las flags y vuelca `STUB_XML` por `stdout` con 0.
fn fake_nmap() -> Vec<u8> {
    format!("#!/bin/sh\ncat <<'NMAP_STUB_EOF'\n{STUB_XML}\nNMAP_STUB_EOF\n").into_bytes()
}

async fn start_target() -> ContainerAsync<GenericImage> {
    let container = GenericImage::new(SSHD_IMAGE, SSHD_TAG)
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
        .with_env_var("LOG_STDOUT", "true")
        .with_copy_to(NMAP_PATH.to_owned(), fake_nmap())
        .start()
        .await
        .expect("el contenedor sshd (objetivo) debe arrancar");
    container
        .exec(
            ExecCommand::new(["chmod", "0755", NMAP_PATH])
                .with_cmd_ready_condition(CmdWaitFor::exit_code(0)),
        )
        .await
        .expect("chmod del stub de nmap");
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

async fn host_and_port(container: &ContainerAsync<GenericImage>, port: u16) -> (String, u16) {
    let host = container
        .get_host()
        .await
        .expect("host del contenedor")
        .to_string();
    let mapped = container
        .get_host_port_ipv4(port)
        .await
        .expect("puerto mapeado");
    (host, mapped)
}

fn url(raw: &str) -> url::Url {
    url::Url::parse(raw).expect("URL de prueba válida")
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[ignore = "requiere Docker"]
async fn queued_scan_request_ends_in_a_published_completed_outcome_and_shutdown_is_prompt() {
    set_aws_test_env();
    let ls = LocalStack::start().await;
    let target = start_target().await;
    let mongo = start_mongo().await;

    // Topología mínima del contrato: colas de entrada con sus DLQ y el topic de
    // desenlaces con una cola de verificación suscrita en bruto.
    let (requests_queue, requests_dlq, _) = ls.queue_with_dlqs("ms-nmap-scan-requests").await;
    let (cancellations_queue, cancellations_dlq, _) =
        ls.queue_with_dlqs("ms-nmap-scan-cancellations").await;
    let (topic_arn, verify_queue) = ls
        .topic_with_raw_queue("scan-outcomes", "e2e-outcomes-verify", None)
        .await;

    let (ssh_host, ssh_port) = host_and_port(&target, SSH_PORT).await;
    let (mongo_host, mongo_port) = host_and_port(&mongo, MONGO_PORT).await;
    let mongo_uri = format!(
        "mongodb://{mongo_host}:{mongo_port}/?directConnection=true&serverSelectionTimeoutMS=5000"
    );

    // `Config` como la armaría `Config::from_env` en el despliegue, apuntando a
    // los contenedores. El cableado de producción construye los adaptadores.
    let config = Config {
        mongo_uri: mongo_uri.clone(),
        mongo_db: TEST_DB.to_owned(),
        ssh_port,
        ssh_connect_timeout: Duration::from_secs(20),
        ssh_command_timeout: Duration::from_secs(40),
        exploitdb_csv: EXPLOITDB_SAMPLE_CSV.to_owned(),
        nvd_enrichment_enabled: false,
        nvd_api_key: None,
        nvd_cache_ttl: None,
        scan_timing: Timing::Polite,
        aws_region: REGION.to_owned(),
        aws_endpoint_url: Some(url(&ls.endpoint)),
        scan_requests_queue_url: url(&requests_queue),
        scan_cancellations_queue_url: url(&cancellations_queue),
        scan_requests_dlq_url: url(&requests_dlq),
        scan_cancellations_dlq_url: url(&cancellations_dlq),
        scan_outcomes_topic_arn: topic_arn,
    };
    let (ports, source, cancellations) = wiring::service_ports_from_config(&config)
        .await
        .expect("el cableado real debe construirse contra LocalStack y Mongo");

    let shutdown = CancellationToken::new();
    let run_task = tokio::spawn({
        let shutdown = shutdown.clone();
        let pipeline_config = PipelineConfig {
            ssh_port: config.ssh_port,
            ssh_timeouts: SshTimeouts {
                connect: config.ssh_connect_timeout,
                command: config.ssh_command_timeout,
            },
            scan_options: ScanOptions::default(),
        };
        async move {
            run(
                ports,
                pipeline_config,
                Some(source),
                Some(cancellations),
                shutdown,
            )
            .await;
        }
    });

    // Como lo dejaría el Gateway: la IP es la del contenedor sshd de prueba y
    // la credencial SSH, la del usuario `scanuser`.
    let correlation_id = "corr-e2e-sqs-sns";
    let ip = ssh_host.parse().unwrap_or(IpAddr::V4(Ipv4Addr::LOCALHOST));
    let payload = json!({
        "correlation_id": correlation_id,
        "ip": ip.to_string(),
        "network_user": SSH_USER,
        "ssh_credentials_ref": SSH_PASS,
        "has_sudo": false,
        "requested_by": "analyst@example.test",
    });
    ls.send(&requests_queue, &payload.to_string(), &[]).await;

    // SNS -> SQS estándar no garantiza orden: se acumulan por routing key hasta
    // ver `started` y `completed`.
    let mut started = None;
    let mut completed = None;
    let deadline = Instant::now() + Duration::from_secs(90);
    while (started.is_none() || completed.is_none()) && Instant::now() < deadline {
        let Some(message) = ls.receive_and_delete(&verify_queue, 5).await else {
            continue;
        };
        let routing_key = message
            .message_attributes()
            .and_then(|attrs| attrs.get("routing_key"))
            .and_then(|value| value.string_value())
            .expect("el desenlace debe traer el atributo routing_key")
            .to_owned();
        let body: Value =
            serde_json::from_str(message.body().expect("cuerpo")).expect("el cuerpo es JSON");
        match routing_key.as_str() {
            "scan.outcome.started" => started = Some(body),
            "scan.outcome.completed" => completed = Some(body),
            other => panic!("routing key inesperada: {other}: {body}"),
        }
    }
    let started = started.expect("debe llegar el desenlace started");
    let completed = completed.expect("debe llegar el desenlace completed");
    assert_eq!(started["correlation_id"], correlation_id);
    assert_eq!(completed["status"], "completed");
    assert_eq!(completed["correlation_id"], correlation_id);
    assert_eq!(
        completed["result"]["ports"].as_array().map(Vec::len),
        Some(2),
        "el ScanResult publicado debe incluir los 2 puertos del stub: {completed}"
    );

    // El pipeline usó el repositorio real: el resultado quedó persistido.
    let repo = MongoRepository::connect(&mongo_uri, TEST_DB)
        .await
        .expect("conexión de verificación a mongo");
    let persisted = repo
        .find_by_correlation_id(&CorrelationId::from(correlation_id))
        .await
        .expect("consulta a mongo")
        .expect("el ScanResult debe estar persistido");
    assert_eq!(persisted.ports.len(), 2);

    // Borrado tras publicar: la solicitud ya no está en su cola (ni en vuelo).
    let deadline = Instant::now() + Duration::from_secs(30);
    while !ls.is_empty(&requests_queue).await {
        assert!(
            Instant::now() < deadline,
            "la solicitud debe borrarse de su cola tras publicar el desenlace"
        );
        tokio::time::sleep(Duration::from_millis(500)).await;
    }

    // Apagado: el long poll (20 s) en curso no retrasa la salida.
    shutdown.cancel();
    tokio::time::timeout(Duration::from_secs(5), run_task)
        .await
        .expect("run debe volver de inmediato tras el apagado")
        .expect("sin panic");
}

/// Una solicitud con JSON válido pero que no pasa la validación de
/// `ScanRequest` (IP con máscara `/32`) va a la DLQ **y** el servicio publica
/// un `Failed` con su `correlation_id`, para que el Gateway cierre el escaneo
/// en vez de dejarlo pendiente. No hace falta sshd: nunca se llega a escanear.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[ignore = "requiere Docker"]
async fn rejected_scan_request_goes_to_the_dlq_and_publishes_a_failed_outcome() {
    set_aws_test_env();
    let ls = LocalStack::start().await;
    let mongo = start_mongo().await;

    let (requests_queue, requests_dlq, _) = ls.queue_with_dlqs("ms-nmap-scan-requests").await;
    let (cancellations_queue, cancellations_dlq, _) =
        ls.queue_with_dlqs("ms-nmap-scan-cancellations").await;
    let (topic_arn, verify_queue) = ls
        .topic_with_raw_queue("scan-outcomes", "e2e-outcomes-rejected", None)
        .await;

    let (mongo_host, mongo_port) = host_and_port(&mongo, MONGO_PORT).await;
    let config = Config {
        mongo_uri: format!(
            "mongodb://{mongo_host}:{mongo_port}/?directConnection=true&serverSelectionTimeoutMS=5000"
        ),
        mongo_db: TEST_DB.to_owned(),
        ssh_port: SSH_PORT,
        ssh_connect_timeout: Duration::from_secs(5),
        ssh_command_timeout: Duration::from_secs(5),
        exploitdb_csv: EXPLOITDB_SAMPLE_CSV.to_owned(),
        nvd_enrichment_enabled: false,
        nvd_api_key: None,
        nvd_cache_ttl: None,
        scan_timing: Timing::Polite,
        aws_region: REGION.to_owned(),
        aws_endpoint_url: Some(url(&ls.endpoint)),
        scan_requests_queue_url: url(&requests_queue),
        scan_cancellations_queue_url: url(&cancellations_queue),
        scan_requests_dlq_url: url(&requests_dlq),
        scan_cancellations_dlq_url: url(&cancellations_dlq),
        scan_outcomes_topic_arn: topic_arn,
    };
    let (ports, source, cancellations) = wiring::service_ports_from_config(&config)
        .await
        .expect("el cableado real debe construirse contra LocalStack y Mongo");

    let shutdown = CancellationToken::new();
    let run_task = tokio::spawn({
        let shutdown = shutdown.clone();
        let pipeline_config = PipelineConfig {
            ssh_port: config.ssh_port,
            ssh_timeouts: SshTimeouts {
                connect: config.ssh_connect_timeout,
                command: config.ssh_command_timeout,
            },
            scan_options: ScanOptions::default(),
        };
        async move {
            run(
                ports,
                pipeline_config,
                Some(source),
                Some(cancellations),
                shutdown,
            )
            .await;
        }
    });

    let correlation_id = "corr-e2e-rejected";
    let payload = json!({
        "correlation_id": correlation_id,
        "ip": "172.31.86.37/32",
        "network_user": SSH_USER,
        "ssh_credentials_ref": SSH_PASS,
        "has_sudo": false,
        "requested_by": "analyst@example.test",
    })
    .to_string();
    ls.send(&requests_queue, &payload, &[]).await;

    let dead = ls
        .receive_and_delete(&requests_dlq, 30)
        .await
        .expect("la solicitud inválida debe quedar en la DLQ para diagnóstico");
    assert_eq!(dead.body(), Some(payload.as_str()));

    let message = ls
        .receive_and_delete(&verify_queue, 30)
        .await
        .expect("debe publicarse un desenlace failed");
    let routing_key = message
        .message_attributes()
        .and_then(|attrs| attrs.get("routing_key"))
        .and_then(|value| value.string_value())
        .expect("el desenlace debe traer el atributo routing_key");
    assert_eq!(routing_key, "scan.outcome.failed");
    let body: Value =
        serde_json::from_str(message.body().expect("cuerpo")).expect("el cuerpo es JSON");
    assert_eq!(body["status"], "failed");
    assert_eq!(body["correlation_id"], correlation_id);
    let printed = body.to_string();
    assert!(
        !printed.contains("172.31.86.37") && !printed.contains(SSH_PASS),
        "el desenlace no debe incluir valores del payload: {printed}"
    );

    shutdown.cancel();
    tokio::time::timeout(Duration::from_secs(5), run_task)
        .await
        .expect("run debe volver de inmediato tras el apagado")
        .expect("sin panic");
}

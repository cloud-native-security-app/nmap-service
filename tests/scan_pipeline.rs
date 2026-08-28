//! Smoke test end-to-end (Nivel 4 de `docs/verification.md`) de la feature
//! `scan_pipeline_wiring`: ejecuta el [`ScanPipeline`] completo
//! (`consumer -> ssh -> scanner -> parser -> repository -> publisher`) contra un
//! contenedor real de `sshd` (con un stub de `nmap` instalado en
//! `/usr/local/bin/nmap`) y otro de MongoDB, levantados con `testcontainers`.
//!
//! Los casos que usan contenedores requieren Docker y van marcados
//! `#[ignore = "requiere Docker"]`: `cargo test` los omite; `cargo test --
//! --ignored` los ejecuta. Nunca se ejecutan contra `db-nmap` de producción.

use std::net::{IpAddr, Ipv4Addr};
use std::sync::Arc;
use std::time::Duration;

use secrecy::SecretString;
use testcontainers::{
    core::{CmdWaitFor, ExecCommand, IntoContainerPort, WaitFor},
    runners::AsyncRunner,
    ContainerAsync, GenericImage, ImageExt,
};

use nmap_service::domain::{CorrelationId, PortState, ScanRequest, SshCredentialsRef};
use nmap_service::messaging::consumer::InMemoryScanRequestSource;
use nmap_service::messaging::publisher::{InMemoryScanResultSink, ScanOutcome};
use nmap_service::parser;
use nmap_service::pipeline::ScanPipeline;
use nmap_service::repository::MongoRepository;
use nmap_service::scanner::ScanOptions;
use nmap_service::ssh::{self, HostKeyStore, SshTimeouts};

const SSHD_IMAGE: &str = "lscr.io/linuxserver/openssh-server";
const SSHD_TAG: &str = "version-9.9_p2-r0";
const SSH_PORT: u16 = 2222;
const USER: &str = "scanuser";
const PASS: &str = "s3cr3t-test";
const NMAP_PATH: &str = "/usr/local/bin/nmap";

const MONGO_IMAGE: &str = "mongo";
const MONGO_TAG: &str = "7";
const MONGO_PORT: u16 = 27017;
const TEST_DB: &str = "db-nmap-test";

/// XML de `nmap` fijo que escupe el stub. Reutiliza el fixture real
/// `tests/fixtures/vuln_findings.xml` (documentado en `tests/fixtures/README.md`:
/// `nmap -sV --script vuln -p 21,6667` contra el objetivo de laboratorio
/// Metasploitable 2): host up, puertos 21 y 6667 abiertos, hallazgos de
/// `--script vuln` (`ftp-vsftpd-backdoor` y `vulners`, ambos `CVE-2011-2523`).
const STUB_XML: &str = include_str!("fixtures/vuln_findings.xml");

/// Stub de `nmap`: ignora las flags y vuelca `STUB_XML` por `stdout` con
/// código 0.
fn fake_nmap() -> Vec<u8> {
    format!("#!/bin/sh\ncat <<'NMAP_STUB_EOF'\n{STUB_XML}\nNMAP_STUB_EOF\n").into_bytes()
}

fn timeouts() -> SshTimeouts {
    SshTimeouts {
        connect: Duration::from_secs(20),
        command: Duration::from_secs(40),
    }
}

fn creds() -> SshCredentialsRef {
    SshCredentialsRef::new(SecretString::from(PASS.to_owned()))
}

fn scan_request(ip: IpAddr, correlation_id: &str) -> ScanRequest {
    ScanRequest {
        correlation_id: CorrelationId::from(correlation_id),
        ip,
        network_user: USER.to_owned(),
        ssh_credentials_ref: creds(),
        has_sudo: false,
        requested_by: "analyst@example.test".to_owned(),
    }
}

async fn start_target(files: &[(&'static str, Vec<u8>)]) -> ContainerAsync<GenericImage> {
    let mut request = GenericImage::new(SSHD_IMAGE, SSHD_TAG)
        .with_exposed_port(SSH_PORT.tcp())
        .with_wait_for(WaitFor::message_on_stdout("[ls.io-init] done."))
        .with_startup_timeout(Duration::from_secs(180))
        .with_env_var("PUID", "1000")
        .with_env_var("PGID", "1000")
        .with_env_var("TZ", "Etc/UTC")
        .with_env_var("USER_NAME", USER)
        .with_env_var("USER_PASSWORD", PASS)
        .with_env_var("PASSWORD_ACCESS", "true")
        .with_env_var("SUDO_ACCESS", "true")
        .with_env_var("LOG_STDOUT", "true");

    for (path, contents) in files {
        request = request.with_copy_to(path.to_string(), contents.clone());
    }

    let container = request
        .start()
        .await
        .expect("el contenedor sshd debe arrancar");

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

fn build_pipeline(
    repo: &MongoRepository,
    sink: &Arc<InMemoryScanResultSink>,
    ssh_port: u16,
) -> ScanPipeline {
    let host_key_store: Arc<dyn HostKeyStore> = Arc::new(repo.host_key_store());
    ScanPipeline::new(
        repo.clone(),
        host_key_store,
        sink.clone(),
        ssh_port,
        timeouts(),
        ScanOptions::default(),
    )
}

#[test]
fn stub_fixture_parses_into_the_expected_scan_result() {
    // Sin Docker: garantiza que el XML del stub es un informe de nmap realista
    // que el parser convierte en un ScanResult con el contenido que esperan los
    // asertos de los tests e2e.
    let result = parser::parse(STUB_XML).expect("el fixture del stub debe parsear");

    assert_eq!(result.host, IpAddr::V4(Ipv4Addr::new(172, 18, 0, 4)));
    assert_eq!(result.ports.len(), 2);
    assert!(result.ports.iter().all(|p| p.state == PortState::Open));
    assert_eq!(
        result
            .ports
            .iter()
            .find(|p| p.port == 21)
            .unwrap()
            .version
            .as_deref(),
        Some("vsftpd 2.3.4")
    );
    // `ftp-vsftpd-backdoor` y `vulners`, ambos con `CVE-2011-2523`.
    assert_eq!(result.vulnerabilities.len(), 2);
    assert!(result
        .vulnerabilities
        .iter()
        .all(|v| v.id.as_deref() == Some("CVE-2011-2523")));
    assert!(result
        .vulnerabilities
        .iter()
        .any(|v| v.nse_script == "ftp-vsftpd-backdoor"));
    assert!(result
        .vulnerabilities
        .iter()
        .any(|v| v.nse_script == "vulners"));
}

#[tokio::test]
#[ignore = "requiere Docker"]
async fn valid_request_flows_through_pipeline_and_is_published_and_persisted() {
    let target = start_target(&[(NMAP_PATH, fake_nmap())]).await;
    let mongo = start_mongo().await;
    let (ip, port) = sshd_endpoint(&target).await;

    let repo = MongoRepository::connect(&mongo_uri(&mongo).await, TEST_DB)
        .await
        .expect("debe conectar con el contenedor mongo");
    let sink: Arc<InMemoryScanResultSink> = Arc::new(InMemoryScanResultSink::new());
    let pipeline = build_pipeline(&repo, &sink, port);

    let source = Arc::new(InMemoryScanRequestSource::from_requests([scan_request(
        ip,
        "corr-e2e-ok",
    )]));

    pipeline.run(source).await;

    // criterio 1: exactamente un Completed, con el correlation_id y el
    // ScanResult que se deduce del XML del stub.
    let published = sink.published();
    assert_eq!(published.len(), 1, "debe publicarse un único desenlace");
    let result = match &published[0] {
        ScanOutcome::Completed {
            correlation_id,
            result,
        } => {
            assert_eq!(correlation_id.as_str(), "corr-e2e-ok");
            result.clone()
        }
        other => panic!("se esperaba Completed, se obtuvo {other:?}"),
    };
    assert_eq!(result.ports.len(), 2);
    assert_eq!(
        result.ports.iter().find(|p| p.port == 21).unwrap().state,
        PortState::Open
    );
    assert_eq!(
        result.ports.iter().find(|p| p.port == 6667).unwrap().state,
        PortState::Open
    );
    assert_eq!(result.vulnerabilities.len(), 2);
    assert!(result
        .vulnerabilities
        .iter()
        .all(|v| v.id.as_deref() == Some("CVE-2011-2523")));
    assert!(result
        .vulnerabilities
        .iter()
        .any(|v| v.nse_script == "ftp-vsftpd-backdoor"));

    // criterio 1: el ScanResult quedó persistido en Mongo.
    let persisted = repo
        .find_by_correlation_id(&CorrelationId::from("corr-e2e-ok"))
        .await
        .expect("consulta a mongo")
        .expect("el ScanResult debe estar persistido");
    assert_eq!(persisted, result);

    // criterio 2: el pipeline usó el HostKeyStore respaldado por Mongo -> una
    // instancia nueva de MongoHostKeyStore ve el fingerprint TOFU del objetivo.
    let fresh_store = MongoRepository::connect(&mongo_uri(&mongo).await, TEST_DB)
        .await
        .expect("reconecta con mongo")
        .host_key_store();
    assert!(
        fresh_store
            .known_fingerprint(&ip.to_string())
            .await
            .expect("consulta al almacén")
            .is_some(),
        "el fingerprint TOFU del objetivo debe haberse guardado en Mongo"
    );
}

#[tokio::test]
#[ignore = "requiere Docker"]
async fn stage_failure_is_published_as_failed_outcome_without_crashing() {
    // Sin stub de nmap en el objetivo: la etapa `scanner` devuelve
    // ScanError::ToolNotAvailable -> el pipeline publica un Failed, no un panic.
    let target = start_target(&[]).await;
    let mongo = start_mongo().await;
    let (ip, port) = sshd_endpoint(&target).await;

    let repo = MongoRepository::connect(&mongo_uri(&mongo).await, TEST_DB)
        .await
        .expect("debe conectar con el contenedor mongo");
    let sink: Arc<InMemoryScanResultSink> = Arc::new(InMemoryScanResultSink::new());
    let pipeline = build_pipeline(&repo, &sink, port);

    let source = Arc::new(InMemoryScanRequestSource::from_requests([scan_request(
        ip,
        "corr-e2e-fail",
    )]));

    pipeline.run(source).await;

    let published = sink.published();
    assert_eq!(published.len(), 1, "debe publicarse un único desenlace");
    match &published[0] {
        ScanOutcome::Failed {
            correlation_id,
            reason,
        } => {
            assert_eq!(correlation_id.as_str(), "corr-e2e-fail");
            assert!(
                reason.to_lowercase().contains("nmap"),
                "el motivo debe describir el fallo de la etapa nmap: {reason}"
            );
            assert!(
                !reason.contains(PASS),
                "el motivo no debe filtrar la credencial: {reason}"
            );
        }
        other => panic!("se esperaba Failed, se obtuvo {other:?}"),
    }

    assert!(
        repo.find_by_correlation_id(&CorrelationId::from("corr-e2e-fail"))
            .await
            .expect("consulta a mongo")
            .is_none(),
        "un escaneo fallido no debe dejar ScanResult en Mongo"
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[ignore = "requiere Docker"]
async fn multiple_requests_are_processed_concurrently() {
    let target = start_target(&[(NMAP_PATH, fake_nmap())]).await;
    let mongo = start_mongo().await;
    let (ip, port) = sshd_endpoint(&target).await;

    let repo = MongoRepository::connect(&mongo_uri(&mongo).await, TEST_DB)
        .await
        .expect("debe conectar con el contenedor mongo");
    let sink: Arc<InMemoryScanResultSink> = Arc::new(InMemoryScanResultSink::new());

    // Warm-up TOFU: la primera conexión registra el fingerprint del objetivo,
    // para que las 3 solicitudes concurrentes compitan en el pipeline y no en el
    // upsert inicial del trust store de Mongo.
    let warmup_store: Arc<dyn HostKeyStore> = Arc::new(repo.host_key_store());
    ssh::connect(
        &ip.to_string(),
        port,
        USER,
        &creds(),
        &warmup_store,
        timeouts(),
    )
    .await
    .expect("warm-up de la conexión SSH");

    let pipeline = build_pipeline(&repo, &sink, port);

    let ids = ["corr-c1", "corr-c2", "corr-c3"];
    let source = Arc::new(InMemoryScanRequestSource::from_requests(
        ids.into_iter().map(|id| scan_request(ip, id)),
    ));

    pipeline.run(source).await;

    // criterio 4: 3 desenlaces, todos con su correlation_id, sin panic.
    let published = sink.published();
    assert_eq!(published.len(), 3, "deben publicarse 3 desenlaces");
    let mut seen: Vec<String> = published
        .iter()
        .map(|o| o.correlation_id().to_string())
        .collect();
    seen.sort();
    assert_eq!(seen, vec!["corr-c1", "corr-c2", "corr-c3"]);
    assert!(
        published
            .iter()
            .all(|o| matches!(o, ScanOutcome::Completed { .. })),
        "las 3 solicitudes deben completarse: {published:?}"
    );

    for id in ids {
        assert!(
            repo.find_by_correlation_id(&CorrelationId::from(id))
                .await
                .expect("consulta a mongo")
                .is_some(),
            "{id} debe estar persistido"
        );
    }
}

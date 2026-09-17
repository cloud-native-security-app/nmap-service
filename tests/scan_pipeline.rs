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

use nmap_service::domain::{CorrelationId, PortState, ScanRequest, SshCredentialsRef, VulnSource};
use nmap_service::enrichment::{CompositeVulnEnricher, ExploitDbEnricher, VulnEnricher};
use nmap_service::messaging::consumer::InMemoryScanRequestSource;
use nmap_service::messaging::publisher::{InMemoryScanResultSink, ScanOutcome, ScanResultSink};
use nmap_service::parser;
use nmap_service::pipeline::{PipelineConfig, ScanPipeline, ServicePorts};
use nmap_service::repository::{MongoRepository, ScanResultRepository};
use nmap_service::scanner::{NmapCliScanner, NmapScanner, ScanOptions};
use nmap_service::ssh::{self, HostKeyStore, RemoteExecutor, RusshExecutor, SshTimeouts};

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

/// CSV fixture con filas reales de Exploit-DB (ver `tests/fixtures/README.md`):
/// incluye `vsftpd 2.3.4` (CVE-2011-2523) y `UnrealIRCd 3.2.8.1` (CVE-2010-2075),
/// que son los servicios de `vuln_findings.xml`.
const EXPLOITDB_SAMPLE_CSV: &str = concat!(
    env!("CARGO_MANIFEST_DIR"),
    "/tests/fixtures/exploitdb_sample.csv"
);

async fn sample_enricher() -> Arc<dyn VulnEnricher> {
    let exploitdb = ExploitDbEnricher::from_csv_path(EXPLOITDB_SAMPLE_CSV)
        .await
        .expect("el CSV fixture de Exploit-DB debe cargar");
    Arc::new(CompositeVulnEnricher::new(vec![
        Arc::new(exploitdb) as Arc<dyn VulnEnricher>
    ]))
}

fn build_pipeline(
    repo: &MongoRepository,
    sink: &Arc<InMemoryScanResultSink>,
    enricher: Arc<dyn VulnEnricher>,
    ssh_port: u16,
) -> ScanPipeline {
    let ports = ServicePorts {
        executor: Arc::new(RusshExecutor) as Arc<dyn RemoteExecutor>,
        scanner: Arc::new(NmapCliScanner) as Arc<dyn NmapScanner>,
        repository: Arc::new(repo.clone()) as Arc<dyn ScanResultRepository>,
        enricher,
        host_key_store: Arc::new(repo.host_key_store()) as Arc<dyn HostKeyStore>,
        sink: sink.clone() as Arc<dyn ScanResultSink>,
    };
    ScanPipeline::new(
        ports,
        PipelineConfig {
            ssh_port,
            ssh_timeouts: timeouts(),
            scan_options: ScanOptions::default(),
        },
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
    let pipeline = build_pipeline(&repo, &sink, sample_enricher().await, port);

    let source = Arc::new(InMemoryScanRequestSource::from_requests([scan_request(
        ip,
        "corr-e2e-ok",
    )]));

    pipeline.run(source).await;

    // feature scan_started_event: el primer desenlace publicado es Started,
    // antes de tocar el objetivo, con el mismo correlation_id.
    let published = sink.published();
    assert_eq!(
        published.len(),
        2,
        "debe publicarse el evento started y el desenlace terminal"
    );
    match &published[0] {
        ScanOutcome::Started { correlation_id } => {
            assert_eq!(correlation_id.as_str(), "corr-e2e-ok");
        }
        other => panic!("se esperaba Started primero, se obtuvo {other:?}"),
    }

    // criterio 1: exactamente un Completed, con el correlation_id y el
    // ScanResult que se deduce del XML del stub.
    let result = match &published[1] {
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
    // Hallazgos de nmap (`--script vuln`): siguen presentes, con su origen NSE.
    assert!(
        result
            .vulnerabilities
            .iter()
            .any(|v| v.nse_script == "ftp-vsftpd-backdoor"
                && v.id.as_deref() == Some("CVE-2011-2523")
                && v.source == VulnSource::NmapNse),
        "el hallazgo NSE de nmap debe seguir presente: {:?}",
        result.vulnerabilities
    );

    // Enriquecimiento offline (feature vuln_enrichment): el puerto 6667
    // (`UnrealIRCd`) cruza con el CSV de Exploit-DB y aporta CVE-2010-2075, que
    // nmap no trajo -> sobrevive al dedup.
    let enriched: Vec<_> = result
        .vulnerabilities
        .iter()
        .filter(|v| v.source == VulnSource::ExploitDb)
        .collect();
    assert!(
        !enriched.is_empty(),
        "el ScanResult debe incluir hallazgos de enrichment: {:?}",
        result.vulnerabilities
    );
    assert!(
        enriched
            .iter()
            .any(|v| v.id.as_deref() == Some("CVE-2010-2075")),
        "enrichment debe aportar CVE-2010-2075 (UnrealIRCd): {enriched:?}"
    );
    assert!(
        enriched.iter().all(|v| v.nse_script.is_empty()
            && v.references
                .iter()
                .any(|r| r.starts_with("https://www.exploit-db.com/exploits/"))),
        "los hallazgos de Exploit-DB llevan referencia y sin script NSE: {enriched:?}"
    );

    // dedup: CVE-2011-2523 lo trajo nmap -> no debe duplicarse desde Exploit-DB.
    assert_eq!(
        result
            .vulnerabilities
            .iter()
            .filter(|v| v.id.as_deref() == Some("CVE-2011-2523"))
            .count(),
        2,
        "CVE-2011-2523 sólo desde los 2 scripts NSE, sin duplicado de Exploit-DB: {:?}",
        result.vulnerabilities
    );

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
    let pipeline = build_pipeline(&repo, &sink, sample_enricher().await, port);

    let source = Arc::new(InMemoryScanRequestSource::from_requests([scan_request(
        ip,
        "corr-e2e-fail",
    )]));

    pipeline.run(source).await;

    // feature scan_started_event: Started primero, luego el Failed terminal.
    let published = sink.published();
    assert_eq!(
        published.len(),
        2,
        "debe publicarse el evento started y el desenlace terminal"
    );
    match &published[0] {
        ScanOutcome::Started { correlation_id } => {
            assert_eq!(correlation_id.as_str(), "corr-e2e-fail");
        }
        other => panic!("se esperaba Started primero, se obtuvo {other:?}"),
    }
    match &published[1] {
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

    let pipeline = build_pipeline(&repo, &sink, sample_enricher().await, port);

    let ids = ["corr-c1", "corr-c2", "corr-c3"];
    let source = Arc::new(InMemoryScanRequestSource::from_requests(
        ids.into_iter().map(|id| scan_request(ip, id)),
    ));

    pipeline.run(source).await;

    // feature scan_started_event: cada solicitud publica su Started antes del
    // terminal -> 3 Started + 3 Completed = 6 desenlaces en total.
    let published = sink.published();
    assert_eq!(
        published.len(),
        6,
        "deben publicarse 6 desenlaces (started + terminal por cada una de las 3 solicitudes)"
    );

    let started: Vec<&ScanOutcome> = published
        .iter()
        .filter(|o| matches!(o, ScanOutcome::Started { .. }))
        .collect();
    let terminal: Vec<&ScanOutcome> = published
        .iter()
        .filter(|o| !matches!(o, ScanOutcome::Started { .. }))
        .collect();
    assert_eq!(started.len(), 3, "debe haber un Started por solicitud");

    // criterio 4: 3 desenlaces terminales, todos con su correlation_id, sin panic.
    assert_eq!(
        terminal.len(),
        3,
        "deben publicarse 3 desenlaces terminales"
    );
    let mut seen: Vec<String> = terminal
        .iter()
        .map(|o| o.correlation_id().to_string())
        .collect();
    seen.sort();
    assert_eq!(seen, vec!["corr-c1", "corr-c2", "corr-c3"]);
    assert!(
        terminal
            .iter()
            .all(|o| matches!(o, ScanOutcome::Completed { .. })),
        "las 3 solicitudes deben completarse: {terminal:?}"
    );

    // Cada correlation_id debe tener su Started antes que su desenlace
    // terminal en el orden global de publicación (el pipeline garantiza el
    // orden por tarea; con 3 tareas concurrentes el entrelazado entre tareas
    // es libre, pero el par started->terminal de una misma tarea nunca se
    // invierte).
    for id in ["corr-c1", "corr-c2", "corr-c3"] {
        let started_idx = published
            .iter()
            .position(|o| matches!(o, ScanOutcome::Started { correlation_id } if correlation_id.as_str() == id))
            .unwrap_or_else(|| panic!("falta Started para {id}"));
        let terminal_idx = published
            .iter()
            .position(|o| {
                !matches!(o, ScanOutcome::Started { .. }) && o.correlation_id().as_str() == id
            })
            .unwrap_or_else(|| panic!("falta el desenlace terminal para {id}"));
        assert!(
            started_idx < terminal_idx,
            "{id}: Started (idx {started_idx}) debe preceder al terminal (idx {terminal_idx})"
        );
    }

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

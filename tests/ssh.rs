//! Tests de integración del cliente SSH (`nmap_service::ssh`) contra un
//! contenedor real de `sshd` levantado con `testcontainers`.
//!
//! Todos requieren Docker y están marcados `#[ignore = "requiere Docker"]`:
//! `cargo test` los omite; `cargo test -- --ignored` los ejecuta.

use std::sync::Arc;
use std::time::Duration;

use secrecy::SecretString;
use testcontainers::{
    core::{IntoContainerPort, WaitFor},
    runners::AsyncRunner,
    ContainerAsync, GenericImage, ImageExt,
};

use nmap_service::domain::SshCredentialsRef;
use nmap_service::ssh::{
    connect, Fingerprint, HostKeyStore, InMemoryHostKeyStore, SshError, SshTimeouts,
};

const SSHD_IMAGE: &str = "lscr.io/linuxserver/openssh-server";
const SSHD_TAG: &str = "version-9.9_p2-r0";
const SSH_PORT: u16 = 2222;
const USER: &str = "scanuser";
const PASS: &str = "s3cr3t-test";

fn timeouts() -> SshTimeouts {
    SshTimeouts {
        connect: Duration::from_secs(20),
        command: Duration::from_secs(20),
    }
}

fn creds(password: &str) -> SshCredentialsRef {
    SshCredentialsRef::new(SecretString::from(password.to_owned()))
}

fn empty_store() -> Arc<dyn HostKeyStore> {
    Arc::new(InMemoryHostKeyStore::new())
}

async fn start_sshd() -> ContainerAsync<GenericImage> {
    GenericImage::new(SSHD_IMAGE, SSHD_TAG)
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
        .with_env_var("LOG_STDOUT", "true")
        .start()
        .await
        .expect("el contenedor sshd debe arrancar")
}

async fn endpoint(container: &ContainerAsync<GenericImage>) -> (String, u16) {
    let host = container
        .get_host()
        .await
        .expect("host del contenedor")
        .to_string();
    let port = container
        .get_host_port_ipv4(SSH_PORT)
        .await
        .expect("puerto mapeado");
    (host, port)
}

#[tokio::test]
#[ignore = "requiere Docker"]
async fn connect_succeeds_and_runs_remote_command() {
    let container = start_sshd().await;
    let (host, port) = endpoint(&container).await;
    let store = empty_store();

    let session = connect(&host, port, USER, &creds(PASS), &store, timeouts())
        .await
        .expect("la conexión debe establecerse");

    let output = session
        .run_command("echo hola-mundo")
        .await
        .expect("el comando remoto debe ejecutarse");

    assert_eq!(output.stdout, "hola-mundo\n");
    assert_eq!(output.stderr, "");
    assert_eq!(output.exit_code, 0);
}

#[tokio::test]
#[ignore = "requiere Docker"]
async fn run_command_captures_stderr_and_nonzero_exit_code() {
    let container = start_sshd().await;
    let (host, port) = endpoint(&container).await;
    let store = empty_store();

    let session = connect(&host, port, USER, &creds(PASS), &store, timeouts())
        .await
        .expect("la conexión debe establecerse");

    let output = session
        .run_command("sh -c 'echo fallo-remoto >&2; exit 7'")
        .await
        .expect("el comando remoto debe ejecutarse");

    assert_eq!(output.stdout, "");
    assert_eq!(output.stderr, "fallo-remoto\n");
    assert_eq!(output.exit_code, 7);
}

#[tokio::test]
#[ignore = "requiere Docker"]
async fn connect_with_wrong_password_fails_with_auth_failed() {
    let container = start_sshd().await;
    let (host, port) = endpoint(&container).await;
    let store = empty_store();

    let err = connect(
        &host,
        port,
        USER,
        &creds("contraseña-incorrecta"),
        &store,
        timeouts(),
    )
    .await
    .expect_err("una contraseña incorrecta debe fallar");

    assert!(
        matches!(err, SshError::AuthFailed),
        "se esperaba AuthFailed, se obtuvo {err:?}"
    );
}

#[tokio::test]
#[ignore = "requiere Docker"]
async fn first_connection_stores_fingerprint_and_second_is_accepted() {
    let container = start_sshd().await;
    let (host, port) = endpoint(&container).await;
    let store = empty_store();

    assert!(
        store
            .known_fingerprint(&host)
            .await
            .expect("consulta al almacén")
            .is_none(),
        "el almacén parte vacío"
    );

    connect(&host, port, USER, &creds(PASS), &store, timeouts())
        .await
        .expect("primera conexión");

    let remembered = store
        .known_fingerprint(&host)
        .await
        .expect("consulta al almacén");
    assert!(
        remembered.is_some(),
        "la primera conexión debe registrar el fingerprint del host"
    );

    connect(&host, port, USER, &creds(PASS), &store, timeouts())
        .await
        .expect("segunda conexión al mismo host debe aceptarse");

    assert_eq!(
        store
            .known_fingerprint(&host)
            .await
            .expect("consulta al almacén"),
        remembered,
        "el fingerprint registrado no cambia entre conexiones"
    );
}

#[tokio::test]
#[ignore = "requiere Docker"]
async fn changed_host_key_is_rejected_with_host_key_mismatch() {
    let container = start_sshd().await;
    let (host, port) = endpoint(&container).await;

    let seeded = InMemoryHostKeyStore::new();
    seeded
        .remember(&host, Fingerprint::from_sha256_bytes([0x42; 32]))
        .await
        .expect("sembrar el almacén en memoria");
    let store: Arc<dyn HostKeyStore> = Arc::new(seeded);

    let err = connect(&host, port, USER, &creds(PASS), &store, timeouts())
        .await
        .expect_err("un fingerprint distinto debe rechazar la conexión");

    assert!(
        matches!(err, SshError::HostKeyMismatch { .. }),
        "se esperaba HostKeyMismatch, se obtuvo {err:?}"
    );
}

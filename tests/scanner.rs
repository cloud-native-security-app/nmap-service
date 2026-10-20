//! Tests de integración de `nmap_service::scanner` contra un contenedor real de
//! `sshd` (`testcontainers`). En vez de `nmap` real se instala un **stub**
//! ejecutable en `/usr/local/bin/nmap` que ignora las flags, verifica que
//! recibió `-oX -` y escupe un XML de `nmap` fijo por `stdout`.
//!
//! Todos requieren Docker y están marcados `#[ignore = "requiere Docker"]`:
//! `cargo test` los omite; `cargo test -- --ignored` los ejecuta.

use std::net::IpAddr;
use std::sync::Arc;
use std::time::Duration;

use secrecy::SecretString;
use testcontainers::{
    core::{CmdWaitFor, ExecCommand, IntoContainerPort, WaitFor},
    runners::AsyncRunner,
    ContainerAsync, GenericImage, ImageExt,
};

use nmap_service::domain::SshCredentialsRef;
use nmap_service::scanner::{self, ScanError};
use nmap_service::ssh::{connect, HostKeyStore, InMemoryHostKeyStore, SshSession, SshTimeouts};

const SSHD_IMAGE: &str = "lscr.io/linuxserver/openssh-server";
const SSHD_TAG: &str = "version-9.9_p2-r0";
const SSH_PORT: u16 = 2222;
const USER: &str = "scanuser";
const PASS: &str = "s3cr3t-test";
const NMAP_PATH: &str = "/usr/local/bin/nmap";
const SUDO_PATH: &str = "/usr/local/bin/sudo";

/// Stub de `nmap`: exige `-oX -`, y si le pasan `-O` exige además correr como
/// root (así el test con `sudo` comprueba que `sudo -n` elevó de verdad).
const FAKE_NMAP: &str = r#"#!/bin/sh
seen_ox=0
want_os=0
prev=""
for arg in "$@"; do
  if [ "$prev" = "-oX" ] && [ "$arg" = "-" ]; then
    seen_ox=1
  fi
  if [ "$arg" = "-O" ]; then
    want_os=1
  fi
  prev="$arg"
done
if [ "$seen_ox" -ne 1 ]; then
  echo "fake-nmap: no recibio -oX -" >&2
  exit 2
fi
if [ "$want_os" -eq 1 ] && [ "$(id -u)" -ne 0 ]; then
  echo "TCP/IP fingerprinting (for OS scan) requires root privileges." >&2
  exit 1
fi
cat <<'XML'
<?xml version="1.0"?>
<nmaprun scanner="nmap" args="fake-nmap" version="7.94">
<host><status state="up"/><address addr="127.0.0.1" addrtype="ipv4"/>
<ports><port protocol="tcp" portid="22"><state state="open"/>
<service name="ssh" product="OpenSSH" version="9.6p1"/></port></ports>
</host>
<runstats><finished exit="success"/></runstats>
</nmaprun>
XML
"#;

/// Stub de `sudo` que siempre deniega como si `sudo -n` no pudiera escalar.
const FAKE_SUDO_DENY: &str = r#"#!/bin/sh
echo "sudo: a password is required" >&2
exit 1
"#;

/// Ejecuta `argv` dentro del contenedor (como root) y espera a que termine con
/// código 0.
async fn exec_ok(container: &ContainerAsync<GenericImage>, argv: &[&str], what: &str) {
    container
        .exec(
            ExecCommand::new(argv.iter().copied())
                .with_cmd_ready_condition(CmdWaitFor::exit_code(0)),
        )
        .await
        .unwrap_or_else(|e| panic!("{what} falló: {e}"));
}

/// Arranca el contenedor de `sshd`, copia los ficheros indicados
/// (`(ruta, contenido)`) y les da permiso de ejecución (`with_copy_to` deja
/// 0644 en `testcontainers` 0.24).
///
/// Con `passwordless_sudo == true` se reescribe, vía `exec` como root, la regla
/// de `sudo` del usuario a `NOPASSWD`: la imagen sólo da `sudo` sin contraseña
/// cuando el usuario **no** tiene contraseña, pero aquí sí la necesitamos para
/// la autenticación SSH del cliente (que sólo soporta contraseña).
async fn start_target(
    passwordless_sudo: bool,
    files: &[(&'static str, &'static str)],
) -> ContainerAsync<GenericImage> {
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
        request = request.with_copy_to(path.to_string(), contents.as_bytes().to_vec());
    }

    let container = request
        .start()
        .await
        .expect("el contenedor sshd debe arrancar");

    for (path, _) in files {
        exec_ok(&container, &["chmod", "0755", path], "chmod del stub").await;
    }

    if passwordless_sudo {
        exec_ok(
            &container,
            &[
                "sh",
                "-c",
                &format!(
                    "sed -i '/^{USER} ALL=/d' /etc/sudoers && \
                     printf '%s\\n' '{USER} ALL=(ALL) NOPASSWD: ALL' >> /etc/sudoers"
                ),
            ],
            "configurar NOPASSWD sudo",
        )
        .await;
    }

    container
}

async fn open_session(container: &ContainerAsync<GenericImage>) -> SshSession {
    let host = container
        .get_host()
        .await
        .expect("host del contenedor")
        .to_string();
    let port = container
        .get_host_port_ipv4(SSH_PORT)
        .await
        .expect("puerto mapeado");

    let store: Arc<dyn HostKeyStore> = Arc::new(InMemoryHostKeyStore::new());
    let timeouts = SshTimeouts {
        connect: Duration::from_secs(20),
        command: Duration::from_secs(40),
    };
    let creds = SshCredentialsRef::new(SecretString::from(PASS.to_owned()));

    connect(&host, port, USER, &creds, &store, timeouts)
        .await
        .expect("la sesión SSH debe establecerse")
}

fn loopback() -> IpAddr {
    "127.0.0.1".parse().expect("IP de loopback válida")
}

#[tokio::test]
#[ignore = "requiere Docker"]
async fn run_scan_without_sudo_returns_the_stub_xml() {
    let container = start_target(false, &[(NMAP_PATH, FAKE_NMAP)]).await;
    let session = open_session(&container).await;

    let xml = scanner::run_scan(&session, loopback(), false)
        .await
        .expect("run_scan sin sudo debe devolver el XML del stub");

    assert!(xml.contains("<nmaprun"), "no parece XML de nmap: {xml}");
    assert!(xml.contains("portid=\"22\""), "{xml}");
}

#[tokio::test]
#[ignore = "requiere Docker"]
async fn run_scan_with_sudo_elevates_and_returns_xml() {
    let container = start_target(true, &[(NMAP_PATH, FAKE_NMAP)]).await;
    let session = open_session(&container).await;

    // El stub exige uid 0 cuando ve `-O`: si `sudo -n` no hubiera elevado,
    // devolvería ScanError::NmapFailed en vez del XML.
    let xml = scanner::run_scan(&session, loopback(), true)
        .await
        .expect("run_scan con sudo debe funcionar y correr como root");

    assert!(xml.contains("<nmaprun"), "{xml}");
}

#[tokio::test]
#[ignore = "requiere Docker"]
async fn run_scan_without_nmap_installed_is_tool_not_available() {
    let container = start_target(false, &[]).await;
    let session = open_session(&container).await;

    let err = scanner::run_scan(&session, loopback(), false)
        .await
        .expect_err("sin nmap instalado debe fallar");

    assert!(
        matches!(err, ScanError::ToolNotAvailable),
        "se esperaba ToolNotAvailable, se obtuvo {err:?}"
    );
}

#[tokio::test]
#[ignore = "requiere Docker"]
async fn run_scan_with_sudo_but_denied_is_insufficient_privileges() {
    let container = start_target(
        false,
        &[(NMAP_PATH, FAKE_NMAP), (SUDO_PATH, FAKE_SUDO_DENY)],
    )
    .await;
    let session = open_session(&container).await;

    let err = scanner::run_scan(&session, loopback(), true)
        .await
        .expect_err("sudo denegado debe fallar");

    assert!(
        matches!(err, ScanError::InsufficientPrivileges),
        "se esperaba InsufficientPrivileges, se obtuvo {err:?}"
    );
}

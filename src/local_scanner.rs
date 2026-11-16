//! Ejecución **local** de `nmap` (modo `network`): corre el binario `nmap`
//! instalado en la propia imagen de `ms-nmap` contra la IP del objetivo, sin
//! SSH ni credenciales.
//!
//! Es el contrapunto de [`crate::scanner`], que ejecuta `nmap` en el objetivo
//! por SSH. El puerto es [`LocalScanner`] (`Arc<dyn LocalScanner>` en el
//! pipeline) y el adaptador de producción es [`LocalNmapScanner`].
//!
//! # Sin privilegios
//!
//! El escaneo es de **conexión TCP** (`-sT`): no usa raw sockets, no pide
//! `CAP_NET_RAW`, no usa `sudo` y nunca añade `-O` (detección de SO, que exige
//! root). Corre como usuario no-root en un contenedor sin capacidades extra
//! (comprobado en NS-00 con `--cap-drop ALL`). La línea de comandos es
//! `nmap -sT -sV --script vuln -T<n> -oX - <ip>`: la categoría `vuln` (nunca
//! `exploit`/`intrusive`, ver `docs/security-scope.md`) y salida XML por
//! `stdout`, que reutiliza [`crate::parser`].
//!
//! # Seguridad
//!
//! - Los argumentos se pasan como `argv` separado a [`tokio::process::Command`];
//!   nunca se interpola nada en una cadena de shell. El objetivo es un
//!   [`IpAddr`] ya validado, así que su texto sólo contiene dígitos, `.`, `:` y
//!   hex.
//! - El proceso se mata si se descarta el futuro (`kill_on_drop`): el timeout o
//!   una cancelación del pipeline (`tokio::select!`) no dejan un `nmap` huérfano.
//! - El `stderr` que viaja en [`LocalScanError::NmapFailed`] se trunca.

use std::ffi::OsString;
use std::net::IpAddr;
use std::process::Stdio;
use std::time::Duration;

use tokio::process::Command;

use crate::scanner::{ScanOptions, Timing};

/// Nombre del binario `nmap` que se resuelve en el `PATH` de la imagen.
const NMAP_PROGRAM: &str = "nmap";

/// `stderr` de `nmap` incluido en [`LocalScanError::NmapFailed`] se trunca a este
/// número de bytes.
const STDERR_MAX_BYTES: usize = 2000;

/// Error al ejecutar `nmap` localmente. Ningún mensaje contiene datos sensibles
/// (en modo `network` no hay credenciales).
#[derive(Debug, thiserror::Error)]
pub enum LocalScanError {
    /// El binario `nmap` no existe en este contenedor.
    #[error("nmap no está instalado en este contenedor")]
    ToolNotAvailable,

    /// El escaneo superó el tiempo máximo y se mató el proceso.
    #[error("el escaneo local de nmap superó el tiempo máximo ({0:?})")]
    Timeout(Duration),

    /// `nmap` terminó con un código de error.
    #[error("nmap terminó con error (código {exit_code}): {stderr}")]
    NmapFailed {
        /// Código de salida (`-1` si lo mató una señal).
        exit_code: i32,
        /// Comienzo de `stderr` (truncado).
        stderr: String,
    },

    /// Fallo de IO al lanzar el proceso o leer su salida.
    #[error("error de E/S al ejecutar nmap: {0}")]
    Io(String),
}

/// Puerto (hexagonal) del escaneo local del modo `network`.
///
/// Abstrae la ejecución de `nmap` en este contenedor para poder inyectar el
/// adaptador real ([`LocalNmapScanner`]) o un doble en los tests del pipeline.
#[async_trait::async_trait]
pub trait LocalScanner: Send + Sync {
    /// Escanea `target_ip` y devuelve el XML crudo de `nmap` (`-oX -`).
    /// `options.timing` fija la plantilla `-T<n>`.
    ///
    /// # Errores
    ///
    /// Ver [`LocalScanError`].
    async fn run_scan(
        &self,
        target_ip: IpAddr,
        options: &ScanOptions,
    ) -> Result<String, LocalScanError>;
}

/// Adaptador de producción de [`LocalScanner`]: lanza el binario `nmap` local.
#[derive(Debug, Clone)]
pub struct LocalNmapScanner {
    program: OsString,
    timeout: Duration,
}

impl LocalNmapScanner {
    /// Usa el `nmap` del `PATH` y `timeout` como tiempo máximo por escaneo.
    pub fn new(timeout: Duration) -> Self {
        Self::with_program(NMAP_PROGRAM, timeout)
    }

    /// Como [`new`](Self::new) pero con otro ejecutable (tests con un `nmap`
    /// falso).
    pub fn with_program(program: impl Into<OsString>, timeout: Duration) -> Self {
        Self {
            program: program.into(),
            timeout,
        }
    }
}

#[async_trait::async_trait]
impl LocalScanner for LocalNmapScanner {
    async fn run_scan(
        &self,
        target_ip: IpAddr,
        options: &ScanOptions,
    ) -> Result<String, LocalScanError> {
        let args = build_args(target_ip, options.timing);
        tracing::debug!(?args, "ejecutando nmap localmente");

        let child = Command::new(&self.program)
            .args(&args)
            .stdin(Stdio::null())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .kill_on_drop(true)
            .spawn()
            .map_err(|err| match err.kind() {
                std::io::ErrorKind::NotFound => LocalScanError::ToolNotAvailable,
                _ => LocalScanError::Io(err.to_string()),
            })?;

        // Si vence el timeout se descarta el futuro de `wait_with_output`, que
        // posee el `Child`: `kill_on_drop` mata el proceso.
        let output = tokio::time::timeout(self.timeout, child.wait_with_output())
            .await
            .map_err(|_| LocalScanError::Timeout(self.timeout))?
            .map_err(|err| LocalScanError::Io(err.to_string()))?;

        if output.status.success() {
            return Ok(String::from_utf8_lossy(&output.stdout).into_owned());
        }
        Err(LocalScanError::NmapFailed {
            exit_code: output.status.code().unwrap_or(-1),
            stderr: truncate_utf8(&String::from_utf8_lossy(&output.stderr), STDERR_MAX_BYTES),
        })
    }
}

/// `argv` de `nmap` (sin el nombre del programa) para un escaneo `network`.
///
/// Fijo y sin privilegios: `-sT -sV --script vuln -T<n> -oX - <ip>`. Nunca `-O`,
/// `-sS`, `-sU` ni `sudo`.
pub fn build_args(target_ip: IpAddr, timing: Timing) -> Vec<String> {
    vec![
        "-sT".to_owned(),
        "-sV".to_owned(),
        "--script".to_owned(),
        "vuln".to_owned(),
        timing.flag().to_owned(),
        "-oX".to_owned(),
        "-".to_owned(),
        target_ip.to_string(),
    ]
}

/// Trunca `s` a como mucho `max` bytes respetando los límites UTF-8; si trunca,
/// añade una elipsis.
fn truncate_utf8(s: &str, max: usize) -> String {
    if s.len() <= max {
        return s.to_owned();
    }
    let mut end = max;
    while !s.is_char_boundary(end) {
        end -= 1;
    }
    format!("{}…", &s[..end])
}

#[cfg(test)]
mod tests {
    use std::net::IpAddr;
    use std::os::unix::fs::PermissionsExt;
    use std::path::{Path, PathBuf};
    use std::sync::atomic::{AtomicUsize, Ordering};
    use std::time::Duration;

    use super::*;
    use crate::scanner::{ScanOptions, Timing};

    static NEXT_DIR: AtomicUsize = AtomicUsize::new(0);

    fn ip(s: &str) -> IpAddr {
        s.parse().expect("IP de prueba válida")
    }

    /// Directorio temporal propio de cada test.
    fn scratch_dir() -> PathBuf {
        let dir = std::env::temp_dir().join(format!(
            "ms-nmap-local-scanner-{}-{}",
            std::process::id(),
            NEXT_DIR.fetch_add(1, Ordering::SeqCst)
        ));
        std::fs::create_dir_all(&dir).expect("crea el directorio temporal");
        dir
    }

    /// Escribe un script ejecutable que hace de `nmap` falso.
    fn fake_nmap(dir: &Path, body: &str) -> PathBuf {
        let path = dir.join("nmap");
        std::fs::write(&path, format!("#!/bin/sh\n{body}\n")).expect("escribe el script");
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o755)).expect("chmod +x");
        path
    }

    fn scanner(program: &Path, timeout: Duration) -> LocalNmapScanner {
        LocalNmapScanner::with_program(program, timeout)
    }

    #[test]
    fn argv_is_a_connect_scan_with_service_and_vuln_detection_and_xml_on_stdout() {
        assert_eq!(
            build_args(ip("192.0.2.10"), Timing::Aggressive),
            [
                "-sT",
                "-sV",
                "--script",
                "vuln",
                "-T4",
                "-oX",
                "-",
                "192.0.2.10"
            ]
        );
    }

    #[test]
    fn argv_never_asks_for_privileges_or_os_detection() {
        for timing in [
            Timing::Paranoid,
            Timing::Sneaky,
            Timing::Polite,
            Timing::Normal,
            Timing::Aggressive,
            Timing::Insane,
        ] {
            let args = build_args(ip("192.0.2.10"), timing);
            assert!(!args.iter().any(|a| a == "-O" || a == "sudo"), "{args:?}");
            // Un escaneo SYN/UDP/de SO requeriría raw sockets.
            assert!(!args.iter().any(|a| a == "-sS" || a == "-sU"), "{args:?}");
            assert!(args.contains(&"-sT".to_owned()), "{args:?}");
        }
    }

    #[test]
    fn the_timing_template_comes_from_the_scan_options() {
        let options = ScanOptions {
            timing: Timing::Normal,
            ..ScanOptions::default()
        };
        let args = build_args(ip("192.0.2.10"), options.timing);
        assert!(args.contains(&"-T3".to_owned()), "{args:?}");
    }

    #[test]
    fn the_target_is_the_last_argv_element_and_ipv6_stays_a_single_element() {
        let args = build_args(ip("2001:db8::1"), Timing::Polite);
        assert_eq!(args.last().map(String::as_str), Some("2001:db8::1"));
        assert_eq!(args.iter().filter(|a| a.contains(':')).count(), 1);
    }

    #[tokio::test]
    async fn run_scan_passes_the_argv_verbatim_without_a_shell_and_returns_stdout() {
        let dir = scratch_dir();
        let argv_file = dir.join("argv");
        let program = fake_nmap(
            &dir,
            &format!(
                "for a in \"$@\"; do echo \"$a\" >> '{}'; done\necho '<nmaprun/>'",
                argv_file.display()
            ),
        );

        let xml = scanner(&program, Duration::from_secs(5))
            .run_scan(ip("192.0.2.10"), &ScanOptions::default())
            .await
            .expect("el escaneo termina bien");

        assert_eq!(xml.trim(), "<nmaprun/>");
        let recorded: Vec<String> = std::fs::read_to_string(&argv_file)
            .expect("el script registró argv")
            .lines()
            .map(str::to_owned)
            .collect();
        assert_eq!(recorded, build_args(ip("192.0.2.10"), Timing::Polite));
    }

    #[tokio::test]
    async fn a_missing_binary_is_tool_not_available() {
        let dir = scratch_dir();
        let err = scanner(&dir.join("does-not-exist"), Duration::from_secs(5))
            .run_scan(ip("192.0.2.10"), &ScanOptions::default())
            .await
            .expect_err("sin binario no hay escaneo");
        assert!(matches!(err, LocalScanError::ToolNotAvailable), "{err:?}");
    }

    #[tokio::test]
    async fn a_non_zero_exit_is_nmap_failed_with_a_truncated_stderr() {
        let dir = scratch_dir();
        let program = fake_nmap(&dir, "head -c 5000 /dev/zero | tr '\\0' 'x' >&2\nexit 3");

        let err = scanner(&program, Duration::from_secs(5))
            .run_scan(ip("192.0.2.10"), &ScanOptions::default())
            .await
            .expect_err("exit code distinto de cero");

        match err {
            LocalScanError::NmapFailed { exit_code, stderr } => {
                assert_eq!(exit_code, 3);
                assert!(stderr.len() < 2100, "stderr sin truncar: {}", stderr.len());
            }
            other => panic!("se esperaba NmapFailed, se obtuvo {other:?}"),
        }
    }

    #[tokio::test]
    async fn exceeding_the_timeout_is_reported_and_the_child_process_is_killed() {
        let dir = scratch_dir();
        let pid_file = dir.join("pid");
        let program = fake_nmap(
            &dir,
            &format!("echo $$ > '{}'\nexec sleep 30", pid_file.display()),
        );

        let started = std::time::Instant::now();
        let err = scanner(&program, Duration::from_millis(300))
            .run_scan(ip("192.0.2.10"), &ScanOptions::default())
            .await
            .expect_err("el escaneo excede el timeout");

        assert!(matches!(err, LocalScanError::Timeout(_)), "{err:?}");
        assert!(started.elapsed() < Duration::from_secs(10));

        let pid = std::fs::read_to_string(&pid_file)
            .expect("el script registró su pid")
            .trim()
            .to_owned();
        let proc_dir = PathBuf::from(format!("/proc/{pid}"));
        for _ in 0..50 {
            if !proc_dir.exists() {
                return;
            }
            tokio::time::sleep(Duration::from_millis(100)).await;
        }
        panic!("el proceso nmap {pid} sigue vivo tras el timeout (kill_on_drop)");
    }
}

//! Orquesta la ejecución remota de `nmap` sobre una [`RemoteSession`] ya
//! establecida y devuelve el XML crudo que `nmap` escribe en `stdout`.
//!
//! El comando se construye a partir de [`ScanOptions`]. Los valores por defecto
//! de `ScanOptions` **sí están autorizados** por `docs/security-scope.md` (a
//! diferencia de los timeouts de `config`, feature 2, que no pueden tener
//! default): sólo detección de servicios/versión (`-sV`), NSE de la categoría
//! `vuln` (nunca `exploit`/`intrusive`), salida XML por `stdout` (`-oX -`) y un
//! timing conservador (`-T2`, [`Timing::Polite`]) para minimizar el riesgo de
//! degradar el servicio del objetivo.
//!
//! Si `has_sudo` es `true` se antepone `sudo -n` (no interactivo: falla rápido
//! si `sudo` pide contraseña o terminal, en vez de colgarse) y se añade `-O`
//! (detección de SO, que requiere root remoto). Si es `false`, ni `sudo` ni
//! `-O`. Ver `docs/security-scope.md`, §"Escalación de privilegios (sudo)".

use std::net::IpAddr;

use crate::ssh::{CommandOutput, RemoteSession, SshError};

/// `stderr` de `nmap` incluido en [`ScanError::NmapFailed`] se trunca a este
/// número de bytes para no arrastrar salidas gigantes a los logs/mensajes.
const STDERR_MAX_BYTES: usize = 2000;

/// Plantilla de temporización de `nmap` (`-T0` a `-T5`).
///
/// El valor por defecto de [`ScanOptions`] es [`Timing::Polite`] (`-T2`):
/// `docs/security-scope.md` exige un default conservador y desaconseja
/// explícitamente `-T4`/`-T5` como default para no degradar el servicio del
/// objetivo.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Timing {
    /// `-T0`: extremadamente lento (evasión de IDS).
    Paranoid,
    /// `-T1`: muy lento (evasión de IDS).
    Sneaky,
    /// `-T2`: lento, usa menos ancho de banda y recursos del objetivo. Default.
    Polite,
    /// `-T3`: ritmo por defecto de `nmap`.
    Normal,
    /// `-T4`: rápido; asume una red fiable. Desaconsejado como default.
    Aggressive,
    /// `-T5`: muy rápido; puede sacrificar precisión. Desaconsejado como default.
    Insane,
}

impl Timing {
    /// Flag `-T<n>` correspondiente para la línea de comandos de `nmap`.
    fn flag(self) -> &'static str {
        match self {
            Timing::Paranoid => "-T0",
            Timing::Sneaky => "-T1",
            Timing::Polite => "-T2",
            Timing::Normal => "-T3",
            Timing::Aggressive => "-T4",
            Timing::Insane => "-T5",
        }
    }
}

/// Opciones con las que [`run_scan_with`] construye la línea de comandos de
/// `nmap`.
///
/// [`ScanOptions::default`] devuelve la configuración estándar de `ms-nmap`:
/// `-sV --script vuln` y `-T2`. Estos defaults están autorizados por
/// `docs/security-scope.md`. Si se personaliza `detection_flags`, sigue siendo
/// responsabilidad de quien llama mantenerse dentro de la **detección**
/// permitida (`-sV`, `--script vuln`): nunca scripts NSE de categoría
/// `exploit`/`intrusive`.
#[derive(Debug, Clone)]
pub struct ScanOptions {
    /// Flags de detección que se pasan a `nmap`, en orden. Default:
    /// `["-sV", "--script", "vuln"]`.
    pub detection_flags: Vec<String>,
    /// Plantilla de temporización (`-T`). Default: [`Timing::Polite`] (`-T2`).
    pub timing: Timing,
}

impl Default for ScanOptions {
    fn default() -> Self {
        Self {
            detection_flags: vec!["-sV".to_owned(), "--script".to_owned(), "vuln".to_owned()],
            timing: Timing::Polite,
        }
    }
}

/// Error al ejecutar `nmap` en el host objetivo.
///
/// Cada modo de fallo relevante es una variante distinta; no hay un error
/// genérico. Ningún mensaje contiene credenciales (aquí no se manejan; ver
/// `docs/security-scope.md`).
#[derive(Debug, thiserror::Error)]
pub enum ScanError {
    /// `nmap` no está instalado (o no está en el `PATH`/`secure_path`) en el
    /// host objetivo. Se detecta por código de salida `127` o por `stderr`
    /// tipo `command not found` / `not found`.
    #[error("nmap no está disponible en el host objetivo")]
    ToolNotAvailable,

    /// Se solicitó `sudo` (`has_sudo == true`) pero `sudo -n` no pudo escalar
    /// privilegios sin intervención (pide contraseña o terminal).
    #[error("sudo -n no pudo escalar privilegios en el host objetivo (requiere intervención interactiva)")]
    InsufficientPrivileges,

    /// Fallo del transporte SSH al lanzar el comando o recolectar su salida.
    #[error(transparent)]
    Ssh(#[from] SshError),

    /// `nmap` se ejecutó pero terminó con un código de error.
    #[error("nmap terminó con error (código {exit_code}): {stderr}")]
    NmapFailed {
        /// Código de salida devuelto por `nmap` (`-1` si el canal se cerró sin
        /// `exit-status`, p. ej. terminación por señal).
        exit_code: i32,
        /// Comienzo de `stderr` de `nmap` (truncado a unos pocos KB).
        stderr: String,
    },
}

/// Ejecuta `nmap` sobre `session` contra `target_ip` con las opciones estándar
/// ([`ScanOptions::default`]) y devuelve el XML que `nmap` escribe en `stdout`.
///
/// Equivale a [`run_scan_with`] con `&ScanOptions::default()`.
///
/// `session` es cualquier [`RemoteSession`]: la [`crate::ssh::SshSession`] real
/// coerciona a `&dyn RemoteSession` en el sitio de llamada.
///
/// # Errores
///
/// Ver [`ScanError`]: `nmap` ausente, `sudo -n` sin privilegios, fallo de
/// transporte SSH, o `nmap` terminando con error.
pub async fn run_scan(
    session: &dyn RemoteSession,
    target_ip: IpAddr,
    has_sudo: bool,
) -> Result<String, ScanError> {
    run_scan_with(session, target_ip, has_sudo, &ScanOptions::default()).await
}

/// Como [`run_scan`], pero con [`ScanOptions`] explícitas.
///
/// Construye la línea de comandos (`sudo -n` y `-O` sólo si `has_sudo`; siempre
/// `-oX -` y `target_ip` al final), la ejecuta vía
/// [`RemoteSession::run_command`] e interpreta la salida.
///
/// `target_ip` es un [`IpAddr`], por lo que su representación textual sólo
/// contiene dígitos, puntos y `:`; no se interpola ninguna cadena arbitraria en
/// el comando.
///
/// # Errores
///
/// Ver [`ScanError`].
pub async fn run_scan_with(
    session: &dyn RemoteSession,
    target_ip: IpAddr,
    has_sudo: bool,
    options: &ScanOptions,
) -> Result<String, ScanError> {
    let command = build_command(target_ip, has_sudo, options);
    tracing::debug!(%command, "ejecutando nmap en el host objetivo");
    let output = session.run_command(&command).await?;
    interpret(output, has_sudo)
}

/// Puerto (hexagonal) para la etapa de escaneo del pipeline.
///
/// Abstrae la ejecución de `nmap` tras un trait dyn-compatible
/// (`Arc<dyn NmapScanner>`) para poder inyectar el adaptador real
/// ([`NmapCliScanner`]) o un doble en tests. La sesión sobre la que se ejecuta
/// llega como [`RemoteSession`], no como un tipo concreto.
#[async_trait::async_trait]
pub trait NmapScanner: Send + Sync {
    /// Ejecuta `nmap` sobre `session` contra `target_ip` con `options` y
    /// devuelve el XML crudo.
    ///
    /// # Errores
    ///
    /// Ver [`ScanError`].
    async fn run_scan(
        &self,
        session: &dyn RemoteSession,
        target_ip: IpAddr,
        has_sudo: bool,
        options: &ScanOptions,
    ) -> Result<String, ScanError>;
}

/// Adaptador de producción de [`NmapScanner`]: delega en la función libre
/// [`run_scan_with`] (invoca el binario `nmap` en el objetivo vía SSH).
#[derive(Debug, Clone, Copy, Default)]
pub struct NmapCliScanner;

#[async_trait::async_trait]
impl NmapScanner for NmapCliScanner {
    async fn run_scan(
        &self,
        session: &dyn RemoteSession,
        target_ip: IpAddr,
        has_sudo: bool,
        options: &ScanOptions,
    ) -> Result<String, ScanError> {
        run_scan_with(session, target_ip, has_sudo, options).await
    }
}

/// Construye la línea de comandos de `nmap` a partir de las opciones.
///
/// - `has_sudo == true`  -> prefijo `sudo -n ` y flag `-O` (detección de SO).
/// - `has_sudo == false` -> sin `sudo` y sin `-O`.
/// - Siempre: flags de detección, `-T<n>`, `-oX -` y la IP objetivo al final.
fn build_command(target_ip: IpAddr, has_sudo: bool, options: &ScanOptions) -> String {
    let mut parts: Vec<String> = Vec::new();

    if has_sudo {
        parts.push("sudo".to_owned());
        parts.push("-n".to_owned());
    }

    parts.push("nmap".to_owned());
    parts.extend(options.detection_flags.iter().cloned());
    parts.push(options.timing.flag().to_owned());

    if has_sudo {
        parts.push("-O".to_owned());
    }

    parts.push("-oX".to_owned());
    parts.push("-".to_owned());
    parts.push(target_ip.to_string());

    parts.join(" ")
}

/// Traduce la salida cruda del comando a `Ok(xml)` o a la variante de
/// [`ScanError`] correspondiente.
///
/// Orden de decisión: herramienta ausente -> `sudo` denegado (sólo si se pidió
/// `sudo`) -> éxito (`exit_code == 0`) -> `nmap` falló.
fn interpret(output: CommandOutput, has_sudo: bool) -> Result<String, ScanError> {
    if looks_like_missing_tool(&output) {
        return Err(ScanError::ToolNotAvailable);
    }

    if has_sudo && output.exit_code != 0 && looks_like_sudo_denied(&output.stderr) {
        return Err(ScanError::InsufficientPrivileges);
    }

    if output.exit_code == 0 {
        return Ok(output.stdout);
    }

    Err(ScanError::NmapFailed {
        exit_code: output.exit_code,
        stderr: truncate_utf8(&output.stderr, STDERR_MAX_BYTES),
    })
}

/// `true` si la salida indica que `nmap` no está instalado en el objetivo.
fn looks_like_missing_tool(output: &CommandOutput) -> bool {
    if output.exit_code == 127 {
        return true;
    }
    if output.exit_code == 0 {
        return false;
    }
    let stderr = output.stderr.to_lowercase();
    stderr.contains("command not found") || stderr.contains("nmap: not found")
}

/// `true` si `stderr` corresponde a `sudo -n` incapaz de escalar sin
/// contraseña o terminal.
fn looks_like_sudo_denied(stderr: &str) -> bool {
    let stderr = stderr.to_lowercase();
    stderr.contains("password is required")
        || stderr.contains("a terminal is required")
        || stderr.contains("no tty present")
        || stderr.contains("sudo: sorry")
}

/// Trunca `s` a como mucho `max` bytes respetando los límites de carácter
/// UTF-8; si trunca, añade una elipsis.
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
    use super::*;

    fn ip() -> IpAddr {
        "198.51.100.7".parse().expect("IP de prueba válida")
    }

    fn output(stdout: &str, stderr: &str, exit_code: i32) -> CommandOutput {
        CommandOutput {
            stdout: stdout.to_owned(),
            stderr: stderr.to_owned(),
            exit_code,
        }
    }

    #[test]
    fn build_command_with_sudo_prefixes_sudo_n_and_adds_os_detection() {
        let cmd = build_command(ip(), true, &ScanOptions::default());

        assert!(cmd.starts_with("sudo -n nmap "), "{cmd}");
        assert!(cmd.split(' ').any(|t| t == "-O"), "{cmd}");
        assert!(cmd.ends_with(" 198.51.100.7"), "{cmd}");
    }

    #[test]
    fn build_command_without_sudo_omits_sudo_and_os_detection() {
        let cmd = build_command(ip(), false, &ScanOptions::default());

        assert!(!cmd.contains("sudo"), "{cmd}");
        assert!(!cmd.split(' ').any(|t| t == "-O"), "{cmd}");
        assert!(cmd.starts_with("nmap "), "{cmd}");
    }

    #[test]
    fn build_command_always_has_detection_flags_xml_timing_and_target() {
        for has_sudo in [true, false] {
            let cmd = build_command(ip(), has_sudo, &ScanOptions::default());

            assert!(cmd.contains("-sV"), "{cmd}");
            assert!(cmd.contains("--script vuln"), "{cmd}");
            assert!(cmd.contains("-oX -"), "{cmd}");
            assert!(cmd.contains("-T2"), "{cmd}");
            assert!(cmd.contains("198.51.100.7"), "{cmd}");
        }
    }

    #[test]
    fn default_timing_is_conservative() {
        let opts = ScanOptions::default();

        assert_eq!(opts.timing.flag(), "-T2");
        assert!(
            !matches!(opts.timing, Timing::Aggressive | Timing::Insane),
            "el timing por defecto no debe ser -T4/-T5"
        );
        let cmd = build_command(ip(), false, &opts);
        assert!(!cmd.contains("-T4") && !cmd.contains("-T5"), "{cmd}");
    }

    #[test]
    fn custom_options_are_reflected_in_the_command() {
        let opts = ScanOptions {
            detection_flags: vec!["-sV".to_owned()],
            timing: Timing::Normal,
        };
        let cmd = build_command(ip(), false, &opts);

        assert!(cmd.contains("-T3"), "{cmd}");
        assert!(!cmd.contains("--script"), "{cmd}");
    }

    #[test]
    fn interpret_exit_127_is_tool_not_available() {
        let err = interpret(output("", "bash: nmap: command not found", 127), false)
            .expect_err("127 debe ser ToolNotAvailable");

        assert!(matches!(err, ScanError::ToolNotAvailable), "{err:?}");
    }

    #[test]
    fn interpret_sudo_missing_nmap_stderr_is_tool_not_available() {
        let err = interpret(output("", "sudo: nmap: command not found", 1), true)
            .expect_err("nmap ausente vía sudo");

        assert!(matches!(err, ScanError::ToolNotAvailable), "{err:?}");
    }

    #[test]
    fn interpret_sudo_password_required_is_insufficient_privileges() {
        let err = interpret(output("", "sudo: a password is required", 1), true)
            .expect_err("sudo pide password");

        assert!(matches!(err, ScanError::InsufficientPrivileges), "{err:?}");
    }

    #[test]
    fn interpret_sudo_terminal_required_is_insufficient_privileges() {
        let err = interpret(
            output("", "sudo: a terminal is required to read the password", 1),
            true,
        )
        .expect_err("sudo pide terminal");

        assert!(matches!(err, ScanError::InsufficientPrivileges), "{err:?}");
    }

    #[test]
    fn interpret_sudo_like_stderr_is_ignored_when_sudo_not_requested() {
        let err = interpret(output("", "sudo: a password is required", 1), false)
            .expect_err("sin has_sudo esto es un fallo genérico de nmap");

        assert!(
            matches!(err, ScanError::NmapFailed { exit_code: 1, .. }),
            "{err:?}"
        );
    }

    #[test]
    fn interpret_success_returns_stdout_xml() {
        let xml = "<?xml version=\"1.0\"?><nmaprun></nmaprun>";

        let out = interpret(output(xml, "warning: algo", 0), true).expect("exit 0 es éxito");

        assert_eq!(out, xml);
    }

    #[test]
    fn interpret_other_nonzero_exit_is_nmap_failed_with_truncated_stderr() {
        let long = "e".repeat(5000);

        let err = interpret(output("", &long, 2), false).expect_err("exit 2 sin patrón conocido");

        match err {
            ScanError::NmapFailed { exit_code, stderr } => {
                assert_eq!(exit_code, 2);
                assert!(
                    stderr.len() <= STDERR_MAX_BYTES + 4,
                    "stderr no truncado: {} bytes",
                    stderr.len()
                );
            }
            other => panic!("se esperaba NmapFailed, se obtuvo {other:?}"),
        }
    }

    #[test]
    fn interpret_signal_terminated_is_nmap_failed() {
        let err = interpret(output("", "", -1), false).expect_err("exit -1 es fallo");

        assert!(
            matches!(err, ScanError::NmapFailed { exit_code: -1, .. }),
            "{err:?}"
        );
    }

    #[test]
    fn scan_error_display_does_not_mention_credentials() {
        let rendered = [
            ScanError::ToolNotAvailable.to_string(),
            ScanError::InsufficientPrivileges.to_string(),
            ScanError::NmapFailed {
                exit_code: 1,
                stderr: "quit".to_owned(),
            }
            .to_string(),
        ]
        .join(" | ");

        for banned in ["password", "contraseña", "secret", "credential"] {
            assert!(
                !rendered.to_lowercase().contains(banned),
                "el mensaje no debe mencionar {banned}: {rendered}"
            );
        }
    }
}

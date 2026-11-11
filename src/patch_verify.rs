//! Verificación autenticada de parches: una etapa best-effort situada entre el
//! enriquecimiento y `repository` que le pregunta al propio objetivo, sobre la
//! sesión SSH que el escaneo ya tiene abierta, si cada CVE de un hallazgo
//! `version_match` sigue realmente sin parchear o ya fue corregido por la
//! distribución (backport).
//!
//! El puerto hexagonal es [`PatchVerifier`]; el adaptador es
//! [`RpmPatchVerifier`] (familia RPM: Amazon Linux, RHEL, Fedora, CentOS, Rocky,
//! AlmaLinux). Sólo ejecuta comandos de **lectura** (`cat /etc/os-release`,
//! `dnf|yum updateinfo list cves`), no requiere `sudo` y reutiliza la sesión
//! (no abre otra conexión).
//!
//! # Reglas de reconciliación
//!
//! Sólo se consideran los hallazgos con `confidence == Some(VersionMatch)` cuyo
//! `id` es un CVE (`CVE-AAAA-NNNN+`). Sea `P` el conjunto de CVE con una
//! actualización de seguridad **disponible y no aplicada** en el objetivo:
//!
//! - CVE en `P`: `confidence = Confirmed` y `patch_state = Unpatched`.
//! - CVE fuera de `P`: `patch_state = Fixed` (la confianza no cambia; el
//!   hallazgo permanece en los datos y el front lo oculta).
//! - sin CVE: sin cambios (no verificado).
//!
//! Los hallazgos `Confirmed` por NSE y los que no son `VersionMatch` nunca se
//! tocan.
//!
//! # Guarda de seguridad (nunca inventar un veredicto)
//!
//! Si el comando que lista los CVE pendientes falla (error de transporte,
//! timeout o código de salida distinto de 0) **todo el objetivo** queda sin
//! verificar y ningún hallazgo se modifica. Lo mismo ocurre con salida vacía y
//! código 0: un host sin repositorios (aislado / *air-gapped*) responde igual
//! que uno totalmente parcheado, y no se puede distinguir de forma barata. La
//! decisión conservadora es no marcar nada como `Fixed`. Limitación conocida:
//! un host completamente parcheado tampoco recibe veredictos.

use std::collections::HashSet;

use async_trait::async_trait;

use crate::domain::{Confidence, PatchState, VulnFinding};
use crate::ssh::{RemoteSession, SshError};

/// Comando de lectura que expone la distribución del objetivo.
const OS_RELEASE_CMD: &str = "cat /etc/os-release";
/// Lista de CVE con actualización de seguridad disponible (preferido).
const DNF_CMD: &str = "dnf updateinfo list cves";
/// Alternativa para hosts sin `dnf`.
const YUM_CMD: &str = "yum updateinfo list cves";
/// Identificadores (`ID`/`ID_LIKE`) de `os-release` de la familia RPM soportada.
const RPM_FAMILY: [&str; 6] = ["amzn", "rhel", "fedora", "centos", "rocky", "almalinux"];

/// Motivo por el que el objetivo completo quedó sin verificar.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SkipReason {
    /// La distribución no es de la familia RPM soportada, o `os-release` no se
    /// pudo leer/interpretar.
    UnsupportedDistro,
    /// El comando de CVE pendientes salió con código distinto de 0 (con `dnf` y
    /// con `yum`).
    QueryFailed,
    /// El comando salió con 0 pero sin ningún CVE: indistinguible de un host sin
    /// metadatos de repositorio; no se marca nada como corregido.
    EmptyPendingSet,
}

/// Resultado de una verificación.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PatchVerifySummary {
    /// `Some` si el objetivo completo quedó sin verificar (ningún hallazgo
    /// modificado).
    pub skipped: Option<SkipReason>,
    /// Hallazgos promovidos a `Confirmed` + `Unpatched`.
    pub unpatched: usize,
    /// Hallazgos marcados `Fixed`.
    pub fixed: usize,
    /// Hallazgos `version_match` que siguen sin veredicto.
    pub unverified: usize,
}

/// Error de un [`PatchVerifier`]. Los hallazgos permanecen intactos.
#[derive(Debug, thiserror::Error)]
pub enum PatchVerifyError {
    /// Falló el transporte SSH (incluye timeout) al ejecutar un comando de
    /// lectura. Sólo lleva el error SSH, nunca la salida del comando.
    #[error("la verificación de parches falló en la sesión SSH: {0}")]
    Session(#[from] SshError),
}

/// Puerto hexagonal: reconcilia los hallazgos `version_match` de un escaneo
/// contra el estado real de parches del objetivo.
///
/// El pipeline lo invoca en modo *best-effort*: un [`Err`] no aborta el escaneo
/// (ver [`crate::pipeline`]).
#[async_trait]
pub trait PatchVerifier: Send + Sync {
    /// Reconcilia `findings` en sitio usando `session`.
    ///
    /// # Errores
    ///
    /// [`PatchVerifyError`] si falla el transporte SSH. En ese caso ningún
    /// hallazgo se modificó.
    async fn verify(
        &self,
        session: &dyn RemoteSession,
        findings: &mut [VulnFinding],
    ) -> Result<PatchVerifySummary, PatchVerifyError>;
}

/// Adaptador para la familia RPM (`dnf`/`yum updateinfo`).
#[derive(Debug, Clone, Copy, Default)]
pub struct RpmPatchVerifier;

/// `true` si `os_release` (contenido de `/etc/os-release`) pertenece a la
/// familia RPM soportada, según `ID` o `ID_LIKE`.
pub fn is_rpm_family(os_release: &str) -> bool {
    os_release
        .lines()
        .filter_map(|line| line.split_once('='))
        .filter(|(key, _)| matches!(key.trim(), "ID" | "ID_LIKE"))
        .flat_map(|(_, value)| {
            value
                .trim()
                .trim_matches(|c| c == '"' || c == '\'')
                .split_whitespace()
                .map(str::to_ascii_lowercase)
                .collect::<Vec<_>>()
        })
        .any(|id| RPM_FAMILY.contains(&id.as_str()))
}

/// `true` si `token` es exactamente `CVE-AAAA-NNNN+` (sin distinguir
/// mayúsculas): año de 4 dígitos y secuencia de 4 o más dígitos.
fn is_cve_id(token: &str) -> bool {
    let mut parts = token.split('-');
    let (Some(prefix), Some(year), Some(seq), None) =
        (parts.next(), parts.next(), parts.next(), parts.next())
    else {
        return false;
    };
    prefix.eq_ignore_ascii_case("CVE")
        && year.len() == 4
        && year.bytes().all(|b| b.is_ascii_digit())
        && seq.len() >= 4
        && seq.bytes().all(|b| b.is_ascii_digit())
}

/// Extrae el conjunto de CVE (en mayúsculas) presentes en `output`.
pub fn parse_pending_cves(output: &str) -> HashSet<String> {
    output
        .split_whitespace()
        .map(|token| token.trim_matches(|c: char| !c.is_ascii_alphanumeric()))
        .filter(|token| is_cve_id(token))
        .map(str::to_ascii_uppercase)
        .collect()
}

/// CVE normalizado de un hallazgo `version_match`, si lo tiene.
fn version_match_cve(finding: &VulnFinding) -> Option<Option<String>> {
    (finding.confidence == Some(Confidence::VersionMatch)).then(|| {
        finding
            .id
            .as_deref()
            .map(str::trim)
            .filter(|id| is_cve_id(id))
            .map(str::to_ascii_uppercase)
    })
}

/// Aplica las reglas de reconciliación del módulo sobre `findings`.
///
/// Precondición: `pending` proviene de una consulta exitosa y no vacía.
pub fn reconcile(findings: &mut [VulnFinding], pending: &HashSet<String>) -> PatchVerifySummary {
    let mut summary = PatchVerifySummary {
        skipped: None,
        unpatched: 0,
        fixed: 0,
        unverified: 0,
    };
    for finding in findings {
        match version_match_cve(finding) {
            None => {}
            Some(None) => summary.unverified += 1,
            Some(Some(cve)) if pending.contains(&cve) => {
                finding.confidence = Some(Confidence::Confirmed);
                finding.patch_state = Some(PatchState::Unpatched);
                summary.unpatched += 1;
            }
            Some(Some(_)) => {
                finding.patch_state = Some(PatchState::Fixed);
                summary.fixed += 1;
            }
        }
    }
    summary
}

/// Resumen de un objetivo sin verificar: nada se modificó.
fn skipped(findings: &[VulnFinding], reason: SkipReason) -> PatchVerifySummary {
    PatchVerifySummary {
        skipped: Some(reason),
        unpatched: 0,
        fixed: 0,
        unverified: findings
            .iter()
            .filter(|f| version_match_cve(f).is_some())
            .count(),
    }
}

/// Consulta los CVE pendientes: `dnf` primero y `yum` si falla. `Ok(None)` si
/// ambos salen con código distinto de 0.
async fn query_pending(session: &dyn RemoteSession) -> Result<Option<String>, SshError> {
    if let Ok(out) = session.run_command(DNF_CMD).await {
        if out.exit_code == 0 {
            return Ok(Some(out.stdout));
        }
    }
    let out = session.run_command(YUM_CMD).await?;
    Ok((out.exit_code == 0).then_some(out.stdout))
}

#[async_trait]
impl PatchVerifier for RpmPatchVerifier {
    async fn verify(
        &self,
        session: &dyn RemoteSession,
        findings: &mut [VulnFinding],
    ) -> Result<PatchVerifySummary, PatchVerifyError> {
        // Sin candidatos (version_match con CVE) no hay nada que preguntar.
        if !findings
            .iter()
            .any(|f| matches!(version_match_cve(f), Some(Some(_))))
        {
            return Ok(reconcile(findings, &HashSet::new()));
        }

        let os_release = session.run_command(OS_RELEASE_CMD).await?;
        if os_release.exit_code != 0 || !is_rpm_family(&os_release.stdout) {
            return Ok(skipped(findings, SkipReason::UnsupportedDistro));
        }

        let Some(stdout) = query_pending(session).await? else {
            return Ok(skipped(findings, SkipReason::QueryFailed));
        };
        let pending = parse_pending_cves(&stdout);
        if pending.is_empty() {
            return Ok(skipped(findings, SkipReason::EmptyPendingSet));
        }
        Ok(reconcile(findings, &pending))
    }
}

#[cfg(test)]
mod tests {
    use std::collections::VecDeque;
    use std::sync::Mutex;

    use super::*;
    use crate::domain::{Severity, VulnSource};
    use crate::ssh::CommandOutput;

    // Procedencia de los fixtures: MODELADOS (no capturados en vivo) a partir de
    // la documentación de `os-release(5)` y de la salida documentada de
    // `dnf updateinfo list cves` (plugin `updateinfo` de DNF: una línea por
    // aviso `<CVE> <Severidad>/Sec. <paquete-nevra>`). Deben revalidarse contra
    // una captura real de AL2023 / RHEL 9 antes de confiar en producción.
    const AL2023_OS_RELEASE: &str = r#"NAME="Amazon Linux"
VERSION="2023"
ID="amzn"
ID_LIKE="fedora"
VERSION_ID="2023"
PLATFORM_ID="platform:al2023"
PRETTY_NAME="Amazon Linux 2023"
"#;
    const RHEL9_OS_RELEASE: &str = r#"NAME="Red Hat Enterprise Linux"
VERSION="9.4 (Plow)"
ID="rhel"
ID_LIKE="fedora"
VERSION_ID="9.4"
PRETTY_NAME="Red Hat Enterprise Linux 9.4 (Plow)"
"#;
    const ROCKY_OS_RELEASE: &str =
        "NAME=\"Rocky Linux\"\nID=\"rocky\"\nID_LIKE=\"rhel centos fedora\"\n";
    const UBUNTU_OS_RELEASE: &str =
        "NAME=\"Ubuntu\"\nVERSION_ID=\"22.04\"\nID=ubuntu\nID_LIKE=debian\n";
    const DEBIAN_OS_RELEASE: &str = "PRETTY_NAME=\"Debian GNU/Linux 12\"\nID=debian\n";

    const DNF_PENDING: &str = "\
Last metadata expiration check: 0:12:03 ago on Tue Oct 21 10:00:00 2026.
CVE-2024-6387 Important/Sec. openssh-8.7p1-38.amzn2023.0.14.x86_64
CVE-2023-38408 Critical/Sec. openssh-8.7p1-38.amzn2023.0.14.x86_64
CVE-2024-6387 Important/Sec. openssh-clients-8.7p1-38.amzn2023.0.14.x86_64
CVE-2024-1234 Moderate/Sec. libfoo-1.2-3.amzn2023.x86_64
";

    fn finding(id: Option<&str>, confidence: Option<Confidence>) -> VulnFinding {
        VulnFinding {
            id: id.map(str::to_owned),
            severity: Severity::High,
            description: "d".to_owned(),
            nse_script: "vulners".to_owned(),
            source: VulnSource::NmapNse,
            references: Vec::new(),
            confidence,
            patch_state: None,
        }
    }

    fn vm(id: &str) -> VulnFinding {
        finding(Some(id), Some(Confidence::VersionMatch))
    }

    // ---- os-release -------------------------------------------------------

    #[test]
    fn rpm_family_is_detected_from_id_or_id_like() {
        assert!(is_rpm_family(AL2023_OS_RELEASE));
        assert!(is_rpm_family(RHEL9_OS_RELEASE));
        assert!(is_rpm_family(ROCKY_OS_RELEASE));
        assert!(is_rpm_family("ID=centos\n"));
        assert!(is_rpm_family("ID=custom\nID_LIKE=\"rhel fedora\"\n"));
    }

    #[test]
    fn non_rpm_or_unparseable_os_release_is_not_rpm_family() {
        assert!(!is_rpm_family(UBUNTU_OS_RELEASE));
        assert!(!is_rpm_family(DEBIAN_OS_RELEASE));
        assert!(!is_rpm_family(""));
        assert!(!is_rpm_family("garbage without equals\n\u{0}\u{1}"));
        // `rhel` como subcadena de otro valor no cuenta.
        assert!(!is_rpm_family("ID=notrhel\n"));
    }

    // ---- CVE parsing ------------------------------------------------------

    #[test]
    fn pending_cves_are_parsed_deduplicated_and_ignore_noise() {
        let set = parse_pending_cves(DNF_PENDING);

        let mut got: Vec<_> = set.iter().map(String::as_str).collect();
        got.sort_unstable();
        assert_eq!(got, ["CVE-2023-38408", "CVE-2024-1234", "CVE-2024-6387"]);
    }

    #[test]
    fn pending_cves_handles_lowercase_punctuation_and_rejects_malformed_ids() {
        let set = parse_pending_cves(
            "cve-2024-0001, CVE-24-1 CVE-2024-123 XCVE-2024-9999 (CVE-2025-00012)",
        );

        let mut got: Vec<_> = set.iter().map(String::as_str).collect();
        got.sort_unstable();
        assert_eq!(got, ["CVE-2024-0001", "CVE-2025-00012"]);
    }

    #[test]
    fn pending_cves_of_empty_output_is_empty() {
        assert!(parse_pending_cves("").is_empty());
        assert!(parse_pending_cves("Last metadata expiration check: 0:01:00 ago.\n").is_empty());
    }

    // ---- reconcile --------------------------------------------------------

    #[test]
    fn reconcile_applies_the_rules_and_leaves_other_findings_untouched() {
        let pending = parse_pending_cves(DNF_PENDING);
        let mut findings = vec![
            vm("CVE-2024-6387"),                                         // pendiente
            vm("cve-2023-38408"),                                        // pendiente (minúsculas)
            vm("CVE-2020-0001"),                                         // no pendiente
            vm("EDB-12345"),                                             // sin CVE
            finding(None, Some(Confidence::VersionMatch)),               // sin id
            finding(Some("CVE-2020-0002"), Some(Confidence::Confirmed)), // NSE
            finding(Some("CVE-2020-0003"), None),                        // desconocida
        ];
        let before = findings.clone();

        let summary = reconcile(&mut findings, &pending);

        assert_eq!(
            summary,
            PatchVerifySummary {
                skipped: None,
                unpatched: 2,
                fixed: 1,
                unverified: 2
            }
        );
        for i in [0, 1] {
            assert_eq!(findings[i].confidence, Some(Confidence::Confirmed));
            assert_eq!(findings[i].patch_state, Some(PatchState::Unpatched));
        }
        assert_eq!(findings[2].confidence, Some(Confidence::VersionMatch));
        assert_eq!(findings[2].patch_state, Some(PatchState::Fixed));
        for i in [3, 4, 5, 6] {
            assert_eq!(findings[i], before[i], "finding {i} no debe tocarse");
        }
    }

    // ---- orquestación con sesión falsa ------------------------------------

    /// Sesión falsa: responde comandos en orden de llegada con respuestas
    /// guionadas por comando y registra los comandos ejecutados.
    struct FakeSession {
        script: Mutex<VecDeque<(&'static str, Result<CommandOutput, SshError>)>>,
        ran: Mutex<Vec<String>>,
    }

    impl FakeSession {
        fn new(script: Vec<(&'static str, Result<CommandOutput, SshError>)>) -> Self {
            Self {
                script: Mutex::new(script.into()),
                ran: Mutex::new(Vec::new()),
            }
        }
        fn ran(&self) -> Vec<String> {
            self.ran.lock().expect("lock").clone()
        }
    }

    #[async_trait]
    impl RemoteSession for FakeSession {
        async fn run_command(&self, cmd: &str) -> Result<CommandOutput, SshError> {
            self.ran.lock().expect("lock").push(cmd.to_owned());
            let (expected, reply) = self
                .script
                .lock()
                .expect("lock")
                .pop_front()
                .unwrap_or_else(|| panic!("comando inesperado: {cmd}"));
            assert_eq!(cmd, expected, "comando fuera de guion");
            reply
        }
    }

    fn ok(stdout: &str) -> Result<CommandOutput, SshError> {
        Ok(CommandOutput {
            stdout: stdout.to_owned(),
            stderr: String::new(),
            exit_code: 0,
        })
    }

    fn exit(code: i32) -> Result<CommandOutput, SshError> {
        Ok(CommandOutput {
            stdout: "SECRETO-NO-DEBE-LOGUEARSE".to_owned(),
            stderr: "boom".to_owned(),
            exit_code: code,
        })
    }

    #[tokio::test]
    async fn rpm_host_reconciles_with_a_single_dnf_query() {
        let session = FakeSession::new(vec![
            (OS_RELEASE_CMD, ok(AL2023_OS_RELEASE)),
            (DNF_CMD, ok(DNF_PENDING)),
        ]);
        let mut findings = vec![vm("CVE-2024-6387"), vm("CVE-2020-0001")];

        let summary = RpmPatchVerifier
            .verify(&session, &mut findings)
            .await
            .expect("ok");

        assert_eq!(summary.unpatched, 1);
        assert_eq!(summary.fixed, 1);
        assert_eq!(findings[0].patch_state, Some(PatchState::Unpatched));
        assert_eq!(findings[1].patch_state, Some(PatchState::Fixed));
        assert_eq!(session.ran(), [OS_RELEASE_CMD, DNF_CMD]);
    }

    #[tokio::test]
    async fn dnf_error_falls_back_to_yum() {
        let session = FakeSession::new(vec![
            (OS_RELEASE_CMD, ok(RHEL9_OS_RELEASE)),
            (DNF_CMD, Err(SshError::Timeout)),
            (YUM_CMD, ok("CVE-2024-6387 Important/Sec. openssh-8.7p1\n")),
        ]);
        let mut findings = vec![vm("CVE-2024-6387")];

        let summary = RpmPatchVerifier
            .verify(&session, &mut findings)
            .await
            .expect("ok");

        assert_eq!(summary.unpatched, 1);
        assert_eq!(findings[0].patch_state, Some(PatchState::Unpatched));
    }

    #[tokio::test]
    async fn dnf_nonzero_exit_falls_back_to_yum_and_both_failing_leaves_all_unverified() {
        let session = FakeSession::new(vec![
            (OS_RELEASE_CMD, ok(AL2023_OS_RELEASE)),
            (DNF_CMD, exit(1)),
            (YUM_CMD, exit(127)),
        ]);
        let mut findings = vec![vm("CVE-2024-6387"), vm("CVE-2020-0001")];
        let before = findings.clone();

        let summary = RpmPatchVerifier
            .verify(&session, &mut findings)
            .await
            .expect("ok");

        assert_eq!(summary.skipped, Some(SkipReason::QueryFailed));
        assert_eq!(findings, before, "nada se marca Fixed si la consulta falla");
    }

    #[tokio::test]
    async fn transport_error_on_every_query_is_an_error_and_findings_are_untouched() {
        let session = FakeSession::new(vec![
            (OS_RELEASE_CMD, ok(AL2023_OS_RELEASE)),
            (DNF_CMD, Err(SshError::Timeout)),
            (YUM_CMD, Err(SshError::Timeout)),
        ]);
        let mut findings = vec![vm("CVE-2020-0001")];
        let before = findings.clone();

        let result = RpmPatchVerifier.verify(&session, &mut findings).await;

        assert!(matches!(
            result,
            Err(PatchVerifyError::Session(SshError::Timeout))
        ));
        assert_eq!(findings, before);
    }

    #[tokio::test]
    async fn empty_output_with_exit_zero_is_treated_as_unverified() {
        let session = FakeSession::new(vec![
            (OS_RELEASE_CMD, ok(AL2023_OS_RELEASE)),
            (DNF_CMD, ok("")),
        ]);
        let mut findings = vec![vm("CVE-2020-0001")];
        let before = findings.clone();

        let summary = RpmPatchVerifier
            .verify(&session, &mut findings)
            .await
            .expect("ok");

        assert_eq!(summary.skipped, Some(SkipReason::EmptyPendingSet));
        assert_eq!(findings, before, "salida vacía no debe marcar Fixed");
    }

    #[tokio::test]
    async fn non_rpm_distro_is_a_no_op_and_runs_no_package_query() {
        let session = FakeSession::new(vec![(OS_RELEASE_CMD, ok(UBUNTU_OS_RELEASE))]);
        let mut findings = vec![vm("CVE-2020-0001")];
        let before = findings.clone();

        let summary = RpmPatchVerifier
            .verify(&session, &mut findings)
            .await
            .expect("ok");

        assert_eq!(summary.skipped, Some(SkipReason::UnsupportedDistro));
        assert_eq!(findings, before);
        assert_eq!(session.ran(), [OS_RELEASE_CMD]);
    }

    #[tokio::test]
    async fn unreadable_os_release_is_a_no_op() {
        let session = FakeSession::new(vec![(OS_RELEASE_CMD, exit(1))]);
        let mut findings = vec![vm("CVE-2020-0001")];
        let before = findings.clone();

        let summary = RpmPatchVerifier
            .verify(&session, &mut findings)
            .await
            .expect("ok");

        assert_eq!(summary.skipped, Some(SkipReason::UnsupportedDistro));
        assert_eq!(findings, before);
    }

    #[tokio::test]
    async fn findings_without_version_match_skip_all_remote_commands() {
        let session = FakeSession::new(vec![]);
        let mut findings = vec![finding(Some("CVE-2020-0002"), Some(Confidence::Confirmed))];

        let summary = RpmPatchVerifier
            .verify(&session, &mut findings)
            .await
            .expect("ok");

        assert_eq!(summary.unpatched + summary.fixed + summary.unverified, 0);
        assert!(
            session.ran().is_empty(),
            "no hay nada que verificar: sin comandos"
        );
    }
}

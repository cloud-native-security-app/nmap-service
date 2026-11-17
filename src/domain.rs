//! Tipos puros del dominio de escaneo: [`ScanRequest`] (solicitud entrante),
//! [`ScanCancellation`] (solicitud de cancelación de un escaneo en curso) y
//! [`ScanResult`] con sus [`PortFinding`] y [`VulnFinding`]. No hacen IO.
//!
//! Todos los tipos implementan `serde::Serialize`/`Deserialize` para poder
//! recibirse desde el Broker, persistirse en MongoDB y volver a publicarse.
//! La única excepción de contenido es [`SshCredentialsRef`], que **siempre** se
//! formatea y serializa de forma redactada (ver su documentación y
//! `docs/security-scope.md`).

use std::fmt;
use std::net::IpAddr;

use secrecy::{ExposeSecret, SecretString};
use serde::{Deserialize, Serialize};
use time::OffsetDateTime;

/// Texto con el que se sustituye cualquier credencial al formatearla o
/// serializarla.
const REDACTED: &str = "[REDACTED]";

/// Identificador de correlación que enlaza una solicitud de escaneo con su
/// resultado y con los mensajes intercambiados con el Broker a lo largo de
/// todo el sistema.
///
/// Es opaco para `ms-nmap`: se recibe, se propaga y se persiste sin
/// interpretarse.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(transparent)]
pub struct CorrelationId(String);

impl CorrelationId {
    /// Crea un identificador a partir de su valor textual.
    pub fn new(value: impl Into<String>) -> Self {
        Self(value.into())
    }

    /// Devuelve el valor textual del identificador.
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl fmt::Display for CorrelationId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

impl From<String> for CorrelationId {
    fn from(value: String) -> Self {
        Self(value)
    }
}

impl From<&str> for CorrelationId {
    fn from(value: &str) -> Self {
        Self(value.to_owned())
    }
}

/// Referencia a las credenciales SSH con las que `ms-nmap` se autentica en el
/// objetivo.
///
/// El contenido se guarda en un [`SecretString`] y **nunca** se expone al
/// formatear (`Debug`/`Display` muestran `[REDACTED]`) ni al serializar (se
/// escribe `[REDACTED]` en lugar del valor). Así no puede filtrarse por
/// `tracing`, en un mensaje de panic ni en un documento persistido
/// (ver `docs/security-scope.md`).
///
/// Al deserializar (p. ej. desde el mensaje del Broker) sí se lee el valor
/// real: la credencial entra al sistema por ahí. Como consecuencia, una ida y
/// vuelta `serialize -> deserialize` de un [`ScanRequest`] pierde la credencial
/// (queda como `[REDACTED]`); es intencionado.
#[derive(Clone)]
pub struct SshCredentialsRef(SecretString);

impl SshCredentialsRef {
    /// Envuelve una credencial ya cargada como secreto.
    pub fn new(secret: SecretString) -> Self {
        Self(secret)
    }

    /// Expone el valor de la credencial. Úsalo solo en el punto exacto en que
    /// hay que entregársela al cliente SSH; nunca para loggear ni serializar.
    pub fn expose(&self) -> &str {
        self.0.expose_secret()
    }
}

impl fmt::Debug for SshCredentialsRef {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_tuple("SshCredentialsRef").field(&REDACTED).finish()
    }
}

impl fmt::Display for SshCredentialsRef {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(REDACTED)
    }
}

impl PartialEq for SshCredentialsRef {
    fn eq(&self, other: &Self) -> bool {
        self.0.expose_secret() == other.0.expose_secret()
    }
}

impl Eq for SshCredentialsRef {}

impl Serialize for SshCredentialsRef {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        serializer.serialize_str(REDACTED)
    }
}

impl<'de> Deserialize<'de> for SshCredentialsRef {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        let raw = String::deserialize(deserializer)?;
        Ok(Self(SecretString::from(raw)))
    }
}

/// Cómo se escanea el objetivo (campo `scan_mode` del contrato
/// `scan-request.schema.json`). Se serializa en minúsculas (`ssh`, `network`).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Default, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum ScanMode {
    /// `ms-nmap` abre una sesión SSH en el objetivo y ejecuta allí `nmap`.
    /// Es el modo por defecto cuando el mensaje no trae `scan_mode`, para que
    /// los productores anteriores al campo sigan siendo válidos.
    #[default]
    Ssh,
    /// `ms-nmap` ejecuta `nmap` desde su propio contenedor contra la IP del
    /// objetivo, sin credenciales (`-sT`, sin `-O`, sin `sudo`).
    Network,
}

/// Datos de acceso SSH al objetivo. Sólo existen en modo [`ScanMode::Ssh`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SshAccess {
    /// Usuario de red con el que `ms-nmap` se autentica por SSH en el objetivo.
    pub network_user: String,
    /// Credenciales SSH para `network_user`. Su contenido va siempre redactado
    /// en `Debug`/`Display` y en la serialización.
    pub ssh_credentials_ref: SshCredentialsRef,
    /// Indica si `network_user` tiene `sudo` disponible en el objetivo, según
    /// lo informado por quien creó la solicitud (Gateway/`ms-usuarios`).
    /// `ms-nmap` no lo verifica por sí mismo. La capa `scanner`
    /// (`nmap_execution`) lo usa para decidir si intenta `nmap -O` (detección
    /// de SO, requiere root remoto) mediante `sudo -n`. Ver
    /// `docs/security-scope.md`.
    pub has_sudo: bool,
}

/// Acceso al objetivo según el modo de escaneo: hace irrepresentables las
/// combinaciones que el contrato prohíbe (modo `ssh` sin credenciales, o modo
/// `network` con ellas).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ScanAccess {
    /// Modo `ssh`: el escaneo se ejecuta en el objetivo con estas credenciales.
    Ssh(SshAccess),
    /// Modo `network`: el escaneo se ejecuta desde este contenedor; no hay
    /// credenciales.
    Network,
}

/// Solicitud de escaneo recibida desde el Broker.
///
/// Es el único disparador válido de un escaneo: `ms-nmap` nunca escanea un
/// objetivo que no llegue en un `ScanRequest` (ver `docs/security-scope.md`).
///
/// Su forma en el cable es la del contrato `scan-request.schema.json`:
/// `scan_mode` (`ssh` por defecto) más, sólo en modo `ssh`, `network_user`,
/// `ssh_credentials_ref` y `has_sudo`. La deserialización valida esa regla
/// (falta un campo SSH en modo `ssh`, o sobra uno en modo `network`, es un
/// error), de modo que un `ScanRequest` en memoria siempre es coherente.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(try_from = "ScanRequestWire", into = "ScanRequestWire")]
pub struct ScanRequest {
    /// Identificador de correlación del flujo completo (solicitud -> resultado).
    pub correlation_id: CorrelationId,
    /// IP del host a escanear. Es el único objetivo autorizado de esta
    /// solicitud.
    pub ip: IpAddr,
    /// Identidad del principal (usuario final) que originó la solicitud aguas
    /// arriba. Solo para trazabilidad/auditoría; la autorización sobre el
    /// objetivo se asume ya verificada por el Gateway/`ms-usuarios`.
    pub requested_by: String,
    /// Modo de escaneo y, en modo `ssh`, las credenciales de acceso.
    pub access: ScanAccess,
    /// Sólo modo `network`: nombre de host tal como lo escribió el usuario
    /// (RFC 1123). Sirve de host virtual HTTP (`http.host`) y para mostrar;
    /// `nmap` nunca lo resuelve: el objetivo escaneado es siempre [`Self::ip`].
    pub target_host: Option<String>,
    /// Sólo modo `network`: puerto de la URL que se escanea además de los
    /// puertos por defecto de `nmap` (1..=65535).
    pub extra_port: Option<u16>,
}

impl ScanRequest {
    /// Modo de escaneo de la solicitud.
    pub fn mode(&self) -> ScanMode {
        match self.access {
            ScanAccess::Ssh(_) => ScanMode::Ssh,
            ScanAccess::Network => ScanMode::Network,
        }
    }

    /// Acceso SSH, o `None` en modo `network`.
    pub fn ssh(&self) -> Option<&SshAccess> {
        match &self.access {
            ScanAccess::Ssh(ssh) => Some(ssh),
            ScanAccess::Network => None,
        }
    }
}

/// Forma plana de [`ScanRequest`] en el cable. Los campos SSH son opcionales
/// aquí y su coherencia con `scan_mode` se comprueba en `TryFrom`.
#[derive(Serialize, Deserialize)]
struct ScanRequestWire {
    correlation_id: CorrelationId,
    /// Se omite al serializar en modo `ssh` (forma histórica byte a byte).
    #[serde(default, skip_serializing_if = "is_default_mode")]
    scan_mode: ScanMode,
    ip: IpAddr,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    network_user: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    ssh_credentials_ref: Option<SshCredentialsRef>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    has_sudo: Option<bool>,
    requested_by: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    target_host: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    extra_port: Option<u16>,
}

/// Longitud máxima de un nombre de host completo (RFC 1035/1123).
const HOSTNAME_MAX_LEN: usize = 253;
/// Longitud máxima de una etiqueta de un nombre de host.
const HOSTNAME_LABEL_MAX_LEN: usize = 63;

/// `true` si `host` es un nombre de host RFC 1123: etiquetas de 1..=63
/// caracteres `[A-Za-z0-9-]` separadas por `.`, sin guion al principio ni al
/// final de cada etiqueta, sin punto final y de como mucho 253 caracteres en
/// total. Replica el `pattern` del contrato y mantiene un `-` inicial fuera de
/// `argv` de `nmap`.
fn is_valid_hostname(host: &str) -> bool {
    !host.is_empty()
        && host.len() <= HOSTNAME_MAX_LEN
        && host.split('.').all(|label| {
            !label.is_empty()
                && label.len() <= HOSTNAME_LABEL_MAX_LEN
                && !label.starts_with('-')
                && !label.ends_with('-')
                && label
                    .bytes()
                    .all(|b| b.is_ascii_alphanumeric() || b == b'-')
        })
}

fn is_default_mode(mode: &ScanMode) -> bool {
    *mode == ScanMode::Ssh
}

impl TryFrom<ScanRequestWire> for ScanRequest {
    type Error = String;

    fn try_from(wire: ScanRequestWire) -> Result<Self, Self::Error> {
        let access = match wire.scan_mode {
            ScanMode::Ssh => ScanAccess::Ssh(SshAccess {
                network_user: wire
                    .network_user
                    .ok_or("missing field `network_user` (required in ssh mode)")?,
                ssh_credentials_ref: wire
                    .ssh_credentials_ref
                    .ok_or("missing field `ssh_credentials_ref` (required in ssh mode)")?,
                has_sudo: wire
                    .has_sudo
                    .ok_or("missing field `has_sudo` (required in ssh mode)")?,
            }),
            ScanMode::Network => {
                let forbidden = [
                    ("network_user", wire.network_user.is_some()),
                    ("ssh_credentials_ref", wire.ssh_credentials_ref.is_some()),
                    ("has_sudo", wire.has_sudo.is_some()),
                ];
                if let Some((field, _)) = forbidden.iter().find(|(_, present)| *present) {
                    return Err(format!("field `{field}` is not allowed in network mode"));
                }
                // Nunca se repite el valor recibido en el error.
                if wire
                    .target_host
                    .as_deref()
                    .is_some_and(|h| !is_valid_hostname(h))
                {
                    return Err("field `target_host` is not a valid RFC 1123 hostname".to_owned());
                }
                if wire.extra_port == Some(0) {
                    return Err("field `extra_port` must be in 1..=65535".to_owned());
                }
                ScanAccess::Network
            }
        };
        if matches!(access, ScanAccess::Ssh(_)) {
            let forbidden = [
                ("target_host", wire.target_host.is_some()),
                ("extra_port", wire.extra_port.is_some()),
            ];
            if let Some((field, _)) = forbidden.iter().find(|(_, present)| *present) {
                return Err(format!("field `{field}` is only allowed in network mode"));
            }
        }
        Ok(Self {
            correlation_id: wire.correlation_id,
            ip: wire.ip,
            requested_by: wire.requested_by,
            access,
            target_host: wire.target_host,
            extra_port: wire.extra_port,
        })
    }
}

impl From<ScanRequest> for ScanRequestWire {
    fn from(request: ScanRequest) -> Self {
        let (scan_mode, network_user, ssh_credentials_ref, has_sudo) = match request.access {
            ScanAccess::Ssh(ssh) => (
                ScanMode::Ssh,
                Some(ssh.network_user),
                Some(ssh.ssh_credentials_ref),
                Some(ssh.has_sudo),
            ),
            ScanAccess::Network => (ScanMode::Network, None, None, None),
        };
        Self {
            correlation_id: request.correlation_id,
            scan_mode,
            ip: request.ip,
            network_user,
            ssh_credentials_ref,
            has_sudo,
            requested_by: request.requested_by,
            target_host: request.target_host,
            extra_port: request.extra_port,
        }
    }
}

/// Solicitud de cancelación de un escaneo en curso, recibida desde el Broker
/// (exchange `scan.cancellations`, cola `ms-nmap.scan-cancellations`, RF-14).
///
/// `ms-nmap` la usa para abortar cooperativamente la tarea en vuelo con el
/// mismo `correlation_id`, si sigue en curso (ver
/// [`crate::pipeline::ScanPipeline::run`]). No lleva ningún dato sensible ni
/// del objetivo original (IP, credenciales): sólo el identificador de
/// correlación y quién pidió la cancelación, para trazabilidad.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ScanCancellation {
    /// Identificador de correlación del escaneo que se quiere cancelar.
    pub correlation_id: CorrelationId,
    /// Identidad del principal que solicitó la cancelación (Gateway /
    /// `ms-usuarios`). Sólo para trazabilidad/auditoría.
    pub requested_by: String,
}

/// Protocolo de transporte de un puerto observado.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Protocol {
    /// TCP.
    Tcp,
    /// UDP.
    Udp,
}

/// Estado de un puerto según `nmap`.
///
/// La capa `parser` (`xml_parser`) mapea las cadenas crudas de `nmap`
/// (`open`, `open|filtered`, ...) a estas variantes.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum PortState {
    /// El puerto acepta conexiones.
    Open,
    /// El puerto es alcanzable pero no hay servicio escuchando.
    Closed,
    /// Un filtro (firewall) impide determinar si está abierto.
    Filtered,
    /// El puerto es alcanzable pero `nmap` no puede decidir si está abierto o
    /// cerrado.
    Unfiltered,
    /// `nmap` no puede distinguir entre abierto y filtrado.
    OpenFiltered,
    /// `nmap` no puede distinguir entre cerrado y filtrado.
    ClosedFiltered,
}

/// Severidad de un hallazgo de vulnerabilidad.
///
/// Los scripts NSE no siempre reportan una severidad normalizada; cuando falta,
/// se usa [`Severity::Unknown`].
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Severity {
    /// Severidad no informada por el script de origen.
    Unknown,
    /// Informativo, sin impacto directo de seguridad.
    Info,
    /// Baja.
    Low,
    /// Media.
    Medium,
    /// Alta.
    High,
    /// Crítica.
    Critical,
}

/// Un puerto descubierto en el objetivo, con el servicio y versión que `nmap`
/// haya podido identificar.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PortFinding {
    /// Número de puerto.
    pub port: u16,
    /// Protocolo de transporte.
    pub protocol: Protocol,
    /// Estado observado.
    pub state: PortState,
    /// Nombre del servicio detectado (`ssh`, `http`, ...), si `nmap` lo
    /// identificó.
    pub service: Option<String>,
    /// Versión del servicio detectada por `-sV`, si `nmap` la identificó.
    pub version: Option<String>,
    /// Identificadores CPE (`cpe:/a:openbsd:openssh:9.9`, ...) que `nmap`
    /// reporta como hijos `<cpe>` del `<service>`. Habilita el cruce por CPE de
    /// los enriquecedores de vulnerabilidades (ver [`crate::enrichment`]). Vacío
    /// si `nmap` no reportó ninguno.
    #[serde(default)]
    pub cpes: Vec<String>,
}

/// Origen de un [`VulnFinding`]: qué componente lo produjo.
///
/// Se serializa en `snake_case` (`nmap_nse`, `exploit_db`) para tener una
/// codificación estable en MongoDB y en los mensajes al Broker.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum VulnSource {
    /// Un script NSE de categoría `vuln` ejecutado por `nmap` en el objetivo.
    NmapNse,
    /// El cruce offline contra el CSV de Exploit-DB
    /// ([`crate::enrichment::ExploitDbEnricher`]).
    ExploitDb,
    /// La consulta online por CPE contra la API NVD 2.0
    /// ([`crate::enrichment::NvdApiEnricher`]).
    Nvd,
}

/// Confianza de un [`VulnFinding`]. Se serializa en `snake_case`.
///
/// Un hallazgo sin confianza (`None`) es de confianza desconocida: no implica
/// ni confirmación ni coincidencia sólo por versión.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Confidence {
    /// El script NSE verificó la vulnerabilidad (estado `VULNERABLE`).
    Confirmed,
    /// Coincidencia por versión/CPE (p. ej. `vulners`); no verificada y puede
    /// ser falso positivo (parches portados por la distribución).
    VersionMatch,
}

/// Estado de parche de un [`VulnFinding`] tras la verificación autenticada
/// contra el objetivo (ver [`crate::patch_verify`]). Se serializa en
/// `snake_case`. Un hallazgo sin estado (`None`) no fue verificado.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum PatchState {
    /// El objetivo informa una actualización de seguridad pendiente para el
    /// CVE: sigue sin parchear.
    Unpatched,
    /// El objetivo no informa actualización pendiente para el CVE: corregido
    /// (p. ej. por un backport de la distribución).
    Fixed,
}

/// Un hallazgo de vulnerabilidad: de un script NSE de categoría `vuln`
/// ([`VulnSource::NmapNse`]) o de un enriquecedor posterior como Exploit-DB
/// ([`VulnSource::ExploitDb`], ver [`crate::enrichment`]).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct VulnFinding {
    /// Identificador de la vulnerabilidad (CVE u otro), si se conoce.
    pub id: Option<String>,
    /// Severidad informada o inferida.
    pub severity: Severity,
    /// Descripción legible del hallazgo.
    pub description: String,
    /// Nombre del script NSE que generó el hallazgo (p. ej.
    /// `http-vuln-cve2017-5638`). Cadena vacía si el hallazgo no proviene de un
    /// script NSE (p. ej. los de [`VulnSource::ExploitDb`]).
    pub nse_script: String,
    /// Componente que produjo el hallazgo.
    #[serde(default = "default_vuln_source")]
    pub source: VulnSource,
    /// URLs de referencia del hallazgo (aviso, entrada de Exploit-DB, ...).
    /// Vacío si no hay ninguna.
    #[serde(default)]
    pub references: Vec<String>,
    /// Qué tan firme es el hallazgo. `None` = desconocido (se omite al
    /// serializar). Ver [`Confidence`].
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub confidence: Option<Confidence>,
    /// Resultado de la verificación de parches contra el objetivo. `None` = no
    /// verificado (se omite al serializar). Ver [`PatchState`].
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub patch_state: Option<PatchState>,
    /// Puerto donde se detectó el hallazgo. `None` = hallazgo a nivel de host
    /// (p. ej. `hostscript` o la verificación autenticada de parches) o puerto
    /// desconocido (se omite al serializar).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub port: Option<u16>,
    /// Protocolo del [`VulnFinding::port`]; `None` cuando `port` es `None`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub protocol: Option<Protocol>,
}

/// Origen por defecto al deserializar un [`VulnFinding`] persistido antes de
/// que existiera el campo `source` (feature `vuln_enrichment`): esos documentos
/// sólo podían venir de scripts NSE.
fn default_vuln_source() -> VulnSource {
    VulnSource::NmapNse
}

/// Resultado de un escaneo: todo lo descubierto sobre un host.
///
/// Estructura variable (número de puertos y vulnerabilidades no fijo), lo que
/// encaja con el modelo documental de MongoDB.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ScanResult {
    /// IP del host escaneado (coincide con [`ScanRequest::ip`]).
    pub host: IpAddr,
    /// Puertos descubiertos.
    pub ports: Vec<PortFinding>,
    /// Vulnerabilidades detectadas por `--script vuln`.
    pub vulnerabilities: Vec<VulnFinding>,
    /// Instante en que terminó el escaneo, serializado como RFC 3339 (incluye
    /// el offset UTC de la marca temporal).
    #[serde(with = "time::serde::rfc3339")]
    pub scanned_at: OffsetDateTime,
}

#[cfg(test)]
mod tests {
    use secrecy::SecretString;
    use time::macros::datetime;

    use super::*;

    fn sample_result() -> ScanResult {
        ScanResult {
            host: "192.0.2.10".parse().expect("IP de prueba válida"),
            ports: vec![
                PortFinding {
                    port: 22,
                    protocol: Protocol::Tcp,
                    state: PortState::Open,
                    service: Some("ssh".to_owned()),
                    version: Some("OpenSSH 9.6p1".to_owned()),
                    cpes: vec!["cpe:/a:openbsd:openssh:9.6p1".to_owned()],
                },
                PortFinding {
                    port: 80,
                    protocol: Protocol::Tcp,
                    state: PortState::Filtered,
                    service: Some("http".to_owned()),
                    version: None,
                    cpes: Vec::new(),
                },
                PortFinding {
                    port: 53,
                    protocol: Protocol::Udp,
                    state: PortState::OpenFiltered,
                    service: None,
                    version: None,
                    cpes: Vec::new(),
                },
            ],
            vulnerabilities: vec![
                VulnFinding {
                    id: Some("CVE-2023-38408".to_owned()),
                    severity: Severity::High,
                    description: "ssh-agent PKCS#11 arbitrary code execution".to_owned(),
                    nse_script: "ssh-vuln-cve2023-38408".to_owned(),
                    source: VulnSource::NmapNse,
                    references: vec!["https://www.openssh.com/txt/release-9.3p2".to_owned()],
                    confidence: None,
                    patch_state: None,
                    port: None,
                    protocol: None,
                },
                VulnFinding {
                    id: Some("CVE-2011-2523".to_owned()),
                    severity: Severity::Unknown,
                    description: "vsftpd 2.3.4 - Backdoor Command Execution (Exploit-DB 49757)"
                        .to_owned(),
                    nse_script: String::new(),
                    source: VulnSource::ExploitDb,
                    references: vec!["https://www.exploit-db.com/exploits/49757".to_owned()],
                    confidence: None,
                    patch_state: None,
                    port: None,
                    protocol: None,
                },
            ],
            scanned_at: datetime!(2026-08-27 12:30:00 UTC),
        }
    }

    fn sample_request(secret: &str) -> ScanRequest {
        ScanRequest {
            correlation_id: CorrelationId::from("corr-42"),
            ip: "192.0.2.10".parse().expect("IP de prueba válida"),
            requested_by: "analyst@example.test".to_owned(),
            access: ScanAccess::Ssh(SshAccess {
                network_user: "scanner".to_owned(),
                ssh_credentials_ref: SshCredentialsRef::new(SecretString::from(secret.to_owned())),
                has_sudo: true,
            }),
            target_host: None,
            extra_port: None,
        }
    }

    #[test]
    fn scan_result_json_round_trip_preserves_every_field() {
        let original = sample_result();

        let json = serde_json::to_string(&original).expect("serializa a JSON");
        let restored: ScanResult = serde_json::from_str(&json).expect("deserializa desde JSON");

        assert_eq!(restored, original);
    }

    #[test]
    fn scan_result_serializes_timestamp_as_rfc3339() {
        let json = serde_json::to_value(sample_result()).expect("serializa a JSON");
        let rendered = json["scanned_at"]
            .as_str()
            .expect("scanned_at es una cadena");

        assert!(
            rendered.starts_with("2026-08-27T12:30:00"),
            "scanned_at no es RFC 3339: {rendered}"
        );
    }

    #[test]
    fn scan_request_debug_does_not_leak_credentials() {
        let secret = "hunter2-super-secret";
        let rendered = format!("{:?}", sample_request(secret));

        assert!(
            !rendered.contains(secret),
            "Debug de ScanRequest no debe exponer la credencial: {rendered}"
        );
        assert!(rendered.contains(REDACTED));
    }

    #[test]
    fn scan_request_serialization_does_not_leak_credentials() {
        let secret = "hunter2-super-secret";
        let json = serde_json::to_string(&sample_request(secret)).expect("serializa a JSON");

        assert!(
            !json.contains(secret),
            "la serialización de ScanRequest no debe exponer la credencial: {json}"
        );
    }

    #[test]
    fn ssh_credentials_ref_display_is_redacted_but_value_is_recoverable() {
        let creds = SshCredentialsRef::new(SecretString::from("top-secret".to_owned()));

        assert_eq!(creds.to_string(), REDACTED);
        assert_eq!(
            format!("{creds:?}"),
            format!("SshCredentialsRef({REDACTED:?})")
        );
        assert_eq!(creds.expose(), "top-secret");
    }

    #[test]
    fn scan_request_deserializes_real_credential_from_broker_message() {
        let json = r#"{
            "correlation_id": "corr-7",
            "ip": "198.51.100.4",
            "network_user": "scanner",
            "ssh_credentials_ref": "real-broker-secret",
            "has_sudo": false,
            "requested_by": "analyst@example.test"
        }"#;

        let request: ScanRequest = serde_json::from_str(json).expect("deserializa la solicitud");

        let ssh = request.ssh().expect("modo ssh por defecto");
        assert_eq!(ssh.ssh_credentials_ref.expose(), "real-broker-secret");
        assert!(!ssh.has_sudo);
        assert_eq!(request.mode(), ScanMode::Ssh);
        assert_eq!(request.correlation_id.as_str(), "corr-7");
        assert_eq!(request.ip, "198.51.100.4".parse::<IpAddr>().unwrap());
    }

    const SSH_JSON: &str = r#"{
        "correlation_id": "corr-7",
        "ip": "198.51.100.4",
        "network_user": "scanner",
        "ssh_credentials_ref": "real-broker-secret",
        "has_sudo": false,
        "requested_by": "analyst@example.test"
    }"#;

    #[test]
    fn ssh_request_without_scan_mode_defaults_to_ssh_and_keeps_its_wire_shape() {
        let request: ScanRequest = serde_json::from_str(SSH_JSON).expect("deserializa");
        assert_eq!(request.mode(), ScanMode::Ssh);

        // Compatibilidad byte a byte: sin `scan_mode` y con los campos SSH en el
        // mismo orden que antes (la credencial va redactada al serializar).
        let json = serde_json::to_string(&request).expect("serializa");
        assert_eq!(
            json,
            r#"{"correlation_id":"corr-7","ip":"198.51.100.4","network_user":"scanner","ssh_credentials_ref":"[REDACTED]","has_sudo":false,"requested_by":"analyst@example.test"}"#
        );
    }

    #[test]
    fn explicit_ssh_mode_is_accepted() {
        let json = SSH_JSON.replacen('{', r#"{"scan_mode": "ssh","#, 1);
        let request: ScanRequest = serde_json::from_str(&json).expect("deserializa");
        assert_eq!(request.mode(), ScanMode::Ssh);
    }

    #[test]
    fn network_request_has_no_ssh_access_and_serializes_without_ssh_fields() {
        let json = r#"{
            "correlation_id": "corr-8",
            "scan_mode": "network",
            "ip": "198.51.100.4",
            "requested_by": "analyst@example.test"
        }"#;
        let request: ScanRequest = serde_json::from_str(json).expect("deserializa");

        assert_eq!(request.mode(), ScanMode::Network);
        assert!(request.ssh().is_none());
        assert_eq!(
            serde_json::to_value(&request).expect("serializa"),
            serde_json::json!({
                "correlation_id": "corr-8",
                "scan_mode": "network",
                "ip": "198.51.100.4",
                "requested_by": "analyst@example.test"
            })
        );
    }

    #[test]
    fn network_request_carrying_any_ssh_field_is_rejected_without_echoing_values() {
        for extra in [
            r#""network_user": "scanner""#,
            r#""ssh_credentials_ref": "leaky-secret-value""#,
            r#""has_sudo": false"#,
        ] {
            let json = format!(
                r#"{{"correlation_id":"c","scan_mode":"network","ip":"198.51.100.4","requested_by":"a",{extra}}}"#
            );
            let err = serde_json::from_str::<ScanRequest>(&json)
                .expect_err("network no admite campos SSH")
                .to_string();
            assert!(!err.contains("leaky-secret-value"), "{err}");
        }
    }

    #[test]
    fn ssh_request_missing_any_ssh_field_is_rejected() {
        for field in ["network_user", "ssh_credentials_ref", "has_sudo"] {
            let mut value: serde_json::Value = serde_json::from_str(SSH_JSON).expect("JSON");
            value.as_object_mut().expect("objeto").remove(field);
            let err = serde_json::from_value::<ScanRequest>(value)
                .expect_err("ssh exige los tres campos")
                .to_string();
            assert!(err.contains(field), "el error debe nombrar {field}: {err}");
        }
    }

    fn network_json(extra: &str) -> String {
        format!(
            r#"{{"correlation_id":"c","scan_mode":"network","ip":"198.51.100.4","requested_by":"a"{extra}}}"#
        )
    }

    #[test]
    fn network_request_accepts_target_host_and_extra_port_and_round_trips_them() {
        let json = network_json(r#","target_host":"app.example.com","extra_port":8443"#);
        let request: ScanRequest = serde_json::from_str(&json).expect("deserializa");

        assert_eq!(request.target_host.as_deref(), Some("app.example.com"));
        assert_eq!(request.extra_port, Some(8443));
        assert_eq!(request.ip, "198.51.100.4".parse::<IpAddr>().unwrap());
        let value = serde_json::to_value(&request).expect("serializa");
        assert_eq!(value["target_host"], "app.example.com");
        assert_eq!(value["extra_port"], 8443);
    }

    #[test]
    fn network_request_without_the_optional_fields_keeps_its_wire_shape() {
        let request: ScanRequest = serde_json::from_str(&network_json("")).expect("deserializa");
        assert_eq!(request.target_host, None);
        assert_eq!(request.extra_port, None);
        let value = serde_json::to_value(&request).expect("serializa");
        assert!(value.get("target_host").is_none() && value.get("extra_port").is_none());
    }

    #[test]
    fn network_request_accepts_each_optional_field_on_its_own() {
        assert!(serde_json::from_str::<ScanRequest>(&network_json(r#","extra_port":1"#)).is_ok());
        assert!(
            serde_json::from_str::<ScanRequest>(&network_json(r#","target_host":"a""#)).is_ok()
        );
    }

    #[test]
    fn invalid_hostnames_are_rejected_without_echoing_the_value() {
        let long_label = "a".repeat(64);
        let too_long = format!("{}.com", ["a".repeat(63).as_str(); 4].join("."));
        for host in [
            "",
            "-leading.example.com",
            "trailing-.example.com",
            "app.-bad.com",
            "app.example.com.",
            "under_score.com",
            "spa ce.com",
            "a..b",
            "--script=evil",
            "ünï.com",
            long_label.as_str(),
            too_long.as_str(),
        ] {
            let json = network_json(&format!(r#","target_host":"{host}""#));
            let err = serde_json::from_str::<ScanRequest>(&json)
                .expect_err(&format!("debe rechazar {host:?}"))
                .to_string();
            assert!(host.is_empty() || !err.contains(host), "{err}");
        }
    }

    #[test]
    fn hostname_limits_are_inclusive() {
        let label63 = "a".repeat(63);
        let host253 = format!("{label63}.{label63}.{label63}.{}", "b".repeat(61));
        assert_eq!(host253.len(), 253);
        for host in [
            label63.as_str(),
            host253.as_str(),
            "A-1.Example.COM",
            "10.example",
        ] {
            let json = network_json(&format!(r#","target_host":"{host}""#));
            assert!(serde_json::from_str::<ScanRequest>(&json).is_ok(), "{host}");
        }
    }

    #[test]
    fn out_of_range_extra_ports_are_rejected() {
        for port in ["0", "65536", "-1", "70000", "1.5", r#""80""#] {
            let json = network_json(&format!(r#","extra_port":{port}"#));
            assert!(
                serde_json::from_str::<ScanRequest>(&json).is_err(),
                "{port}"
            );
        }
        let max = network_json(r#","extra_port":65535"#);
        assert!(serde_json::from_str::<ScanRequest>(&max).is_ok());
    }

    #[test]
    fn ssh_request_carrying_target_host_or_extra_port_is_rejected() {
        for (field, value) in [
            ("target_host", r#""app.example.com""#),
            ("extra_port", "8443"),
        ] {
            let mut json: serde_json::Value = serde_json::from_str(SSH_JSON).expect("JSON");
            json[field] = serde_json::from_str(value).expect("valor");
            let err = serde_json::from_value::<ScanRequest>(json)
                .expect_err("ssh no admite campos network")
                .to_string();
            assert!(err.contains(field), "{err}");
        }
    }

    #[test]
    fn unknown_scan_mode_is_rejected() {
        let json = SSH_JSON.replacen('{', r#"{"scan_mode": "agent","#, 1);
        assert!(serde_json::from_str::<ScanRequest>(&json).is_err());
    }

    #[test]
    fn scan_mode_uses_a_stable_string_encoding() {
        assert_eq!(serde_json::to_string(&ScanMode::Ssh).unwrap(), "\"ssh\"");
        assert_eq!(
            serde_json::to_string(&ScanMode::Network).unwrap(),
            "\"network\""
        );
    }

    #[test]
    fn enums_use_a_stable_string_encoding() {
        assert_eq!(
            serde_json::to_string(&Protocol::Udp).expect("serializa"),
            "\"udp\""
        );
        assert_eq!(
            serde_json::to_string(&PortState::OpenFiltered).expect("serializa"),
            "\"open_filtered\""
        );
        assert_eq!(
            serde_json::to_string(&Severity::Critical).expect("serializa"),
            "\"critical\""
        );
        assert_eq!(
            serde_json::to_string(&VulnSource::NmapNse).expect("serializa"),
            "\"nmap_nse\""
        );
        assert_eq!(
            serde_json::to_string(&VulnSource::ExploitDb).expect("serializa"),
            "\"exploit_db\""
        );
        assert_eq!(
            serde_json::to_string(&VulnSource::Nvd).expect("serializa"),
            "\"nvd\""
        );
    }

    #[test]
    fn scan_cancellation_json_round_trip_preserves_every_field() {
        let original = ScanCancellation {
            correlation_id: CorrelationId::from("corr-cancel-1"),
            requested_by: "analyst@example.test".to_owned(),
        };

        let json = serde_json::to_value(&original).expect("serializa a JSON");
        assert_eq!(
            json,
            serde_json::json!({
                "correlation_id": "corr-cancel-1",
                "requested_by": "analyst@example.test"
            }),
            "ScanCancellation no debe llevar campos extra: {json}"
        );

        let restored: ScanCancellation =
            serde_json::from_value(json).expect("deserializa desde JSON");
        assert_eq!(restored, original);
    }

    #[test]
    fn vuln_finding_deserializes_with_defaults_for_pre_enrichment_documents() {
        // Documento persistido antes de la feature `vuln_enrichment`: sin
        // `source` ni `references`.
        let json = r#"{
            "id": "CVE-2011-2523",
            "severity": "high",
            "description": "vsFTPd 2.3.4 backdoor",
            "nse_script": "ftp-vsftpd-backdoor"
        }"#;

        let finding: VulnFinding = serde_json::from_str(json).expect("deserializa");

        assert_eq!(finding.source, VulnSource::NmapNse);
        assert!(finding.references.is_empty());
    }

    #[test]
    fn vuln_finding_omits_confidence_when_none_and_uses_snake_case_otherwise() {
        let mut finding = VulnFinding {
            id: Some("CVE-2011-2523".to_owned()),
            severity: Severity::High,
            description: "d".to_owned(),
            nse_script: "vulners".to_owned(),
            source: VulnSource::NmapNse,
            references: Vec::new(),
            confidence: None,
            patch_state: None,
            port: None,
            protocol: None,
        };

        let json = serde_json::to_value(&finding).expect("serializa");
        assert!(json.get("confidence").is_none(), "{json}");

        finding.confidence = Some(Confidence::VersionMatch);
        let json = serde_json::to_value(&finding).expect("serializa");
        assert_eq!(json["confidence"], "version_match");

        finding.confidence = Some(Confidence::Confirmed);
        let json = serde_json::to_value(&finding).expect("serializa");
        assert_eq!(json["confidence"], "confirmed");

        let restored: VulnFinding = serde_json::from_value(json).expect("deserializa");
        assert_eq!(restored, finding);
    }

    #[test]
    fn vuln_finding_omits_patch_state_when_none_and_uses_snake_case_otherwise() {
        let mut finding = VulnFinding {
            id: Some("CVE-2011-2523".to_owned()),
            severity: Severity::High,
            description: "d".to_owned(),
            nse_script: "vulners".to_owned(),
            source: VulnSource::NmapNse,
            references: Vec::new(),
            confidence: None,
            patch_state: None,
            port: None,
            protocol: None,
        };

        let json = serde_json::to_value(&finding).expect("serializa");
        assert!(json.get("patch_state").is_none(), "{json}");

        finding.patch_state = Some(PatchState::Unpatched);
        let json = serde_json::to_value(&finding).expect("serializa");
        assert_eq!(json["patch_state"], "unpatched");

        finding.patch_state = Some(PatchState::Fixed);
        let json = serde_json::to_value(&finding).expect("serializa");
        assert_eq!(json["patch_state"], "fixed");

        let restored: VulnFinding = serde_json::from_value(json).expect("deserializa");
        assert_eq!(restored, finding);
    }

    #[test]
    fn vuln_finding_persisted_before_patch_state_deserializes_with_none() {
        let json = r#"{"id":"CVE-1","severity":"high","description":"d","nse_script":"vulners","confidence":"version_match"}"#;

        let finding: VulnFinding = serde_json::from_str(json).expect("deserializa");

        assert_eq!(finding.patch_state, None);
    }

    #[test]
    fn vuln_finding_port_and_protocol_are_omitted_when_none_and_round_trip() {
        let mut finding = VulnFinding {
            id: Some("CVE-2011-2523".to_owned()),
            severity: Severity::High,
            description: "d".to_owned(),
            nse_script: "vulners".to_owned(),
            source: VulnSource::NmapNse,
            references: Vec::new(),
            confidence: None,
            patch_state: None,
            port: None,
            protocol: None,
        };

        let json = serde_json::to_value(&finding).expect("serializa");
        assert!(json.get("port").is_none(), "{json}");
        assert!(json.get("protocol").is_none(), "{json}");

        finding.port = Some(21);
        finding.protocol = Some(Protocol::Tcp);
        let json = serde_json::to_value(&finding).expect("serializa");
        assert_eq!(json["port"], 21);
        assert_eq!(json["protocol"], "tcp");

        let restored: VulnFinding = serde_json::from_value(json).expect("deserializa");
        assert_eq!(restored, finding);
    }

    #[test]
    fn vuln_finding_persisted_before_port_deserializes_with_none() {
        let json = r#"{"id":"CVE-1","severity":"high","description":"d","nse_script":"vulners"}"#;

        let finding: VulnFinding = serde_json::from_str(json).expect("deserializa");

        assert_eq!(finding.port, None);
        assert_eq!(finding.protocol, None);
    }

    #[test]
    fn vuln_finding_accepts_explicit_null_port_from_other_services() {
        let json = r#"{"id":null,"severity":"low","description":"d","nse_script":"","port":null,"protocol":null}"#;

        let finding: VulnFinding = serde_json::from_str(json).expect("deserializa");

        assert_eq!((finding.port, finding.protocol), (None, None));
    }
}

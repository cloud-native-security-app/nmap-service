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

/// Solicitud de escaneo recibida desde el Broker.
///
/// Es el único disparador válido de un escaneo: `ms-nmap` nunca escanea un
/// objetivo que no llegue en un `ScanRequest` (ver `docs/security-scope.md`).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ScanRequest {
    /// Identificador de correlación del flujo completo (solicitud -> resultado).
    pub correlation_id: CorrelationId,
    /// IP del host a escanear. Es el único objetivo autorizado de esta
    /// solicitud.
    pub ip: IpAddr,
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
    /// Identidad del principal (usuario final) que originó la solicitud aguas
    /// arriba. Solo para trazabilidad/auditoría; la autorización sobre el
    /// objetivo se asume ya verificada por el Gateway/`ms-usuarios`.
    pub requested_by: String,
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
                },
                VulnFinding {
                    id: Some("CVE-2011-2523".to_owned()),
                    severity: Severity::Unknown,
                    description: "vsftpd 2.3.4 - Backdoor Command Execution (Exploit-DB 49757)"
                        .to_owned(),
                    nse_script: String::new(),
                    source: VulnSource::ExploitDb,
                    references: vec!["https://www.exploit-db.com/exploits/49757".to_owned()],
                },
            ],
            scanned_at: datetime!(2026-08-27 12:30:00 UTC),
        }
    }

    fn sample_request(secret: &str) -> ScanRequest {
        ScanRequest {
            correlation_id: CorrelationId::from("corr-42"),
            ip: "192.0.2.10".parse().expect("IP de prueba válida"),
            network_user: "scanner".to_owned(),
            ssh_credentials_ref: SshCredentialsRef::new(SecretString::from(secret.to_owned())),
            has_sudo: true,
            requested_by: "analyst@example.test".to_owned(),
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

        assert_eq!(request.ssh_credentials_ref.expose(), "real-broker-secret");
        assert!(!request.has_sudo);
        assert_eq!(request.correlation_id.as_str(), "corr-7");
        assert_eq!(request.ip, "198.51.100.4".parse::<IpAddr>().unwrap());
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
}

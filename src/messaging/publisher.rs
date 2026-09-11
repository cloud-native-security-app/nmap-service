//! Publicación del desenlace de un escaneo (resultado o fallo) de vuelta hacia
//! el Broker, para que `ms-analisis` lo consuma y redacte el informe final.
//!
//! La tecnología concreta de cola de mensajes (RabbitMQ / NATS / Kafka / Redis
//! Streams / ...) todavía no está decidida (ver `docs/architecture.md`,
//! §"Decisiones de diseño"). Por eso el resto del servicio depende sólo del
//! trait [`ScanResultSink`] y nunca de un cliente de broker concreto. Este
//! módulo aporta además:
//!
//! - [`ScanOutcome`]: unifica los dos desenlaces posibles del pipeline — éxito
//!   ([`ScanOutcome::Completed`]) y fallo ([`ScanOutcome::Failed`]) — en un solo
//!   tipo serializable. Se publican **ambos** (ver `docs/architecture.md`).
//! - [`encode_outcome`]: serializa un [`ScanOutcome`] al cuerpo de mensaje
//!   canónico (JSON) que consumirá `ms-analisis`.
//! - [`InMemoryScanResultSink`]: implementación de [`ScanResultSink`] para
//!   desarrollo, tests y el pipeline end-to-end (feature `scan_pipeline_wiring`)
//!   mientras el broker real no esté decidido; registra todo lo publicado para
//!   poder inspeccionarlo.
//! - [`log_outcome_published`]: traza de publicación identificada por
//!   `correlation_id`.
//!
//! # Formato del mensaje
//!
//! [`ScanOutcome`] usa una representación *internally tagged* con la clave
//! `status`. `ms-analisis` distingue los dos casos por ese campo:
//!
//! ```json
//! { "status": "completed",
//!   "correlation_id": "corr-42",
//!   "result": { "host": "192.0.2.10", "ports": [ ... ], "vulnerabilities": [ ... ],
//!               "scanned_at": "2026-08-27T12:30:00+00:00" } }
//! ```
//!
//! ```json
//! { "status": "failed",
//!   "correlation_id": "corr-42",
//!   "reason": "etapa SSH: tiempo de espera agotado" }
//! ```
//!
//! El objeto anidado `result` es exactamente la serialización de
//! [`crate::domain::ScanResult`], que **no** incluye el `correlation_id` (vive en
//! el `ScanRequest` original). Por eso [`ScanOutcome`] lo lleva aparte en ambas
//! variantes: así `ms-analisis` puede correlacionar el desenlace con la solicitud
//! sin importar si fue éxito o fallo.
//!
//! # Seguridad
//!
//! El `reason` de [`ScanOutcome::Failed`] es un `String` ya formateado por el
//! llamador (feature `scan_pipeline_wiring`) a partir del error tipado de la
//! etapa que falló. Este módulo no lo inspecciona ni lo enriquece: es
//! responsabilidad del llamador que ese texto no contenga credenciales ni el
//! valor de `ssh_credentials_ref` (ver `docs/security-scope.md`). Los tipos de
//! error de cada capa ya redactan las credenciales en su `Display`, de modo que
//! formatear `err.to_string()` es seguro.

use std::sync::Mutex;

use serde::{Deserialize, Serialize};

use crate::domain::{CorrelationId, ScanResult};

/// Desenlace de un escaneo, listo para publicarse hacia el Broker.
///
/// El pipeline termina siempre en uno de estos dos casos y **ambos** se
/// publican: `ms-analisis` necesita saber tanto que un escaneo terminó con
/// resultado como que falló y por qué.
///
/// Se serializa *internally tagged* con la clave `status` (`"completed"` /
/// `"failed"`); ver el formato de mensaje en la documentación del módulo.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "status", rename_all = "snake_case")]
pub enum ScanOutcome {
    /// El escaneo terminó y produjo un [`ScanResult`].
    Completed {
        /// Identificador de correlación de la solicitud original. Se incluye
        /// aparte porque [`ScanResult`] no lo transporta.
        correlation_id: CorrelationId,
        /// Todo lo descubierto sobre el host.
        result: ScanResult,
    },
    /// Alguna etapa del pipeline (SSH / nmap / parseo / Mongo) falló y el
    /// escaneo no pudo completarse.
    Failed {
        /// Identificador de correlación de la solicitud original.
        correlation_id: CorrelationId,
        /// Motivo legible del fallo, ya formateado por el llamador a partir del
        /// error tipado de la etapa que falló. No debe contener credenciales
        /// (ver §Seguridad del módulo).
        reason: String,
    },
}

impl ScanOutcome {
    /// Construye el desenlace de éxito a partir del `correlation_id` de la
    /// solicitud y el [`ScanResult`] producido.
    pub fn completed(correlation_id: CorrelationId, result: ScanResult) -> Self {
        Self::Completed {
            correlation_id,
            result,
        }
    }

    /// Construye el desenlace de fallo a partir del `correlation_id` de la
    /// solicitud y un motivo legible.
    pub fn failed(correlation_id: CorrelationId, reason: impl Into<String>) -> Self {
        Self::Failed {
            correlation_id,
            reason: reason.into(),
        }
    }

    /// Devuelve el `correlation_id` de la solicitud original, independientemente
    /// de la variante.
    pub fn correlation_id(&self) -> &CorrelationId {
        match self {
            Self::Completed { correlation_id, .. } | Self::Failed { correlation_id, .. } => {
                correlation_id
            }
        }
    }

    /// Devuelve la etiqueta de estado (`"completed"` / `"failed"`) que aparece en
    /// el campo `status` del mensaje.
    pub fn status_label(&self) -> &'static str {
        match self {
            Self::Completed { .. } => "completed",
            Self::Failed { .. } => "failed",
        }
    }
}

/// Motivo por el que no se pudo publicar un desenlace hacia el Broker.
///
/// Cada variante es distinguible para que el llamador reaccione distinto: un
/// fallo de serialización es un bug de datos (no se resuelve reintentando),
/// mientras que un fallo de transporte suele ser transitorio. Ninguna hace que
/// el proceso muera.
#[derive(Debug, thiserror::Error)]
pub enum PublishError {
    /// Fallo al entregar el mensaje al broker: conexión caída, canal cerrado,
    /// publish rechazado, etc.
    #[error("fallo de transporte al publicar hacia el Broker: {0}")]
    Transport(String),

    /// El desenlace no se pudo serializar al cuerpo de mensaje. No se resuelve
    /// reintentando.
    #[error("no se pudo serializar el mensaje de resultado: {0}")]
    Serialization(String),
}

/// Serializa un [`ScanOutcome`] al cuerpo de mensaje canónico (JSON UTF-8) que
/// consume `ms-analisis`.
///
/// Los adaptadores concretos de [`ScanResultSink`] deberían usar esta función
/// para producir el payload, de modo que el formato del mensaje sea idéntico sea
/// cual sea la tecnología de broker. Un fallo de `serde` se traduce a
/// [`PublishError::Serialization`]; nunca entra en pánico.
pub fn encode_outcome(outcome: &ScanOutcome) -> Result<Vec<u8>, PublishError> {
    serde_json::to_vec(outcome).map_err(|err| PublishError::Serialization(err.to_string()))
}

/// Registra en `tracing` (nivel `INFO`) la publicación de un desenlace,
/// identificándolo por su `correlation_id`.
///
/// Los adaptadores concretos de [`ScanResultSink`] deben llamarla al publicar
/// cada mensaje (la implementación de este módulo ya lo hace).
///
/// # Seguridad
///
/// Sólo emite los campos que devuelve `outcome_log_fields`: `correlation_id`,
/// `status` y, para el caso de éxito, los recuentos de puertos y
/// vulnerabilidades. Esa función no tiene forma de exponer el `reason` de un
/// fallo ni el `ScanResult` completo (ver `docs/security-scope.md`); testear
/// `outcome_log_fields` directamente evita depender de un subscriber global de
/// `tracing` en los tests.
pub fn log_outcome_published(outcome: &ScanOutcome) {
    let fields = outcome_log_fields(outcome);
    match fields.counts {
        Some((ports, vulnerabilities)) => tracing::info!(
            correlation_id = %fields.correlation_id,
            status = fields.status,
            ports,
            vulnerabilities,
            "desenlace de escaneo publicado hacia el Broker"
        ),
        None => tracing::info!(
            correlation_id = %fields.correlation_id,
            status = fields.status,
            "desenlace de escaneo publicado hacia el Broker"
        ),
    }
}

/// Campos no sensibles que [`log_outcome_published`] emite a `tracing`.
///
/// Estructuralmente incapaz de contener el `reason` de un fallo o el
/// `ScanResult`: sólo el `correlation_id`, la etiqueta de estado y, para el
/// éxito, los recuentos `(puertos, vulnerabilidades)`.
struct OutcomeLogFields<'a> {
    correlation_id: &'a CorrelationId,
    status: &'static str,
    counts: Option<(usize, usize)>,
}

/// Extrae de un [`ScanOutcome`] únicamente los campos aptos para logging.
///
/// Función pura: no hace IO ni toca `tracing`, de modo que su comportamiento se
/// puede verificar en un test unitario sin instalar un subscriber global (cuya
/// caché de interés tiene una carrera conocida al correr tests en paralelo).
fn outcome_log_fields(outcome: &ScanOutcome) -> OutcomeLogFields<'_> {
    match outcome {
        ScanOutcome::Completed {
            correlation_id,
            result,
        } => OutcomeLogFields {
            correlation_id,
            status: "completed",
            counts: Some((result.ports.len(), result.vulnerabilities.len())),
        },
        ScanOutcome::Failed { correlation_id, .. } => OutcomeLogFields {
            correlation_id,
            status: "failed",
            counts: None,
        },
    }
}

/// Destino de los desenlaces de escaneo, independiente de la tecnología concreta
/// del broker.
///
/// Un adaptador concreto (RabbitMQ, NATS, ...) implementará este trait; el
/// pipeline (feature `scan_pipeline_wiring`) publica a través de él sin conocer
/// el transporte. Es dyn-compatible: se comparte como `Arc<dyn ScanResultSink>`.
#[async_trait::async_trait]
pub trait ScanResultSink: Send + Sync {
    /// Publica un desenlace (éxito o fallo) hacia el Broker.
    ///
    /// - `Ok(())`: el mensaje se entregó (o se encoló de forma duradera, según
    ///   el adaptador).
    /// - `Err(PublishError::Serialization)`: el desenlace no se pudo serializar;
    ///   reintentar no ayuda.
    /// - `Err(PublishError::Transport)`: fallo de comunicación con el broker; el
    ///   llamador decide si reintenta. **No** es fatal para el proceso.
    async fn publish(&self, outcome: &ScanOutcome) -> Result<(), PublishError>;
}

/// Implementación de [`ScanResultSink`] que acumula en memoria todo lo publicado.
///
/// Se usa en los tests unitarios de este crate y como destino del pipeline
/// end-to-end mientras la tecnología real de broker no esté decidida. Cada
/// llamada a [`publish`](ScanResultSink::publish):
///
/// 1. serializa el desenlace con [`encode_outcome`] (así un `ScanOutcome`
///    inserializable produce [`PublishError::Serialization`], igual que con un
///    broker real),
/// 2. emite la traza vía [`log_outcome_published`],
/// 3. guarda una copia del desenlace, recuperable con [`published`](Self::published).
pub struct InMemoryScanResultSink {
    published: Mutex<Vec<ScanOutcome>>,
}

impl InMemoryScanResultSink {
    /// Crea un destino vacío.
    pub fn new() -> Self {
        Self {
            published: Mutex::new(Vec::new()),
        }
    }

    /// Devuelve una copia de todos los desenlaces publicados hasta ahora, en
    /// orden de publicación.
    pub fn published(&self) -> Vec<ScanOutcome> {
        match self.published.lock() {
            Ok(guard) => guard.clone(),
            Err(poisoned) => poisoned.into_inner().clone(),
        }
    }
}

impl Default for InMemoryScanResultSink {
    fn default() -> Self {
        Self::new()
    }
}

#[async_trait::async_trait]
impl ScanResultSink for InMemoryScanResultSink {
    async fn publish(&self, outcome: &ScanOutcome) -> Result<(), PublishError> {
        encode_outcome(outcome)?;
        log_outcome_published(outcome);
        match self.published.lock() {
            Ok(mut guard) => guard.push(outcome.clone()),
            Err(poisoned) => poisoned.into_inner().push(outcome.clone()),
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use time::macros::datetime;

    use super::*;
    use crate::domain::{PortFinding, PortState, Protocol, Severity, VulnFinding, VulnSource};

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
            ],
            vulnerabilities: vec![VulnFinding {
                id: Some("CVE-2023-38408".to_owned()),
                severity: Severity::High,
                description: "ssh-agent PKCS#11 arbitrary code execution".to_owned(),
                nse_script: "ssh-vuln-cve2023-38408".to_owned(),
                source: VulnSource::NmapNse,
                references: Vec::new(),
            }],
            scanned_at: datetime!(2026-08-27 12:30:00 UTC),
        }
    }

    #[test]
    fn completed_outcome_serializes_to_expected_message_shape() {
        let outcome = ScanOutcome::completed(CorrelationId::from("corr-42"), sample_result());

        let json = serde_json::to_value(&outcome).expect("serializa a JSON");

        assert_eq!(json["status"], "completed");
        assert_eq!(json["correlation_id"], "corr-42");
        assert_eq!(json["result"]["host"], "192.0.2.10");
        assert_eq!(json["result"]["ports"][0]["port"], 22);
        assert_eq!(json["result"]["ports"][0]["protocol"], "tcp");
        assert_eq!(json["result"]["ports"][0]["state"], "open");
        assert_eq!(json["result"]["ports"][0]["service"], "ssh");
        assert_eq!(json["result"]["ports"][1]["state"], "filtered");
        assert_eq!(json["result"]["vulnerabilities"][0]["id"], "CVE-2023-38408");
        assert_eq!(json["result"]["vulnerabilities"][0]["severity"], "high");
        assert!(
            json["result"]["scanned_at"]
                .as_str()
                .expect("scanned_at es cadena")
                .starts_with("2026-08-27T12:30:00"),
            "scanned_at no es RFC 3339: {}",
            json["result"]["scanned_at"]
        );
        // El caso de éxito no lleva `reason`.
        assert!(json.get("reason").is_none());
    }

    #[test]
    fn failed_outcome_serializes_with_correlation_id_and_reason() {
        let outcome = ScanOutcome::failed(
            CorrelationId::from("corr-99"),
            "etapa SSH: autenticación SSH rechazada",
        );

        let json = serde_json::to_value(&outcome).expect("serializa a JSON");

        assert_eq!(json["status"], "failed");
        assert_eq!(json["correlation_id"], "corr-99");
        assert_eq!(json["reason"], "etapa SSH: autenticación SSH rechazada");
        // El caso de fallo no lleva `result`.
        assert!(json.get("result").is_none());
    }

    #[test]
    fn outcome_json_round_trip_preserves_every_field() {
        for outcome in [
            ScanOutcome::completed(CorrelationId::from("corr-1"), sample_result()),
            ScanOutcome::failed(CorrelationId::from("corr-2"), "Mongo: conexión rechazada"),
        ] {
            let json = serde_json::to_string(&outcome).expect("serializa");
            let restored: ScanOutcome = serde_json::from_str(&json).expect("deserializa");
            assert_eq!(restored, outcome);
        }
    }

    #[test]
    fn encode_outcome_produces_parseable_json_bytes() {
        let bytes = encode_outcome(&ScanOutcome::failed(
            CorrelationId::from("corr-7"),
            "nmap: binario no disponible en el objetivo",
        ))
        .expect("serializa a bytes");

        let value: serde_json::Value =
            serde_json::from_slice(&bytes).expect("los bytes son JSON válido");
        assert_eq!(value["status"], "failed");
        assert_eq!(value["correlation_id"], "corr-7");
    }

    #[test]
    fn correlation_id_accessor_works_for_both_variants() {
        assert_eq!(
            ScanOutcome::completed(CorrelationId::from("a"), sample_result())
                .correlation_id()
                .as_str(),
            "a"
        );
        assert_eq!(
            ScanOutcome::failed(CorrelationId::from("b"), "x")
                .correlation_id()
                .as_str(),
            "b"
        );
    }

    #[tokio::test]
    async fn in_memory_sink_records_published_success_and_failure_in_order() {
        let sink = InMemoryScanResultSink::new();

        sink.publish(&ScanOutcome::completed(
            CorrelationId::from("c1"),
            sample_result(),
        ))
        .await
        .expect("publica el éxito");
        sink.publish(&ScanOutcome::failed(
            CorrelationId::from("c2"),
            "etapa parseo: XML malformado",
        ))
        .await
        .expect("publica el fallo");

        let published = sink.published();
        assert_eq!(published.len(), 2);
        assert!(matches!(published[0], ScanOutcome::Completed { .. }));
        assert_eq!(published[0].correlation_id().as_str(), "c1");
        match &published[1] {
            ScanOutcome::Failed {
                correlation_id,
                reason,
            } => {
                assert_eq!(correlation_id.as_str(), "c2");
                assert_eq!(reason, "etapa parseo: XML malformado");
            }
            other => panic!("se esperaba Failed, se obtuvo {other:?}"),
        }
    }

    #[test]
    fn failed_reason_is_stored_verbatim_from_the_caller() {
        // Contrato: `reason` es un String ya formateado por el llamador (feature
        // `scan_pipeline_wiring`). El publisher no lo inspecciona ni lo
        // enriquece; el llamador es responsable de que no contenga credenciales
        // (docs/security-scope.md). Los Display de los errores de cada capa ya
        // redactan la credencial, así que `err.to_string()` es seguro.
        let reason = "etapa SSH: tiempo de espera agotado";
        match ScanOutcome::failed(CorrelationId::from("c"), reason) {
            ScanOutcome::Failed { reason: stored, .. } => assert_eq!(stored, reason),
            other => panic!("se esperaba Failed, se obtuvo {other:?}"),
        }
    }

    #[test]
    fn log_fields_for_a_failure_expose_only_correlation_id_and_status() {
        // Se testea la función pura en vez de capturar por un subscriber global
        // de `tracing`: esa vía es flaky al correr tests en paralelo (carrera en
        // la caché de interés de `tracing`).
        let outcome = ScanOutcome::failed(
            CorrelationId::from("corr-42"),
            "etapa SSH: fallo con token super-secreto",
        );
        let fields = outcome_log_fields(&outcome);

        assert_eq!(fields.correlation_id.as_str(), "corr-42");
        assert_eq!(fields.status, "failed");
        // Sin `counts` y, estructuralmente, sin forma de llevar el `reason`.
        assert_eq!(fields.counts, None);
    }

    #[test]
    fn log_fields_for_a_success_carry_counts_not_the_result() {
        let outcome = ScanOutcome::completed(CorrelationId::from("corr-7"), sample_result());
        let fields = outcome_log_fields(&outcome);

        assert_eq!(fields.correlation_id.as_str(), "corr-7");
        assert_eq!(fields.status, "completed");
        assert_eq!(fields.counts, Some((2, 1)));
    }

    #[test]
    fn log_outcome_published_does_not_panic_for_either_variant() {
        log_outcome_published(&ScanOutcome::completed(
            CorrelationId::from("c"),
            sample_result(),
        ));
        log_outcome_published(&ScanOutcome::failed(CorrelationId::from("c"), "x"));
    }
}

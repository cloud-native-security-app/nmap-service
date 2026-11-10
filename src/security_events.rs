//! Puerto de eventos de seguridad de ms-nmap y su tipo de mensaje (feature
//! `security_event_publisher`, tarea KAP-07): hechos inmutables que se
//! publican en el Kinesis Data Stream `security-events` para que el panel de
//! administración (KAP-09) y otros consumidores los lean sin acoplarse a quien
//! los produce. El contrato es `broker/contracts/security-event.schema.json`;
//! `tests/security_event_contract.rs` valida cada evento emitido contra él.
//! Es el espejo del módulo homónimo del Gateway (KAP-06).
//!
//! ms-nmap produce cuatro tipos: `scan.started`, `scan.completed`,
//! `scan.failed` y `finding.critical`. Los demás los producen el Gateway y
//! `user-service`; [`EventType`] cubre los 11 valores del contrato para poder
//! deserializar los ejemplos.
//!
//! Los adaptadores viven en [`crate::messaging::kinesis`] (real) y en este
//! módulo ([`NoopSecurityEventPublisher`], [`RecordingSecurityEventPublisher`]).
//!
//! ## Decisiones de diseño
//!
//! - **Un fallo de publicación nunca llega al escaneo**: los puntos de
//!   emisión usan [`emit`]/[`emit_all`], que publican en una tarea `tokio`
//!   desacoplada con un tope de [`PUBLISH_TIMEOUT`] por evento y solo loggean
//!   el tipo de evento. El pipeline no espera a Kinesis ni puede fallar por
//!   él. El costo es que un evento puede perderse si el proceso muere antes de
//!   que la tarea corra; es aceptable porque el estado del escaneo (Mongo/SNS)
//!   es la fuente de verdad.
//! - **Los constructores validan el schema**: cada constructor tipado rechaza
//!   con [`InvalidSecurityEvent`] un valor que el schema no aceptaría (largo,
//!   patrón, severidad). El error nombra el campo, nunca el valor.
//! - **Nada sensible**: ningún evento lleva credenciales, IP de objetivos,
//!   texto de errores ni salida de `nmap`; los motivos son códigos cortos.
//! - **Clave de partición**: `scan_id` ([`SecurityEvent::partition_key`]);
//!   todos los eventos de un escaneo comparten shard y conservan su orden de
//!   publicación.

use std::sync::{Arc, Mutex};
use std::time::Duration;

use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use time::format_description::well_known::Rfc3339;
use time::OffsetDateTime;

use crate::domain::{Confidence, PatchState, Protocol, ScanResult, Severity};

/// Tiempo máximo que la tarea de [`emit`]/[`emit_all`] espera a que el
/// adaptador publique cada evento antes de soltarlo.
pub const PUBLISH_TIMEOUT: Duration = Duration::from_secs(5);

/// Máximo de caracteres de `scan_id` según el schema.
const MAX_ID_CHARS: usize = 128;
/// Máximo de caracteres de un `reason_code`.
const MAX_REASON_CODE_CHARS: usize = 64;

/// Tope de eventos `finding.critical` por escaneo. El stream `security-events`
/// tiene un solo shard (1000 registros/s, 1 MiB/s): un host con cientos de CVE
/// altos no debe saturarlo. Los hallazgos por encima del tope se conservan
/// (en el resultado persistido y en los contadores de `scan.completed`) pero no
/// emiten evento propio; se emiten primero los críticos y luego los altos.
pub const MAX_FINDING_CRITICAL_EVENTS: usize = 50;

/// Tipo de un [`SecurityEvent`]; cubre los 11 valores del contrato aunque
/// ms-nmap solo produce algunos.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum EventType {
    /// Un usuario pidió un escaneo y el Broker lo aceptó.
    #[serde(rename = "scan.requested")]
    ScanRequested,
    /// Un usuario pidió cancelar un escaneo y el Broker lo aceptó.
    #[serde(rename = "scan.cancelled")]
    ScanCancelled,
    /// ms-nmap empezó un escaneo.
    #[serde(rename = "scan.started")]
    ScanStarted,
    /// ms-nmap terminó un escaneo.
    #[serde(rename = "scan.completed")]
    ScanCompleted,
    /// ms-nmap falló un escaneo.
    #[serde(rename = "scan.failed")]
    ScanFailed,
    /// ms-nmap encontró un hallazgo alto o crítico.
    #[serde(rename = "finding.critical")]
    FindingCritical,
    /// Un usuario completó el login.
    #[serde(rename = "auth.login")]
    AuthLogin,
    /// Un usuario cerró sesión.
    #[serde(rename = "auth.logout")]
    AuthLogout,
    /// Una petición superó el límite de tasa.
    #[serde(rename = "ratelimit.hit")]
    RatelimitHit,
    /// Un mensaje se envió a una dead-letter queue.
    #[serde(rename = "message.deadlettered")]
    MessageDeadlettered,
    /// `user-service` registró una acción de auditoría.
    #[serde(rename = "audit.recorded")]
    AuditRecorded,
}

impl EventType {
    /// Valor del contrato (`scan.started`, ...).
    pub fn as_str(self) -> &'static str {
        match self {
            Self::ScanRequested => "scan.requested",
            Self::ScanCancelled => "scan.cancelled",
            Self::ScanStarted => "scan.started",
            Self::ScanCompleted => "scan.completed",
            Self::ScanFailed => "scan.failed",
            Self::FindingCritical => "finding.critical",
            Self::AuthLogin => "auth.login",
            Self::AuthLogout => "auth.logout",
            Self::RatelimitHit => "ratelimit.hit",
            Self::MessageDeadlettered => "message.deadlettered",
            Self::AuditRecorded => "audit.recorded",
        }
    }
}

/// Servicio que produjo un [`SecurityEvent`].
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum EventSource {
    /// El Gateway.
    #[serde(rename = "gateway")]
    Gateway,
    /// ms-nmap (este servicio).
    #[serde(rename = "nmap-service")]
    NmapService,
    /// `user-service`.
    #[serde(rename = "user-service")]
    UserService,
}

/// Evento de seguridad inmutable: el sobre del contrato
/// `security-event.schema.json`. Se construye con los constructores tipados
/// (uno por evento que produce ms-nmap) o se deserializa de un registro del
/// stream.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SecurityEvent {
    event_id: String,
    event_type: EventType,
    occurred_at: String,
    source: EventSource,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    actor_sub: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    scan_id: Option<String>,
    payload: Value,
}

/// Un constructor de [`SecurityEvent`] recibió un valor que el schema
/// rechazaría. Nombra el campo, nunca el valor.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
#[error("el evento '{event_type}' tiene un valor inválido en el campo '{field}'")]
pub struct InvalidSecurityEvent {
    /// Tipo del evento que se intentaba construir.
    pub event_type: &'static str,
    /// Campo (del sobre o del `payload`) con el valor inválido.
    pub field: &'static str,
}

/// Errores al publicar un [`SecurityEvent`]. Ninguna variante incluye el
/// cuerpo del evento.
#[derive(Debug, thiserror::Error)]
pub enum SecurityEventError {
    /// El adaptador no pudo entregar el evento al stream. La causa original
    /// se conserva en `source` (solo visible vía la cadena de `source()`).
    #[error("no se pudo publicar el evento de seguridad")]
    PublishFailed(#[source] Box<dyn std::error::Error + Send + Sync>),
    /// No se pudo serializar el evento a JSON.
    #[error("no se pudo serializar el evento de seguridad")]
    SerializationFailed(#[source] serde_json::Error),
}

/// Puerto: "publicar un [`SecurityEvent`]". `ServicePorts` guarda un
/// `Arc<dyn SecurityEventPublisher>` para que los tests que no ejercen eventos
/// no necesiten LocalStack.
///
/// Los llamadores del pipeline no usan este método directamente sino
/// [`emit`]/[`emit_all`], que garantizan que un fallo nunca afecte al escaneo.
#[async_trait::async_trait]
pub trait SecurityEventPublisher: Send + Sync {
    /// Publica `event`, devolviendo éxito solo cuando el destino lo aceptó.
    async fn publish(&self, event: &SecurityEvent) -> Result<(), SecurityEventError>;
}

/// Recuento de hallazgos por severidad del payload de `scan.completed`.
///
/// Mapeo 1:1 con [`Severity`] (el schema usa los mismos seis nombres): cada
/// [`crate::domain::VulnFinding`] del resultado suma en el contador de su
/// severidad; `unknown` agrupa los hallazgos sin severidad informada. Los
/// puertos abiertos ([`crate::domain::PortFinding`]) no tienen severidad y no
/// se cuentan.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct FindingCounts {
    /// Hallazgos de severidad crítica.
    pub critical: u64,
    /// Hallazgos de severidad alta.
    pub high: u64,
    /// Hallazgos de severidad media.
    pub medium: u64,
    /// Hallazgos de severidad baja.
    pub low: u64,
    /// Hallazgos informativos.
    pub info: u64,
    /// Hallazgos sin severidad informada.
    pub unknown: u64,
}

impl FindingCounts {
    /// Suma un hallazgo de `severity`.
    pub fn record(&mut self, severity: Severity) {
        let counter = match severity {
            Severity::Critical => &mut self.critical,
            Severity::High => &mut self.high,
            Severity::Medium => &mut self.medium,
            Severity::Low => &mut self.low,
            Severity::Info => &mut self.info,
            Severity::Unknown => &mut self.unknown,
        };
        *counter += 1;
    }
}

impl SecurityEvent {
    fn new(
        event_type: EventType,
        scan_id: &str,
        payload: Value,
    ) -> Result<Self, InvalidSecurityEvent> {
        if !valid_id(scan_id) {
            return Err(InvalidSecurityEvent {
                event_type: event_type.as_str(),
                field: "scan_id",
            });
        }
        Ok(Self {
            event_id: uuid::Uuid::new_v4().to_string(),
            event_type,
            occurred_at: now_rfc3339(),
            source: EventSource::NmapService,
            actor_sub: None,
            scan_id: Some(scan_id.to_string()),
            payload,
        })
    }

    /// `scan.started`: ms-nmap empezó el escaneo `scan_id` (su
    /// `correlation_id`). Sin payload.
    pub fn scan_started(scan_id: &str) -> Result<Self, InvalidSecurityEvent> {
        Self::new(EventType::ScanStarted, scan_id, json!({}))
    }

    /// `scan.completed`: el escaneo `scan_id` terminó tras `duration_ms`
    /// milisegundos con `counts` hallazgos por severidad.
    pub fn scan_completed(
        scan_id: &str,
        duration_ms: u64,
        counts: FindingCounts,
    ) -> Result<Self, InvalidSecurityEvent> {
        Self::new(
            EventType::ScanCompleted,
            scan_id,
            json!({
                "duration_ms": duration_ms,
                "finding_counts": {
                    "critical": counts.critical,
                    "high": counts.high,
                    "medium": counts.medium,
                    "low": counts.low,
                    "info": counts.info,
                    "unknown": counts.unknown,
                },
            }),
        )
    }

    /// `scan.failed`: el escaneo `scan_id` falló por `reason_code` (slug
    /// corto, nunca texto de error).
    pub fn scan_failed(scan_id: &str, reason_code: &str) -> Result<Self, InvalidSecurityEvent> {
        if !valid_reason_code(reason_code) {
            return Err(InvalidSecurityEvent {
                event_type: EventType::ScanFailed.as_str(),
                field: "reason_code",
            });
        }
        Self::new(
            EventType::ScanFailed,
            scan_id,
            json!({ "reason_code": reason_code }),
        )
    }

    /// `finding.critical`: el escaneo `scan_id` encontró un hallazgo
    /// `severity` (solo `high` o `critical`) con `confidence` en
    /// `port`/`protocol`. `cve_id` es `None` si el hallazgo no tiene un CVE
    /// (ver [`is_cve_id`]).
    pub fn finding_critical(
        scan_id: &str,
        port: u16,
        protocol: Protocol,
        cve_id: Option<&str>,
        severity: Severity,
        confidence: Confidence,
    ) -> Result<Self, InvalidSecurityEvent> {
        let invalid = |field| InvalidSecurityEvent {
            event_type: EventType::FindingCritical.as_str(),
            field,
        };
        let severity = match severity {
            Severity::High => "high",
            Severity::Critical => "critical",
            _ => return Err(invalid("severity")),
        };
        if cve_id.is_some_and(|id| !is_cve_id(id)) {
            return Err(invalid("cve_id"));
        }
        let protocol = match protocol {
            Protocol::Tcp => "tcp",
            Protocol::Udp => "udp",
        };
        let confidence = match confidence {
            Confidence::Confirmed => "confirmed",
            Confidence::VersionMatch => "version_match",
        };
        Self::new(
            EventType::FindingCritical,
            scan_id,
            json!({
                "port": port,
                "protocol": protocol,
                "cve_id": cve_id,
                "severity": severity,
                "confidence": confidence,
            }),
        )
    }

    /// UUID v4 único de este evento (los consumidores deduplican por él:
    /// Kinesis entrega al menos una vez).
    pub fn event_id(&self) -> &str {
        &self.event_id
    }

    /// Tipo del evento.
    pub fn event_type(&self) -> EventType {
        self.event_type
    }

    /// Tipo del evento como texto del contrato.
    pub fn event_type_str(&self) -> &'static str {
        self.event_type.as_str()
    }

    /// Instante del evento, RFC 3339 en UTC.
    pub fn occurred_at(&self) -> &str {
        &self.occurred_at
    }

    /// Servicio que produjo el evento.
    pub fn source(&self) -> EventSource {
        self.source
    }

    /// `sub` del usuario que causó el evento, si aplica (nunca en los eventos
    /// de ms-nmap).
    pub fn actor_sub(&self) -> Option<&str> {
        self.actor_sub.as_deref()
    }

    /// Identificador del escaneo al que pertenece el evento, si aplica.
    pub fn scan_id(&self) -> Option<&str> {
        self.scan_id.as_deref()
    }

    /// Carga útil específica del tipo de evento.
    pub fn payload(&self) -> &Value {
        &self.payload
    }

    /// Clave de partición de Kinesis: `scan_id` (mantiene en orden todos los
    /// eventos de un escaneo), si no `actor_sub`, si no `event_id`.
    pub fn partition_key(&self) -> &str {
        self.scan_id
            .as_deref()
            .or(self.actor_sub.as_deref())
            .unwrap_or(&self.event_id)
    }
}

/// Eventos que deja un escaneo terminado: primero `scan.completed` (con
/// `duration_ms` y los contadores de **todos** los hallazgos por severidad) y
/// luego un `finding.critical` por hallazgo alto o crítico, hasta
/// [`MAX_FINDING_CRITICAL_EVENTS`] (los críticos primero).
///
/// Un hallazgo no emite `finding.critical` si:
///
/// - su `patch_state` es [`PatchState::Fixed`] (el objetivo ya no es
///   vulnerable: sería una falsa alarma); o
/// - no tiene `confidence` (el schema exige `confirmed` o `version_match` y
///   afirmar cualquiera de los dos sería inventar un dato).
///
/// `port` y `protocol` son `0` y `tcp`: el dominio no asocia un
/// [`crate::domain::VulnFinding`] a un puerto (ver `docs/architecture.md`).
/// `cve_id` es `None` si el id del hallazgo no tiene forma de CVE.
pub fn completion_events(
    scan_id: &str,
    duration_ms: u64,
    result: &ScanResult,
) -> Vec<Result<SecurityEvent, InvalidSecurityEvent>> {
    let mut counts = FindingCounts::default();
    for finding in &result.vulnerabilities {
        counts.record(finding.severity);
    }
    let mut events = vec![SecurityEvent::scan_completed(scan_id, duration_ms, counts)];

    let candidates = |severity: Severity| {
        result.vulnerabilities.iter().filter(move |finding| {
            finding.severity == severity && finding.patch_state != Some(PatchState::Fixed)
        })
    };
    let ordered = candidates(Severity::Critical).chain(candidates(Severity::High));
    for (finding, confidence) in ordered.filter_map(|f| f.confidence.map(|c| (f, c))) {
        if events.len() > MAX_FINDING_CRITICAL_EVENTS {
            tracing::info!(
                cap = MAX_FINDING_CRITICAL_EVENTS,
                "hallazgos altos/críticos por encima del tope: solo cuentan en scan.completed"
            );
            break;
        }
        events.push(SecurityEvent::finding_critical(
            scan_id,
            0,
            Protocol::Tcp,
            finding.id.as_deref().filter(|id| is_cve_id(id)),
            finding.severity,
            confidence,
        ));
    }
    events
}

/// `true` si `value` tiene la forma de un CVE que acepta el schema
/// (`CVE-AAAA-NNNN+`).
pub fn is_cve_id(value: &str) -> bool {
    let Some(rest) = value.strip_prefix("CVE-") else {
        return false;
    };
    let Some((year, seq)) = rest.split_once('-') else {
        return false;
    };
    year.len() == 4
        && year.bytes().all(|b| b.is_ascii_digit())
        && seq.len() >= 4
        && seq.bytes().all(|b| b.is_ascii_digit())
}

fn valid_id(value: &str) -> bool {
    (1..=MAX_ID_CHARS).contains(&value.chars().count())
}

fn valid_reason_code(value: &str) -> bool {
    let mut chars = value.chars();
    chars.next().is_some_and(|c| c.is_ascii_lowercase())
        && value.chars().count() <= MAX_REASON_CODE_CHARS
        && chars.all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || c == '_')
}

fn now_rfc3339() -> String {
    OffsetDateTime::now_utc()
        .format(&Rfc3339)
        .unwrap_or_else(|_| "1970-01-01T00:00:00Z".to_string())
}

/// Emite `event` sin esperar ni propagar nada. Equivale a [`emit_all`] con un
/// único evento.
pub fn emit(
    publisher: &Arc<dyn SecurityEventPublisher>,
    event: Result<SecurityEvent, InvalidSecurityEvent>,
) {
    emit_all(publisher, vec![event]);
}

/// Emite `events` sin esperar ni propagar nada: los publica en orden desde una
/// única tarea `tokio` desacoplada, con tope de [`PUBLISH_TIMEOUT`] por
/// evento. Al primer fallo o timeout el resto del lote se descarta (si Kinesis
/// está caído, no tiene sentido encadenar timeouts). Un evento inválido o la
/// ausencia de runtime solo se loggean (tipo de evento y campo, nunca el
/// contenido). Es el único punto de emisión que debe usar el pipeline.
pub fn emit_all(
    publisher: &Arc<dyn SecurityEventPublisher>,
    events: Vec<Result<SecurityEvent, InvalidSecurityEvent>>,
) {
    let events: Vec<SecurityEvent> = events
        .into_iter()
        .filter_map(|event| match event {
            Ok(event) => Some(event),
            Err(err) => {
                tracing::warn!(
                    event_type = err.event_type,
                    field = err.field,
                    "evento de seguridad descartado: valor inválido para el contrato"
                );
                None
            }
        })
        .collect();
    if events.is_empty() {
        return;
    }
    let Ok(runtime) = tokio::runtime::Handle::try_current() else {
        tracing::warn!("eventos de seguridad descartados: no hay runtime tokio activo");
        return;
    };
    let publisher = Arc::clone(publisher);
    runtime.spawn(async move {
        for event in &events {
            match tokio::time::timeout(PUBLISH_TIMEOUT, publisher.publish(event)).await {
                Ok(Ok(())) => {}
                Ok(Err(_)) => {
                    tracing::error!(
                        event_type = event.event_type_str(),
                        "no se pudo publicar un evento de seguridad (el escaneo no se ve afectado)"
                    );
                    return;
                }
                Err(_) => {
                    tracing::error!(
                        event_type = event.event_type_str(),
                        "se agotó el tiempo publicando un evento de seguridad (el escaneo no se ve afectado)"
                    );
                    return;
                }
            }
        }
    });
}

/// Adaptador que descarta todo evento: se usa cuando
/// `SECURITY_EVENTS_STREAM_NAME` no está definida.
#[derive(Debug, Clone, Copy, Default)]
pub struct NoopSecurityEventPublisher;

#[async_trait::async_trait]
impl SecurityEventPublisher for NoopSecurityEventPublisher {
    async fn publish(&self, _event: &SecurityEvent) -> Result<(), SecurityEventError> {
        Ok(())
    }
}

/// Adaptador en memoria que conserva los eventos publicados, para tests que
/// verifican qué emite el pipeline sin Kinesis.
#[derive(Debug, Default)]
pub struct RecordingSecurityEventPublisher {
    events: Mutex<Vec<SecurityEvent>>,
}

impl RecordingSecurityEventPublisher {
    /// Crea un grabador vacío.
    pub fn new() -> Self {
        Self::default()
    }

    /// Copia de los eventos publicados hasta ahora, en orden.
    pub fn events(&self) -> Vec<SecurityEvent> {
        self.events
            .lock()
            .unwrap_or_else(|poison| poison.into_inner())
            .clone()
    }

    /// Cede el turno al runtime (sin esperas de reloj) hasta que haya al
    /// menos `count` eventos, con un tope de intentos, y devuelve lo
    /// grabado. [`emit`] publica en una tarea aparte, así que los tests la
    /// usan en vez de dormir.
    pub async fn wait_for(&self, count: usize) -> Vec<SecurityEvent> {
        for _ in 0..10_000 {
            let events = self.events();
            if events.len() >= count {
                return events;
            }
            tokio::task::yield_now().await;
        }
        self.events()
    }
}

#[async_trait::async_trait]
impl SecurityEventPublisher for RecordingSecurityEventPublisher {
    async fn publish(&self, event: &SecurityEvent) -> Result<(), SecurityEventError> {
        self.events
            .lock()
            .unwrap_or_else(|poison| poison.into_inner())
            .push(event.clone());
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use std::sync::atomic::{AtomicUsize, Ordering};
    use std::sync::Arc;

    use super::*;
    use crate::domain::{Confidence, Protocol, Severity};

    fn counts() -> FindingCounts {
        let mut counts = FindingCounts::default();
        for severity in [
            Severity::Critical,
            Severity::High,
            Severity::High,
            Severity::Medium,
            Severity::Low,
            Severity::Info,
            Severity::Unknown,
            Severity::Unknown,
        ] {
            counts.record(severity);
        }
        counts
    }

    #[test]
    fn partition_key_is_the_scan_id() {
        let event = SecurityEvent::scan_started("scan-1").unwrap();
        assert_eq!(event.partition_key(), "scan-1");
        assert_eq!(event.scan_id(), Some("scan-1"));
    }

    #[test]
    fn envelope_has_uuid_v4_id_rfc3339_utc_timestamp_and_nmap_source() {
        let event = SecurityEvent::scan_started("scan-1").unwrap();
        let id = uuid::Uuid::parse_str(event.event_id()).expect("event_id debe ser UUID");
        assert_eq!(id.get_version_num(), 4);
        assert!(event.occurred_at().ends_with('Z'));
        time::OffsetDateTime::parse(
            event.occurred_at(),
            &time::format_description::well_known::Rfc3339,
        )
        .expect("occurred_at debe ser RFC 3339");
        let value = serde_json::to_value(&event).unwrap();
        assert_eq!(value["source"], "nmap-service");
        assert_eq!(value["event_type"], "scan.started");
        assert_eq!(value["payload"], serde_json::json!({}));
        assert!(value.get("actor_sub").is_none());
    }

    #[test]
    fn scan_completed_carries_duration_and_counts_by_severity() {
        let value =
            serde_json::to_value(SecurityEvent::scan_completed("s", 42_000, counts()).unwrap())
                .unwrap();
        assert_eq!(value["payload"]["duration_ms"], 42_000);
        assert_eq!(
            value["payload"]["finding_counts"],
            serde_json::json!({
                "critical": 1, "high": 2, "medium": 1, "low": 1, "info": 1, "unknown": 2
            })
        );
    }

    #[test]
    fn scan_failed_carries_only_the_reason_code() {
        let value =
            serde_json::to_value(SecurityEvent::scan_failed("s", "ssh_timeout").unwrap()).unwrap();
        assert_eq!(
            value["payload"],
            serde_json::json!({"reason_code": "ssh_timeout"})
        );
    }

    #[test]
    fn finding_critical_carries_port_protocol_cve_severity_and_confidence() {
        let with_cve = serde_json::to_value(
            SecurityEvent::finding_critical(
                "s",
                22,
                Protocol::Tcp,
                Some("CVE-2023-38408"),
                Severity::Critical,
                Confidence::Confirmed,
            )
            .unwrap(),
        )
        .unwrap();
        assert_eq!(
            with_cve["payload"],
            serde_json::json!({
                "port": 22, "protocol": "tcp", "cve_id": "CVE-2023-38408",
                "severity": "critical", "confidence": "confirmed"
            })
        );
        let without_cve = serde_json::to_value(
            SecurityEvent::finding_critical(
                "s",
                0,
                Protocol::Udp,
                None,
                Severity::High,
                Confidence::VersionMatch,
            )
            .unwrap(),
        )
        .unwrap();
        assert!(without_cve["payload"]["cve_id"].is_null());
        assert_eq!(without_cve["payload"]["confidence"], "version_match");
    }

    #[test]
    fn constructors_refuse_values_the_schema_would_reject() {
        assert!(SecurityEvent::scan_started("").is_err());
        assert!(SecurityEvent::scan_started(&"x".repeat(129)).is_err());
        assert!(SecurityEvent::scan_started(&"x".repeat(128)).is_ok());
        assert!(SecurityEvent::scan_failed("s", "Not A Slug").is_err());
        assert!(SecurityEvent::scan_failed("s", "").is_err());
        assert!(SecurityEvent::scan_failed("s", &"a".repeat(65)).is_err());
        let finding = |sev, cve| {
            SecurityEvent::finding_critical("s", 80, Protocol::Tcp, cve, sev, Confidence::Confirmed)
        };
        assert!(finding(Severity::Medium, None).is_err());
        assert!(finding(Severity::Unknown, None).is_err());
        assert!(finding(Severity::High, Some("EDB-1234")).is_err());
        assert!(finding(Severity::High, Some("CVE-2023-123")).is_err());
        assert!(finding(Severity::High, Some("CVE-2023-1234")).is_ok());
    }

    #[test]
    fn cve_id_helper_accepts_only_the_schema_pattern() {
        assert!(is_cve_id("CVE-2011-2523"));
        assert!(is_cve_id("CVE-2024-123456"));
        assert!(!is_cve_id("cve-2011-2523"));
        assert!(!is_cve_id("CVE-2011-252"));
        assert!(!is_cve_id("EDB-12345"));
        assert!(!is_cve_id("CVE-2011-2523 "));
    }

    #[test]
    fn invalid_event_error_names_the_field_but_never_the_value() {
        let err = SecurityEvent::scan_failed("s", "secret value!").expect_err("slug inválido");
        let text = err.to_string();
        assert!(text.contains("reason_code"));
        assert!(!text.contains("secret"));
    }

    #[tokio::test]
    async fn recording_publisher_keeps_published_events_in_order() {
        let recorder = RecordingSecurityEventPublisher::new();
        recorder
            .publish(&SecurityEvent::scan_started("a").unwrap())
            .await
            .unwrap();
        recorder
            .publish(&SecurityEvent::scan_failed("a", "ssh_timeout").unwrap())
            .await
            .unwrap();
        let types: Vec<_> = recorder
            .events()
            .iter()
            .map(|e| e.event_type_str().to_string())
            .collect();
        assert_eq!(types, ["scan.started", "scan.failed"]);
    }

    #[tokio::test]
    async fn noop_publisher_accepts_everything() {
        NoopSecurityEventPublisher
            .publish(&SecurityEvent::scan_started("a").unwrap())
            .await
            .unwrap();
    }

    #[tokio::test]
    async fn emit_delivers_in_the_background() {
        let recorder = Arc::new(RecordingSecurityEventPublisher::new());
        let port: Arc<dyn SecurityEventPublisher> = recorder.clone();
        emit(&port, SecurityEvent::scan_started("a"));
        assert_eq!(recorder.wait_for(1).await.len(), 1);
    }

    #[tokio::test]
    async fn emit_all_publishes_in_order_and_skips_invalid_events() {
        let recorder = Arc::new(RecordingSecurityEventPublisher::new());
        let port: Arc<dyn SecurityEventPublisher> = recorder.clone();
        emit_all(
            &port,
            vec![
                SecurityEvent::scan_started("a"),
                SecurityEvent::scan_started(""),
                SecurityEvent::scan_failed("a", "ssh_timeout"),
            ],
        );
        let events = recorder.wait_for(2).await;
        let types: Vec<_> = events.iter().map(SecurityEvent::event_type_str).collect();
        assert_eq!(types, ["scan.started", "scan.failed"]);
    }

    #[tokio::test]
    async fn emit_with_a_failing_publisher_neither_panics_nor_blocks() {
        let port: Arc<dyn SecurityEventPublisher> = Arc::new(FailingPublisher::default());
        emit(&port, SecurityEvent::scan_started("a"));
        // `emit` es síncrona: si hubiera esperado o propagado el fallo, no
        // habría devuelto el control aquí.
        tokio::task::yield_now().await;
    }

    #[tokio::test]
    async fn emit_all_stops_the_batch_after_the_first_failure() {
        let failing = Arc::new(FailingPublisher::default());
        let port: Arc<dyn SecurityEventPublisher> = failing.clone();
        emit_all(
            &port,
            vec![
                SecurityEvent::scan_started("a"),
                SecurityEvent::scan_started("b"),
                SecurityEvent::scan_started("c"),
            ],
        );
        for _ in 0..50 {
            tokio::task::yield_now().await;
        }
        assert_eq!(failing.calls.load(Ordering::SeqCst), 1);
    }

    #[tokio::test]
    async fn emit_with_an_invalid_event_drops_it_without_publishing() {
        let recorder = Arc::new(RecordingSecurityEventPublisher::new());
        let port: Arc<dyn SecurityEventPublisher> = recorder.clone();
        emit(&port, SecurityEvent::scan_started(""));
        for _ in 0..10 {
            tokio::task::yield_now().await;
        }
        assert!(recorder.events().is_empty());
    }

    #[tokio::test(start_paused = true)]
    async fn emit_gives_up_on_a_hanging_publisher_after_the_timeout() {
        let hanging = Arc::new(HangingPublisher);
        let port: Arc<dyn SecurityEventPublisher> = hanging.clone();
        emit(&port, SecurityEvent::scan_started("a"));
        drop(port);
        tokio::task::yield_now().await;
        assert_eq!(Arc::strong_count(&hanging), 2, "la tarea sigue publicando");

        tokio::time::advance(PUBLISH_TIMEOUT + std::time::Duration::from_secs(1)).await;
        for _ in 0..10 {
            tokio::task::yield_now().await;
        }
        assert_eq!(
            Arc::strong_count(&hanging),
            1,
            "la tarea debe haberse soltado"
        );
    }

    fn vuln(
        id: Option<&str>,
        severity: Severity,
        confidence: Option<Confidence>,
        patch_state: Option<crate::domain::PatchState>,
    ) -> crate::domain::VulnFinding {
        crate::domain::VulnFinding {
            id: id.map(str::to_owned),
            severity,
            description: "d".to_owned(),
            nse_script: "vulners".to_owned(),
            source: crate::domain::VulnSource::NmapNse,
            references: Vec::new(),
            confidence,
            patch_state,
        }
    }

    fn result_with(vulnerabilities: Vec<crate::domain::VulnFinding>) -> crate::domain::ScanResult {
        crate::domain::ScanResult {
            host: "198.51.100.7".parse().unwrap(),
            ports: Vec::new(),
            vulnerabilities,
            scanned_at: time::macros::datetime!(2026-11-09 12:30:00 UTC),
        }
    }

    fn types(events: &[Result<SecurityEvent, InvalidSecurityEvent>]) -> Vec<&'static str> {
        events
            .iter()
            .map(|e| e.as_ref().unwrap().event_type_str())
            .collect()
    }

    #[test]
    fn completion_events_start_with_scan_completed_counting_every_finding() {
        let result = result_with(vec![
            vuln(
                Some("CVE-2023-38408"),
                Severity::Critical,
                Some(Confidence::Confirmed),
                None,
            ),
            vuln(None, Severity::Medium, None, None),
            vuln(None, Severity::Unknown, None, None),
        ]);
        let events = completion_events("s", 1_500, &result);
        assert_eq!(types(&events), ["scan.completed", "finding.critical"]);
        let completed = events[0].as_ref().unwrap();
        assert_eq!(completed.payload()["duration_ms"], 1_500);
        assert_eq!(completed.payload()["finding_counts"]["critical"], 1);
        assert_eq!(completed.payload()["finding_counts"]["medium"], 1);
        assert_eq!(completed.payload()["finding_counts"]["unknown"], 1);
    }

    #[test]
    fn finding_events_are_ordered_critical_first_and_use_port_zero_tcp() {
        let result = result_with(vec![
            vuln(
                Some("CVE-2024-6387"),
                Severity::High,
                Some(Confidence::VersionMatch),
                None,
            ),
            vuln(
                Some("CVE-2023-38408"),
                Severity::Critical,
                Some(Confidence::Confirmed),
                None,
            ),
        ]);
        let events = completion_events("s", 1, &result);
        let payloads: Vec<_> = events[1..]
            .iter()
            .map(|e| e.as_ref().unwrap().payload().clone())
            .collect();
        assert_eq!(payloads[0]["severity"], "critical");
        assert_eq!(payloads[1]["severity"], "high");
        assert_eq!(payloads[0]["port"], 0);
        assert_eq!(payloads[0]["protocol"], "tcp");
    }

    #[test]
    fn findings_without_confidence_or_already_fixed_get_no_event_but_are_counted() {
        let result = result_with(vec![
            vuln(None, Severity::High, None, None),
            vuln(
                Some("CVE-2024-6387"),
                Severity::High,
                Some(Confidence::VersionMatch),
                Some(crate::domain::PatchState::Fixed),
            ),
            vuln(
                Some("CVE-2024-1111"),
                Severity::High,
                Some(Confidence::Confirmed),
                Some(crate::domain::PatchState::Unpatched),
            ),
        ]);
        let events = completion_events("s", 1, &result);
        assert_eq!(types(&events), ["scan.completed", "finding.critical"]);
        assert_eq!(
            events[0].as_ref().unwrap().payload()["finding_counts"]["high"],
            3
        );
    }

    #[test]
    fn a_finding_id_that_is_not_a_cve_is_reported_as_null() {
        let result = result_with(vec![vuln(
            Some("EDB-12345"),
            Severity::High,
            Some(Confidence::Confirmed),
            None,
        )]);
        let events = completion_events("s", 1, &result);
        assert!(events[1].as_ref().unwrap().payload()["cve_id"].is_null());
    }

    #[test]
    fn finding_events_are_capped_and_the_rest_only_count_in_scan_completed() {
        let findings = (0..MAX_FINDING_CRITICAL_EVENTS + 7)
            .map(|_| vuln(None, Severity::High, Some(Confidence::Confirmed), None))
            .collect();
        let events = completion_events("s", 1, &result_with(findings));
        assert_eq!(events.len(), 1 + MAX_FINDING_CRITICAL_EVENTS);
        assert_eq!(MAX_FINDING_CRITICAL_EVENTS, 50);
        assert_eq!(
            events[0].as_ref().unwrap().payload()["finding_counts"]["high"],
            MAX_FINDING_CRITICAL_EVENTS as u64 + 7
        );
    }

    #[test]
    fn the_cap_keeps_the_most_severe_findings() {
        let mut findings: Vec<_> = (0..MAX_FINDING_CRITICAL_EVENTS)
            .map(|_| vuln(None, Severity::High, Some(Confidence::Confirmed), None))
            .collect();
        findings.push(vuln(
            None,
            Severity::Critical,
            Some(Confidence::Confirmed),
            None,
        ));
        let events = completion_events("s", 1, &result_with(findings));
        assert_eq!(
            events[1].as_ref().unwrap().payload()["severity"],
            "critical"
        );
    }

    #[test]
    fn an_invalid_scan_id_yields_only_invalid_results_without_panicking() {
        let events = completion_events("", 1, &result_with(Vec::new()));
        assert_eq!(events.len(), 1);
        assert!(events[0].is_err());
    }

    #[derive(Default)]
    struct FailingPublisher {
        calls: AtomicUsize,
    }

    #[async_trait::async_trait]
    impl SecurityEventPublisher for FailingPublisher {
        async fn publish(&self, _event: &SecurityEvent) -> Result<(), SecurityEventError> {
            self.calls.fetch_add(1, Ordering::SeqCst);
            Err(SecurityEventError::PublishFailed("boom".into()))
        }
    }

    struct HangingPublisher;

    #[async_trait::async_trait]
    impl SecurityEventPublisher for HangingPublisher {
        async fn publish(&self, _event: &SecurityEvent) -> Result<(), SecurityEventError> {
            std::future::pending().await
        }
    }
}

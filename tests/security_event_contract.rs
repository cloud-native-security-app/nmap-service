//! Paridad de contrato de `SecurityEvent` (tarea KAP-07): cada evento que
//! construye ms-nmap valida contra
//! `../broker/contracts/security-event.schema.json`, y los ejemplos de
//! `../broker/contracts/examples/security-event/` se deserializan en el tipo de
//! este servicio. Así un cambio del schema rompe este build en vez de divergir
//! en silencio (ningún servicio depende del crate `broker`).
//!
//! Los tests leen el checkout hermano `../broker` en tiempo de ejecución; si no
//! existe (este repo clonado solo) imprimen un aviso y pasan, igual que
//! `broker/tests/topology_parity.rs`: sin el otro repo no pueden gatear nada.

use std::path::PathBuf;

use jsonschema::Validator;
use nmap_service::domain::{Confidence, Protocol, Severity};
use nmap_service::security_events::{EventSource, FindingCounts, SecurityEvent};
use serde_json::Value;

fn broker_path(relative: &str) -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../broker/contracts")
        .join(relative)
}

/// Schema compilado del contrato, o `None` (con aviso) si `../broker` falta.
fn schema_validator() -> Option<Validator> {
    let path = broker_path("security-event.schema.json");
    let Ok(text) = std::fs::read_to_string(&path) else {
        eprintln!(
            "SKIP: {} not found (sibling broker checkout absent)",
            path.display()
        );
        return None;
    };
    let schema: Value = serde_json::from_str(&text).expect("el schema debe ser JSON válido");
    Some(jsonschema::validator_for(&schema).expect("el schema debe compilar"))
}

fn assert_valid(validator: &Validator, event: &SecurityEvent) {
    let value = serde_json::to_value(event).expect("el evento debe serializar");
    let errors: Vec<String> = validator
        .iter_errors(&value)
        .map(|e| format!("{e} en {}", e.instance_path()))
        .collect();
    assert!(
        errors.is_empty(),
        "el evento {} no valida contra el schema: {errors:?}\n{value}",
        event.event_type_str()
    );
}

#[test]
fn every_nmap_constructor_validates_against_the_broker_schema() {
    let Some(validator) = schema_validator() else {
        return;
    };
    let mut counts = FindingCounts::default();
    counts.record(Severity::Critical);
    counts.record(Severity::Unknown);
    let finding = |severity, cve, confidence| {
        SecurityEvent::finding_critical(
            "corr-42",
            Some(22),
            Some(Protocol::Tcp),
            cve,
            severity,
            confidence,
        )
    };
    let events = [
        SecurityEvent::scan_started("corr-42"),
        SecurityEvent::scan_completed("corr-42", 0, FindingCounts::default()),
        SecurityEvent::scan_completed("corr-42", 42_000, counts),
        SecurityEvent::scan_failed("corr-42", "ssh_timeout"),
        SecurityEvent::scan_failed("corr-42", "rejected_request"),
        finding(
            Severity::Critical,
            Some("CVE-2023-38408"),
            Confidence::Confirmed,
        ),
        finding(Severity::High, None, Confidence::VersionMatch),
        SecurityEvent::finding_critical(
            "corr-42",
            Some(0),
            Some(Protocol::Udp),
            None,
            Severity::High,
            Confidence::Confirmed,
        ),
        // Hallazgo a nivel de host: sin puerto ni protocolo (null).
        SecurityEvent::finding_critical(
            "corr-42",
            None,
            None,
            Some("CVE-2024-6387"),
            Severity::High,
            Confidence::VersionMatch,
        ),
        SecurityEvent::finding_critical(
            "corr-42",
            Some(u16::MAX),
            Some(Protocol::Tcp),
            Some("CVE-2011-2523"),
            Severity::Critical,
            Confidence::VersionMatch,
        ),
    ];
    for event in events {
        let event = event.expect("el constructor debe aceptar la entrada");
        assert_eq!(event.source(), EventSource::NmapService);
        assert_valid(&validator, &event);
    }
}

#[test]
fn schema_rejects_what_the_constructors_refuse_to_build() {
    // Salvaguarda de la prueba anterior: el validador no es permisivo.
    let Some(validator) = schema_validator() else {
        return;
    };
    let invalid = serde_json::json!({
        "event_id": "3f2b8c1e-5d4a-4e7b-9a10-2c6d8e0f1a06",
        "event_type": "finding.critical",
        "occurred_at": "2026-11-09T12:30:00Z",
        "source": "nmap-service",
        "scan_id": "corr-42",
        "payload": {
            "port": 22, "protocol": "tcp", "cve_id": null,
            "severity": "medium", "confidence": "confirmed"
        }
    });
    assert!(!validator.is_valid(&invalid));
}

#[test]
fn broker_examples_deserialize_into_security_event_and_round_trip() {
    let dir = broker_path("examples/security-event");
    let Ok(entries) = std::fs::read_dir(&dir) else {
        eprintln!(
            "SKIP: {} not found (sibling broker checkout absent)",
            dir.display()
        );
        return;
    };
    let mut checked = 0;
    for entry in entries {
        let path = entry.expect("entrada legible").path();
        if path.extension().and_then(|e| e.to_str()) != Some("json") {
            continue;
        }
        let text = std::fs::read_to_string(&path).expect("ejemplo legible");
        let original: Value = serde_json::from_str(&text).expect("ejemplo JSON");
        let event: SecurityEvent = serde_json::from_value(original.clone())
            .unwrap_or_else(|e| panic!("{} no deserializa: {e}", path.display()));
        let again = serde_json::to_value(&event).expect("serializa");
        assert_eq!(
            again,
            original,
            "{} no hace round trip exacto",
            path.display()
        );
        checked += 1;
    }
    assert!(
        checked >= 11,
        "se esperaban al menos los 11 ejemplos del contrato"
    );
}

#[test]
fn nmap_examples_have_the_same_shape_as_the_constructors_output() {
    // Los ejemplos de los cuatro eventos de ms-nmap y la salida de los
    // constructores difieren solo en los campos generados (id y hora).
    let dir = broker_path("examples/security-event");
    if !dir.is_dir() {
        eprintln!("SKIP: {} not found", dir.display());
        return;
    }
    let example = |name: &str| -> Value {
        let text = std::fs::read_to_string(dir.join(name)).expect("ejemplo legible");
        serde_json::from_str(&text).expect("ejemplo JSON")
    };
    let strip = |mut value: Value| -> Value {
        let object = value.as_object_mut().expect("objeto");
        object.remove("event_id");
        object.remove("occurred_at");
        value
    };
    let mut counts = FindingCounts::default();
    for (severity, times) in [
        (Severity::Critical, 1),
        (Severity::High, 2),
        (Severity::Medium, 3),
        (Severity::Low, 4),
        (Severity::Info, 5),
    ] {
        for _ in 0..times {
            counts.record(severity);
        }
    }
    let pairs = [
        (
            "scan-started.json",
            SecurityEvent::scan_started("corr-42").unwrap(),
        ),
        (
            "scan-completed.json",
            SecurityEvent::scan_completed("corr-42", 42_000, counts).unwrap(),
        ),
        (
            "scan-failed.json",
            SecurityEvent::scan_failed("corr-42", "ssh_timeout").unwrap(),
        ),
        (
            "finding-critical.json",
            SecurityEvent::finding_critical(
                "corr-42",
                Some(22),
                Some(Protocol::Tcp),
                Some("CVE-2023-38408"),
                Severity::Critical,
                Confidence::Confirmed,
            )
            .unwrap(),
        ),
    ];
    for (file, event) in pairs {
        assert_eq!(
            strip(serde_json::to_value(&event).unwrap()),
            strip(example(file)),
            "{file} difiere de la salida del constructor"
        );
    }
}

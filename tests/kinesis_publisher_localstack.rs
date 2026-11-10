//! Test de integración de `KinesisSecurityEventPublisher` (tarea KAP-07)
//! contra un LocalStack real levantado con `testcontainers` (sin mocks, sin
//! cuenta AWS): se crea el stream, se publica con el adaptador, se lee con
//! `GetRecords` y el cuerpo se valida contra el schema del contrato
//! (`../broker/contracts/security-event.schema.json`; si el repo hermano no
//! está, solo se omite la validación del schema).
//!
//! Requiere Docker: `#[ignore = "requiere Docker"]`, se ejecuta con
//! `cargo test -- --ignored`.

mod common;

use std::path::PathBuf;

use nmap_service::domain::{Confidence, Protocol, Severity};
use nmap_service::messaging::kinesis::KinesisSecurityEventPublisher;
use nmap_service::security_events::{
    FindingCounts, SecurityEvent, SecurityEventError, SecurityEventPublisher,
};
use serde_json::Value;

const STREAM: &str = "security-events";

fn schema() -> Option<Value> {
    let path = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../broker/contracts/security-event.schema.json");
    match std::fs::read_to_string(&path) {
        Ok(text) => Some(serde_json::from_str(&text).expect("schema JSON")),
        Err(_) => {
            eprintln!(
                "SKIP schema: {} not found (sibling broker checkout absent)",
                path.display()
            );
            None
        }
    }
}

#[tokio::test]
#[ignore = "requiere Docker"]
async fn publishes_the_four_nmap_events_that_read_back_valid_with_scan_id_as_partition_key() {
    let localstack = common::LocalStack::start().await;
    localstack.create_stream(STREAM).await;
    let publisher =
        KinesisSecurityEventPublisher::from_client(localstack.kinesis.clone(), STREAM.to_string());

    let mut counts = FindingCounts::default();
    counts.record(Severity::Critical);
    let events = [
        SecurityEvent::scan_started("corr-42").unwrap(),
        SecurityEvent::scan_completed("corr-42", 1_500, counts).unwrap(),
        SecurityEvent::finding_critical(
            "corr-42",
            22,
            Protocol::Tcp,
            Some("CVE-2023-38408"),
            Severity::Critical,
            Confidence::Confirmed,
        )
        .unwrap(),
        SecurityEvent::scan_failed("corr-43", "ssh_timeout").unwrap(),
    ];
    for event in &events {
        publisher.publish(event).await.expect("publicar el evento");
    }

    let records = localstack.read_stream(STREAM, events.len()).await;
    assert_eq!(
        records.len(),
        events.len(),
        "deben llegar todos los eventos"
    );
    let validator = schema().map(|s| jsonschema::validator_for(&s).expect("schema compila"));
    for (record, event) in records.iter().zip(&events) {
        let body: Value = serde_json::from_slice(record.data().as_ref()).expect("cuerpo JSON");
        assert_eq!(body, serde_json::to_value(event).unwrap());
        assert_eq!(record.partition_key(), event.scan_id());
        if let Some(validator) = &validator {
            assert!(
                validator.is_valid(&body),
                "no valida contra el schema: {body}"
            );
        }
        let parsed: SecurityEvent = serde_json::from_value(body).expect("deserializa");
        assert_eq!(&parsed, event);
    }
}

#[tokio::test]
#[ignore = "requiere Docker"]
async fn publishing_to_a_missing_stream_yields_publish_failed_without_the_body() {
    let localstack = common::LocalStack::start().await;
    let publisher =
        KinesisSecurityEventPublisher::from_client(localstack.kinesis.clone(), "no-existe".into());

    let err = publisher
        .publish(&SecurityEvent::scan_started("corr-secret-42").unwrap())
        .await
        .expect_err("un stream inexistente debe fallar");

    assert!(matches!(err, SecurityEventError::PublishFailed(_)));
    assert!(!err.to_string().contains("corr-secret-42"));
}

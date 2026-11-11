//! Paridad de contrato de `ScanOutcome` (tarea KAP-07b, `finding-port`): el
//! mensaje `completed` que publica ms-nmap valida contra
//! `../broker/contracts/scan-outcome.schema.json`, con hallazgos con y sin
//! puerto. Un cambio del schema rompe este build en vez de divergir en
//! silencio.
//!
//! Lee el checkout hermano `../broker` en tiempo de ejecución; si no existe
//! imprime un aviso y pasa, igual que `security_event_contract.rs`.

use std::path::PathBuf;

use jsonschema::Validator;
use nmap_service::domain::{
    Confidence, CorrelationId, PatchState, Protocol, ScanResult, Severity, VulnFinding, VulnSource,
};
use nmap_service::messaging::publisher::ScanOutcome;
use serde_json::Value;
use time::OffsetDateTime;

fn schema_validator() -> Option<Validator> {
    let path = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../broker/contracts/scan-outcome.schema.json");
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

fn finding(port: Option<u16>, protocol: Option<Protocol>) -> VulnFinding {
    VulnFinding {
        id: Some("CVE-2024-6387".to_owned()),
        severity: Severity::High,
        description: "d".to_owned(),
        nse_script: "vulners".to_owned(),
        source: VulnSource::NmapNse,
        references: Vec::new(),
        confidence: Some(Confidence::Confirmed),
        patch_state: Some(PatchState::Unpatched),
        port,
        protocol,
    }
}

fn completed(findings: Vec<VulnFinding>) -> Value {
    let result = ScanResult {
        host: "192.0.2.10".parse().unwrap(),
        ports: Vec::new(),
        vulnerabilities: findings,
        scanned_at: OffsetDateTime::UNIX_EPOCH,
    };
    serde_json::to_value(ScanOutcome::completed(
        CorrelationId::from("corr-42"),
        result,
    ))
    .expect("serializa")
}

#[test]
fn findings_with_and_without_port_validate_against_the_broker_schema() {
    let Some(validator) = schema_validator() else {
        return;
    };
    let message = completed(vec![
        finding(Some(22), Some(Protocol::Tcp)),
        finding(Some(161), Some(Protocol::Udp)),
        finding(None, None),
    ]);
    let errors: Vec<String> = validator
        .iter_errors(&message)
        .map(|e| format!("{e} en {}", e.instance_path()))
        .collect();
    assert!(errors.is_empty(), "{errors:?}\n{message}");
}

#[test]
fn schema_rejects_port_zero_so_the_parity_check_is_not_vacuous() {
    let Some(validator) = schema_validator() else {
        return;
    };
    let message = completed(vec![finding(Some(0), Some(Protocol::Tcp))]);
    assert!(!validator.is_valid(&message));
}

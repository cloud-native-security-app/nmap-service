//! Paridad de contrato de `ScanRequest` (tarea NS-02): los ejemplos de
//! `../broker/contracts/examples/scan-request/` y el schema
//! `scan-request.schema.json` coinciden con lo que acepta o rechaza
//! `ScanRequest::deserialize`. Un cambio del contrato (o del dominio) rompe este
//! build en vez de divergir en silencio.
//!
//! Lee el checkout hermano `../broker` en tiempo de ejecución; si no existe
//! imprime un aviso y pasa, igual que `scan_outcome_contract.rs`.

use std::path::PathBuf;

use jsonschema::Validator;
use nmap_service::domain::{ScanMode, ScanRequest};
use serde_json::Value;

fn contracts_dir() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../broker/contracts")
}

fn schema_validator() -> Option<Validator> {
    let path = contracts_dir().join("scan-request.schema.json");
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

fn example(relative: &str) -> Option<String> {
    let path = contracts_dir().join("examples/scan-request").join(relative);
    match std::fs::read_to_string(&path) {
        Ok(text) => Some(text),
        Err(_) => {
            eprintln!("SKIP: {} not found", path.display());
            None
        }
    }
}

#[test]
fn ssh_example_validates_and_deserializes_as_ssh_mode() {
    let (Some(validator), Some(text)) = (schema_validator(), example("ssh.json")) else {
        return;
    };
    let json: Value = serde_json::from_str(&text).expect("JSON");
    assert!(validator.is_valid(&json), "ssh.json debe validar");

    let request: ScanRequest = serde_json::from_str(&text).expect("deserializa");
    assert_eq!(request.mode(), ScanMode::Ssh);
    assert!(request.ssh().is_some());
}

#[test]
fn network_example_validates_and_deserializes_as_network_mode() {
    let (Some(validator), Some(text)) = (schema_validator(), example("network.json")) else {
        return;
    };
    let json: Value = serde_json::from_str(&text).expect("JSON");
    assert!(validator.is_valid(&json), "network.json debe validar");

    let request: ScanRequest = serde_json::from_str(&text).expect("deserializa");
    assert_eq!(request.mode(), ScanMode::Network);
    assert!(request.ssh().is_none());
}

#[test]
fn network_hostname_example_validates_and_keeps_host_and_port() {
    let (Some(validator), Some(text)) = (schema_validator(), example("network-hostname.json"))
    else {
        return;
    };
    let json: Value = serde_json::from_str(&text).expect("JSON");
    assert!(
        validator.is_valid(&json),
        "network-hostname.json debe validar"
    );

    let request: ScanRequest = serde_json::from_str(&text).expect("deserializa");
    assert_eq!(request.mode(), ScanMode::Network);
    assert!(request.target_host.is_some(), "target_host presente");
    assert!(request.extra_port.is_some(), "extra_port presente");
}

#[test]
fn every_invalid_example_is_rejected_by_both_the_schema_and_the_domain() {
    let Some(validator) = schema_validator() else {
        return;
    };
    let dir = contracts_dir().join("examples/scan-request/invalid");
    let Ok(entries) = std::fs::read_dir(&dir) else {
        eprintln!("SKIP: {} not found", dir.display());
        return;
    };
    let mut checked = 0;
    for entry in entries {
        let path = entry.expect("entrada").path();
        let text = std::fs::read_to_string(&path).expect("lee el ejemplo");
        let json: Value = serde_json::from_str(&text).expect("JSON");
        assert!(
            !validator.is_valid(&json),
            "{} debe ser inválido para el schema",
            path.display()
        );
        assert!(
            serde_json::from_str::<ScanRequest>(&text).is_err(),
            "{} debe ser rechazado por ScanRequest",
            path.display()
        );
        checked += 1;
    }
    assert!(checked >= 6, "se esperaban al menos 6 ejemplos inválidos");
}

#[test]
fn serialized_requests_validate_against_the_schema() {
    let Some(validator) = schema_validator() else {
        return;
    };
    for name in ["ssh.json", "network.json", "network-hostname.json"] {
        let Some(text) = example(name) else { return };
        let request: ScanRequest = serde_json::from_str(&text).expect("deserializa");
        let json = serde_json::to_value(&request).expect("serializa");
        assert!(validator.is_valid(&json), "{name} serializado: {json}");
    }
}

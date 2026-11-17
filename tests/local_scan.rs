//! Escaneo local (modo `network`, NS-02) contra un objetivo real: ejecuta el
//! [`LocalNmapScanner`] de producción sobre un contenedor `nginx` levantado con
//! `testcontainers` y parsea el XML con el parser del servicio.
//!
//! Requiere un daemon de Docker **y** el binario `nmap` en el `PATH` del host de
//! pruebas (en la imagen de producción lo instala el `Dockerfile`; en una
//! máquina de desarrollo, `apt install nmap` / `brew install nmap`). Por eso va
//! marcado `#[ignore]`: `cargo test` lo omite y `cargo test -- --ignored` lo
//! ejecuta (`make test-integration`).
//!
//! El escaneo se dirige a la IP del contenedor en la red bridge de Docker, no a
//! un puerto mapeado: `nmap` recorre los puertos habituales de esa IP.

use std::time::Duration;

use nmap_service::domain::PortState;
use nmap_service::local_scanner::{LocalNmapScanner, LocalScanTarget, LocalScanner};
use nmap_service::parser;
use nmap_service::scanner::{ScanOptions, Timing};
use testcontainers::{
    core::{IntoContainerPort, WaitFor},
    runners::AsyncRunner,
    GenericImage, ImageExt,
};

#[tokio::test]
#[ignore = "requiere Docker y nmap en el PATH"]
async fn local_scanner_finds_the_open_http_port_of_a_real_container() {
    let container = GenericImage::new("nginx", "1.18")
        .with_exposed_port(80.tcp())
        .with_wait_for(WaitFor::message_on_stdout("ready for start up"))
        .with_startup_timeout(Duration::from_secs(120))
        .start()
        .await
        .expect("el contenedor nginx debe arrancar");
    let target = container
        .get_bridge_ip_address()
        .await
        .expect("IP del contenedor en la red bridge");

    // `-T4` (Aggressive) acota la duración de `-sV --script vuln` en la prueba.
    let options = ScanOptions {
        timing: Timing::Aggressive,
        ..ScanOptions::default()
    };
    let xml = LocalNmapScanner::new(Duration::from_secs(600))
        .run_scan(&LocalScanTarget::from_ip(target), &options)
        .await
        .expect("el escaneo local termina bien");

    let result = parser::parse(&xml).expect("el XML de nmap se parsea");
    assert_eq!(result.host, target);
    let http = result
        .ports
        .iter()
        .find(|p| p.port == 80)
        .expect("el puerto 80 aparece en el resultado");
    assert_eq!(http.state, PortState::Open);
    assert_eq!(http.service.as_deref(), Some("http"));
    assert!(
        http.version.as_deref().is_some_and(|v| v.contains("nginx")),
        "versión detectada por -sV: {:?}",
        http.version
    );
}

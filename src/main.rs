//! Binario `ms-nmap`: envoltorio delgado que inicializa el runtime `tokio` y el
//! subscriber de `tracing`, resuelve la configuración, arma los adaptadores
//! reales en [`nmap_service::wiring`] y delega el resto en [`nmap_service::run`].
//!
//! Nunca hace `panic`: un fallo de configuración o de conexión a MongoDB se
//! registra con `tracing::error!` y el proceso termina de forma limpia.

use nmap_service::config::Config;
use nmap_service::scanner::ScanOptions;
use nmap_service::ssh::SshTimeouts;
use nmap_service::{run, wiring, PipelineConfig};

#[tokio::main]
async fn main() {
    tracing_subscriber::fmt::init();

    let config = match Config::from_env() {
        Ok(config) => config,
        Err(err) => {
            tracing::error!(error = %err, "configuración inválida; ms-nmap no puede arrancar");
            return;
        }
    };

    let ports = match wiring::service_ports_from_config(&config).await {
        Ok(ports) => ports,
        Err(err) => {
            tracing::error!(error = %err, "no se pudo inicializar ms-nmap");
            return;
        }
    };

    let pipeline_config = PipelineConfig {
        ssh_port: config.ssh_port,
        ssh_timeouts: SshTimeouts {
            connect: config.ssh_connect_timeout,
            command: config.ssh_command_timeout,
        },
        scan_options: ScanOptions::default(),
    };

    run(ports, pipeline_config, None).await;
}

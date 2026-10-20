//! Binario `ms-nmap`: envoltorio delgado que inicializa el runtime `tokio` y el
//! subscriber de `tracing`, resuelve la configuración, arma los adaptadores
//! reales en [`nmap_service::wiring`] y delega el resto en [`nmap_service::run`].
//!
//! Nunca hace `panic`: un fallo de configuración o de conexión a MongoDB se
//! registra con `tracing::error!` y el proceso termina de forma limpia. Con
//! `SIGTERM`/`Ctrl-C` deja de consumir, espera a los escaneos en vuelo hasta un
//! plazo acotado y sale (ver [`nmap_service::run`]).

use tokio_util::sync::CancellationToken;

use nmap_service::config::Config;
use nmap_service::scanner::ScanOptions;
use nmap_service::ssh::SshTimeouts;
use nmap_service::{run, shutdown_signal, wiring, PipelineConfig};

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

    let (ports, source, cancellations) = match wiring::service_ports_from_config(&config).await {
        Ok(wired) => wired,
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
        scan_options: ScanOptions {
            timing: config.scan_timing,
            ..ScanOptions::default()
        },
    };

    let shutdown = CancellationToken::new();
    tokio::spawn({
        let shutdown = shutdown.clone();
        async move {
            shutdown_signal().await;
            tracing::info!(
                "señal de apagado recibida; se deja de consumir y se drenan los escaneos"
            );
            shutdown.cancel();
        }
    });

    run(
        ports,
        pipeline_config,
        Some(source),
        Some(cancellations),
        shutdown,
    )
    .await;
}

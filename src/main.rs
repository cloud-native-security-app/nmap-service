//! Binario `ms-nmap`: envoltorio delgado que inicializa el runtime `tokio` y el
//! subscriber de `tracing`, y delega toda la lógica en [`nmap_service::run`].

#[tokio::main]
async fn main() {
    tracing_subscriber::fmt::init();
    nmap_service::run().await;
}

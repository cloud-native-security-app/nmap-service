# Bitácora histórica (append-only)

> Cada vez que se cierra una sesión, su resumen se añade aquí.
> No edites entradas anteriores. Solo añades al final.

---

## 2026-08-27 — Feature 1: scaffolding

- **Agente:** implementer + reviewer
- **Estado final:** `done` (reviewer aprobó, ver `progress/review_scaffolding.md`)

### Qué se hizo

- Inicializado el crate Rust `nmap-service` (edition 2021, `publish = false`):
  lib `nmap_service` (`src/lib.rs`) + bin delgado `ms-nmap` (`src/main.rs`).
- `src/lib.rs`: `#![deny(missing_docs)]`, `pub mod` para `config`, `domain`,
  `messaging`, `parser`, `repository`, `scanner`, `ssh`, y `pub async fn run()`
  stub con rustdoc.
- `src/main.rs`: `#[tokio::main]` + `tracing_subscriber::fmt::init()` + llamada a
  `nmap_service::run()`.
- Stubs de módulo (solo `//!` doc) para cada capa. `messaging` como
  `src/messaging/mod.rs` con `pub mod consumer;` / `pub mod publisher;` sin lógica.
- `Cargo.toml`: deps `tokio` (rt-multi-thread, macros), `tracing`,
  `tracing-subscriber`, `serde` (derive), `serde_json`; dev-dep `testcontainers`.

### Verificación

- `./init.sh` → EXIT 0. `cargo fmt --check`, `cargo clippy --all-targets -- -D
  warnings`, `cargo build`, `cargo test` (0 tests), `cargo doc --no-deps`: todo limpio.
- Sin tests propios: el scaffolding no introduce lógica pura testeable.

### Notas / seguimiento

- Docker no disponible en el shell de la sesión; irrelevante para esta feature
  (no hay tests `#[ignore = "requiere Docker"]` todavía). Relevante para features
  4, 5, 7, 10.
- Detalle: `progress/impl_scaffolding.md`, `progress/review_scaffolding.md`.
- Commit pendiente (lo gestiona el leader).

---

## 2026-08-27 — Feature 2: config

- **Agente:** implementer + reviewer
- **Estado final:** `done` (reviewer aprobó en ronda 2, ver `progress/review_config.md`)

### Qué se hizo

- `src/config.rs` deja de ser stub e implementa la carga/validación de config
  desde variables de entorno.
- `struct Config`: `mongo_uri: String`, `broker_endpoint: String`,
  `broker_credential: secrecy::SecretString`, `ssh_connect_timeout: Duration`,
  `ssh_command_timeout: Duration`. `#[derive(Debug)]` seguro (la credencial se
  redacta).
- `Config::from_env() -> Result<Config, ConfigError>` (sync) delega en la
  función privada `from_source(lookup: Fn(&str) -> Option<String>)` que
  contiene toda la validación.
- `ConfigError` (`thiserror`): `MissingVar(&'static str)` e
  `InvalidValue { var: &'static str, reason: String }`. Sin `String` genérico,
  sin panic/unwrap/expect fuera de tests.
- Nombres de env vars como `pub const` (`MS_NMAP_MONGO_URI`,
  `MS_NMAP_BROKER_ENDPOINT`, `MS_NMAP_BROKER_CREDENTIAL`,
  `MS_NMAP_SSH_CONNECT_TIMEOUT_SECS`, `MS_NMAP_SSH_COMMAND_TIMEOUT_SECS`).
  **Todas requeridas**; ausente/vacía → `MissingVar`. Timeout no numérico o
  cero → `InvalidValue`. Ningún valor de configuración hardcodeado.
- Deps nuevas: `secrecy = "0.10"` (redacción de la credencial del Broker en
  `Debug`; la reutiliza la feature 3) y `thiserror = "2"` (convención de
  errores por módulo). No se añadió `serial_test`: los tests inyectan un
  `HashMap` en `from_source`, no mutan `std::env`.

### Verificación

- 8 tests unitarios en `#[cfg(test)] mod tests` de `src/config.rs`: camino
  feliz con valores concretos (strings, `Duration`, credencial expuesta),
  `MissingVar` tipado para cada variable requerida (incl. ambos timeouts),
  variable vacía tratada como ausente, `InvalidValue` para timeout no numérico
  y cero, y `Debug` no filtra la credencial.
- `./init.sh` → EXIT 0: `cargo fmt --check`, `cargo clippy --all-targets -- -D
  warnings`, `cargo test` (8 passed), `cargo doc --no-deps` todo limpio.

### Notas / seguimiento

- Ronda 1 recibió CHANGES_REQUESTED: tenía defaults de timeout hardcodeados
  (`DEFAULT_SSH_*`) y trataba los timeouts como opcionales, contra
  `docs/architecture.md` §Capas p.1. Ronda 2 los eliminó y volvió requeridas
  las env vars de timeout.
- Detalle: `progress/impl_config.md`, `progress/review_config.md`.
- Commit pendiente (lo gestiona el leader).

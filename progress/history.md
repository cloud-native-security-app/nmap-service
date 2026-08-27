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

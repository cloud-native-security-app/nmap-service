# Implementación — Feature 1: scaffolding

**Agente:** implementer
**Fecha:** 2026-08-27
**Estado:** implementada y verificada, pendiente de review (NO marcada `done`)

## Qué se creó

| Archivo | Contenido |
|---------|-----------|
| `Cargo.toml` | Paquete `nmap-service`, `edition = "2021"`, `publish = false`. Lib `nmap_service` (`src/lib.rs`) + bin `ms-nmap` (`src/main.rs`). |
| `src/lib.rs` | `#![deny(missing_docs)]`, doc de crate, `pub mod` para `config`, `domain`, `messaging`, `parser`, `repository`, `scanner`, `ssh`, y `pub async fn run()` stub con rustdoc. |
| `src/main.rs` | Envoltorio delgado: `#[tokio::main]`, `tracing_subscriber::fmt::init()`, `nmap_service::run().await`. Sin `#![deny(missing_docs)]`. |
| `src/config.rs` | Stub: solo `//!` doc de módulo. |
| `src/domain.rs` | Stub: solo `//!` doc de módulo. |
| `src/ssh.rs` | Stub: solo `//!` doc de módulo. |
| `src/scanner.rs` | Stub: solo `//!` doc de módulo. |
| `src/parser.rs` | Stub: solo `//!` doc de módulo. |
| `src/repository.rs` | Stub: solo `//!` doc de módulo. |
| `src/messaging/mod.rs` | Stub con `//!` doc + `pub mod consumer;` / `pub mod publisher;` (submódulos previstos en `docs/architecture.md`). Sin lógica. |
| `src/messaging/consumer.rs` | Stub: solo `//!` doc de módulo. |
| `src/messaging/publisher.rs` | Stub: solo `//!` doc de módulo. |
| `Cargo.lock` | Generado por cargo (aplicación → se versiona). |

## Dependencias (Cargo.toml)

- `tokio` = "1", features `["rt-multi-thread", "macros"]`
- `tracing` = "0.1"
- `tracing-subscriber` = "0.3" (features por defecto; `fmt::init()` funciona con ellas)
- `serde` = "1", features `["derive"]` (justificado por feature `domain_model`: todos los tipos derivan Serialize/Deserialize)
- `serde_json` = "1"
- dev-dependency: `testcontainers` = "0.24"

## Decisiones

- **`messaging` como directorio** (`src/messaging/mod.rs`) en lugar de archivo plano, porque `docs/architecture.md` §7 define los submódulos `consumer` y `publisher`. Se declaran ambos `pub mod` con su doc de módulo pero **sin ninguna lógica** (traits/impl pertenecen a las features 8 y 9).
- **`run()` es `async fn` sin `await` real**: es un stub del scaffolding. No dispara `clippy::unused_async` (lint `pedantic`, no incluido en `-D warnings` que solo cubre `clippy::all` + warnings de rustc). Emite un `tracing::info!` para que el binario haga algo observable.
- **Nombre de lib `nmap_service`** (guion → guion bajo) y bin `ms-nmap` explícitos en `Cargo.toml` para dejar claros ambos targets.
- Sin `unwrap`/`expect`/`panic!`/`println!`/`dbg!`/TODO en el código.
- Sin tests: el scaffolding no introduce lógica pura testeable. `cargo test` corre con 0 tests (OK, según instrucción del líder y `docs/verification.md`).

## Verificación

`./init.sh` → **EXIT=0** (todo verde):

- `cargo fmt --check` → sin diferencias
- `cargo clippy --all-targets -- -D warnings` → sin warnings
- `cargo build` → compila sin warnings
- `cargo test` → 0 passed; 0 failed (lib + bin + doc-tests)
- `cargo test -- --ignored` → 0 tests (no hay tests de integración todavía)
- `cargo doc --no-deps` → genera sin errores ni warnings

Nota: Docker no está disponible en el shell actual, pero la feature 1 no
introduce tests `#[ignore = "requiere Docker"]`, así que no constituye bloqueo.

## Criterios de acceptance — checklist

1. `Cargo.toml` edition 2021 con tokio (rt-multi-thread, macros), tracing, tracing-subscriber, serde, serde_json → **OK**
2. `src/lib.rs` con los 7 módulos `pub` visibles para `tests/` → **OK**
3. `src/main.rs` delgado: runtime tokio + tracing_subscriber + llamada a `nmap_service::run()` → **OK**
4. `#![deny(missing_docs)]` en `src/lib.rs` → **OK**
5. `testcontainers` como dev-dependency → **OK**
6. `cargo build` sin warnings → **OK**

## Archivos para el reviewer

- `/home/o-aguirre/Documents/duoc/cloud-native/nmap-service/Cargo.toml`
- `/home/o-aguirre/Documents/duoc/cloud-native/nmap-service/src/lib.rs`
- `/home/o-aguirre/Documents/duoc/cloud-native/nmap-service/src/main.rs`
- `/home/o-aguirre/Documents/duoc/cloud-native/nmap-service/src/{config,domain,ssh,scanner,parser,repository}.rs`
- `/home/o-aguirre/Documents/duoc/cloud-native/nmap-service/src/messaging/{mod,consumer,publisher}.rs`

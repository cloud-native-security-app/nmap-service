# Review — feature 1 "scaffolding"

**Agente:** reviewer
**Fecha:** 2026-08-27
**Veredicto:** APPROVED

## Verificación ejecutada por el reviewer

| Comando | Resultado |
|---------|-----------|
| `./init.sh` | EXIT=0 — todo verde, `[OK] Entorno listo` |
| `cargo build` (tras `cargo clean`) | compila sin warnings |
| `cargo fmt --check` | sin diferencias |
| `cargo clippy --all-targets -- -D warnings` | sin warnings |
| `RUSTDOCFLAGS="-D warnings" cargo doc --no-deps` | genera sin warnings |
| `cargo test` / `cargo test -- --ignored` | 0 tests, 0 fallos (scaffolding no introduce lógica testeable) |

## Criterios de acceptance de la feature 1

1. **Cargo.toml (edition 2021) con tokio (rt-multi-thread, macros), tracing, tracing-subscriber, serde, serde_json** — OK.
   `edition = "2021"`, `tokio = { version = "1", features = ["rt-multi-thread", "macros"] }`, `tracing = "0.1"`, `tracing-subscriber = "0.3"`, `serde = { version = "1", features = ["derive"] }`, `serde_json = "1"`.
2. **src/lib.rs con los 7 módulos (config, domain, ssh, scanner, parser, repository, messaging) declarados `pub`** — OK. `pub mod` para los 7 en `src/lib.rs:11-17`. `messaging` es directorio (`src/messaging/mod.rs`) con `pub mod consumer;` / `pub mod publisher;`, submódulos previstos en `docs/architecture.md` §7. Visibles para `tests/` (crate externo) porque son `pub` de la lib `nmap_service`.
3. **src/main.rs delgado: runtime tokio + tracing_subscriber + llamada a lib::run()** — OK. `src/main.rs` son 8 líneas: `#[tokio::main] async fn main()`, `tracing_subscriber::fmt::init()`, `nmap_service::run().await`. Sin lógica de negocio. Sin `#![deny(missing_docs)]` (correcto: `main.rs` compila como crate aparte, ver `docs/conventions.md`).
4. **#![deny(missing_docs)] en src/lib.rs** — OK. `src/lib.rs:9`.
5. **testcontainers como dev-dependency** — OK. `[dev-dependencies] testcontainers = "0.24"`.
6. **cargo build sin warnings** — OK. Verificado tras `cargo clean`.

## Checkpoints

- **C1 — El arnés está completo:** [x]
  - 4 archivos base presentes (`AGENTS.md`, `init.sh`, `feature_list.json`, `progress/current.md`).
  - 4 docs presentes.
  - `./init.sh` termina con exit code 0.
- **C2 — El estado es coherente:** [x]
  - Solo feature 1 en `in_progress`; el resto `pending`.
  - Ninguna feature `done` todavía (no aplica la exigencia de tests asociados).
  - `progress/current.md` describe la sesión activa, sin basura de sesiones anteriores.
- **C3 — El código respeta la arquitectura:** [x]
  - `src/` solo contiene los módulos previstos (`config`, `domain`, `ssh`, `scanner`, `parser`, `repository`, `messaging` + submódulos `consumer`/`publisher` de arch §7). Sin capas extra.
  - Toda dependencia justificada: tokio/tracing/tracing-subscriber/serde/serde_json están en la acceptance explícita de la feature 1; `testcontainers` idem (dev-dep). Sin deps injustificadas.
  - Sin `println!`/`dbg!`/`unwrap()`/`expect()`/`panic!`/TODO en `src/` (revisados los 12 archivos; los stubs solo contienen `//!` doc de módulo; `run()` solo emite `tracing::info!`).
  - `cargo doc --no-deps` sin warnings (con `-D warnings`).
- **C4 — La verificación es real:** [ ] parcial — esperado en esta etapa
  - No hay tests en `tests/` ni `cargo test` con > 0 tests. Es correcto para el scaffolding: no introduce lógica pura ni cruces de IO. Los tests de integración por módulo (`ssh`, `scanner`, `repository`, `messaging`) llegan con las features 4-10. No es motivo de rechazo de la feature 1: su `acceptance` no pide tests y `docs/verification.md` no exige tests para el scaffolding.
  - `cargo clippy --all-targets -- -D warnings` sin advertencias: [x].
- **C5 — La sesión se cerró bien:** [x] (a cargo del leader al cerrar)
  - Sin archivos temporales sospechosos. `target/` y `*.tmp` en `.gitignore`. Los untracked (`Cargo.toml`, `Cargo.lock`, `src/`, `progress/impl_scaffolding.md`) son artefactos legítimos pendientes de commit.
  - `Cargo.lock` presente y debe versionarse (el crate produce binario `ms-nmap`) — correcto.
  - Feature 1 reflejada como `in_progress`, NO marcada `done` (correcto: pendiente de este veredicto).
  - Pendiente para el cierre de sesión del leader: añadir entrada en `progress/history.md` y mover `progress/current.md`.

## Scope creep

Ninguno. Los stubs de `config`, `domain`, `ssh`, `scanner`, `parser`, `repository`, `messaging/*` contienen únicamente `//!` doc de módulo. `run()` es un stub declarado como tal en su rustdoc, sin lógica de pipeline. No se adelantó nada de las features 2-10.

## Observaciones menores (no bloqueantes)

- `run()` es `async fn` sin `.await` real. No dispara lint en `-D warnings` (`clippy::unused_async` es `pedantic`). Aceptable como stub; la feature `scan_pipeline_wiring` le dará cuerpo.
- `tracing-subscriber` se incluye con features por defecto; `fmt::init()` funciona. OK.

## Cambios requeridos

Ninguno.

# Review — feature 11 (hexagonal_ports)

**Veredicto:** APPROVED

Refactor de puertos y adaptadores para `ssh`, `scanner` y `repository`, con
inyección de dependencias en `lib::run()` vía `ServicePorts` y composition root
en `src/wiring.rs` + `src/main.rs`. Sin cambio de comportamiento observable.

## Checkpoints C1–C5

- C1: [x] Arnés completo; `./init.sh` exit 0 (3 corridas consecutivas, ver abajo).
- C2: [x] Solo la feature 11 en `in_progress`. `progress/current.md` describe la
  sesión activa. Toda feature `done` conserva sus tests verdes.
- C3: [x] `src/` respeta `docs/architecture.md`: los módulos nuevos `pipeline`
  (feature 10) y `wiring` (feature 11) están ahora documentados como capas 8–9 en
  `docs/architecture.md`; el checkpoint literal lista un set más antiguo pero la
  fuente de verdad (architecture.md) fue actualizada de forma coherente.
  `cargo doc` sin warnings (incluido `RUSTDOCFLAGS="-D warnings"`). Sin
  `unwrap`/`expect`/`panic!`/`todo!` fuera de tests (`src/ssh.rs`, `src/scanner.rs`,
  `src/repository.rs`, `src/pipeline.rs`, `src/lib.rs`, `src/main.rs`, `src/wiring.rs`
  verificados).
- C4: [x] `cargo clippy --all-targets -- -D warnings` limpio. `cargo test` 83
  verdes; `cargo test -- --ignored` 18 verdes contra contenedores Docker reales
  (repository 6, scan_pipeline 3, scanner 4, ssh 5). Tests de integración por
  módulo IO intactos.
- C5: [x] Sin archivos temporales sospechosos. Único untracked legítimo:
  `src/wiring.rs` (código nuevo de la feature) e `progress/impl_hexagonal_ports.md`
  (informe). `history.md` / `feature_list.json` los cierra el leader tras aprobar.

## Los 6 criterios de acceptance, uno a uno

### 1. Puerto SSH (`src/ssh.rs`)  — [x]
- `RemoteExecutor` (`connect(host, port, user, credentials, store, timeouts) ->
  Result<Box<dyn RemoteSession>, SshError>`) y `RemoteSession` (`run_command`),
  ambos `#[async_trait]` + `Send + Sync` → dyn-compatibles (`Arc<dyn RemoteExecutor>`,
  `Box<dyn RemoteSession>`). El usuario aprobó los dos traits.
- Adaptador `RusshExecutor` (unit struct) implementa `RemoteExecutor` delegando en
  la función libre `connect` y boxeando el `SshSession`.
- `impl RemoteSession for SshSession` delega en el `run_command` inherente.
- La función libre `pub async fn connect` (ssh.rs:538) y el `SshSession::run_command`
  inherente (ssh.rs:430) **siguen existiendo**. `tests/ssh.rs` sin cambios
  (`use nmap_service::ssh::{connect, ..., SshSession, ...}`) y sus 5 tests Docker
  pasan.

### 2. Puerto scanner (`src/scanner.rs`)  — [x]
- `NmapScanner` (`run_scan(&self, &dyn RemoteSession, ip, has_sudo, &ScanOptions)`)
  implementado por `NmapCliScanner` (unit struct) que delega en `run_scan_with`.
- Funciones libres `run_scan` / `run_scan_with` cambian el parámetro de
  `&SshSession` a `&dyn RemoteSession`. `tests/scanner.rs` **sin cambios**:
  `scanner::run_scan(&session, ...)` con `session: SshSession` coerciona a
  `&dyn RemoteSession` en el sitio de llamada. Los 4 tests Docker pasan.

### 3. Puerto repository (`src/repository.rs`)  — [x]
- `ScanResultRepository` (`save` / `find_by_id` / `find_by_correlation_id`)
  implementado por `MongoRepository`, delegando en los métodos inherentes con
  ruta calificada (`MongoRepository::save(self, ...)` etc.).
- Métodos inherentes conservados; `tests/repository.rs` sin cambios, sus 6 tests
  Docker pasan.
- `MongoHostKeyStore` / `HostKeyStore` intactos (ya eran puerto de feature 7).

### 4. Inyección en `lib::run()` + composition root  — [x]
- `run(ports: ServicePorts, config: PipelineConfig, source: Option<Arc<dyn ScanRequestSource>>)`.
  Ya no llama a `Config::from_env` ni a `MongoRepository::connect`: solo construye
  el `ScanPipeline` a partir de los puertos y despacha.
- `wiring::service_ports_from_config(&Config) -> Result<ServicePorts, WiringError>`
  es el único sitio que nombra adaptadores concretos: `RusshExecutor`,
  `NmapCliScanner`, `MongoRepository::connect(...)`.
- **`HostKeyStore` de producción sigue siendo el de Mongo**:
  `wiring.rs:56 → Arc::new(repo.host_key_store())`, NO `InMemory`.
- `src/main.rs` sigue delgado: tracing → `Config::from_env` →
  `wiring::service_ports_from_config` → `PipelineConfig` desde `Config` →
  `run(ports, cfg, None)`. Match arms que loggean con `tracing::error!` y
  `return`; sin `anyhow`, sin panic.
- `run()` con `source == None` conserva el comportamiento de feature 10:
  `tracing::warn!` de "adaptador de broker pendiente" y retorno limpio. Verificado
  además por el test `stub_fixture_parses_into_the_expected_scan_result` y por que
  `main` compila y no hay panics.

### 5. Todos los tests siguen pasando SIN cambio de comportamiento  — [x] (criterio central)
- `./init.sh` ejecutado **3 veces** → exit 0 estable las 3.
- Recuentos por binario (idénticos en las 3 corridas):
  - unit (`src/lib.rs`): **83** passed  (baseline feature 10: 82 → +1)
  - `tests/repository.rs`: 6 ignored en `cargo test`, **6** passed con `--ignored`
  - `tests/scan_pipeline.rs`: 1 passed + 3 ignored → **3** passed con `--ignored`
  - `tests/scanner.rs`: 4 ignored → **4** passed con `--ignored`
  - `tests/ssh.rs`: 5 ignored → **5** passed con `--ignored`
  - Total Docker: **18** (= baseline). Total no-Docker: 83 + 1 (scan_pipeline stub) = 84.
- El +1 unit es exactamente el bonus permitido:
  `pipeline::tests::ssh_stage_failure_is_published_as_failed_outcome_without_docker`
  con un `FailingExecutor` falso (`RemoteExecutor` que devuelve `SshError::AuthFailed`)
  + `UnusedScanner`/`UnusedRepository` con `unreachable!()`. Verifica
  `ScanOutcome::Failed`, `correlation_id` y no-fuga de credencial (`!reason.contains(SECRET)`).
- Análisis del `git diff` de tests — **solo construcción, cero lógica/asserts tocados**:
  - `tests/scanner.rs`, `tests/ssh.rs`, `tests/repository.rs`: **0 cambios**.
  - `tests/scan_pipeline.rs`: único cambio = el helper `build_pipeline` arma un
    `ServicePorts { executor: RusshExecutor, scanner: NmapCliScanner,
    repository: repo.clone(), host_key_store: repo.host_key_store(), sink }` +
    `PipelineConfig { ssh_port, ssh_timeouts, scan_options }`, en lugar de la
    firma posicional vieja de `ScanPipeline::new`. Los 3 tests e2e
    (`valid_request_flows_through_pipeline_and_is_published_and_persisted`,
    `stage_failure_is_published_as_failed_outcome_without_crashing`,
    `multiple_requests_are_processed_concurrently`) y `build_source` /
    fixtures / asserts intactos.
  - `src/pipeline.rs` `#[cfg(test)]`: los 3 tests previos
    (`next_valid_request_skips_poison_messages_and_ends_on_none`,
    `next_valid_request_stops_on_transport_error`,
    `stage_error_strings_become_failed_outcomes_without_leaking_credentials`)
    son byte-idénticos (solo cambian líneas de contexto). Solo se añaden imports
    y el nuevo test-bonus.
- `ScanPipeline` ahora consume los puertos: `run_stages` usa
  `self.executor.connect(...)`, `self.scanner.run_scan(session.as_ref(), ...)`,
  `self.repository.save(...)`. Ya no llama a `ssh::connect`,
  `scanner::run_scan_with` ni a métodos inherentes de `MongoRepository`. El orden
  de etapas, el mapeo `err.to_string()` y `process_one` / `run` /
  `next_valid_request` no cambian.

### 6. `docs/architecture.md`  — [x]
- La sección "Hexagonal parcial, a propósito" fue reemplazada por "Hexagonal
  completo (puertos y adaptadores)" con tabla puerto→adaptador (incluye
  `RemoteExecutor`, `RemoteSession`, `NmapScanner`, `ScanResultRepository`), la
  mención de `pipeline::ServicePorts` y del composition root en
  `src/wiring.rs` + `src/main.rs`, y la justificación de la separación en dos
  traits SSH.
- Sección "Capas": añadidas capa 8 `pipeline` y 9 `wiring`; `run(ports, config,
  source)` con la nueva firma; `main` renumerado a 11.

## Verificaciones adicionales

- `cargo fmt --check`: limpio.
- `cargo clippy --all-targets -- -D warnings`: 0 warnings.
- `RUSTDOCFLAGS="-D warnings" cargo doc --no-deps`: exit 0, 0 warnings.
  `#![deny(missing_docs)]` activo → todos los traits/structs/campos/métodos nuevos
  (`RemoteExecutor`, `RemoteSession`, `RusshExecutor`, `NmapScanner`,
  `NmapCliScanner`, `ScanResultRepository`, `ServicePorts` con sus 5 campos,
  `PipelineConfig` con sus 3 campos, `wiring::service_ports_from_config`,
  `WiringError::Mongo`) llevan rustdoc.
- `Cargo.toml` / `Cargo.lock`: **sin cambios** — no se añadió ninguna dependencia
  (`async-trait`, `thiserror` ya estaban).
- Traits dyn-compatibles vía `#[async_trait::async_trait]`; usados como
  `Arc<dyn ...>` en `ServicePorts` / `ScanPipeline` y `Box<dyn RemoteSession>`
  como retorno de `connect`.
- Sin `unwrap`/`expect`/`panic!` fuera de tests. Sin llamadas bloqueantes nuevas
  en async (los adaptadores solo delegan en código async ya existente).
- Sin scope creep: NO se implementó adaptador real de broker (sink sigue siendo
  `InMemoryScanResultSink`, documentado en `wiring.rs` y `lib.rs`), NI la feature
  12 (Dockerfile). `feature_list.json` sin `done` marcado por el implementer.

## Cambios requeridos

Ninguno.

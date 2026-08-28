# Feature 11 — hexagonal_ports — informe de implementación

Refactor sin cambio de comportamiento. Extrae puertos (traits) para ssh,
scanner y repository e inyecta sus adaptadores en `lib::run()` vía
`ServicePorts`. Red de seguridad: 83 tests unitarios + 18 `#[ignore]` (Docker),
todos verdes antes y después.

## Cambios por archivo

### `src/ssh.rs`
- Nuevo puerto `RemoteExecutor` (`async fn connect(...) -> Box<dyn RemoteSession>`),
  dyn-compatible vía `async-trait`.
- Nuevo puerto `RemoteSession` (`async fn run_command`).
- `impl RemoteSession for SshSession` — delega en el `run_command` inherente.
- Nuevo adaptador `RusshExecutor` (unit struct) — `impl RemoteExecutor` llamando
  a la función libre `connect` ya existente y boxeando el `SshSession`.
- **No se borró** la función libre `pub async fn connect` ni los métodos
  inherentes de `SshSession` (`tests/ssh.rs` los usa sin cambios).

### `src/scanner.rs`
- Nuevo puerto `NmapScanner` (`async fn run_scan(&self, &dyn RemoteSession, ...)`).
- Nuevo adaptador `NmapCliScanner` (unit struct) — delega en `run_scan_with`.
- Las funciones libres `run_scan` / `run_scan_with` ahora reciben
  `&dyn RemoteSession` en vez de `&SshSession`. `tests/scanner.rs` **sin
  cambios**: `&SshSession` coerciona a `&dyn RemoteSession` en el sitio de
  llamada.
- Doc-links `SshSession` -> `RemoteSession`.

### `src/repository.rs`
- Nuevo puerto `ScanResultRepository` (`save` / `find_by_id` /
  `find_by_correlation_id`).
- `impl ScanResultRepository for MongoRepository` — delega en los métodos
  inherentes (fully-qualified `MongoRepository::save(self, ...)` etc.), que se
  conservan (`tests/repository.rs` los usa directo).
- `MongoHostKeyStore` / `HostKeyStore` intactos (ya eran puerto, feature 7).

### `src/pipeline.rs`
- `ScanPipeline` pasa a guardar `Arc<dyn RemoteExecutor>`, `Arc<dyn NmapScanner>`,
  `Arc<dyn ScanResultRepository>`, `Arc<dyn HostKeyStore>`, `Arc<dyn ScanResultSink>`
  y un `PipelineConfig`.
- `ScanPipeline::new(ports: ServicePorts, config: PipelineConfig)` (firma nueva).
- Nuevos structs públicos `ServicePorts` y `PipelineConfig` (todos los campos
  documentados).
- `run_stages` usa `self.executor.connect`, `self.scanner.run_scan(session.as_ref(), ...)`,
  `self.repository.save`. `process_one` / `run` / `next_valid_request` sin cambio
  de lógica.
- **Bonus test (sin Docker):** `ssh_stage_failure_is_published_as_failed_outcome_without_docker`
  con un `RemoteExecutor` falso -> verifica `ScanOutcome::Failed` y no-fuga de
  credencial. (+1 test unitario: 82 -> 83.)

### `src/wiring.rs` (nuevo, `pub mod wiring`)
- `service_ports_from_config(&Config) -> Result<ServicePorts, WiringError>`:
  composition root. Construye `RusshExecutor`, `NmapCliScanner`,
  `MongoRepository::connect(...)`, deriva el `HostKeyStore` **de Mongo**
  (`repo.host_key_store()`) — criterio: el TOFU de producción sigue siendo el de
  Mongo. `sink` = `InMemoryScanResultSink` (no hay adaptador real de broker;
  documentado en el módulo).
- `WiringError::Mongo(#[from] RepoError)`.

### `src/lib.rs`
- `pub mod wiring;`, `pub use pipeline::{PipelineConfig, ServicePorts};`.
- `run()` -> `run(ports: ServicePorts, config: PipelineConfig, source: Option<Arc<dyn ScanRequestSource>>)`.
  Con `source == None` (caso actual) loggea "adaptador de broker pendiente" y
  retorna limpio — mismo comportamiento observable que la feature 10, sin panic.
  Con `Some` llamaría a `ScanPipeline::run`.

### `src/main.rs`
- Sigue delgado: tracing + `Config::from_env` -> `wiring::service_ports_from_config`
  -> `run(ports, pipeline_config, None)`. Sin `anyhow`, sin panic (match arms que
  loggean y retornan). No se añadió ninguna dependencia.

### `tests/scan_pipeline.rs`
- Único cambio: el helper `build_pipeline` construye `ServicePorts` (con
  `RusshExecutor` + `NmapCliScanner` + `MongoRepository` reales) + `PipelineConfig`.
  Lógica de los 3 tests e2e sin tocar.

### `docs/architecture.md`
- §"Hexagonal parcial" -> "Hexagonal completo (puertos y adaptadores)" con tabla
  puerto/adaptador y mención del composition root (`src/wiring.rs` + `src/main.rs`).
- §Capas: añadidas capas `pipeline` (8) y `wiring` (9); `run()` con nueva firma.

## Cargo.toml
Sin cambios (todas las deps ya estaban: `async-trait`, `thiserror`, ...).

## Verificación
- `cargo fmt --check`: limpio.
- `cargo clippy --all-targets -- -D warnings`: 0 warnings.
- `RUSTDOCFLAGS="-D warnings" cargo doc --no-deps`: 0 warnings.
- `cargo test`: 83 passed.
- `cargo test -- --ignored`: 18 passed (repository 6, scan_pipeline 3, scanner 4,
  ssh 5) contra contenedores Docker reales.
- `./init.sh`: exit 0, tres corridas consecutivas.
- Sin `unwrap`/`expect`/`panic!` fuera de tests.

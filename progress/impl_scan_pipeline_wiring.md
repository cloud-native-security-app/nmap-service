# Implementación — feature 10 `scan_pipeline_wiring`

Estado: implementada y verificada. **Pendiente de revisión** (feature sigue
`in_progress` en `feature_list.json`).

## Qué se hizo

### A. `src/config.rs` (ampliación mínima del wiring)

- Nuevas env vars **requeridas** (mismo patrón que feature 2: sin default,
  ausente/vacía/inválida -> `ConfigError`):
  - `MS_NMAP_SSH_PORT` (`SSH_PORT_VAR`) -> `Config::ssh_port: u16`. Se valida
    con `parse_port`: no numérico o fuera de `1..=65535` -> `InvalidValue`;
    ausente/vacía -> `MissingVar`. El `ScanRequest` no trae puerto SSH y el
    test e2e usa el puerto aleatorio del contenedor.
  - `MS_NMAP_MONGO_DB` (`MONGO_DB_VAR`) -> `Config::mongo_db: String`, para
    `MongoRepository::connect(uri, db_name)`. **Decisión**: env var explícita
    (no derivar del path del URI) — es consistente con el resto de la config
    (todo por env, nada implícito) y evita ambigüedad cuando el URI no lleva
    path o lleva parámetros.
- Tests añadidos en `config.rs`: `valid_vars()` incluye las 2 nuevas; asserts
  de valores parseados en el test de config válida; + `missing_mongo_db_var…`,
  `missing_ssh_port_var…`, `non_numeric_ssh_port…`, `out_of_range_ssh_port…`
  (`"0"` y `"70000"`).
- No se añadió nada más a `Config`.

### B. `src/pipeline.rs` (nuevo módulo, `pub mod pipeline;` en `lib.rs`)

- `pub struct ScanPipeline { repo: MongoRepository, host_key_store:
  Arc<dyn HostKeyStore>, sink: Arc<dyn ScanResultSink>, ssh_port: u16,
  ssh_timeouts: SshTimeouts, scan_options: ScanOptions }`. Deriva `Clone`
  (todos los campos lo son y es barato); `run` clona una copia por solicitud
  para despacharla a una tarea `tokio::spawn`.
- `pub async fn process_one(&self, request: ScanRequest)`:
  `ssh::connect(&request.ip.to_string(), ssh_port, &network_user,
  &ssh_credentials_ref, &host_key_store, ssh_timeouts)` ->
  `scanner::run_scan_with(&session, ip, has_sudo, &scan_options)` ->
  `parser::parse(&xml)` -> `repo.save(&result, &correlation_id)` ->
  `sink.publish(ScanOutcome::completed(...))`.
  Cualquier `Err` de las etapas 1-4 se transforma en
  `ScanOutcome::failed(correlation_id, err.to_string())` y se publica. **Nunca**
  propaga un error ni hace panic. Si `sink.publish` falla, se registra con
  `tracing::error!` (con `correlation_id`, sin credenciales) y termina — sin
  reintentos. Loggea inicio y desenlace de cada solicitud con `correlation_id`.
- `pub async fn run(&self, source: Arc<dyn ScanRequestSource>)`: bucle
  consumidor. `Ok(Some)` -> `tokio::spawn(process_one)` (pipeline clonado,
  concurrencia real). `Ok(None)` -> sale. `MalformedPayload|InvalidSchema` ->
  `tracing::warn!` y continúa. `Transport` -> `tracing::error!` y sale
  (**decisión**: reconexión/backoff es responsabilidad del adaptador de broker
  concreto, aún sin decidir; este bucle no reintenta). Al salir, espera con un
  `JoinSet` a que terminen las tareas en vuelo.
- Helper libre `next_valid_request(&dyn ScanRequestSource) -> Option<ScanRequest>`
  (extraído para poder testear la lógica del bucle sin Docker).
- Tests unitarios (sin Docker): `next_valid_request_skips_poison_messages_and_
  ends_on_none`, `next_valid_request_stops_on_transport_error` (con una
  `ScanRequestSource` de test), y `stage_error_strings_become_failed_outcomes_
  without_leaking_credentials` (construcción del `ScanOutcome::Failed` +
  `correlation_id` correcto + `reason` sin credencial).
  `process_one`/`run` completos con SSH+Mongo reales van en el test e2e (según
  `docs/verification.md` §Nivel 4 y el propio enunciado).

### C. `src/lib.rs` — `run()` como composition root

- `Config::from_env()` -> `MongoRepository::connect(&cfg.mongo_uri,
  &cfg.mongo_db)` -> `Arc<dyn HostKeyStore> = Arc::new(repo.host_key_store())`
  (**el store de producción es el de Mongo**, no el `InMemory`) -> construye
  `ScanPipeline` con `SshTimeouts { connect, command }` de la config,
  `cfg.ssh_port` y `ScanOptions::default()`.
- **Decisión sobre el adaptador de broker**: no existe uno real (features 8/9
  sólo tienen stubs `InMemory`; tecnología de broker sin decidir). `run()`
  construye lo que puede (config, Mongo, pipeline), emite
  `tracing::warn!("…el adaptador de broker aún no existe; el pipeline no
  consumirá…")` y retorna limpio. El sink placeholder es
  `InMemoryScanResultSink`. Conectar el `source` real queda fuera del alcance
  de esta feature (será cuando exista el adaptador; solapa con feature 11).
- **Firma**: se mantiene `pub async fn run()` (`-> ()`), `main.rs` sin cambios.
  Los fallos de config/Mongo se manejan con `tracing::error!` + retorno limpio
  (nunca panic). No se añadió `anyhow`.

### D. `Cargo.toml`

Sin cambios. `tokio::task::JoinSet` ya está disponible (feature
`rt-multi-thread` implica `rt`). No hizo falta `anyhow` (no se usa en el borde).

## Tests

- **`tests/scan_pipeline.rs`** (e2e, `#[ignore = "requiere Docker"]`). El stub
  de `nmap` vuelca el fixture real **`tests/fixtures/vuln_findings.xml`** (ya
  documentado en `tests/fixtures/README.md`: `nmap -sV --script vuln -p 21,6667`
  contra Metasploitable 2 de laboratorio). No se añadió ningún fixture nuevo
  (revisión round 1, punto 1).
  - `stub_fixture_parses_into_the_expected_scan_result` (sin Docker): valida
    que el fixture parsea al `ScanResult` esperado (host `172.18.0.4`, puertos
    21 y 6667 abiertos, `vsftpd 2.3.4`, 2 hallazgos `CVE-2011-2523` de
    `ftp-vsftpd-backdoor` y `vulners`).
  - `valid_request_flows_through_pipeline_and_is_published_and_persisted`
    (criterios 1 y 2): sshd + stub nmap en `/usr/local/bin/nmap` + `mongo:7`.
    Verifica 1 `ScanOutcome::Completed` con `correlation_id` correcto y
    puertos/vulns del XML (2 puertos abiertos, 2 vulns `CVE-2011-2523`); que el
    `ScanResult` quedó en Mongo (`find_by_correlation_id`); y que una
    **segunda** instancia de `MongoHostKeyStore` ve el fingerprint TOFU del
    objetivo (prueba que el pipeline usó el store de Mongo).
  - `stage_failure_is_published_as_failed_outcome_without_crashing`
    (criterio 3): objetivo sin stub de nmap -> `ScanError::ToolNotAvailable`
    -> 1 `ScanOutcome::Failed` con `correlation_id`, `reason` menciona nmap y
    no filtra la credencial; sin panic; nada persistido.
  - `multiple_requests_are_processed_concurrently` (criterio 4):
    `#[tokio::test(flavor = "multi_thread")]`, 3 solicitudes concurrentes al
    mismo sshd -> 3 desenlaces `Completed`, cada uno con su `correlation_id`,
    los 3 persistidos. Warm-up TOFU previo para que la contención sea del
    pipeline y no del upsert inicial del trust store.

## Verificación

- `./init.sh` **verde 3 veces seguidas** (incluye `cargo test -- --ignored`
  con contenedores reales sshd + mongo). Logs en el scratchpad de la sesión.
- `cargo clippy --all-targets -- -D warnings`, `cargo fmt --check`,
  `cargo doc --no-deps` limpios (persisten sólo las 2 advertencias rustdoc
  pre-existentes en `messaging/publisher.rs`, ajenas a esta feature).
- Sin regresión: los 82 tests unitarios y los de integración de features 1-9
  siguen pasando.
- Sin `unwrap`/`expect`/`panic!` fuera de tests. Sin llamadas bloqueantes en
  async (russh y mongodb son async; `JoinSet`/`tokio::spawn` para concurrencia).

## Revisión round 1 (CHANGES_REQUESTED) — atendida

1. Fixture sin procedencia: **eliminado `tests/fixtures/pipeline_stub_scan.xml`**.
   El e2e ahora reutiliza `tests/fixtures/vuln_findings.xml` (real, documentado)
   y los asserts de los 2 tests afectados se ajustaron a su contenido.
2. `src/messaging/publisher.rs` líneas 170/174: los enlaces intra-doc
   `[`outcome_log_fields`]` pasan a texto plano `` `outcome_log_fields` ``.
   `RUSTDOCFLAGS="-D warnings" cargo doc --no-deps` -> 0 warnings.

## Archivos tocados

- `src/config.rs` (ampliación + tests)
- `src/pipeline.rs` (nuevo)
- `src/lib.rs` (`pub mod pipeline;` + `run()` composition root)
- `src/messaging/publisher.rs` (2 doc-comments: quitar enlace intra-doc a ítem privado — revisión round 1)
- `tests/scan_pipeline.rs` (nuevo; usa el fixture existente `vuln_findings.xml`)
- `feature_list.json` (status -> `in_progress`)
- `progress/current.md`

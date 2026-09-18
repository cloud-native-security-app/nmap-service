# Implementación — feature 16: `scan_cancellation`

> Escrito por el implementer. La feature queda en `feature_list.json` con
> `status: "in_progress"`: el líder debe lanzar un `reviewer` antes de marcarla
> `done`.

## Fix tras CHANGES_REQUESTED del reviewer (ronda 2)

El reviewer marcó `CHANGES_REQUESTED` (ver `progress/review.md`) por una
condición de carrera real: `process_one` registraba el `CancellationToken`
**después** de `self.sink.publish(&ScanOutcome::started(...)).await`, no "al
arrancar" como exige literalmente el criterio de aceptación 5. Una cancelación
que llegara mientras esa publicación seguía en curso no encontraba el token
todavía registrado y se descartaba como "`correlation_id` desconocido", aunque
la tarea sí estaba en vuelo.

Corregido en `src/pipeline.rs::process_one`: el registro
(`self.cancellations.register(correlation_id.clone())`) ahora ocurre **antes**
de `self.sink.publish(&ScanOutcome::started(...)).await`, no después. El
desregistro sigue exactamente donde estaba (al terminar, en los 3 caminos:
éxito, fallo de etapa, cancelación), sin cambios ahí.

Se añadió el test que exige el punto 2 del fix:
`pipeline::tests::cancellation_while_started_publish_is_in_flight_finds_the_token_and_cancels`.
Usa un nuevo doble `SlowStartedSink` cuya publicación de `Started` se bloquea
(vía `tokio::sync::Notify`) hasta que el test la libera explícitamente; mientras
está bloqueada, el test cancela la tarea y comprueba `pipeline.cancellations.cancel(&correlation_id) == true`
(el token se encuentra, no es un no-op de "desconocido"), libera la publicación
y verifica que el desenlace final es `ScanOutcome::Failed` con
`CANCELLATION_REASON` — nunca `Completed`. El `executor` de ese test es el
`SlowExecutor` ya existente (nunca resuelve por sí mismo), así que si el fix se
revirtiera el test colgaría (`handle.await`) en vez de pasar en falso.

Después del fix: `cargo build`/`fmt --check`/`clippy -D warnings`/`cargo doc`
limpios, 135 tests unitarios verdes (134 + el nuevo), y `./init.sh` completo
con Docker corrido 3 veces en verde (detalle en la sección "Verificación"
actualizada más abajo). No se tocó nada más de lo ya aprobado por el reviewer
(dominio, puerto/adaptador, segundo bucle en el mismo `JoinSet`, `Cargo.toml`,
el resto de tests, ni el e2e con stub lento de `nmap`).

## Qué se implementó

- `domain::ScanCancellation { correlation_id: CorrelationId, requested_by: String }`
  (`src/domain.rs`), `Serialize`/`Deserialize` sin `rename`/`rename_all` (coincide
  con el naming default de serde, igual que `ScanRequest`). Test de round-trip
  serde que verifica la forma exacta del JSON (sin campos extra).
- `messaging::consumer` (`src/messaging/consumer.rs`):
  - `parse_scan_cancellation(raw: &[u8]) -> Result<ScanCancellation, ConsumeError>`,
    mismo patrón en dos etapas que `parse_scan_request` (JSON roto ->
    `MalformedPayload`; esquema inválido -> `InvalidSchema`). No hay credencial
    que redactar en el mensaje de error, a diferencia de `ScanRequest`.
  - `log_cancellation_received` (nivel INFO, sólo `correlation_id` +
    `requested_by`).
  - Trait `ScanCancellationSource` (`#[async_trait]`, `Send + Sync`,
    dyn-compatible): `async fn next_cancellation(&self) -> Result<Option<ScanCancellation>, ConsumeError>`.
    Reutiliza `ConsumeError` tal cual (mismo tipo, mismo contrato
    fatal/no-fatal que `ScanRequestSource`), tal como pide el acceptance
    ("mismo contrato de errores").
  - `InMemoryScanCancellationSource`: mismo patrón que
    `InMemoryScanRequestSource` (`Mutex<VecDeque<Result<...>>>` con manejo de
    poison), con `from_cancellations`/`from_raw_messages` y `#[derive(Default)]`
    para una fuente vacía lista para los call-sites que no cancelan nada.
- `pipeline.rs`:
  - `CancellationRegistry` (privado): `Arc<Mutex<HashMap<CorrelationId, CancellationToken>>>`
    con `register`/`unregister`/`cancel`. `cancel` devuelve `bool` (encontrado o
    no) para poder loggear "no-op" sin que sea nunca un error. Registro y
    desregistro toman el mismo `Mutex`, así que una cancelación tardía sobre una
    tarea ya desregistrada nunca encuentra el token: no-op seguro, no condición
    de carrera.
  - `ScanPipeline` gana el campo `cancellations: CancellationRegistry`
    (`#[derive(Clone, Default)]`, barato de clonar).
  - `process_one`: registra el token **al arrancar, antes de publicar
    `ScanOutcome::started`** (ver "Fix tras CHANGES_REQUESTED" arriba), envuelve
    `run_stages` en
    `tokio::select! { result = self.run_stages(&request) => ..., () = token.cancelled() => ... }`,
    y desregistra siempre al terminar (los 3 caminos: éxito, fallo de etapa,
    cancelación). La rama de cancelación publica
    `ScanOutcome::failed(correlation_id, "escaneo cancelado por solicitud explícita")`
    (constante `CANCELLATION_REASON`).
  - `ScanPipeline::run` ahora firma
    `pub async fn run(&self, source: Arc<dyn ScanRequestSource>, cancellations: Arc<dyn ScanCancellationSource>)`.
    El segundo bucle de cancelaciones corre en el **mismo `JoinSet`** que las
    tareas de solicitudes (una tarea más, vía `tasks.spawn`), tal como pide el
    acceptance ("mismo JoinSet/tokio::spawn que el de solicitudes"). Usa un
    helper `next_valid_cancellation` (copia exacta del patrón de
    `next_valid_request`: descarta `MalformedPayload`/`InvalidSchema` con
    `warn!` y continúa, detiene en `Transport`). Cada cancelación entregada se
    aplica vía `apply_cancellation`, que llama a `self.cancellations.cancel(...)`
    y loggea "aplicada" o "no-op" según el resultado, nunca un error.
- `src/lib.rs`: `run()` gana el parámetro
  `cancellations: Option<Arc<dyn ScanCancellationSource>>`; si es `None`
  (caso de `src/main.rs` hoy, sin adaptador de broker real todavía) se usa
  `InMemoryScanCancellationSource::default()` internamente para no exigirle a
  `main.rs` que invente un stub.
- `src/main.rs`: `run(ports, pipeline_config, None, None).await;`.
- `tests/scan_pipeline.rs`: los 3 call-sites existentes de `pipeline.run(source)`
  pasan ahora también `Arc::new(InMemoryScanCancellationSource::default())`.
  Nuevo test e2e `#[ignore = "requiere Docker"]`
  `cancellation_received_mid_scan_stops_it_and_publishes_failed_outcome`: usa un
  nuevo stub `slow_fake_nmap(20)` (duerme 20s antes de volcar el XML) y una
  `DelayedCancellationSource` de prueba (duerme 3s antes de entregar la
  cancelación en cola) para garantizar que la cancelación llega mientras la
  etapa `scanner` sigue bloqueada en el `sleep` del stub. Verifica: el pipeline
  termina en <15s (no espera los 20s del stub), publica `Started` y luego
  `Failed` con "cancel" en el motivo, y el `ScanResult` **no** queda persistido
  en Mongo.

## Cargo.toml

Se añadió `tokio-util = "0.7"` como dependencia directa (antes sólo llegaba
transitivamente vía `mongodb`/`russh`/`reqwest`). **Corrección respecto al
informe de research** (`progress/research_domain_and_ports.md`, punto 7): el
research sugería `tokio-util = { version = "0.7", features = ["sync"] }`, pero
`cargo build` falló porque **`tokio-util` 0.7.19 no tiene ningún feature
llamado `sync`** (sus features son `codec`, `compat`, `io`, `io-util`,
`join-map`, `net`, `rt`, `time`, `full`). Inspeccioné el `Cargo.toml`/`lib.rs`
fuente del crate vendored en `~/.cargo/registry`: el módulo `tokio_util::sync`
(que contiene `CancellationToken`) **no está detrás de ningún `#[cfg(feature = ...)]`**
— se compila siempre, con las features por defecto (vacías). Corregido a
`tokio-util = "0.7"` sin features extra; el comentario en `Cargo.toml` explica
la corrección para quien lo lea después.

## Seguridad (`docs/security-scope.md`)

- `ScanCancellation` no lleva IP, `network_user` ni `ssh_credentials_ref` del
  escaneo original — sólo `correlation_id` y `requested_by`. Ni el logging de
  esta feature (`log_cancellation_received`, `apply_cancellation`) ni el
  `ScanOutcome::Failed` publicado en cancelación exponen nada del objetivo.
- No se tocó la lógica de TOFU, `sudo -n`, ni el alcance de detección de
  `scanner`: esta feature sólo añade un mecanismo de aborto cooperativo
  alrededor de `run_stages`, sin nueva lógica de escaneo. El contrato
  best-effort del resto del pipeline (enrichment, evento `started`) no cambió.
- Una cancelación a mitad de `run_stages` puede interrumpir la conexión SSH o
  la ejecución de `nmap` ya en curso en el objetivo (el proceso remoto de
  `nmap`/la sesión SSH quedan a cargo de que `russh` cierre el canal al soltar
  el `Box<dyn RemoteSession>`; no se implementó limpieza adicional porque el
  acceptance no la pide y no hay señal de que deje el objetivo en un estado
  inconsistente — es el mismo corte abrupto que ya ocurre si el proceso
  `ms-nmap` muriera a mitad de un escaneo).

## Verificación

- `cargo build --all-targets`: sin errores.
- `cargo fmt --check`: sin diferencias.
- `cargo clippy --all-targets -- -D warnings`: sin warnings.
- `cargo doc --no-deps` (y también probado con `--document-private-items`):
  sin errores ni warnings de rustdoc (corregí 3 enlaces intra-doc a ítems
  privados que sólo se veían con `--document-private-items`, reemplazándolos
  por texto plano).
- `cargo test` (sin Docker): **135 tests unitarios, todos verdes** (134 de la
  ronda 1 + `cancellation_while_started_publish_is_in_flight_finds_the_token_and_cancels`
  de la ronda 2 del fix), incluyendo:
  - `domain::tests::scan_cancellation_json_round_trip_preserves_every_field`
  - `messaging::consumer::tests::{valid_cancellation_message_parses_into_scan_cancellation, syntactically_broken_cancellation_json_is_malformed_payload, cancellation_missing_required_field_is_invalid_schema, in_memory_cancellation_source_delivers_in_order_then_none, in_memory_cancellation_source_from_raw_yields_error_then_continues, in_memory_cancellation_source_default_is_empty, log_cancellation_received_records_correlation_id}`
  - `pipeline::tests::{next_valid_cancellation_skips_poison_messages_and_ends_on_none, next_valid_cancellation_stops_on_transport_error, cancellation_registry_cancel_after_register_marks_the_token_cancelled, cancellation_registry_cancel_unknown_id_is_a_safe_noop, cancellation_registry_unregister_prevents_late_cancellation_from_finding_the_token, cancellation_mid_flight_stops_process_one_and_publishes_cancellation_failed_outcome, cancellation_while_started_publish_is_in_flight_finds_the_token_and_cancels, cancellation_after_process_one_finished_is_a_safe_noop, run_consumes_both_sources_and_a_cancellation_for_an_unknown_id_is_harmless}`
- `./init.sh` completo (incluye Docker vía `testcontainers`): **6 corridas
  consecutivas en verde en total** (3 antes del fix + 3 después), incluido el
  e2e `cancellation_received_mid_scan_stops_it_and_publishes_failed_outcome` en
  `tests/scan_pipeline.rs` y, tras el fix, el nuevo unitario de la ventana de
  carrera. No se observó el flake intermitente de `enrichment::nvd::tests`
  documentado en sesiones anteriores (feature 14, ajeno a esta feature) en
  ninguna de las 6 corridas.

## Alcance respetado

- No se tocó `run_stages` etapa por etapa (el `tokio::select!` envuelve la
  llamada completa, como sugería el research) ni la lógica de negocio de SSH,
  `nmap`, parseo, enrichment o persistencia.
- No se añadió un cuarto estado `Cancelled` a `ScanOutcome`: la cancelación se
  publica como `ScanOutcome::Failed` con un motivo explícito, tal como exige el
  acceptance (el contrato de broker no tiene ese cuarto estado todavía).
- No se modificó `docs/architecture.md` ni `docs/security-scope.md`: el
  acceptance de esta feature no lo pide (a diferencia de las features 13/14),
  y no se detectó ninguna decisión de diseño nueva que requiriera
  documentarse ahí.
- No se marcó la feature como `done` ni se tocó `progress/history.md`: eso
  queda para el líder tras el veredicto del `reviewer`.

## Estado final

`feature_list.json`: feature 16 sigue en `"status": "in_progress"`.
`progress/current.md` actualizado con el resumen de la sesión y el próximo
paso (lanzar `reviewer`).

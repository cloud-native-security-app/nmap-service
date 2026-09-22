# Implementación — feature 15: scan_started_event

## Resumen

Se añadió un tercer desenlace, `ScanOutcome::Started`, que `ScanPipeline::process_one`
publica hacia el Broker (vía el `ScanResultSink` inyectado) **antes** de tocar el
objetivo (SSH/nmap), para que RF-07/RF-08 (estado EN_PROGRESO / notificación en
tiempo real vía Gateway) tengan una señal de arranque, no sólo el desenlace final.

## Cambios de código

### `src/messaging/publisher.rs`

- Nueva variante `ScanOutcome::Started { correlation_id: CorrelationId }`, parte
  del mismo enum *internally tagged* (`#[serde(tag = "status", ...)]`), por lo
  que serializa exactamente a `{"status":"started","correlation_id":"..."}` sin
  `result` ni `reason`.
- Constructor `ScanOutcome::started(correlation_id)`.
- `ScanOutcome::correlation_id()` y `status_label()` cubren la nueva variante
  (`"started"`).
- `outcome_log_fields()` (helper puro de logging) devuelve `status: "started"`,
  `counts: None` — mismo contrato de no-fuga que `Completed`/`Failed`: nunca hay
  forma estructural de filtrar credenciales.
- Doc del módulo actualizada (formato de mensaje, quién consume `started` —
  sólo el Gateway, nunca `ms-analisis`).

### `src/pipeline.rs`

- `ScanPipeline::process_one`: publica `ScanOutcome::started(correlation_id.clone())`
  a través de `self.sink` **antes** de llamar a `self.run_stages(&request)`.
- Publicación best-effort: si `sink.publish` devuelve `Err`, se loggea con
  `tracing::warn!(correlation_id, error, ...)` (sin credenciales) y se continúa
  igual con `run_stages` — nunca se aborta el escaneo por esto.
- Exactamente una publicación `Started` por invocación de `process_one` (una
  sola llamada, sin bucles ni reintentos).
- Doc del módulo y de `process_one` actualizada para reflejar el nuevo paso.

## Tests

### Unitarios (`src/messaging/publisher.rs`, sin Docker)

- `started_outcome_serializes_to_exact_message_shape_with_no_extra_fields`:
  verifica el JSON exacto (`serde_json::json!`) y `status_label()`.
- `outcome_json_round_trip_preserves_every_field`: ahora incluye `Started` en
  el vector de casos (regresión de `Completed`/`Failed` sigue verde).
- `correlation_id_accessor_works_for_all_variants` (renombrado desde
  `..._for_both_variants`): cubre `Started`.
- `log_fields_for_started_expose_only_correlation_id_and_status`.
- `log_outcome_published_does_not_panic_for_any_variant` (renombrado desde
  `..._for_either_variant`): incluye `Started`.

### Unitarios (`src/pipeline.rs`, sin Docker)

- `ssh_stage_failure_is_published_as_failed_outcome_without_docker`: actualizado
  para esperar **2** desenlaces — `Started` primero, `Failed` después — mismo
  `correlation_id`, sin debilitar el assert original de que el `reason` no
  filtra la credencial.
- `started_publish_failure_is_best_effort_and_does_not_abort_the_scan` (nuevo):
  usa un `FlakySink` de test que falla sólo la primera llamada a `publish`
  (la del evento `started`) y verifica que el pipeline sigue igual y publica el
  desenlace terminal (`Failed`, vía `FailingExecutor`) con el mismo
  `correlation_id` — el fallo de `started` nunca se propaga.

### E2E (`tests/scan_pipeline.rs`, `#[ignore = "requiere Docker"]`)

Las 3 pruebas existentes se actualizaron sin debilitar ningún assert previo del
resultado final:

- `valid_request_flows_through_pipeline_and_is_published_and_persisted`: ahora
  espera 2 eventos (`Started` en `published[0]`, `Completed` en `published[1]`)
  y conserva todos los asserts sobre el `ScanResult` final.
- `stage_failure_is_published_as_failed_outcome_without_crashing`: ahora espera
  2 eventos (`Started` en `published[0]`, `Failed` en `published[1]`), conserva
  el assert de que el `reason` no filtra la credencial.
- `multiple_requests_are_processed_concurrently`: con 3 solicitudes concurrentes
  ahora se publican 6 eventos (3 `Started` + 3 `Completed`); se separan por tipo
  para conservar los asserts originales sobre los 3 desenlaces terminales, y se
  añade una verificación de que, para cada `correlation_id`, su índice de
  `Started` en el orden global de publicación precede al de su terminal
  (el entrelazado entre tareas concurrentes es libre, pero el par
  started→terminal de una misma tarea nunca se invierte).

## `feature_list.json`

- Feature `id: 15` (`scan_started_event`) cambiada de `"pending"` a
  `"in_progress"` al empezar. **No** se marcó `"done"` — queda pendiente del
  veredicto del `reviewer`.

## Verificación

- `./init.sh` corrido 4 veces con estos cambios en verde (fmt, clippy, 118 tests
  unitarios + tests de integración con Docker — incluidos los 3 e2e de
  `tests/scan_pipeline.rs` — y `cargo doc` sin warnings).
- **Nota para el reviewer**: en una de las corridas de `./init.sh` durante la
  sesión, 2 tests de `enrichment::nvd::tests` fallaron de forma intermitente
  (`unreachable_server_yields_ok_with_no_findings_never_panics` y
  `enrich_maps_the_mocked_nvd_response_to_a_vuln_finding`). Confirmé con
  `git stash` que esta flakiness **ya existe en la base** (commit `96f0288`,
  antes de tocar nada de esta feature) y no está relacionada con
  `messaging::publisher` ni `pipeline`: es un problema preexistente de la
  feature 14 (`nvd_enrichment`), probablemente el rate limiter de
  `NvdApiEnricher` bajo presión de CPU al correr la suite completa en paralelo.
  Aislado (`cargo test --lib enrichment::nvd`) pasa consistentemente. No lo
  toqué — está fuera del scope de la feature 15 (regla de una sola feature por
  sesión).

## Alcance no tocado

- No se implementó nada de la feature 16 (`scan_cancellation`): ni
  `ScanCancellation`, ni `ScanCancellationSource`, ni el registro de
  `CancellationToken`. El evento `Started` que esta feature publica es
  independiente de esa mecánica.
- No se tocó SSH real, ejecución de `nmap` ni manejo de credenciales: el evento
  se publica antes de esas etapas, usando el `ScanResultSink` ya existente.

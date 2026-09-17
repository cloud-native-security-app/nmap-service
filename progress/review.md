# Review — feature 15 (scan_started_event)

**Veredicto:** APPROVED

## Verificación realizada

- Leídos `docs/architecture.md`, `docs/conventions.md`, `docs/security-scope.md`, `CHECKPOINTS.md`.
- Revisado el diff real (`git diff`) de `src/messaging/publisher.rs`, `src/pipeline.rs`, `tests/scan_pipeline.rs`, `feature_list.json`, `progress/current.md` contra los 9 criterios de `acceptance` de la feature 15 en `feature_list.json`.
- `./init.sh` ejecutado **3 veces** con los cambios sin commitear (Docker disponible): las 3 corridas terminaron con exit code 0 (`fmt`, `clippy -D warnings`, 118 tests unitarios, tests de integración con `testcontainers` incluidos los 3 e2e de `tests/scan_pipeline.rs`, `cargo doc --no-deps`).
- Investigado el flake reportado en `enrichment::nvd::tests` (ver sección dedicada abajo).
- `grep` de `unwrap()/expect()/panic!()/println!/dbg!` en los archivos modificados: todas las ocurrencias están dentro de `mod tests` (`src/pipeline.rs` desde línea 319, `src/messaging/publisher.rs` desde línea 334) — nada fuera de test sin justificar.

## Cumplimiento del acceptance de la feature 15

1. `ScanOutcome::Started { correlation_id }` con tag `status: "started"`, sin `result`/`reason`, y `ScanOutcome::started(...)` — verificado en `src/messaging/publisher.rs:96-101,115-118` y test `started_outcome_serializes_to_exact_message_shape_with_no_extra_fields`. OK.
2. `status_label()` devuelve `"started"`; `outcome_log_fields` maneja la variante sin panic y sin exponer más que `correlation_id`+`status` (`counts: None`) — test `log_fields_for_started_expose_only_correlation_id_and_status`. OK.
3. `ScanPipeline::process_one` publica `started` **antes** de `run_stages` (que engloba ssh/scanner/parser/enrichment/repository) — `src/pipeline.rs:139-149`, y luego continúa hasta el desenlace terminal. OK.
4. Publicación best-effort: en fallo del sink, `tracing::warn!` con `correlation_id`+`error` (sin credenciales) y continúa — `src/pipeline.rs:143-148`, cubierto por `started_publish_failure_is_best_effort_and_does_not_abort_the_scan` con `FlakySink`. OK.
5. Exactamente un evento `started` por invocación (una sola llamada, sin bucle) — confirmado leyendo `process_one`; los tests de concurrencia (`multiple_requests_are_processed_concurrently`) confirman 3 `Started` para 3 solicitudes. OK.
6. Round-trip serde exacto (`{"status":"started","correlation_id":"..."}`) y regresión de `Completed`/`Failed` — tests `started_outcome_serializes_to_exact_message_shape_with_no_extra_fields` y `outcome_json_round_trip_preserves_every_field` (incluye las 3 variantes). OK.
7. Test unitario con `InMemoryScanResultSink`: 2 desenlaces en orden Started→terminal, mismo `correlation_id` — `ssh_stage_failure_is_published_as_failed_outcome_without_docker` actualizado. OK.
8. `tests/scan_pipeline.rs` (e2e, `#[ignore]`) actualizado sin debilitar asserts previos: las 3 pruebas verifican Started antes del terminal (éxito 2 eventos, fallo 2 eventos, concurrencia 6 eventos con Started precediendo a su terminal por `correlation_id`). OK.
9. `./init.sh` en verde (3 corridas) — ver arriba. OK.

Todos los archivos tocados (`publisher.rs`, `pipeline.rs`, `tests/scan_pipeline.rs`) tienen su test correspondiente actualizado o nuevo. No hay violaciones de capas: `pipeline` sigue usando sólo el puerto `ScanResultSink` inyectado, `messaging` no se acopla a ninguna tecnología concreta de broker, y no se tocó `ssh`/`scanner`/`repository`/`enrichment` ni ninguna lógica de credenciales — consistente con `docs/architecture.md` y `docs/security-scope.md`. Nombres y estructura siguen `docs/conventions.md` (snake_case, tests descriptivos, imports agrupados, thiserror ya existente sin cambios).

## Sobre el flake reportado en `enrichment::nvd::tests`

Verificación independiente, sin confiar en el reporte del implementer:

- Con los cambios de la feature 15 aplicados, corrí `cargo test --lib` 3 veces seguidas: la corrida 3 falló intermitentemente en `enrichment::nvd::tests::cache_hit_avoids_a_second_http_call` y `enrichment::nvd::tests::unreachable_server_yields_ok_with_no_findings_never_panics`.
- Hice `git stash` para volver exactamente al commit base `96f0288` (sin ningún cambio de la feature 15) y corrí `cargo test --lib` 5 veces seguidas: la corrida 3 falló con **los mismos dos tests exactos** (`cache_hit_avoids_a_second_http_call`, `unreachable_server_yields_ok_with_no_findings_never_panics`).
- Conclusión: el flake es preexistente y no lo introduce ni lo agrava la feature 15. La feature 15 no toca `src/enrichment/nvd.rs` ni ningún archivo de `enrichment/`. Coincide con lo declarado por el implementer en `progress/impl_scan_started_event.md` y `progress/current.md`.
- No bloquea esta feature. Recomiendo que el leader registre este flake como su propio hallazgo/feature de mantenimiento (p. ej. estabilizar el rate limiter de `NvdApiEnricher` en tests bajo carga de CPU), tal como ya sugiere la nota dejada en `progress/current.md`. Las 3 corridas de `./init.sh` que usé para este veredicto (que corren la suite completa vía `cargo test` normal, no en aislamiento repetido) terminaron las 3 en verde, por lo que el requisito duro de "`init.sh` en verde" se cumple para esta sesión.

## Checkpoints (`CHECKPOINTS.md`)

- C1: [x] — Existen los 4 archivos base y los 4 docs; `./init.sh` terminó con exit code 0 en las 3 corridas realizadas.
- C2: [x] — Una sola feature (`15`) en `in_progress`; `progress/current.md` describe la sesión activa sin basura de sesiones anteriores; no hay ninguna feature marcada `done` sin tests (la 15 sigue `in_progress`, correctamente, a la espera de este veredicto).
- C3: [x] — `src/` sólo contiene los módulos previstos (`messaging`, `pipeline` modificados, sin módulos nuevos); no hay `unwrap()/panic!()/println!/dbg!` fuera de tests sin justificar en los archivos tocados; `cargo doc --no-deps` generó sin errores en las 3 corridas.
- C4: [x] — Tests de integración e2e actualizados (`tests/scan_pipeline.rs`, `#[ignore = "requiere Docker"]`) corriendo contra `testcontainers` real; `cargo test` mostró 118 tests unitarios + los de integración, todos verdes en las 3 corridas de `./init.sh`; `cargo clippy --all-targets -- -D warnings` sin advertencias.
- C5: [x] — No hay archivos sin trackear sospechosos aparte de `progress/impl_scan_started_event.md` (documentación del implementer, esperada); `progress/current.md` refleja correctamente el estado (feature 15, pendiente de veredicto, no marcada `done` prematuramente).

## Cambios requeridos

Ninguno. La feature 15 cumple los 9 criterios de aceptación, respeta arquitectura y convenciones, tiene tests unitarios y e2e correspondientes, y `./init.sh` corre en verde de forma reproducible. El flake de `enrichment::nvd` es preexistente (confirmado independientemente contra el commit base) y queda fuera del alcance de esta feature; se recomienda abrirlo como hallazgo/feature separada, no como bloqueo de esta revisión.

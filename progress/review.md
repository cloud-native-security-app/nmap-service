# Review — feature 16 (scan_cancellation)

**Veredicto:** APPROVED

## Verificación del fix (ronda 2)

`src/pipeline.rs::process_one`: `let token = self.cancellations.register(correlation_id.clone());`
ahora está en la línea 228, **antes** de `self.sink.publish(&ScanOutcome::started(...)).await`
(líneas 230-234). El registro ocurre efectivamente "al arrancar `process_one`", cumpliendo el
criterio de aceptación 5 al pie de la letra.

- **Desregistro sigue atómico y único.** `self.cancellations.unregister(&correlation_id);` (línea
  263) ocurre exactamente una vez, después de que el `tokio::select!` (líneas 242-261) resuelve por
  cualquiera de sus dos ramas (éxito/fallo de `run_stages`, o cancelación vía `token.cancelled()`).
  No hay ningún `return`/`?`/`panic!` entre el registro (línea 228) y el desregistro (línea 263): el
  flujo de `process_one` es completamente lineal, así que mover el registro más arriba no introduce
  una ventana nueva en la que el token pueda quedar huérfano por un retorno temprano. El único riesgo
  residual (que un panic dentro de `run_stages` deje el token sin desregistrar) ya existía antes del
  fix — el orden del registro no lo afecta ni lo agrava, y no es un unwrap/panic fuera de tests
  (`docs/conventions.md`) introducido por este cambio.
- **El nuevo test cubre la ventana correcta.** `cancellation_while_started_publish_is_in_flight_finds_the_token_and_cancels`
  (`src/pipeline.rs` líneas 1084-1149) usa `SlowStartedSink`, cuyo `publish` se bloquea en
  `release.notified().await` únicamente para `ScanOutcome::Started` (líneas 1070-1082). El test
  espera `entered_publish.notified()` (línea 1118, señal emitida *dentro* de esa publicación, no
  después) y sólo entonces llama a `pipeline.cancellations.cancel(&correlation_id)`, aseverando que
  devuelve `true` (línea 1119-1123) — es decir, exactamente la ventana "cancelación llega mientras
  `sink.publish(Started)` sigue en curso", no una cancelación posterior. El `executor` es
  `SlowExecutor`, que nunca resuelve por sí mismo (`std::future::pending`), así que si el fix se
  revirtiera (registro después del publish) el `cancel()` de la línea 1119 devolvería `false` y el
  `assert!` fallaría de inmediato (no un colgado silencioso, lo cual es aún mejor que sólo colgar).
  Verificado: `cargo test` (8 corridas aisladas de este test con `--exact`) da `ok` las 8 veces —
  sin señales de flakiness en el `Notify`/`select!`.
- El resto de `process_one` (rama de éxito/fallo de `run_stages`, rama de cancelación, publicación
  del desenlace terminal, logging) no cambió respecto a la ronda 1 ya aprobada.

## Checkpoints

- C1: [x] `AGENTS.md`, `init.sh`, `feature_list.json`, `progress/current.md`, los 4 docs existen; `./init.sh` corrido 2 veces completas (con Docker), exit 0 ambas.
- C2: [x] Solo la feature 16 en `in_progress` (`feature_list.json`: 15 `done` + 1 `in_progress`, confirmado por script). `progress/current.md` describe la sesión activa y el próximo paso, sin basura de sesiones previas.
- C3: [x] `src/pipeline.rs` respeta la arquitectura hexagonal (el registro/desregistro vive en `CancellationRegistry`, privado a `pipeline`, sin fugas a otras capas); `src/domain.rs`/`src/messaging/consumer.rs` siguen el mismo patrón que `ScanRequest`/`ScanRequestSource` ya aprobado en la ronda 1. Sin `unwrap()`/`panic!()`/`println!`/`dbg!` fuera de tests. `cargo clippy --all-targets -- -D warnings` y `cargo fmt --check` limpios (parte de las 2 corridas de `./init.sh`). `cargo doc --no-deps` sin errores/warnings.
- C4: [x] `cargo test` (135 unitarios, incluido el nuevo test de la ventana de carrera) y `cargo test -- --ignored` (con Docker/testcontainers, incluido el e2e `cancellation_received_mid_scan_stops_it_and_publishes_failed_outcome` en `tests/scan_pipeline.rs`) verdes en las 2 corridas completas de `./init.sh` que ejecuté, más 8 corridas aisladas adicionales del test de la ventana de carrera (todas `ok`, sin flake). Sin señales del flake conocido de `enrichment::nvd::tests`: los 5 tests de `nvd_cache_*` en `tests/repository.rs` (integración con Mongo real) y los tests unitarios de `src/enrichment/nvd.rs` (parte de los 135 de `cargo test`) pasaron en ambas corridas.
- C5: [x] Sin archivos sospechosos (`*.tmp`, etc.); solo los `progress/*.md` esperados sin trackear (`impl_scan_cancellation.md`, `research_domain_and_ports.md`, `research_pipeline_concurrency.md`). `progress/current.md` refleja el estado real (feature 16 en `in_progress`, pendiente de este veredicto para que el líder la marque `done`).

## Confirmación de no regresión

- `git diff -- src/domain.rs src/lib.rs src/main.rs src/messaging/consumer.rs Cargo.toml tests/scan_pipeline.rs` muestra únicamente cambios **aditivos** (nuevo tipo `ScanCancellation`, nuevo trait/adaptador `ScanCancellationSource`/`InMemoryScanCancellationSource`, nuevo parámetro `cancellations` en `run()`, dependencia `tokio-util` justificada): nada de lo ya aprobado en la ronda 1 para estos archivos cambió de forma incompatible.
- La feature 15 (`scan_started_event`, comiteada en `6a4ba12`) no fue tocada más allá de lo estrictamente necesario para pasar `cancellations` como parámetro adicional a `run()`; la publicación de `ScanOutcome::started` y su contrato best-effort siguen intactos (tests `ssh_stage_failure_is_published_as_failed_outcome_without_docker`, `started_publish_failure_is_best_effort_and_does_not_abort_the_scan`, ambos verdes).
- Acceptance completo de la feature 16 (`feature_list.json` id 16) verificado punto por punto: dominio, puerto/adaptador, segundo bucle en el mismo `JoinSet`, registro/desregistro atómico corregido, `tokio::select!` con motivo explícito de cancelación, sin fuga de credenciales/IP, `Cargo.toml` justificado, tests unitarios sin Docker, test de integración con Docker, `./init.sh` en verde sin regresión en features 1-15.

## Cambios requeridos

Ninguno.

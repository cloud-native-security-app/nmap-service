# Feature 9 — broker_publisher

Estado: implementada + `./init.sh` verde (unit + integración Docker + fmt +
clippy + doc). Pendiente de review y de marcar `done`.

## Archivos tocados

- `src/messaging/publisher.rs` — reescrito (era stub `//!`).
- `src/messaging/mod.rs` — doc del módulo actualizada (ya no es "stub del
  scaffolding"; enlaza los dos traits).
- `feature_list.json` — feature 9 `pending` -> `in_progress`.
- `progress/current.md` — plan y bitácora.

Sin dependencias nuevas en `Cargo.toml`: se reutilizan `serde`, `serde_json`,
`async-trait`, `thiserror`, `tracing` (directas) y `tracing-subscriber` +
`time`/macros (dev-deps ya presentes, sólo en tests).

## Decisiones de diseño (simetría con `consumer.rs`)

- **`trait ScanResultSink`** (`#[async_trait::async_trait]`, `Send + Sync`,
  dyn-compatible). Método único
  `publish(&self, outcome: &ScanOutcome) -> Result<(), PublishError>`. Modelo
  push, espejo del `next_request` pull del consumer.
- **`ScanOutcome`** unifica éxito y fallo en un tipo `Serialize`/`Deserialize`
  con `#[serde(tag = "status", rename_all = "snake_case")]`:
  - `Completed { correlation_id, result }` -> `{ "status": "completed",
    "correlation_id": "...", "result": {<ScanResult>} }`
  - `Failed { correlation_id, reason }` -> `{ "status": "failed",
    "correlation_id": "...", "reason": "..." }`
  - **Ambos casos llevan `correlation_id` aparte** porque `ScanResult` no lo
    transporta (vive en el `ScanRequest`); `ms-analisis` lo necesita para
    correlacionar tanto el éxito como el fallo. Formato documentado en el
    rustdoc del módulo porque es contrato con `ms-analisis`.
  - Constructores `ScanOutcome::completed(...)` / `::failed(...)`, accesores
    `correlation_id()` y `status_label()`.
- **`PublishError`** (`thiserror`, variantes distinguibles): `Transport(String)`
  (fallo al entregar al broker, suele ser transitorio) y `Serialization(String)`
  (bug de datos, no se resuelve reintentando). Sin genérico, sin panic.
- **`encode_outcome(&ScanOutcome) -> Result<Vec<u8>, PublishError>`**: produce el
  cuerpo JSON canónico; los adaptadores reales lo reutilizan para que el shape
  sea idéntico sea cual sea el broker. Error de `serde` -> `Serialization`.
- **`log_outcome_published(&ScanOutcome)`**: `tracing::info!` con `correlation_id`
  + `status` (+ recuentos de puertos/vulns en el caso de éxito). **Nunca** emite
  el `reason` del fallo ni el `ScanResult` completo. `pub` para que los
  adaptadores reales la reutilicen; el stub ya la llama al publicar. Espejo de
  `log_request_received` del consumer.
- **`InMemoryScanResultSink`** (stub): `Mutex<Vec<ScanOutcome>>`, `new()` +
  `Default`, `published() -> Vec<ScanOutcome>` para inspección en tests. Cada
  `publish` (1) serializa con `encode_outcome` (así `Serialization` es alcanzable
  igual que con un broker real), (2) traza vía `log_outcome_published`, (3)
  guarda copia. `Mutex` tolerante a poison, sin `.await` con el lock tomado.

## Seguridad

- El `reason` de `Failed` es un `String` ya formateado por el llamador (feature
  10) a partir del `Display` del error tipado de la etapa que falló. Los
  `Display` de `SshError`/`ScanError`/etc. ya redactan credenciales (tests de
  features 4/5 lo cubren), así que `err.to_string()` es seguro. El publisher no
  inspecciona ni enriquece el `reason`. Contrato documentado en el rustdoc del
  módulo y en `ScanOutcome::Failed::reason`.
- `log_outcome_published` no vuelca `reason` ni `ScanResult` — test lo verifica.

## Corrección post-review

- Doc: el ejemplo JSON del rustdoc usaba `...Z`; ajustado a `+00:00` para
  coincidir con la salida real de `time::serde::rfc3339`.
- **Flakiness eliminada**: el test de logging original instalaba un
  `tracing_subscriber` global vía `with_default` y capturaba la traza por un
  `MakeWriter` en memoria — misma técnica que el test análogo de `consumer.rs`.
  Al correr en paralelo, la caché global de interés de `tracing` tiene una
  carrera conocida y el evento se descartaba de forma no determinista
  (`./init.sh` en rojo intermitente).
  - Fix: se extrajo la construcción de los campos de log a una función pura
    privada `outcome_log_fields(&ScanOutcome) -> OutcomeLogFields<'_>`
    (`correlation_id`, `status`, `counts: Option<(usize, usize)>`).
    `log_outcome_published` la usa; los tests testean **esa función pura**, sin
    `tracing` ni subscriber global. No se añadió ninguna dependencia
    (`serial_test` descartado). El contrato de seguridad queda además reforzado:
    `OutcomeLogFields` es estructuralmente incapaz de contener el `reason` o el
    `ScanResult`.
  - Verificado: `./init.sh` 5/5 verde (exit 0) + `cargo test --lib` 10/10 verde.

## Tests (`#[cfg(test)] mod tests` en el módulo) — 10, todos verdes

- `completed_outcome_serializes_to_expected_message_shape`: shape concreto —
  `status=="completed"`, `correlation_id`, `result.host`, `result.ports[0].port`
  / `protocol` / `state` / `service`, `result.ports[1].state`,
  `result.vulnerabilities[0].id` / `severity`, `scanned_at` RFC 3339, sin
  `reason`. (criterio explícito de acceptance)
- `failed_outcome_serializes_with_correlation_id_and_reason`: `status=="failed"`,
  `correlation_id`, `reason`, sin `result`.
- `outcome_json_round_trip_preserves_every_field`: `Completed` y `Failed`.
- `encode_outcome_produces_parseable_json_bytes`.
- `correlation_id_accessor_works_for_both_variants`.
- `in_memory_sink_records_published_success_and_failure_in_order`: el stub
  registra éxito y fallo, inspeccionables y en orden.
- `failed_reason_is_stored_verbatim_from_the_caller`: contrato de `reason`.
- `log_fields_for_a_failure_expose_only_correlation_id_and_status`: `outcome_log_fields`
  para `Failed` -> `correlation_id`, `status == "failed"`, `counts == None`
  (sin forma estructural de llevar el `reason`).
- `log_fields_for_a_success_carry_counts_not_the_result`: para `Completed` ->
  `counts == Some((2, 1))`, nunca el `ScanResult`.
- `log_outcome_published_does_not_panic_for_either_variant`.

## Verificación

`./init.sh` -> `[OK] Entorno listo`, exit 0, **5/5 ejecuciones seguidas**
(flakiness resuelta). `cargo test` 75 unit verdes (65 previos + 10 nuevos),
10/10 ejecuciones. Regresión features 1-8: unit + integración (`--ignored`,
Docker: repository/scanner/ssh) verdes. `cargo fmt --check`, `cargo clippy
--all-targets -- -D warnings`, `cargo doc --no-deps` limpios.

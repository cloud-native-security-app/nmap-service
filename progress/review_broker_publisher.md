# Review — feature 9 (broker_publisher)

**Veredicto:** APPROVED

Revisado contra `docs/architecture.md`, `docs/conventions.md`,
`docs/verification.md`, `docs/security-scope.md`, `CHECKPOINTS.md` y los 3
criterios de `acceptance` de la feature 9.

## Criterios de aceptación de la feature 9

### Criterio 1 — trait `ScanResultSink` desacoplado del broker + stub inspeccionable
**CUMPLE.**
- `src/messaging/publisher.rs:200` define `pub trait ScanResultSink: Send + Sync`
  con `#[async_trait::async_trait]`, método único
  `async fn publish(&self, outcome: &ScanOutcome) -> Result<(), PublishError>`.
- El trait NO menciona ninguna lib de broker. Los únicos `use` del módulo son
  `std::sync::Mutex`, `serde`, `serde_json` (en `encode_outcome`), `tracing` y
  `crate::domain`. Ningún cliente RabbitMQ/NATS/Kafka/Redis. La tecnología
  concreta se documenta como "aún sin decidir" (módulo doc, líneas 4-8), acorde
  con `docs/architecture.md` §"Decisiones de diseño".
- `InMemoryScanResultSink` (`publisher.rs:223`): `Mutex<Vec<ScanOutcome>>`, con
  `new()` + `Default` + `published() -> Vec<ScanOutcome>` para inspección en
  tests. `publish` serializa (para exponer `Serialization` como en un broker
  real), traza y guarda copia; sin `.await` con el lock tomado; tolerante a
  poison.
- Es dyn-compatible (`Arc<dyn ScanResultSink>`), igual que `ScanRequestSource`.

### Criterio 2 — se publica éxito y fallo (con motivo del error)
**CUMPLE.**
- `ScanOutcome` (`publisher.rs:72`) `#[serde(tag = "status", rename_all = "snake_case")]`
  con dos variantes:
  - `Completed { correlation_id: CorrelationId, result: ScanResult }`
  - `Failed { correlation_id: CorrelationId, reason: String }`
- El caso de fallo lleva `correlation_id` **y** `reason`. `correlation_id` va
  aparte en ambas variantes porque `ScanResult` no lo transporta (vive en el
  `ScanRequest`); decisión correcta y documentada para que `ms-analisis` pueda
  correlacionar también los fallos.
- `reason` es `String` provisto por el llamador (`ScanOutcome::failed(_, impl Into<String>)`,
  `publisher.rs:105`). El módulo no lo inspecciona ni lo enriquece. Contrato de
  seguridad documentado (módulo doc §Seguridad, líneas 46-54 y doc de
  `Failed::reason`): el llamador formatea a partir del `Display` del error
  tipado de cada capa, que ya redacta credenciales (verificado por tests de
  features 4/5). El publisher no vuelca credenciales.
- `log_outcome_published` (`publisher.rs:173`) solo emite `correlation_id`,
  `status` y recuentos de puertos/vulns; nunca el `reason` ni el `ScanResult`.
  Test `log_outcome_published_records_correlation_id_and_status_only` lo verifica
  con un subscriber a buffer (comprueba que "super-secreto" NO aparece).

### Criterio 3 — test unitario: serialización al formato de mensaje esperado
**CUMPLE (y excede el mínimo).**
- `completed_outcome_serializes_to_expected_message_shape` comprueba shape
  concreto, no `is_ok()`: `status == "completed"`, `correlation_id`,
  `result.host`, `result.ports[0].port/protocol/state/service`,
  `result.ports[1].state`, `result.vulnerabilities[0].id/severity`,
  `result.scanned_at` empieza con RFC 3339, y ausencia de `reason`.
- `failed_outcome_serializes_with_correlation_id_and_reason` cubre el caso de
  fallo serializado: `status == "failed"`, `correlation_id`, `reason` textual, y
  ausencia de `result`.
- Adicionales: round-trip `Completed`+`Failed`, `encode_outcome` produce bytes
  JSON parseables, accesor `correlation_id()` en ambas variantes, stub registra
  éxito y fallo en orden, `reason` almacenado verbatim.
- 8 tests nuevos, todos verdes.

## Otras verificaciones

- **`./init.sh` -> exit 0** (`[OK] Entorno listo`). fmt + clippy
  (`--all-targets -- -D warnings`) + `cargo test` + `cargo test -- --ignored`
  (Docker) + `cargo doc --no-deps` todos verdes.
- **Recuento de tests:** lib 73 verdes (65 baseline + 8 nuevos). Integración
  Docker `--ignored`: repository 6, scanner 4, ssh 5 = 15 verdes. **Sin
  regresión** en features 1-8.
- **Simetría con `consumer.rs` (feature 8):** misma forma — `#[async_trait]`,
  `Send + Sync`, dyn-compatible, error `thiserror` propio por dirección.
  `PublishError { Transport(String), Serialization(String) }`: variantes
  distinguibles (transitorio vs. bug de datos), no genérico, sin panic. Encaja
  con `ConsumeError` del consumer. Los helpers `log_outcome_published` /
  `encode_outcome` reflejan `log_request_received` / `parse_scan_request`.
- **`src/messaging/mod.rs`:** el diff es únicamente docstring (quita la nota de
  "stub del scaffolding", enlaza los dos traits). Sin scope creep.
- **Sin scope creep:** `git diff` toca solo `src/messaging/publisher.rs`,
  `src/messaging/mod.rs` (docstring), `feature_list.json` (status
  pending->in_progress), `progress/`. `consumer.rs`, `src/lib.rs` (`run()`) y el
  resto de módulos intactos.
- **Sin deps nuevas:** `Cargo.toml`/`Cargo.lock` no aparecen en el diff. Se
  reutilizan serde, serde_json, async-trait, thiserror, tracing (deps directas) y
  time/macros + tracing-subscriber en tests.
- **Rustdoc:** todo ítem público documentado (`#![deny(missing_docs)]` +
  `cargo doc` limpio). El **formato del mensaje** que consumirá `ms-analisis`
  está documentado en el rustdoc del módulo (§"Formato del mensaje", con
  ejemplos JSON de ambos casos).
- **`unwrap()`/`expect()`/`panic!`:** solo en `#[cfg(test)]`. Código de
  producción del módulo sin panics.

## Checkpoints

- C1: [x] — arnés completo, `./init.sh` exit 0.
- C2: [x] — una sola feature `in_progress` (la 9); features `done` con tests que
  pasan; `progress/current.md` describe la sesión activa.
- C3: [x] — `src/` sin módulos nuevos (solo se rellena `messaging::publisher`);
  sin deps nuevas; sin `println!`/`dbg!`/`unwrap` fuera de tests; `cargo doc`
  sin warnings.
- C4: [~] — `cargo test` > 0 y verde; tests Docker (`testcontainers`) verdes;
  clippy limpio. **Observación (no bloqueante, no introducida por esta feature):**
  no existe `tests/messaging.rs`. La capa `messaging` hoy solo tiene stubs en
  memoria (no hay tecnología de broker que cruce IO real); el test de
  integración que ejercita `messaging` end-to-end está planificado explícitamente
  como feature 10 (`scan_pipeline_wiring`, nivel 4 de `docs/verification.md`).
  Feature 8 se cerró bajo el mismo criterio. Registrar para no perderlo al
  cerrar la feature 10.
- C5: [x] (al cerrar) — feature reflejada como `in_progress` durante el trabajo;
  el líder debe pasar la 9 a `done` y añadir la entrada en `progress/history.md`
  tras esta aprobación.

## Cambios requeridos

Ninguno. Feature aprobada.

## Nota menor (opcional, no bloquea)

El ejemplo JSON del rustdoc del módulo muestra `"scanned_at": "2026-08-27T12:30:00Z"`.
La serialización real vía `time::serde::rfc3339` emite el offset como `+00:00`,
no `Z`. El test solo valida el prefijo, así que no hay bug; conviene ajustar el
ejemplo del doc para que coincida con el contrato exacto que verá `ms-analisis`.

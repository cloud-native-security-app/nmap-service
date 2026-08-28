# Review — feature 8 (broker_consumer)

**Veredicto:** APPROVED

Revisor estricto. Evaluado contra `docs/architecture.md`, `docs/conventions.md`,
`docs/verification.md`, `docs/security-scope.md`, `CHECKPOINTS.md`.

## Archivos modificados desde la última sesión

- `src/messaging/consumer.rs` — reescrito (era stub `//!`). +468 líneas.
- `feature_list.json` — feature 8 `pending` -> `in_progress` (único cambio).
- `progress/current.md`, `progress/impl_broker_consumer.md` — bitácora/informe.

Sin scope creep: `publisher.rs`, `messaging/mod.rs`, `lib.rs`, `Cargo.toml` y el
resto de módulos intactos. Verificado con `git diff HEAD --stat`.

## init.sh

`./init.sh` -> exit 0, `[OK] Entorno listo`.

- `cargo fmt --check`: sin diferencias.
- `cargo clippy --all-targets -- -D warnings`: sin warnings.
- `cargo test` (unit): **65 passed / 0 failed** (9 nuevos en `messaging::consumer::tests`).
- `cargo test -- --ignored` (Docker/testcontainers): repository 6, scanner 4, ssh 5 =
  **15 passed / 0 failed**. Sin regresión en features 4-5-7.
- `cargo doc --no-deps`: sin errores (`#![deny(missing_docs)]` satisfecho).

## Checkpoints

- C1: [x] — 4 archivos base y 4 docs presentes; `./init.sh` exit 0.
- C2: [x] — una sola feature `in_progress` (id 8); features `done` con tests verdes;
  `progress/current.md` describe la sesión activa.
- C3: [x] — `src/` sólo contiene los módulos previstos (`messaging/consumer.rs` es
  parte de `messaging`). Sin deps nuevas en `Cargo.toml` (no se tocó). Sin
  `println!`/`dbg!`/`todo!`; todos los `unwrap`/`expect`/`panic!` están dentro de
  `#[cfg(test)] mod tests`. `cargo doc` limpio: rustdoc en `ConsumeError` (+ 3
  variantes), `parse_scan_request`, `log_request_received`, `IncomingScanRequest`
  (+ campo `request` + `new`), `ScanRequestSource` (+ `next_request`),
  `InMemoryScanRequestSource` (+ `from_requests` + `from_raw_messages`).
- C4: [x] — `cargo clippy` limpio; `cargo test` > 0 y todo verde. Nota: no hay
  `tests/messaging.rs` de integración, pero es correcto: la tecnología de broker
  está sin decidir (`docs/architecture.md`), no hay adaptador real que cruce IO
  ni contenedor contra el que probar, y la acceptance de la feature 8 exige
  explícitamente sólo tests unitarios. El test de integración de `messaging`
  llega con el adaptador real / `scan_pipeline_wiring`.
- C5: [x] — sin archivos temporales sospechosos (`progress/impl_broker_consumer.md`
  es el informe legítimo). El cierre de sesión (mover a `history.md`, vaciar
  `current.md`, marcar `done`) queda para el leader tras esta aprobación.

## Criterios de acceptance (feature 8), uno a uno

### 1. Trait `ScanRequestSource` desacoplado de la tecnología del broker + stub

APROBADO.

- `trait ScanRequestSource: Send + Sync` con método único
  `async fn next_request(&self) -> Result<Option<IncomingScanRequest>, ConsumeError>`.
  No menciona RabbitMQ/NATS/Kafka/Redis ni ningún tipo de una lib de broker. El
  único acoplamiento externo es `async_trait` (ya era dependencia directa) y
  tipos propios (`IncomingScanRequest`, `ConsumeError`).
- `IncomingScanRequest` (`#[non_exhaustive]`, campo `pub request: ScanRequest`)
  es punto de extensión documentado para un token de ack/nack futuro sin romper
  la firma del trait.
- `ConsumeError::Transport(String)` modela el fallo de broker con un `String`
  genérico, sin filtrar tipos concretos.
- `InMemoryScanRequestSource` presente y usable: `from_requests` (solicitudes ya
  validadas) y `from_raw_messages` (parsea cada cuerpo al construir). Cola FIFO
  tras `Mutex`, tolerante a poison, sin `.await` con el lock tomado. Es
  dyn-compatible (`Arc<dyn ScanRequestSource>`), documentado.
- Decisión de modelo (pull `next_request` vs callback) y ausencia de ack/nack
  documentadas en `progress/impl_broker_consumer.md`.

### 2. Mensajes malformados/incompletos -> error explícito, sin tumbar el proceso

APROBADO.

- `parse_scan_request(raw: &[u8]) -> Result<ScanRequest, ConsumeError>` en dos
  etapas: `serde_json::from_slice` a `Value` (fallo -> `MalformedPayload`), luego
  `from_value` a `ScanRequest` (fallo -> `InvalidSchema`). Sin `unwrap`/`expect`/
  `panic!` en el camino de producción.
- `ConsumeError` con `thiserror`, 3 variantes distinguibles y no genéricas:
  `MalformedPayload` / `InvalidSchema` / `Transport`, cada una con `#[error(...)]`.
- Tests: (a) `syntactically_broken_json_is_malformed_payload` — JSON roto ->
  `MalformedPayload`; (b) `missing_required_field_is_invalid_schema` — falta `ip`
  -> `InvalidSchema` y `detail.contains("ip")`; además
  `non_utf8_garbage_is_rejected_without_panic` (bytes `0xff 0xfe 0x00 0x42`).

### 3. Log con `correlation_id`, sin credenciales en texto plano

APROBADO.

- `log_request_received(&ScanRequest)` -> `tracing::info!` con campos explícitos
  `correlation_id`, `network_user`, `target_ip`, `has_sudo`. No emite
  `ssh_credentials_ref` ni el `ScanRequest` completo ni el cuerpo crudo.
- Los mensajes de `ConsumeError` no incluyen el payload crudo: `MalformedPayload`
  lleva sólo `serde_json::Error::to_string()` (posición del fallo, no contenido);
  `InvalidSchema` pasa por `redact_credential`, que sustituye el valor de
  `ssh_credentials_ref` por `[REDACTED]` por si `serde` lo incluyó en un
  "invalid type: ...".
- Tests: `log_request_received_records_correlation_id_without_credential`
  (subscriber a buffer en memoria: la línea contiene `corr-42`, no contiene el
  secreto ni la cadena `REDACTED`), `malformed_payload_error_does_not_echo_body`,
  `invalid_schema_error_redacts_credential_with_unexpected_type` (credencial como
  número: `9081726354` no aparece en el error).
- Refuerzo del dominio: `SshCredentialsRef` ya redacta en `Debug`/`Display`/
  `Serialize`, así que un `tracing::debug!(?request)` accidental tampoco filtraría.

### 4. Tests unitarios: válido -> `ScanRequest` (campos concretos); inválido -> rechazado

APROBADO.

- `valid_message_parses_into_scan_request` comprueba campos concretos, no
  `is_ok()`: `correlation_id == "corr-42"`, `ip == 203.0.113.7`, `has_sudo`,
  `network_user == "netops"`, `requested_by == "analyst@example.test"`,
  `ssh_credentials_ref.expose() == SECRET`.
- Rechazo cubierto por 4 tests (JSON roto, no-UTF8, campo ausente, tipo
  inesperado en la credencial) + el path de `InMemoryScanRequestSource`
  (`in_memory_source_from_raw_yields_error_then_continues`: un mensaje envenenado
  se entrega como `Err` y no interrumpe los siguientes).

## Observaciones no bloqueantes (para futuras iteraciones, NO condicionan la aprobación)

1. `redact_credential` hace `String::replace` del valor de la credencial sobre el
   mensaje de error de `serde`. Para una credencial de 1-2 caracteres (p. ej.
   `"a"`) esto podría corromper el texto del mensaje (`"expected a string"` ->
   `"expected [REDACTED] string"`). No es una fuga de seguridad y las
   `ssh_credentials_ref` reales no son tan cortas; anotar si en el futuro se
   endurece.
2. `serde_json::from_value::<ScanRequest>(payload.clone())` clona el `Value`
   completo para poder reusarlo en `redact_credential`. Coste menor; aceptable.
3. Falta test de integración `tests/messaging.rs` (C4 / `docs/verification.md`
   nivel 3 lista `messaging`). Correcto de diferir hasta que exista un adaptador
   real de broker; conviene que el leader lo deje explícito en la feature 9/10 o
   en una nota de `docs/`.

## Cambios requeridos

Ninguno. Feature 8 lista para marcar `done`.

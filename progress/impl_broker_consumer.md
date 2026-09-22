# Feature 8 — broker_consumer

Estado: implementada + `./init.sh` verde (unit + integración Docker + fmt +
clippy + doc). Pendiente de review y de marcar `done`.

## Archivos tocados

- `src/messaging/consumer.rs` — reescrito (era stub `//!`).
- `feature_list.json` — feature 8 `pending` -> `in_progress`.
- `progress/current.md` — plan y bitácora.

Sin dependencias nuevas en `Cargo.toml` (se reutilizan `serde_json`,
`async-trait`, `thiserror`, `tracing`; `tracing-subscriber` sólo en el test de
logging, ya era dependencia directa).

## Decisiones de diseño

- **`trait ScanRequestSource`** (async vía `async-trait`, `Send + Sync`,
  dyn-compatible). Método único `next_request(&self) -> Result<Option<IncomingScanRequest>, ConsumeError>`:
  `Ok(Some)` = solicitud válida, `Ok(None)` = stream cerrado, `Err` = mensaje
  ilegible (no fatal) o fallo de transporte. Modelo pull, el más simple para que
  el pipeline de la feature 10 haga el bucle.
- **`IncomingScanRequest`**: wrapper `#[non_exhaustive]` sobre `ScanRequest` con
  campo `pub request`. Hoy no hay token de ack/nack (broker sin decidir); el
  wrapper existe como punto de extensión para añadirlo sin romper la firma del
  trait.
- **`parse_scan_request(raw: &[u8]) -> Result<ScanRequest, ConsumeError>`** en
  dos etapas: `from_slice` a `serde_json::Value` (fallo -> `MalformedPayload`),
  luego `from_value` a `ScanRequest` (fallo -> `InvalidSchema`). Nunca
  `panic`/`unwrap`; basura binaria y no-UTF8 devuelven `Err` tipado.
- **`ConsumeError`** (`thiserror`, mensajes `#[error(...)]`): `MalformedPayload`
  (JSON roto), `InvalidSchema` (campo ausente o tipo incorrecto), `Transport`
  (fallo del broker).
- **Seguridad de credenciales en errores**: el payload crudo nunca entra al
  error. Los errores de sintaxis de `serde_json` sólo llevan posición. Para el
  caso en que `ssh_credentials_ref` llegue con un tipo inesperado (p. ej. un
  número) y `serde` lo incluya en su texto "invalid type: ...", `redact_credential`
  sustituye ese valor por `[REDACTED]` antes de construir `InvalidSchema`.
- **Logging**: `log_request_received(&ScanRequest)` emite `tracing::info!` con
  `correlation_id`, `network_user`, `target_ip`, `has_sudo` — campos explícitos,
  nunca `ssh_credentials_ref` ni el `ScanRequest` entero. `pub` para que los
  adaptadores reales la reutilicen; el stub ya la llama al entregar.
- **`InMemoryScanRequestSource`** (stub): cola FIFO tras `Mutex` (tolerante a
  poison, sin `.await` con el lock tomado). `from_requests` (solicitudes ya
  validadas) y `from_raw_messages` (parsea cada cuerpo al construir). Un mensaje
  inválido se entrega como `Err(ConsumeError)` en su turno y **no** interrumpe
  la entrega de los siguientes — el parseo es responsabilidad de la fuente, no
  del llamador (documentado en el rustdoc del tipo).

## Tests (`#[cfg(test)] mod tests` en el módulo) — 9, todos verdes

- `valid_message_parses_into_scan_request`: JSON completo -> campos concretos
  (correlation_id, ip, has_sudo, network_user, requested_by, credencial expuesta).
- `syntactically_broken_json_is_malformed_payload`.
- `non_utf8_garbage_is_rejected_without_panic`.
- `missing_required_field_is_invalid_schema` (sin `ip`) — tipado, sin panic.
- `malformed_payload_error_does_not_echo_body` — la credencial no aparece en el
  error.
- `invalid_schema_error_redacts_credential_with_unexpected_type` — credencial
  como número: no aparece en el error.
- `in_memory_source_delivers_in_order_then_none`.
- `in_memory_source_from_raw_yields_error_then_continues`.
- `log_request_received_records_correlation_id_without_credential` — subscriber a
  buffer en memoria: la línea lleva `corr-42` y no lleva la credencial.

## Verificación

`./init.sh` -> `[OK] Entorno listo`. Regresión features 1-7: unit + tests de
integración (`--ignored`, Docker) verdes. `cargo fmt --check`, `cargo clippy
--all-targets -- -D warnings`, `cargo doc --no-deps` limpios.

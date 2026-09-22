# Research: patrones de puertos `*Source` y convenciones de dominio/errores

> Escrito por el leader a partir de los hallazgos del explorer (agente Explore,
> sin permiso de escritura) para la feature 16 (`scan_cancellation`).

## 1. `ScanRequestSource` trait — `src/messaging/consumer.rs:160-173`

```rust
#[async_trait::async_trait]
pub trait ScanRequestSource: Send + Sync {
    async fn next_request(&self) -> Result<Option<IncomingScanRequest>, ConsumeError>;
}
```

- Usa `#[async_trait::async_trait]` (atributo totalmente cualificado).
- `Send + Sync`, dyn-compatible: doc comment dice explícitamente que se comparte
  como `Arc<dyn ScanRequestSource>`.
- Devuelve `Result<Option<IncomingScanRequest>, ConsumeError>` — envuelve el tipo
  de dominio en un wrapper local `IncomingScanRequest`, no `ScanRequest` directo.

`IncomingScanRequest` (consumer.rs:139-151):
```rust
#[derive(Debug)]
#[non_exhaustive]
pub struct IncomingScanRequest {
    pub request: ScanRequest,
}

impl IncomingScanRequest {
    pub fn new(request: ScanRequest) -> Self {
        Self { request }
    }
}
```
`#[non_exhaustive]`: punto de extensión documentado para un futuro token de ack/nack.

## 2. `InMemoryScanRequestSource` — consumer.rs:189-244

```rust
pub struct InMemoryScanRequestSource {
    queue: Mutex<VecDeque<Result<ScanRequest, ConsumeError>>>,
}

impl InMemoryScanRequestSource {
    pub fn from_requests<I>(requests: I) -> Self
    where I: IntoIterator<Item = ScanRequest>,
    { Self { queue: Mutex::new(requests.into_iter().map(Ok).collect()) } }

    pub fn from_raw_messages<I>(messages: I) -> Self
    where I: IntoIterator, I::Item: AsRef<[u8]>,
    {
        Self {
            queue: Mutex::new(
                messages.into_iter().map(|raw| parse_scan_request(raw.as_ref())).collect(),
            ),
        }
    }

    fn dequeue(&self) -> Option<Result<ScanRequest, ConsumeError>> {
        match self.queue.lock() {
            Ok(mut guard) => guard.pop_front(),
            Err(poisoned) => poisoned.into_inner().pop_front(),
        }
    }
}

#[async_trait::async_trait]
impl ScanRequestSource for InMemoryScanRequestSource {
    async fn next_request(&self) -> Result<Option<IncomingScanRequest>, ConsumeError> {
        match self.dequeue() {
            None => Ok(None),
            Some(Err(err)) => Err(err),
            Some(Ok(request)) => {
                log_request_received(&request);
                Ok(Some(IncomingScanRequest::new(request)))
            }
        }
    }
}
```

- `from_requests`: toma `ScanRequest` ya válidos, los envuelve en `Ok`.
- `from_raw_messages`: toma bytes crudos (`AsRef<[u8]>`), corre cada uno por
  `parse_scan_request` **al construir**, y guarda el `Result<ScanRequest, ConsumeError>`
  por slot; un mensaje malformado queda como `Err(ConsumeError)` guardado que se
  entrega en su turno sin interrumpir las entregas siguientes (test
  `in_memory_source_from_raw_yields_error_then_continues`, consumer.rs:388-409).
- `std::sync::Mutex<VecDeque<...>>` (no el de tokio), con manejo explícito de
  poison (`Err(poisoned) => poisoned.into_inner()`), nunca `.unwrap()/.expect()`
  sobre el lock.

**Patrón a replicar** para `InMemoryScanCancellationSource`: mismos dos
constructores (`from_cancellations`/`from_raw_messages` o equivalente), mismo
`Mutex<VecDeque<Result<...>>>` con manejo de poison, mismo estilo de logging al
entregar.

## 3. `ConsumeError` — consumer.rs:43-59, y decisión fatal/no-fatal en `pipeline.rs`

```rust
#[derive(Debug, thiserror::Error)]
pub enum ConsumeError {
    #[error("el mensaje del Broker no es JSON válido: {0}")]
    MalformedPayload(String),

    #[error("el mensaje del Broker no tiene la forma de un ScanRequest: {0}")]
    InvalidSchema(String),

    #[error("fallo de transporte con el Broker: {0}")]
    Transport(String),
}
```

- No fatal (se descarta/loggea, el loop continúa): `MalformedPayload`, `InvalidSchema`.
- Fatal (el loop se detiene): `Transport`.

Decisión implementada en el helper privado `next_valid_request` (pipeline.rs:267-290),
usado por `ScanPipeline::run` (pipeline.rs:251-264):

```rust
async fn next_valid_request(source: &dyn ScanRequestSource) -> Option<ScanRequest> {
    loop {
        match source.next_request().await {
            Ok(Some(incoming)) => return Some(incoming.request),
            Ok(None) => return None,
            Err(err @ (ConsumeError::MalformedPayload(_) | ConsumeError::InvalidSchema(_))) => {
                tracing::warn!(error = %err, "solicitud del Broker descartada; se continúa");
            }
            Err(err @ ConsumeError::Transport(_)) => {
                tracing::error!(
                    error = %err,
                    "fallo de transporte con el Broker; se detiene el consumo"
                );
                return None;
            }
        }
    }
}
```

**Patrón a replicar** para `ScanCancellationSource`: un helper equivalente
(`next_valid_cancellation` o loop inline en la nueva tarea del bucle de
cancelaciones) que hace `tracing::warn!` + continúa en `MalformedPayload`/
`InvalidSchema`, y `tracing::error!` + detiene en `Transport`. `run()` usa un
`JoinSet<()>` (pipeline.rs:252) para las tareas concurrentes de solicitudes — el
acceptance de la feature 16 pide explícitamente "mismo JoinSet/tokio::spawn que
el de solicitudes" para el segundo bucle de cancelaciones.

## 4. `domain.rs` — derives, naming JSON, `CorrelationId`

`CorrelationId` (domain.rs:27-59) — newtype sobre `String`, serde transparente:
```rust
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(transparent)]
pub struct CorrelationId(String);

impl CorrelationId {
    pub fn new(value: impl Into<String>) -> Self { Self(value.into()) }
    pub fn as_str(&self) -> &str { &self.0 }
}

impl fmt::Display for CorrelationId { /* f.write_str(&self.0) */ }
impl From<String> for CorrelationId { fn from(value: String) -> Self { Self(value) } }
impl From<&str> for CorrelationId { fn from(value: &str) -> Self { Self(value.to_owned()) } }
```
`#[serde(transparent)]`: (de)serializa como string JSON plano, no `{"0": "..."}`.

`ScanRequest` (domain.rs:133-156):
```rust
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ScanRequest {
    pub correlation_id: CorrelationId,
    pub ip: IpAddr,
    pub network_user: String,
    pub ssh_credentials_ref: SshCredentialsRef,
    pub has_sudo: bool,
    pub requested_by: String,
}
```
Sin `#[serde(rename)]` en ningún campo — los nombres de campo Rust ya son
`snake_case`, así que el default de serde ya coincide con el wire schema
(confirmado por el fixture JSON de consumer.rs:259-271, que usa
`correlation_id`, `ip`, `network_user`, `ssh_credentials_ref`, `has_sudo`,
`requested_by` literal). Los enums usan `#[serde(rename_all = "lowercase")]` o
`"snake_case"` (p. ej. `Protocol` en domain.rs:159-166, `VulnSource` en
domain.rs:238-249) — no aplica a un struct plano como `ScanCancellation`.

**Tipo exacto a añadir** (coincide con el `feature_list.json` id 16 y con el
naming default de serde, sin `rename_all`/`rename`):
```rust
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ScanCancellation {
    pub correlation_id: CorrelationId,
    pub requested_by: String,
}
```
Nota: no existe `contracts/scan-cancellation.schema.json` en este repo (vive en
el repo hermano `broker`, no presente en este checkout) — no hay nada bajo este
repo que matchee `*scan-cancellation*` ni `*.schema.json`. El implementer debe
construir el tipo a partir de la descripción textual del acceptance
(`{correlation_id, requested_by}`), no de un schema real disponible aquí.

## 5. Logging al recibir un mensaje — consumer.rs:111-130

```rust
/// Registra en `tracing` (nivel `INFO`) la recepción de una solicitud,
/// identificándola por su `correlation_id`.
/// ...
/// # Seguridad
/// Sólo emite campos no sensibles (`correlation_id`, `network_user`, IP objetivo
/// y `has_sudo`). Nunca registra `ssh_credentials_ref` ni el cuerpo crudo del
/// mensaje (ver `docs/security-scope.md`).
pub fn log_request_received(request: &ScanRequest) {
    tracing::info!(
        correlation_id = %request.correlation_id,
        network_user = %request.network_user,
        target_ip = %request.ip,
        has_sudo = request.has_sudo,
        "solicitud de escaneo recibida del Broker"
    );
}
```

**Patrón a replicar** para `log_cancellation_received(cancellation: &ScanCancellation)`:
función libre `pub fn` (no un método), llamada desde el `next_*` del source en
memoria justo antes de envolver/devolver, `tracing::info!` con campos
estructurados `%`-displayed (`correlation_id = %..., requested_by = %...`),
mensaje en español, sin volcar el payload crudo. Hay un test dedicado que
verifica que el log contiene el campo identificador pero nunca el secreto
(consumer.rs:439-465, `log_request_received_records_correlation_id_without_credential`)
— para la cancelación no hay secreto que redactar, pero debería existir un test
equivalente que verifique presencia de `correlation_id` y ausencia del cuerpo
crudo.

## 6. Reglas de estilo/estructura relevantes (`docs/conventions.md`, `docs/architecture.md`)

- **Manejo de errores explícito y tipado por módulo**: enums basados en
  `thiserror`, nunca `String`/`Box<dyn Error>` en el tipo de retorno de una API
  pública; `anyhow` queda confinado a `main.rs`/bordes del proceso
  (conventions.md:16-18, architecture.md:172-174). `ConsumeError` para
  `ScanCancellationSource` debe seguir exactamente la misma forma/semántica que
  el de `ScanRequestSource` (reutilizado, no reinventado — el acceptance de la
  feature 16 dice explícitamente "mismo contrato de errores").
- **Nunca `unwrap()`/`expect()`/`panic!()`** fuera de tests, salvo caso
  verdaderamente irrecuperable y documentado con un comentario `//` explicando
  por qué (conventions.md:19-21); los locks usan `match` a prueba de poison, no
  `.unwrap()` (ver `InMemoryScanRequestSource::dequeue`).
- **Puertos (traits) vs adaptadores**: los traits viven en el módulo de la capa
  que abstraen (p. ej. `ScanRequestSource`/`ScanResultSink` en `messaging`,
  `RemoteExecutor`/`HostKeyStore` en `ssh`), son `#[async_trait::async_trait]` +
  `Send + Sync` + dyn-compatible, inyectados como campos `Arc<dyn Trait>`
  agrupados en `pipeline::ServicePorts`; el **único** lugar que nombra
  adaptadores concretos es el composition root `src/wiring.rs` + `src/main.rs`
  (architecture.md:51-77, 130-140). El nuevo trait `ScanCancellationSource` va en
  `messaging::consumer` (o submódulo) igual que `ScanRequestSource`; su
  adaptador de producción real (broker aún sin decidir) no se implementa aún,
  reflejando el mismo patrón de fila "pendiente" que ya existe en
  architecture.md:56-66.
- **Estructura de módulo**: doc `//!` primero, luego bloque `use std`, línea en
  blanco, bloque de crates externos, línea en blanco, bloque `crate::...`
  (agrupación forzada por rustfmt), conventions.md:49-65.
- **Naming**: módulos/archivos `snake_case`, tipos/traits `PascalCase`,
  funciones/variables `snake_case`, constantes `UPPER_SNAKE` (conventions.md:39-47).
- **Tests sin Docker vs con Docker**: unitarios en `#[cfg(test)] mod tests` al
  final del mismo archivo fuente (ven ítems privados vía `use super::*`);
  integración con IO real (SSH/Mongo via `testcontainers`) bajo `tests/`,
  marcados `#[ignore = "requiere Docker"]` para que `cargo test` normal quede
  rápido/sin Docker, mientras `cargo test -- --ignored` (corrido por `init.sh`)
  ejercita los de Docker (conventions.md:30-37, 67-81). El acceptance de la
  feature 16 sigue exactamente este split: tests unitarios del registro de
  tokens sin Docker, y un test de integración `#[ignore = "requiere Docker"]`
  reutilizando el patrón sshd de `tests/scan_pipeline.rs`.
- **Rustdoc obligatorio** en todo ítem público (`pub fn`/`struct`/`enum`/`trait`),
  forzado por `#![deny(missing_docs)]` en `src/lib.rs` (conventions.md:22-29);
  comentarios evitados por defecto, solo para el "por qué" no obvio
  (conventions.md:101-105).
- **Disciplina async**: runtime tokio, sin llamadas bloqueantes en una tarea
  async sin `spawn_blocking` (conventions.md:13-15, architecture.md:215-216) —
  relevante porque la cancelación debe usar `tokio::select!`/`CancellationToken`
  (async-nativo), no primitivas bloqueantes.
- **Sin capas nuevas sin razón documentada** en `feature_list.json`
  (architecture.md:142-143) — el registro/mecánica de cancelación debe vivir
  dentro de los módulos existentes `pipeline`/`messaging`, no un módulo nuevo de
  alto nivel, salvo que se justifique.

## 7. Cargo.toml — `async-trait` y `tokio-util`

`async-trait` ya es dependencia directa:
```
async-trait = "0.1"
```
(línea 28 de `[dependencies]`.)

`tokio-util` **no** es dependencia directa en `Cargo.toml` — solo aparece
transitivamente en `Cargo.lock` (versión `0.7.19`, traída por otras deps como
`mongodb`/el árbol de `reqwest`; aparece como dependencia de al menos 3 paquetes
en `Cargo.lock`, p. ej. líneas 242, 1164, 2008, 3503). El acceptance de la
feature 16 exige explícitamente añadirla directa: `tokio-util` con feature
`sync` (para `CancellationToken`), p. ej.:
```
tokio-util = { version = "0.7", features = ["sync"] }
```
aunque el crate ya esté vendored transitivamente — no es usable directamente
desde `src/` sin declararla como dependencia directa. El implementer debe
justificar esto en su informe (`progress/impl_scan_cancellation.md`), tal como
pide el acceptance ("se justifica en el informe").

# Research: mecánica de concurrencia de `ScanPipeline`

> Escrito por el leader a partir de los hallazgos del explorer (agente Explore,
> sin permiso de escritura) para la feature 16 (`scan_cancellation`).

## 1. Estructura de `ScanPipeline` hoy

`src/pipeline.rs:89-97`:
```rust
#[derive(Clone)]
pub struct ScanPipeline {
    executor: Arc<dyn RemoteExecutor>,
    scanner: Arc<dyn NmapScanner>,
    repository: Arc<dyn ScanResultRepository>,
    enricher: Arc<dyn VulnEnricher>,
    host_key_store: Arc<dyn HostKeyStore>,
    sink: Arc<dyn ScanResultSink>,
    config: PipelineConfig,
}
```
Se construye vía `ScanPipeline::new(ports: ServicePorts, config: PipelineConfig)`
(`src/pipeline.rs:107-117`), constructor posicional de 2 argumentos.
`ServicePorts` (`src/pipeline.rs:44-68`) agrupa los 6 puertos, todos
`Arc<dyn _>`. `PipelineConfig` (`src/pipeline.rs:72-81`) trae `ssh_port`,
`ssh_timeouts`, `scan_options`. `ScanPipeline` es `#[derive(Clone)]`: barato de
clonar porque todo es `Arc` o `Copy`/pequeño; `run` clona una copia por tarea
(`src/pipeline.rs:255`).

## 2. Cómo funciona `ScanPipeline::run()` hoy

`src/pipeline.rs:251-264`:
```rust
pub async fn run(&self, source: Arc<dyn ScanRequestSource>) {
    let mut tasks: JoinSet<()> = JoinSet::new();

    while let Some(request) = next_valid_request(source.as_ref()).await {
        let pipeline = self.clone();
        tasks.spawn(async move { pipeline.process_one(request).await });
    }

    while let Some(joined) = tasks.join_next().await {
        if let Err(err) = joined {
            tracing::error!(error = %err, "una tarea de escaneo no terminó limpiamente");
        }
    }
}
```
Usa `tokio::task::JoinSet<()>` (import en `src/pipeline.rs:26`), no
`tokio::spawn` suelto. Un solo bucle secuencial: consume solicitudes una a una
de `source`, y por cada una `tasks.spawn(...)` con el pipeline clonado — el
spawn no bloquea, así que las tareas corren concurrentemente mientras el loop
sigue pidiendo la siguiente. Al agotarse la fuente (`next_valid_request`
devuelve `None`), entra en un segundo bucle `while let Some(joined) =
tasks.join_next().await` que drena todas las tareas en vuelo antes de
retornar. **No hay hoy ningún registro de tareas por `correlation_id`** — el
`JoinSet` es anónimo, no indexado.

## 3. Cómo se invoca `process_one` desde `run()`

`src/pipeline.rs:255-256`:
```rust
let pipeline = self.clone();
tasks.spawn(async move { pipeline.process_one(request).await });
```
Recibe solo `request: ScanRequest` (por valor, movido al closure). No recibe
`sink` explícito porque ya está en `self.sink` (clonado junto con todo lo demás
al hacer `pipeline.clone()`). Firma pública: `pub async fn process_one(&self,
request: ScanRequest)` (`src/pipeline.rs:133`), sin retorno (`()`) — todo se
publica internamente vía `self.sink.publish(...)`.

## 4. Forma de `run_stages` y puntos de espera async

`run_stages` (`src/pipeline.rs:183-233`, privado):
```rust
async fn run_stages(&self, request: &ScanRequest) -> Result<ScanResult, String>
```
Secuencia y sus `.await` (en orden):
1. `self.executor.connect(...).await` — SSH connect (`src/pipeline.rs:184-195`), `map_err(...)?`.
2. `self.scanner.run_scan(session.as_ref(), ...).await` — ejecución de nmap (`src/pipeline.rs:197-206`), `map_err(...)?`.
3. `parser::parse(&xml)` — **síncrono**, sin `.await` (`src/pipeline.rs:208`).
4. `self.enricher.enrich(&result.ports).await` — enriquecimiento, best-effort con `unwrap_or_else` en vez de `?` (`src/pipeline.rs:213-224`), nunca se propaga como error de etapa.
5. `self.repository.save(&result, &request.correlation_id).await` — persistencia Mongo (`src/pipeline.rs:227-230`), `map_err(...)?`.

4 puntos `.await` en total (connect, run_scan, enrich, save). El diseño más
natural para insertar cancelación cooperativa es envolver **toda la llamada a
`run_stages`** en un `tokio::select!` contra el `CancellationToken`, en
`process_one`, justo donde hoy está `let outcome = match
self.run_stages(&request).await { ... }` (`src/pipeline.rs:153`). Esto evita
reescribir `run_stages` etapa por etapa — el `select!` corta el future en
cuanto el runtime le devuelve control, que ocurrirá en el próximo `.await`
pendiente dentro de esa función. Para que el test e2e pueda cancelar "a mitad
de camino" basta con que la etapa nmap sea lo bastante lenta (ver punto 8); no
hace falta tocar la firma de `run_stages`.

## 5. Uso existente de `tokio_util` / `CancellationToken`

```
$ grep -rn "tokio_util\|CancellationToken" --include="*.rs" src tests
(sin resultados)
```
Ningún uso hoy. En `Cargo.toml` no aparece `tokio-util` como dependencia
directa — solo `tokio = { version = "1", features = ["rt-multi-thread",
"macros", "time", "net"] }`. En `Cargo.lock` sí existe transitivamente
(`tokio-util 0.7.19`, arrastrada probablemente por `mongodb`/`russh`/`reqwest`).
**Hay que añadirla explícitamente** a `[dependencies]` con la feature `sync`
(Cargo no permite usar una dependencia transitiva de terceros sin declararla):
```
tokio-util = { version = "0.7", features = ["sync"] }
```
fijando la misma versión mayor que ya resuelve el lockfile (0.7.x).

## 6. Cómo `run()` consume la fuente de solicitudes

```rust
// run() — src/pipeline.rs:254
while let Some(request) = next_valid_request(source.as_ref()).await {
```
```rust
// helper — src/pipeline.rs:273-290
async fn next_valid_request(source: &dyn ScanRequestSource) -> Option<ScanRequest> {
    loop {
        match source.next_request().await {
            Ok(Some(incoming)) => return Some(incoming.request),
            Ok(None) => return None,
            Err(err @ (ConsumeError::MalformedPayload(_) | ConsumeError::InvalidSchema(_))) => {
                tracing::warn!(error = %err, "solicitud del Broker descartada; se continúa");
            }
            Err(err @ ConsumeError::Transport(_)) => {
                tracing::error!(error = %err, "fallo de transporte con el Broker; se detiene el consumo");
                return None;
            }
        }
    }
}
```
Un `while let Some(x) = helper(source).await` donde el helper hace `loop {
match source.next_request().await { ... } }`, absorbiendo mensajes malformados
con `warn!` y continuando, terminando en `Ok(None)` o `Transport`. Para
`ScanCancellationSource`, replicar exactamente esta forma: un
`next_valid_cancellation(source: &dyn ScanCancellationSource) -> Option<ScanCancellation>`
con el mismo `loop`+`match`, y un segundo bucle `while let Some(cancellation) =
next_valid_cancellation(cancel_source.as_ref()).await { ... }` corriendo
concurrentemente al de solicitudes (dos tareas en paralelo dentro de `run`,
p. ej. con `tokio::join!` o spawneando el bucle de cancelaciones como tarea
adicional — ambos streams son independientes y no deben bloquearse entre sí).

## 7. Composition root y cómo inyectar el nuevo puerto

Composition root real en `src/wiring.rs`, función
`service_ports_from_config(config: &Config) -> Result<ServicePorts, WiringError>`
(`src/wiring.rs:81-131`). El pegamento final está en `src/main.rs:32`
(`run(ports, pipeline_config, None).await;`) y en `src/lib.rs:43-58`:
```rust
pub async fn run(
    ports: ServicePorts,
    config: PipelineConfig,
    source: Option<Arc<dyn ScanRequestSource>>,
) {
    let pipeline = ScanPipeline::new(ports, config);
    match source {
        Some(source) => pipeline.run(source).await,
        None => tracing::warn!(...),
    }
}
```
No hay patrón builder — todo posicional. Para añadir la fuente de
cancelaciones sin más ceremonia que la que ya usa el crate:

- Añadir un parámetro más a la función libre `run()` de `src/lib.rs`:
  `cancellations: Option<Arc<dyn ScanCancellationSource>>` (junto al `source`
  existente). Rompe la firma, pero el único llamador real es `main.rs` y los
  tests e2e llaman a `pipeline.run(source)` directamente — el crate es un
  binario interno sin compromiso semver, así que romper esta firma es
  aceptable y coherente con cómo ya se hizo antes.
- `ScanPipeline::run` pasa a `pub async fn run(&self, source: Arc<dyn
  ScanRequestSource>, cancellations: Arc<dyn ScanCancellationSource>)` — rompe
  los 3 call-sites de `tests/scan_pipeline.rs` (líneas ~247, 380, 456), que
  habrá que actualizar pasando un `InMemoryScanCancellationSource` vacío/stub
  en cada uno donde no se necesite cancelar nada.
- `ScanCancellationSource` **no** debería vivir dentro de `ServicePorts`: el
  acceptance lo describe como un stream paralelo, simétrico a
  `ScanRequestSource` (que tampoco vive en `ServicePorts`, se pasa aparte a
  `run`) — no como un puerto más del pipeline propiamente.

No existe ningún builder pattern en el crate (`Config::from_env()`,
`ServicePorts { .. }`/`PipelineConfig { .. }` con struct literal) — mantener
parámetros posicionales/struct-literal es lo coherente con el resto del código.

## 8. Patrones de test para simular latencia / tareas lentas

**Unitarios en `src/pipeline.rs` (sin Docker):** no hay hoy ningún test que
simule latencia. Los dobles de prueba (`FailingExecutor`, `UnusedScanner`,
`UnusedRepository`, `StubEnricher`, `FlakySink`, `src/pipeline.rs:514-529` y
alrededores) responden instantáneamente. El único `Duration` en tests es para
`SshTimeouts` en `test_config()` (`src/pipeline.rs:582-591`), no para simular
lentitud.

**E2E en `tests/scan_pipeline.rs` (con Docker, `#[ignore = "requiere Docker"]`):**
tampoco hay mecanismo de latencia artificial. El stub de nmap (`fake_nmap()`,
`tests/scan_pipeline.rs:51-55`) es instantáneo:
```rust
fn fake_nmap() -> Vec<u8> {
    format!("#!/bin/sh\ncat <<'NMAP_STUB_EOF'\n{STUB_XML}\nNMAP_STUB_EOF\n").into_bytes()
}
```
`cat` de heredoc que vuelca el XML fijo de inmediato — sin `sleep`. El test de
concurrencia (`multiple_requests_are_processed_concurrently`,
`tests/scan_pipeline.rs:422-527`) prueba 3 solicitudes en paralelo pero no
depende de que cada una tarde.

**Implicación para el test e2e de la feature 16:** no hay patrón reutilizable
de "tarea lenta" — hay que crearlo. Forma más directa, siguiendo el estilo de
`fake_nmap()`: un stub que duerma antes de imprimir el XML:
```rust
fn slow_fake_nmap(delay_secs: u64) -> Vec<u8> {
    format!("#!/bin/sh\nsleep {delay_secs}\ncat <<'NMAP_STUB_EOF'\n{STUB_XML}\nNMAP_STUB_EOF\n").into_bytes()
}
```
copiado a `NMAP_PATH` igual que `start_target(&[(NMAP_PATH, fake_nmap())])`
(`tests/scan_pipeline.rs:80-113`, ya soporta un array arbitrario de
`(path, contents)` vía `with_copy_to` + `chmod 0755`), de forma que el `.await`
de `self.scanner.run_scan(...)` en `run_stages` quede bloqueado el tiempo
suficiente (p. ej. `sleep 10`/`sleep 30`) para que el test publique una
`ScanCancellation` con el mismo `correlation_id` mientras la tarea sigue en el
`JoinSet`, y verifique que el `select!` corta antes de que el `sleep` termine y
se publique `ScanOutcome::failed(correlation_id, "escaneo cancelado por
solicitud explícita")` en vez de `ScanOutcome::Completed`.

## Otros datos relevantes

- `ScanOutcome::failed(correlation_id: CorrelationId, reason: impl Into<String>) -> Self`
  está en `src/messaging/publisher.rs:133` — firma ya lista para el mensaje de
  cancelación pedido.
- `ScanRequestSource` (`src/messaging/consumer.rs:161-173`) es `#[async_trait]`,
  `Send + Sync`, dyn-compatible — plantilla exacta a replicar para
  `ScanCancellationSource`.
- Cargo.toml tiene `async-trait = "0.1"` (reutilizable para el nuevo trait) y
  `tokio` sin la feature `sync`; el acceptance sugiere un registro
  `Arc<Mutex<HashMap<CorrelationId, CancellationToken>>>` con
  `std::sync::Mutex` (coherente con el uso ya visto en
  `InMemoryScanRequestSource` y en los tests de `pipeline.rs`), así que no
  haría falta `tokio::sync::Mutex` ni la feature `sync` de tokio para esto —
  solo `tokio-util` con su propia feature `sync` para `CancellationToken`.

**Rutas citadas:** `src/pipeline.rs`, `src/wiring.rs`,
`src/messaging/consumer.rs`, `src/messaging/publisher.rs`, `src/lib.rs`,
`src/main.rs`, `tests/scan_pipeline.rs`, `Cargo.toml`, `Cargo.lock`,
`feature_list.json`.

# Implementación — feature 17: `broker_adapter`

> Escrito por el implementer. La feature queda en `feature_list.json` con
> `status: "in_progress"`: el líder debe lanzar un `reviewer` antes de marcarla
> `done`.

## Qué se implementó

Adaptador real de RabbitMQ para los tres puertos de mensajería que hasta ahora
solo tenían stubs en memoria. El patrón es el de `gateway::broker`
(`gateway/src/broker.rs` + `gateway/progress/explore_lapin_publish.md` +
`explore_lapin_testcontainers.md`), no uno inventado: `lapin` 2.x sobre AMQPS,
runtime tokio vía `tokio-executor-trait`/`tokio-reactor-trait`, TLS con el
almacén nativo en producción (`OwnedTLSConfig::default()`) y CA de laboratorio
en los tests (`OwnedTLSConfig::cert_chain`).

- `Cargo.toml` (+ `Cargo.lock`): `lapin` (`default-features = false, features
  = ["rustls"]`), `tokio-executor-trait = "2"`, `tokio-reactor-trait = "1"`,
  `futures-util = "0.3"` (para `Consumer::next()` en producción) y `rustls =
  "0.23"` como dev-dependency (gotcha de doble-proveedor criptográfico). Las
  verificaciones en `Cargo.lock` muestran que el binario de test arrastra tanto
  `ring` como `aws-lc-rs` (`bollard`/`testcontainers` traen el segundo), así que
  `install_crypto_provider_once` en los tests es **necesario**, no meramente
  defensivo.
- `src/config.rs`: nueva variable requerida `MS_NMAP_BROKER_VHOST` (el
  endpoint no incluía vhost; el vhost vive en `Config::broker_vhost`). La
  doc de `Config::broker_endpoint` fija la forma esperada (`esquema://host:puerto`,
  sin userinfo ni vhost). Tests unitarios nuevos de var faltante/vacía.
- `src/messaging/rabbitmq.rs` (nuevo): 
  - `RabbitMqScanRequestSource` (`ScanRequestSource`): consume
    `ms-nmap.scan-requests` (exchange `scan.requests`, routing key
    `scan.request`). Mensaje malformado -> `nack(requeue: false)` (dead-letter
    automático a la `.dlq` ya aprovisionada por `definitions.json`, con
    `x-delivery-limit`) y se sigue consumiendo, no es fatal. Mensaje válido ->
    `ack` antes de devolver al pipeline.
  - `RabbitMqScanCancellationSource` (`ScanCancellationSource`): mismo patrón
    sobre `ms-nmap.scan-cancellations`.
  - `RabbitMqScanResultSink` (`ScanResultSink`): publica en `scan.outcomes`
    con `confirm_select` activo; la routing key se deriva por `match`
    exhaustivo sobre el `status` (`scan.outcome.started/completed/failed`). Sin
    `confirm_select` no pueden convivir la garantía del Broker y el criterio de
    aceptación "publicar sin confirmación de RabbitMQ".
  - `connect_channel` compartido (URI AMQPS construida con usuario fijo
    `ms-nmap` + credencial + vhost), `BrokerError` (variantes
    `ConnectionFailed`/`SetupFailed`), helpers `build_amqps_uri`/`strip_scheme`
    con sus tests unitarios (la URI **siempre** es `amqps://`, se ignora el
    esquema recibido — el servicio nunca habla AMQP en claro).
  - No se declara topología: las colas/exchanges son del `broker` (usuario
    `ms-nmap` tiene `configure: "^$"`). Solo `basic_consume`/`basic_publish`.
- `src/messaging/publisher.rs`: nueva variante `PublishError::NotAcknowledged`,
  distinta de `PublishError::Transport` (el nack real del Broker vs. fallo de
  transporte).
- `src/wiring.rs`: `service_ports_from_config` ahora construye los tres
  adaptadores reales desde `Config` (trust nativo, sin CA custom) y devuelve
  `(ServicePorts, Arc<dyn ScanRequestSource>, Arc<dyn ScanCancellationSource>)`;
  nuevo `WiringError::Broker` (fallo de arranque -> proceso termina limpio,
  mismo criterio que `WiringError::Mongo`). `src/main.rs` deja de pasar
  `None, None`.
- `rabbitmq/`: copia literal (fuente de verdad `broker/rabbitmq/`, repo
  hermano, solo lectura, mismo patrón que usó `gateway`) de
  `definitions.json`, `rabbitmq.conf` y `tls/*.pem`.
- `tests/broker_adapter.rs` (nuevo, `#[ignore = "requiere Docker"]`
  testcontainers con `rabbitmq:4.3.5-management` real y la topología real):
  1. `scan_request_source_delivers_a_scan_request_published_by_the_gateway`
  2. `scan_request_source_dead_letters_a_malformed_message_and_keeps_consuming`
     (poison message -> DLQ, el consumo sigue con el mensaje válido posterior)
  3. `scan_cancellation_source_delivers_a_cancellation_published_by_the_gateway`
  4. `scan_result_sink_publishes_each_status_with_its_exact_contract_routing_key`
  5. `published_scan_request_ends_in_a_published_completed_outcome_through_real_adapters`
     (smoke e2e del criterio "opcional pero deseable": RabbitMQ + sshd + Mongo
     reales, los 3 adaptadores reales + repos reales en `ServicePorts`,
     ScanRequest publicado externamente termina en un `ScanOutcome::completed`
     publicado en `scan.outcomes` con la routing key correcta, y el resultado
     queda persistido en Mongo; sin stubs en memoria).

## Decisiones de diseño

- **Ack inmediato en `next_request`/`next_cancellation`**: el `Delivery` se
  ackea antes de devolver al pipeline. Justificado en la doc del módulo: el
  pipeline no tiene ningún punto de espera async entre recibir el valor y
  pasarlo a `tokio::spawn`, así que devolver `Ok(Some(_))` es el instante en
  que la solicitud queda encolada en el pipeline.
- **Usuario RabbitMQ fijo `ms-nmap`**: es parte del contrato de la topología
  (unique usuario con los permisos read/write correctos), no una credencial;
  la contraseña sí viaja por separado en `Config::broker_credential` y solo se
  usa al construir la URI dentro de una función privada.
- **Tres conexiones AMQPS separadas** (source/cancallations/sink): mismo
  enfoque que `gateway`, aislamiento de canales por puerto.
- **Credenciales**: ninguna contraseña aparece en `BrokerError`,
  `ConsumeError` ni `PublishError` (envuelven el `Display` de `lapin::Error`,
  que no incluye la URI completa). Test unitario de forma de `build_amqps_uri`
  comprueba que la contraseña aparece exactamente una vez.

## Consistencia de docs (in-repo y raíz)

- In-repo, `docs/architecture.md`: la tecnología del broker pasa de "aún sin
  confirmar" a RabbitMQ/AMQPS confirmada; la tabla de puertos/adversarios
  reemplaza los "pendiente: broker sin decidir" por los adaptadores reales; las
  capas 8 (messaging) y 10 (wiring) describen el submódulo `rabbitmq` y
  `WiringError::Broker`.
- In-repo, `README.md`: fila nueva `MS_NMAP_BROKER_VHOST`, descripción
  actualizada de `MS_NMAP_BROKER_ENDPOINT` (forma `esquema://host:puerto`,
  AMQPS forzado) y ejemplo de `docker run` con la var nueva.
- Raíz `security-app` (archivos **no versionados**): `docker-compose.yml`
  (bloque `nmap-service`: endpoint `amqps://rabbitmq:5671`, `BROKER_VHOST`,
  monta la CA de laboratorio y fija `SSL_CERT_FILE` — el cert lab es
  autofirmado y el trust store nativo no lo acepta) y `START.md` (sección 2 y
  "Huecos conocidos" #2: el contenedor ya no termina solo; queda consumiendo).

## Verificación

- `cargo build` limpio; `cargo test`: **143 tests unitarios verdes** en 3
  corridas completas (hubo 2 fallos en la **primera** ejecución, ambos de
  `enrichment::nvd` con wiremock, reproducibles por el proceso compartido de
  wiremock 0.6 bajo paralelismo; pasan en aislamiento y en todas las corridas
  siguientes — flakiness preexistente de la feature 14, no introducido ni
  tocado aquí).
- `tests/broker_adapter.rs`: 5/5 verdes (aislado y en paralelo, 2 corridas del
  archivo completo sin flakiness).
- `./init.sh` verde **3 veces consecutivas** (incluye fmt `--check`, clippy
  `--all-targets -- -D warnings`, tests unitarios, todos los `#[ignore]` con
  Docker, y `cargo doc` con `missing_docs`).
- `cargo fmt --check` sin diferencias; `cargo clippy --all-targets -- -D
  warnings` sin warnings.

## Sin regresión

Features 1-16 intactas: solo se tocó lo listado arriba; los tests previos
(ssh, scanner, parseo, mongo, pipeline e2e, cancelación) siguen pasando dentro
de `./init.sh`.
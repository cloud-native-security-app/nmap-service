# Review — feature 17 (broker_adapter)

**Veredicto:** APPROVED

## Checkpoints
- C1: [x]
- C2: [x]
- C3: [x]
- C4: [x]
- C5: [x]

## Cambios requeridos (si aplica)

Ninguno.

## Detalle de la revisión

Ejecuté el protocolo de `.claude/agents/reviewer.md`: leí los 4 docs
(`architecture.md`, `conventions.md`, `security-scope.md`, `CHECKPOINTS.md`),
el informe del implementador (`progress/impl_broker_adapter.md`), el estado
(`git status`/`git diff`, `progress/current.md`), la fuente de verdad del
contrato (`broker/contracts/README.md` + `broker/rabbitmq/definitions.json`)
y el patrón de referencia (`gateway/src/broker.rs`).

### Lo que se revisó archivo por archivo

- **`src/messaging/rabbitmq.rs`** (nuevo): implementa los tres puertos de
  mensajería. Patrón idéntico al de `gateway::broker` que se cita como
  referencia (lapin 2.5.5, `ConnectionProperties` con
  `tokio-executor-trait`/`tokio-reactor-trait`, `OwnedTLSConfig::default()`
  en producción y `cert_chain` con la CA de laboratorio en tests,
  `confirm_select` solo en el canal del publicador, y sin declaración de
  topología — solo `basic_consume`/`basic_publish`, coherente con el
  permiso `configure: "^$"` del usuario `ms-nmap`). Respeta capas: solo
  `messaging` conoce la tecnología. Nombres/exchanges/colas/routing keys
  coinciden exactamente con `broker/rabbitmq/definitions.json`
  (`ms-nmap.scan-requests`, `ms-nmap.scan-cancellations`, `scan.outcomes`,
  `scan.outcome.started/completed/failed`). Sin `unwrap`/`panic!` en código
  de producción (todos están en `#[cfg(test)]`). Errores tipados
  (`BrokerError::ConnectionFailed/SetupFailed`, mapeo a
  `ConsumeError::Transport`, nueva `PublishError::NotAcknowledged`), sin
  credenciales en ningún Display — el test
  `build_amqps_uri_never_leaks_only_the_endpoint_without_the_password`
  (línea 631) comprueba que la contraseña aparece exactamente una vez.
  Mensaje malformado -> `nack(requeue: false)` y se sigue consumiendo
  (no es fatal), tal como exige el acceptance. `routing_key_for` es un
  `match` exhaustivo (línea 538) — una variante nueva de `ScanOutcome` deja
  de compilar en vez de enrutarse mal.
- **`src/config.rs`**: `MS_NMAP_BROKER_VHOST` requerida sin default
  (constante + doc + tests `missing_broker_vhost_var_yields_typed_missing_var_error`
  y `empty_broker_vhost_var_is_treated_as_missing`). Documenta la forma de
  `broker_endpoint` (`esquema://host:puerto`, sin userinfo/vhost).
- **`src/wiring.rs`**: composition root construye los 3 adaptadores reales y
  devuelve `(ServicePorts, Arc<dyn ScanRequestSource>, Arc<dyn ScanCancellationSource>)`;
  nuevo `WiringError::Broker(#[from] BrokerError)` — un Broker inaccesible al
  arrancar detiene el proceso limpio (mismo criterio que `WiringError::Mongo`),
  nunca `panic`. `src/main.rs` pasa `Some(source), Some(cancellations)`.
- **`src/messaging/publisher.rs`**: `PublishError::NotAcknowledged`
  (nack real del Broker, distinta de `Transport`).
- **`Cargo.toml`**: dependencias nuevas (lapin 2 con `rustls`,
  tokio-executor-trait, tokio-reactor-trait, futures-util, rustls dev)
  todas justificadas en comentarios que citan la feature y la referencia de
  `gateway`. `lapin` resuelve a 2.5.5 en `Cargo.lock` — la misma versión
  verificada en `gateway`.
- **`rabbitmq/`**: copia de `broker/rabbitmq/` (verificado con `diff -r`: los
  archivos comunes son idénticos; correctamente NO se copió `tls/ca_key.pem`,
  la clave privada de la CA de laboratorio).
- **`tests/broker_adapter.rs`** (nuevo): 5 tests `#[ignore = "requiere Docker"]`
  con RabbitMQ 4.3.5-management real + topología real + CA de laboratorio.
  Cubren los 3 adaptadores, el poison-message -> DLQ con consumo continuado,
  las 3 routing keys del contrato, y el smoke e2e con los 3 adaptadores +
  sshd + Mongo reales (todos los puertos reales, sin stubs en memoria).
  Mismo patrón de testcontainers que `tests/scan_pipeline.rs`.
- Contexto de seguridad: IPs de prueba reservadas (`192.0.2.x`,
  `198.51.100.x`), contenedores locales de laboratorio, credenciales
  `lab-only-*` — respeta `docs/security-scope.md`. No se escanea ningún
  objetivo real; no se declara topología (no se exige más permiso que el
  asignado); TOFU de host keys intacto.

### Ejecución de `./init.sh`

Corrió completo y **verde** durante esta revisión: `cargo fmt --check`,
`cargo clippy --all-targets -- -D warnings`, 143 tests unitarios (incluye los
nuevos de `config` y `rabbitmq`), y todos los `#[ignore]` de Docker: 5/5 de
`broker_adapter`, 11/11 de `repository`, 4/4 de `scan_pipeline`, 4/4 de
`scanner`, 5/5 de `ssh`. `cargo doc` sin errores (crate con
`#![deny(missing_docs)]`).

### Observaciones menores (no bloqueantes, fuera del acceptance)

1. `src/lib.rs:66-70`: el mensaje del branch `source == None` sigue
   diciendo "El adaptador de broker (ScanRequestSource real) aún no
   existe...". Es texto ya obsoleto tras la feature 17. No es alcanzable en
   producción (main siempre pasa `Some`) y no incumple ningún criterio del
   acceptance; conviene actualizarlo en una sesión futura.

### Conclusión

Feature completa según acceptance: adaptador real AMQPS para los 3 puertos,
wiring conectado, `WiringError::Broker` tipado (sin panic), tests de
integración reales con la topología del broker como fuente de verdad (incluye
el smoke e2e "opcional pero deseable"), `./init.sh` verde, sin regresión en
features 1-16. Queda en `in_progress` por protocolo: el líder la marca `done`
y cierra la sesión en `feature_list.json`/`progress/history.md`.
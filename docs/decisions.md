# Registro de decisiones (ADR)

> Decisiones técnicas relevantes de `ms-nmap`, destiladas del historial de
> implementación de las 18 funcionalidades originales. Cada entrada es breve:
> contexto, decisión y consecuencia. El detalle de diseño vigente está en
> `docs/architecture.md`; los límites de alcance, en `docs/security-scope.md`.

## Historial de funcionalidades

Todas completadas en la rama `develop`: scaffolding, config, domain_model,
ssh_client, nmap_execution, xml_parser, mongo_persistence, broker_consumer,
broker_publisher, scan_pipeline_wiring, hexagonal_ports, containerization,
vuln_enrichment, nvd_enrichment, scan_started_event, scan_cancellation,
broker_adapter y configurable_scan_timing.

## ADR-01 — Crate de biblioteca con `main.rs` delgado

- **Contexto:** los tests de integración en `tests/` compilan como crate
  externo y sólo ven la API pública de una biblioteca.
- **Decisión:** `src/lib.rs` expone los módulos como `pub` y activa
  `#![deny(missing_docs)]`; `src/main.rs` sólo inicializa runtime y `tracing`.
- **Consecuencia:** todo ítem público lleva rustdoc (`cargo doc` forma parte
  de `make verify`).

## ADR-02 — Cliente SSH: `russh` directo

- **Contexto:** hace falta acceso programático a la host key durante el
  handshake, con almacén de confianza propio (no `known_hosts` de archivo).
- **Decisión:** `russh` (async nativo sobre tokio, sin FFI). Su
  `Handler::check_server_key` rechaza por defecto, lo que encaja con TOFU.
  Backend criptográfico `ring` (`default-features = false`).
- **Consecuencia:** las variantes de `SshError` se mapean desde los errores
  finos de `russh` sin parsear texto.

## ADR-03 — `HostKeyStore` asíncrono y compartido

- **Contexto:** el trust store TOFU debe sobrevivir reinicios y compartirse
  entre réplicas, por lo que se respalda en MongoDB.
- **Decisión:** `HostKeyStore` pasa a ser un trait async con `&self`
  (mutabilidad interior) y se comparte como `Arc<dyn HostKeyStore>`, sin
  `Mutex` externo. Errores propios `HostKeyStoreError` (`Unavailable`,
  `Corrupt`), expuestos como `SshError::HostKeyStore`.
- **Consecuencia:** ante cualquier fallo del almacén o mismatch de
  fingerprint, `check_server_key` devuelve `false`: nunca se acepta una clave
  sin verificar.

## ADR-04 — Tests de integración con contenedores reales

- **Contexto:** `ssh`, `scanner` y `repository` cruzan IO real.
- **Decisión:** `testcontainers` (sshd para SSH/scanner, MongoDB oficial para
  repository), todos marcados `#[ignore = "requiere Docker"]` y ejecutados
  con `cargo test -- --ignored`. Los fixtures de XML de `nmap` son salida
  real.
- **Consecuencia:** no se sustituyen por mocks; sin Docker, el bloqueo se
  documenta en lugar de ocultarse.

## ADR-05 — Hexagonal completo con composition root único

- **Contexto:** cada frontera de IO debía poder sustituirse en tests de
  extremo a extremo.
- **Decisión:** puertos como traits dyn-compatible, inyectados vía
  `pipeline::ServicePorts`; sólo `src/wiring.rs` y `src/main.rs` nombran
  adaptadores concretos. `ssh::RemoteExecutor` (conectar) y
  `ssh::RemoteSession` (ejecutar) son traits separados.
- **Consecuencia:** el refactor se hizo después del pipeline, usando los
  tests end-to-end como red de seguridad.

## ADR-06 — Persistencia documental en MongoDB

- **Decisión:** driver oficial `mongodb`; los resultados de escaneo son
  documentos de estructura variable. Los tipos de dominio se serializan con
  cuidado de los gotchas de (de)serialización BSON.
- **Consecuencia:** se persisten resultados (`scan_results`), host keys y
  caché NVD (`nvd_cache`).

## ADR-07 — Enriquecimiento offline con Exploit-DB

- **Decisión:** sólo se empaqueta `files_exploits.csv` (pineado a un commit)
  y se indexa en memoria; no se instala `searchsploit` para no romper la
  imagen distroless. Sin egress de red.
- **Consecuencia:** detección pasiva, misma categoría que
  `nmap --script vuln` (ver `docs/security-scope.md`).

## ADR-08 — Enriquecimiento NVD opt-in

- **Decisión:** segundo adaptador `VulnEnricher`, consulta la API NVD 2.0 por
  CPE sólo si `MS_NMAP_NVD_ENRICHMENT_ENABLED=true`. Nunca envía la IP del
  objetivo, el `correlation_id` ni credenciales. El módulo se divide en
  `enrichment/{mod,exploitdb,nvd}.rs` para evitar archivos de más de 800
  líneas.
- **Consecuencia:** deshabilitado, no hay ninguna llamada de red hacia NVD.

## ADR-09 — Caché NVD con índice TTL sobre fecha BSON

- **Decisión:** `cached_at` es `bson::DateTime`, no cadena RFC 3339.
- **Consecuencia:** el índice TTL de MongoDB sólo expira documentos con un
  campo de fecha BSON real; con una cadena nunca expirarían.

## ADR-10 — Adaptador RabbitMQ (AMQPS) reutilizando el patrón de `gateway`

- **Decisión:** `lapin` 2.x con `rustls`, executor/reactor de tokio, TLS vía
  almacén nativo en producción y CA de laboratorio inyectada en tests. Usuario
  RabbitMQ fijo `ms-nmap` (parte del contrato de topología); la contraseña
  viaja aparte en `MS_NMAP_BROKER_CREDENTIAL`. Se conecta siempre por AMQPS
  (el esquema del endpoint se ignora). Tres conexiones separadas
  (solicitudes, cancelaciones, resultados).
- **Consecuencia:** ack inmediato al entregar al pipeline (no hay punto de
  espera async antes de `tokio::spawn`). En tests se instala el proveedor
  criptográfico de `rustls` una vez para evitar un cuelgue por doble
  proveedor.

## ADR-11 — Sin servidor HTTP

- **Decisión:** el servicio es un worker asíncrono puro, sin health ni
  readiness. Es explícito, no un olvido.
- **Consecuencia:** se puede añadir como funcionalidad independiente.

## ADR-12 — Verificación TTL en tests de repositorio

- **Decisión:** un test de integración consulta al servidor real que el índice
  `expireAfterSeconds` sobre `cached_at` se creó con el TTL configurado
  (`nvd_cache_store`).
- **Consecuencia:** el contrato del ADR-09 queda cubierto contra MongoDB real.

## ADR-13 — Eventos de ciclo de vida y cancelación

- **Decisión:** se publica un tercer `ScanOutcome` (`started`, routing key
  `scan.outcome.started`, consumido sólo por el Gateway) y se consumen
  cancelaciones (`{correlation_id, requested_by}`) con cancelación
  cooperativa mediante `tokio_util::sync::CancellationToken`. Los contratos
  los fija el repo `broker`.
- **Consecuencia:** un escaneo en curso puede abortarse sin matar el proceso.

## ADR-14 — Timing de `nmap` configurable, flags de detección fijos

- **Contexto:** el default `Timing::Polite` (`-T2`) es seguro pero lento con
  `--script vuln`.
- **Decisión:** `MS_NMAP_SCAN_TIMING` opcional (`polite|normal|aggressive`;
  otro valor es `ConfigError::InvalidValue`). Ausente equivale a `polite`.
  `detection_flags` (`-sV --script vuln`) no se vuelve configurable.
- **Consecuencia:** el despliegue puede acelerar escaneos de laboratorio sin
  cambiar el default seguro.

## ADR-15 — Imagen distroless multi-stage con bases pineadas

- **Decisión:** builder `rust` + stage `exploitdb` + runtime
  `gcr.io/distroless/cc-debian12:nonroot`, bases fijadas por tag y digest.
  Cacheo de dependencias con árbol de fuentes mínimo. `nmap` no está en la
  imagen (se ejecuta en el objetivo vía SSH).
- **Consecuencia:** la CA de laboratorio del Broker se hornea con un build
  context adicional `tls`; ver el plan `odd/tasks/ci-cd-deploy.md` para
  hacerla opcional en AWS.

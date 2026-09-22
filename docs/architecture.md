# Arquitectura — Qué significa "hacer un buen trabajo"

> Este documento define el estándar de calidad. Los agentes revisores
> evalúan código contra este archivo. Si no está aquí, no es un requisito.

## Alcance de este repo

Este repo implementa **únicamente `ms-nmap`**: recibe una solicitud de escaneo
(IP, usuario de red, credenciales/permisos), se conecta por SSH al objetivo,
ejecuta `nmap` ahí, interpreta el resultado y lo publica de vuelta hacia el
Broker. `ms-usuarios`, `ms-analisis` (el agente IA que redacta el informe), el
Gateway y el Broker en sí mismo son otros servicios — no se implementan aquí.

## Decisiones de diseño ya tomadas

- **SSH al objetivo, no escaneo local.** `ms-nmap` se conecta por SSH a la IP
  objetivo con el usuario de red dado y ejecuta `nmap` en esa máquina remota
  (no escanea la red desde su propio host).
- **Se usa el binario `nmap` real**, no una reimplementación en Rust. La
  detección de vulnerabilidades se apoya en scripts NSE (`--script vuln`), no
  en una base de CVEs propia.
- **Comunicación asíncrona vía cola de mensajes** con el Broker **RabbitMQ
  sobre AMQPS** (contrato fijado en el repo hermano `broker`:
  `subject/contracts/README.md` y `subject/rabbitmq/definitions.json`; la
  tecnología ya está decidida desde la feature `broker_adapter`, no es una
  decisión abierta). La capa de mensajería se aísla detrás de los traits
  `ScanRequestSource`, `ScanCancellationSource` y `ScanResultSink`: el resto
  del servicio no conoce la tecnología concreta del broker, sólo los
  adaptadores reales de `messaging::rabbitmq` (y el `wiring`).
- **Persistencia en MongoDB** (`db-nmap`) vía el driver oficial `mongodb`
  (async). Los resultados de escaneo son documentos de estructura variable
  (número de puertos/servicios/vulnerabilidades no es fijo), lo que encaja
  mejor con un modelo documental que con uno relacional.
- **`src/lib.rs` + `src/main.rs` delgado**, no un binario puro. Los tests de
  integración en `tests/` compilan como un crate externo: solo pueden ver la
  API pública de una *librería*, nunca los módulos internos de un binario.
  Como varias features exigen tests de integración contra `ssh`, `parser`,
  `repository`, etc., esos módulos deben ser `pub` en `src/lib.rs`, y
  `src/main.rs` se limita a inicializar el runtime/tracing y llamar a la lib.
- **Verificación de host key SSH por Trust On First Use (TOFU).** `ssh`
  define el trait `HostKeyStore`; la primera conexión a un host guarda su
  fingerprint, conexiones posteriores lo comparan y rechazan la conexión si
  cambió (posible MITM). El almacén persistente (Mongo) se implementa en
  `repository`, no en `ssh`, para que el trust store sobreviva reinicios y se
  comparta entre réplicas del servicio.
- **Privilegios de escaneo controlados por `ScanRequest.has_sudo`.** `nmap
  -O` (detección de SO) requiere root remoto; solo se intenta si la solicitud
  indica que el usuario de red tiene sudo, usando `sudo -n` (no interactivo,
  falla rápido en vez de colgarse esperando password).
- **Sin servidor HTTP por ahora.** El servicio es un worker asíncrono puro
  (consumer de Broker); no expone health/readiness ni ninguna otra ruta HTTP
  en esta ronda de features. Es una decisión explícita, no un olvido — se
  puede agregar como feature independiente más adelante sin tocar el resto.
- **Hexagonal completo (puertos y adaptadores).** Cada capa que cruza un
  límite de IO se expone como un **puerto** (trait dyn-compatible) con su
  **adaptador** de producción, y todos se inyectan en `lib::run()` agrupados en
  el struct `pipeline::ServicePorts`:

  | Puerto (trait)                     | Módulo        | Adaptador de producción         |
  |------------------------------------|---------------|---------------------------------|
  | `messaging::ScanRequestSource`     | `messaging`   | `messaging::rabbitmq::RabbitMqScanRequestSource` |
  | `messaging::ScanCancellationSource` | `messaging`  | `messaging::rabbitmq::RabbitMqScanCancellationSource` |
  | `messaging::ScanResultSink`        | `messaging`   | `messaging::rabbitmq::RabbitMqScanResultSink` |
  | `ssh::HostKeyStore`                | `ssh`         | `repository::MongoHostKeyStore`  |
  | `ssh::RemoteExecutor` (`connect`)  | `ssh`         | `ssh::RusshExecutor`             |
  | `ssh::RemoteSession` (`run_command`) | `ssh`       | `ssh::SshSession`               |
  | `scanner::NmapScanner`             | `scanner`     | `scanner::NmapCliScanner`        |
  | `enrichment::VulnEnricher`         | `enrichment`  | `enrichment::CompositeVulnEnricher` (con `enrichment::ExploitDbEnricher` siempre, y `enrichment::NvdApiEnricher` si el egress a NVD está habilitado) |
  | `enrichment::NvdCache`             | `enrichment`  | `repository::MongoNvdCache` (colección `nvd_cache`, TTL) |
  | `repository::ScanResultRepository` | `repository`  | `repository::MongoRepository`   |

  El **composition root** —el único sitio que nombra los adaptadores
  concretos— vive en `src/wiring.rs` (`wiring::service_ports_from_config`) y
  `src/main.rs`. `ssh`, `scanner` y `repository` conservan además sus funciones
  y métodos inherentes: los adaptadores son una capa fina encima y los tests de
  integración los siguen usando directamente. `ssh::RemoteExecutor` y
  `ssh::RemoteSession` se separaron en dos traits (conectar vs. ejecutar) para
  que el adaptador de sesión sea trivialmente `SshSession` y `scanner` dependa
  sólo de `&dyn RemoteSession`. Este patrón se completó en la feature
  `hexagonal_ports`, después de `scan_pipeline_wiring`, usando los tests
  end-to-end existentes como red de seguridad del refactor.

## Capas

1. **`config`** — carga de configuración desde variables de entorno (Mongo,
   broker, timeouts SSH, egress opt-in de NVD). Sin valores hardcodeados.
2. **`domain`** — tipos puros: `ScanRequest`, `ScanResult`, `PortFinding`,
   `VulnFinding`. Sin IO.
3. **`ssh`** — conexión SSH y ejecución de comandos remotos. Expone
   `SshSession` y `SshError` (variantes: auth, timeout, host inalcanzable).
4. **`scanner`** — orquesta la ejecución de `nmap` sobre una `SshSession` ya
   establecida y devuelve el XML crudo.
5. **`parser`** — convierte el XML de `nmap` en `ScanResult`. Sin IO, testeable
   con fixtures. Captura también los `<cpe>` de cada servicio en
   `PortFinding.cpes`.
6. **`enrichment` (`src/enrichment/`)** — etapa entre `parser` y `repository`:
   cruza el `service`+`version`/CPE de cada `PortFinding` contra bases de
   vulnerabilidades/exploits conocidos y añade `VulnFinding`s. Puerto
   `VulnEnricher` (dyn-compatible, `async`), definido en `enrichment::mod`
   junto con `CompositeVulnEnricher` y `EnrichError`. Dos adaptadores, cada uno
   en su submódulo:
   - `enrichment::exploitdb::ExploitDbEnricher` (`source: VulnSource::ExploitDb`):
     un **lookup local sin egress de red** sobre `files_exploits.csv` de
     Exploit-DB (bundleado en la imagen, ver "Despliegue"); su matcher es
     deliberadamente conservador.
   - `enrichment::nvd::NvdApiEnricher` (`source: VulnSource::Nvd`): consulta la
     API NVD 2.0 por CPE. **Egress de red opt-in**
     (`MS_NMAP_NVD_ENRICHMENT_ENABLED`, ver `docs/security-scope.md`), con caché
     persistente en Mongo con TTL (`enrichment::NvdCache`, adaptador real
     `repository::MongoNvdCache`) y rate limiting propio acorde a los límites de
     NVD (sin dependencias externas de limitador).

   `CompositeVulnEnricher` combina los adaptadores habilitados y es el punto de
   extensión para adaptadores de API futuros (Vulners, ...) sin tocar el
   pipeline. Es **best-effort**: un fallo se registra con `tracing::warn!` y el
   escaneo continúa con los hallazgos de `nmap` (nunca produce
   `ScanOutcome::Failed`); esto aplica tanto al composite (un enricher que falla
   no tumba a los demás) como, dentro de `NvdApiEnricher`, a un CPE individual
   (un CPE que falla no aborta los demás CPEs de la misma llamada). Los
   `VulnFinding` añadidos se deduplican por CVE contra los que ya trajo `nmap` y
   entre sí.
7. **`repository`** — persistencia del `ScanResult` en MongoDB, del trust store
   TOFU (`MongoHostKeyStore`) y de la caché de NVD con TTL (`MongoNvdCache`,
   colección `nvd_cache`, índice `expireAfterSeconds` sobre `cached_at`).
8. **`messaging`** — `consumer` (recibe `ScanRequest` y `ScanCancellation` del
   Broker) y `publisher` (envía `ScanOutcome`/`ScanResult` o error al Broker),
   cada uno detrás de un trait para no acoplar el resto del servicio a la
   tecnología del broker. El submódulo `rabbitmq` implementa los tres traits
   con `lapin` sobre AMQPS (`RabbitMqScanRequestSource`,
   `RabbitMqScanCancellationSource`, `RabbitMqScanResultSink`): TLS con el
   almacén de certificados nativo del proceso en producción, `confirm_select`
   en el canal del publicador (no se confirma un mensaje que el Broker no
   aceptó), y sin declarar topología (las colas/exchanges los declara el
   `broker`, ver "Qué NO hacer"). El patrón es el mismo que ya resolvió
   `gateway::broker`.
9. **`pipeline` (`src/pipeline.rs`)** — orquesta
   `consumer -> ssh -> scanner -> parser -> enrichment -> repository -> publisher`
   en `ScanPipeline`, construido a partir de los puertos inyectados
   (`ServicePorts` + `PipelineConfig`). Un fallo de etapa se publica como
   desenlace de error, nunca `panic` (excepción: `enrichment` es best-effort y
   no falla el escaneo).
10. **`wiring` (`src/wiring.rs`)** — composition root: construye los adaptadores
    reales de cada puerto desde la `Config` y los agrupa en `ServicePorts`. Si el
    CSV de Exploit-DB no carga, el servicio no arranca (`WiringError::Enrichment`).
    `NvdApiEnricher` sólo se construye (y por tanto sólo existe la posibilidad de
    egress hacia NVD) si `config.nvd_enrichment_enabled` es `true`. Conecta
    también los tres adaptadores de broker contra el Broker por AMQPS (almacén
    de certificados nativo del proceso, sin CA custom) y devuelve junto a los
    `ServicePorts` los adaptadores reales de `ScanRequestSource` y
    `ScanCancellationSource` para `lib::run`; un Broker inaccesible al arrancar
    detiene el proceso de forma limpia con `WiringError::Broker` (mismo
    criterio que `WiringError::Mongo`), nunca `panic`.
11. **`lib` (`src/lib.rs`)** — declara `pub mod` para cada capa anterior y
    expone `pub async fn run(ports, config, source)` que arma el `ScanPipeline`
    y lo pone a consumir.
12. **`main` (`src/main.rs`)** — envoltorio delgado: inicializa runtime tokio,
    tracing y config, llama a `wiring::service_ports_from_config` y a
    `lib::run(...)`. Sin lógica de negocio propia.

No introducir capas adicionales hasta que haya una razón concreta
documentada en `feature_list.json`.

## Flujo de datos

```
Broker  ──(ScanRequest)──▶  messaging::consumer
                                   │
                                   ▼
                        ssh::connect(ip, user, creds)
                                   │
                                   ▼
                    scanner::run_scan(session, ip)  →  XML crudo
                                   │
                                   ▼
                        parser::parse(xml)  →  ScanResult
                                   │
                                   ▼
           enrichment::VulnEnricher::enrich(&ports)  (best-effort)
                    →  + VulnFinding{source: exploit_db | nvd}, dedup por CVE
                       (nvd sólo si egress habilitado, ver security-scope.md)
                                   │
                        ┌──────────┴──────────┐
                        ▼                     ▼
             repository::save(result)   messaging::publisher
                  (MongoDB / db-nmap)     ──(ScanResult | error)──▶ Broker
```

## Manejo de errores

- Cada capa (`ssh`, `scanner`, `parser`, `repository`, `messaging`) define su
  propio tipo de error con variantes específicas (no un `String` genérico ni
  `Box<dyn Error>` como tipo de retorno de la API pública).
- Un fallo en cualquier etapa del pipeline se convierte en un mensaje de error
  publicado hacia el Broker — nunca en un panic ni en un proceso que muere en
  silencio.
- Las credenciales SSH nunca aparecen en logs, mensajes de error, ni en los
  documentos persistidos en texto plano (ver `docs/security-scope.md`).

## Despliegue

- El servicio se empaqueta con un `Dockerfile` multi-stage en la raíz (feature
  `containerization`):
  - **Stage builder** (`rust:1.98-bookworm`): compila `ms-nmap` en release, con
    una capa previa que cachea la compilación de dependencias.
  - **Stage exploitdb**: descarga `files_exploits.csv` de Exploit-DB, pineado a
    un commit concreto del repo `gitlab.com/exploit-database/exploitdb` (no
    `latest`/`main`). Sólo el CSV, no el CLI `searchsploit` (feature
    `vuln_enrichment`).
  - **Stage runtime** (`gcr.io/distroless/cc-debian12:nonroot`): contiene el
    binario `ms-nmap`, los certificados CA del sistema (TLS a MongoDB, al Broker
    y, si está habilitado, a la API NVD, todos vía `rustls`) y
    `files_exploits.csv` en `/opt/exploitdb/` (dato de sólo lectura para
    `enrichment`; la ruta se fija con `ENV MS_NMAP_EXPLOITDB_CSV`). Corre como
    usuario no-root (`nonroot`, uid 65532).
- La imagen final **no incluye**: la toolchain de Rust, el código fuente, shell
  ni coreutils, el CLI `searchsploit`, ni el binario `nmap`. `nmap` se ejecuta en
  la máquina objetivo vía SSH (ver "SSH al objetivo, no escaneo local"), no en el
  contenedor de `ms-nmap`. Tampoco lleva `openssh-client`: `russh` es Rust puro.
  El enriquecimiento de vulnerabilidades de Exploit-DB es un lookup en memoria
  sobre el CSV bundleado: **sin egress de red**. El enriquecimiento de NVD
  (`enrichment::nvd::NvdApiEnricher`) sí es egress de red, pero **opt-in**: sólo
  ocurre si el despliegue fija `MS_NMAP_NVD_ENRICHMENT_ENABLED=true` (ver
  `docs/security-scope.md`).
- Toda la configuración se inyecta por variables de entorno (ver `config` y
  `README.md`). Las imágenes base se fijan por tag concreto y por digest
  `@sha256:...` (nunca `latest`).
- `testcontainers` (tests de integración) es independiente del empaquetado: sólo
  levanta contenedores desechables de `sshd`/MongoDB para las pruebas.

## Qué NO hacer

- No reimplementar la lógica de escaneo de `nmap` en Rust.
- No hacer llamadas SSH bloqueantes dentro del runtime async sin
  `spawn_blocking` si la librería SSH elegida no es nativamente async.
- No acoplar `scanner`, `parser` ni `repository` a la tecnología concreta del
  broker — solo `messaging` puede conocerla.
- No escanear un objetivo que no venga acompañado de una solicitud válida y
  autorizada (ver `docs/security-scope.md`).

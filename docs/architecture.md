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
- **Comunicación asíncrona vía cola de mensajes** con el Broker (tecnología
  concreta — RabbitMQ/NATS/Kafka/Redis Streams — aún sin confirmar). Por eso
  la capa de mensajería se aísla detrás de los traits `ScanRequestSource` y
  `ScanResultSink`: el resto del servicio no debe conocer la tecnología
  concreta del broker.
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

## Capas

1. **`config`** — carga de configuración desde variables de entorno (Mongo,
   broker, timeouts SSH). Sin valores hardcodeados.
2. **`domain`** — tipos puros: `ScanRequest`, `ScanResult`, `PortFinding`,
   `VulnFinding`. Sin IO.
3. **`ssh`** — conexión SSH y ejecución de comandos remotos. Expone
   `SshSession` y `SshError` (variantes: auth, timeout, host inalcanzable).
4. **`scanner`** — orquesta la ejecución de `nmap` sobre una `SshSession` ya
   establecida y devuelve el XML crudo.
5. **`parser`** — convierte el XML de `nmap` en `ScanResult`. Sin IO, testeable
   con fixtures.
6. **`repository`** — persistencia del `ScanResult` en MongoDB.
7. **`messaging`** — `consumer` (recibe `ScanRequest` del Broker) y
   `publisher` (envía `ScanResult` o error al Broker), cada uno detrás de un
   trait para no acoplar el resto del servicio a la tecnología del broker.
8. **`lib` (`src/lib.rs`)** — declara `pub mod` para cada capa anterior y
   expone una función de arranque (p. ej. `pub async fn run(...)`) que conecta
   `consumer -> ssh -> scanner -> parser -> repository -> publisher`.
9. **`main` (`src/main.rs`)** — envoltorio delgado: inicializa runtime tokio,
   tracing y config, y llama a `lib::run(...)`. Sin lógica de negocio propia.

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

## Qué NO hacer

- No reimplementar la lógica de escaneo de `nmap` en Rust.
- No hacer llamadas SSH bloqueantes dentro del runtime async sin
  `spawn_blocking` si la librería SSH elegida no es nativamente async.
- No acoplar `scanner`, `parser` ni `repository` a la tecnología concreta del
  broker — solo `messaging` puede conocerla.
- No escanear un objetivo que no venga acompañado de una solicitud válida y
  autorizada (ver `docs/security-scope.md`).

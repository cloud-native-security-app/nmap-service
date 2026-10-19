# nmap-service

`ms-nmap`: microservicio de escaneo dentro de una plataforma de
ciberseguridad blue/red team. Recibe una solicitud de escaneo (IP, usuario de
red y permisos) a través del Broker, se conecta por SSH al objetivo, ejecuta
`nmap` para detectar puertos abiertos, servicios, versiones y
vulnerabilidades, persiste el resultado en MongoDB (`db-nmap`) y lo publica
de vuelta hacia el Broker para que otro servicio (`ms-analisis`) genere el
informe final con IA.

Este repo implementa **únicamente** `ms-nmap`. `ms-usuarios`, `ms-analisis`,
el Gateway y el Broker viven en otros repos.

Stack: Rust (async con `tokio`), persistencia en MongoDB, tests de
integración con `testcontainers`.

## Desarrollo

Documentación de referencia en `docs/`:

| Documento | Contenido |
|-----------|-----------|
| `docs/architecture.md` | Alcance del servicio, decisiones de diseño, capas y flujo de datos |
| `docs/conventions.md` | Estilo Rust, nombres y estructura de módulos |
| `docs/verification.md` | Niveles de verificación y tests de integración |
| `docs/security-scope.md` | Límites de autorización y alcance (SSH, credenciales, escaneo) |
| `docs/decisions.md` | Registro de decisiones técnicas (ADR) |

Antes de implementar algo que dispare escaneo activo, conexión SSH real o
manejo de credenciales, lee `docs/security-scope.md`.

### Verificación

```
make verify
```

Ejecuta, en orden: `cargo fmt --check`, `cargo clippy --all-targets -- -D
warnings`, `cargo test`, `cargo test -- --ignored` (tests de integración con
`testcontainers`, requieren Docker) y `cargo doc --no-deps`. Cada paso también
está disponible como target individual (`fmt-check`, `lint`, `test`,
`test-integration`, `doc`).

### Desarrollo asistido por IA

El trabajo asistido por IA usa [gentle-ai](https://github.com/Gentleman-Programming/gentle-ai):
cada funcionalidad sustancial se planifica en un documento ODD en
`odd/tasks/<feature>.md` (checklist, criterios de aceptación y evidencia de
verificación), espejado en la memoria persistente Engram bajo el tópico
`odd/<feature>/tasks`. Los commits siguen Conventional Commits.

## Despliegue (Docker)

El `Dockerfile` de la raíz produce una imagen multi-stage:

- **builder**: `rust:1.98-bookworm`, compila el binario `ms-nmap` en release.
- **exploitdb**: descarga `files_exploits.csv` de Exploit-DB, pineado a un
  commit concreto.
- **runtime**: `gcr.io/distroless/cc-debian12:nonroot`, contiene el binario
  `ms-nmap`, el CSV `files_exploits.csv` (dato de sólo lectura) y los
  certificados CA del sistema, y corre como usuario no-root (`nonroot`, uid
  65532).

La imagen final **no incluye**: la toolchain de Rust, el código fuente, shell
ni coreutils, el CLI `searchsploit`, ni el binario `nmap`. `nmap` se ejecuta en
la máquina objetivo vía SSH, no en este contenedor (ver `docs/architecture.md`).
El servicio es un worker asíncrono puro: **no expone ningún servidor ni puerto
HTTP**.

### Construir

```
docker build -t ms-nmap .
```

### Ejecutar

`ms-nmap` lee **toda** su configuración de variables de entorno. La mayoría son
obligatorias (si falta alguna, registra el error y termina sin arrancar); las
excepciones son `MS_NMAP_NVD_API_KEY` (genuinamente opcional) y
`MS_NMAP_NVD_CACHE_TTL_SECS` (obligatoria sólo si el enriquecimiento NVD está
habilitado):

| Variable | Descripción |
|----------|-------------|
| `MS_NMAP_MONGO_URI` | URI de conexión a MongoDB (`db-nmap`), p. ej. `mongodb://host:27017` |
| `MS_NMAP_MONGO_DB` | Nombre de la base de datos donde se persisten los resultados y el trust store SSH |
| `MS_NMAP_SSH_PORT` | Puerto SSH del objetivo al que conectarse (p. ej. `22`) |
| `MS_NMAP_BROKER_ENDPOINT` | Endpoint del Broker de mensajería del que se consumen solicitudes/cancelaciones y al que se publican desenlaces. Forma esperada: `esquema://host:puerto` (p. ej. `amqps://broker.lab:5671`), **sin** usuario ni vhost — `ms-nmap` conecta siempre por AMQPS (el esquema recibido se ignora), fija el usuario RabbitMQ del servicio (`ms-nmap`) y añade `MS_NMAP_BROKER_CREDENTIAL` y `MS_NMAP_BROKER_VHOST` |
| `MS_NMAP_BROKER_CREDENTIAL` | Contraseña del usuario RabbitMQ `ms-nmap` contra el Broker (secreto) |
| `MS_NMAP_BROKER_VHOST` | Vhost de RabbitMQ al que conectarse (p. ej. `security-app`), definido en la topología del Broker |
| `AWS_REGION` | Región AWS de SQS/SNS (p. ej. `us-east-1`). Obligatoria. Las credenciales salen de la cadena de proveedores por defecto de AWS (rol de la tarea ECS), nunca de variables propias |
| `AWS_ENDPOINT_URL` | Endpoint AWS alternativo, **sólo LocalStack** (p. ej. `http://localstack:4566`). Opcional: ausente en AWS real |
| `MS_NMAP_SCAN_REQUESTS_QUEUE_URL` | URL de la cola SQS de solicitudes de escaneo (obligatoria) |
| `MS_NMAP_SCAN_CANCELLATIONS_QUEUE_URL` | URL de la cola SQS de cancelaciones de escaneo (obligatoria) |
| `MS_NMAP_SCAN_REQUESTS_DLQ_URL` | URL de la DLQ de solicitudes de escaneo (obligatoria) |
| `MS_NMAP_SCAN_CANCELLATIONS_DLQ_URL` | URL de la DLQ de cancelaciones de escaneo (obligatoria) |
| `MS_NMAP_SCAN_OUTCOMES_TOPIC_ARN` | ARN del topic SNS de desenlaces, `arn:<partición>:sns:<región>:<cuenta de 12 dígitos>:<nombre>` (obligatoria) |
| `MS_NMAP_SSH_CONNECT_TIMEOUT_SECS` | Timeout en segundos para establecer la conexión SSH con el objetivo |
| `MS_NMAP_SSH_COMMAND_TIMEOUT_SECS` | Timeout en segundos para la ejecución del comando `nmap` remoto |
| `MS_NMAP_EXPLOITDB_CSV` | Ruta al CSV `files_exploits.csv` de Exploit-DB para el enriquecimiento offline de vulnerabilidades. En la imagen Docker ya viene fijada por `ENV` a `/opt/exploitdb/files_exploits.csv` (el CSV se bundlea en la build); sólo hay que definirla al ejecutar fuera del contenedor |
| `MS_NMAP_NVD_ENRICHMENT_ENABLED` | `true`/`false` (obligatoria, sin default): habilita el enriquecimiento online contra la API NVD 2.0. En `false`, `ms-nmap` no hace ninguna llamada de red hacia NVD |
| `MS_NMAP_NVD_API_KEY` | API key de NVD (opcional; sube el límite de tasa permitido). Vacía o ausente = modo sin autenticar |
| `MS_NMAP_NVD_CACHE_TTL_SECS` | TTL en segundos de la caché de hallazgos de NVD en MongoDB. Sólo obligatoria si `MS_NMAP_NVD_ENRICHMENT_ENABLED=true`; si es `false`, no se lee |

El enriquecimiento de vulnerabilidades offline (cruce de servicio+versión
contra Exploit-DB) es **offline**: `ms-nmap` indexa el CSV bundleado en
memoria y resuelve el lookup localmente, sin llamadas de red a Exploit-DB ni a
ninguna API. El enriquecimiento por CPE contra la API NVD 2.0 sí hace egress de
red, pero es **opt-in** (`MS_NMAP_NVD_ENRICHMENT_ENABLED`) y sólo envía el CPE
del servicio (nunca la IP del objetivo, el `correlation_id` ni credenciales).
Ambos son detección pasiva, misma categoría que `nmap --script vuln` (ver
`docs/security-scope.md`).

```
docker run --rm \
  -e MS_NMAP_MONGO_URI=mongodb://mongo:27017 \
  -e MS_NMAP_MONGO_DB=db-nmap \
  -e MS_NMAP_SSH_PORT=22 \
  -e MS_NMAP_BROKER_ENDPOINT=amqps://broker.lab:5671 \
  -e MS_NMAP_BROKER_CREDENTIAL=*** \
  -e MS_NMAP_BROKER_VHOST=security-app \
  -e MS_NMAP_SSH_CONNECT_TIMEOUT_SECS=10 \
  -e MS_NMAP_SSH_COMMAND_TIMEOUT_SECS=300 \
  -e MS_NMAP_NVD_ENRICHMENT_ENABLED=false \
  ms-nmap
```

Para habilitar el enriquecimiento NVD, añade además:

```
  -e MS_NMAP_NVD_ENRICHMENT_ENABLED=true \
  -e MS_NMAP_NVD_CACHE_TTL_SECS=86400 \
  -e MS_NMAP_NVD_API_KEY=*** \
```

(`MS_NMAP_NVD_API_KEY` es opcional incluso con el enriquecimiento habilitado.)

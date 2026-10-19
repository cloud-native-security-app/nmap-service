# nmap-service

`ms-nmap`: microservicio de escaneo dentro de una plataforma de
ciberseguridad blue/red team. Recibe una solicitud de escaneo (IP, usuario de
red y permisos) a través de una cola SQS, se conecta por SSH al objetivo, ejecuta
`nmap` para detectar puertos abiertos, servicios, versiones y
vulnerabilidades, persiste el resultado en MongoDB (`db-nmap`) y lo publica
de vuelta en un topic SNS para que otro servicio (`ms-analisis`) genere el
informe final con IA.

Este repo implementa **únicamente** `ms-nmap`. `ms-usuarios`, `ms-analisis`,
el Gateway y el Broker viven en otros repos.

Stack: Rust (async con `tokio`), mensajería con AWS SQS (entrada) y SNS
(salida) vía el SDK oficial, persistencia en MongoDB, tests de integración con
`testcontainers` (LocalStack, MongoDB y `sshd` reales).

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

### Tests de integración con LocalStack

SQS y SNS se prueban contra un [LocalStack](https://www.localstack.cloud/) real
(`localstack/localstack:4.4`) que cada test levanta con `testcontainers`: no hace
falta cuenta AWS ni configuración previa, sólo Docker (`docker ps` debe
responder). Los tests con LocalStack comparten el arnés `tests/common/mod.rs`:

| Test | Qué cubre |
|------|-----------|
| `tests/sqs_sources_localstack.rs` | Fuentes de solicitudes/cancelaciones: long poll, borrado tras manejar, malformados a la DLQ, redrive tras 3 recepciones |
| `tests/sns_sink_localstack.rs` | Publicación en SNS con el atributo `routing_key` y el filtro del Gateway; guarda de tamaño |
| `tests/messaging_e2e_localstack.rs` | De punta a punta: solicitud en SQS -> `wiring` real -> `sshd` con `nmap` falso + MongoDB -> desenlace `completed` en SNS -> solicitud borrada -> apagado inmediato |

```
cargo test --test messaging_e2e_localstack -- --ignored
```

El LocalStack para correr el servicio localmente (docker compose) vive en el repo
`infra`.

### Desarrollo asistido por IA

El trabajo asistido por IA usa [gentle-ai](https://github.com/Gentleman-Programming/gentle-ai):
cada funcionalidad sustancial se planifica en un documento ODD en
`odd/tasks/<feature>.md` (checklist, criterios de aceptación y evidencia de
verificación), espejado en la memoria persistente Engram bajo el tópico
`odd/<feature>/tasks`. Los commits siguen Conventional Commits.

## CI/CD

### En cada pull request y push a `develop` (`.github/workflows/ci.yml`)

- **verify**: Rust 1.98 (el mismo del builder del `Dockerfile`) y `make verify`
  (fmt, clippy `-D warnings`, `cargo test`, `cargo test -- --ignored` con
  LocalStack, MongoDB y un `sshd` en Docker, `cargo doc`).
- **docker-build**: `docker build .` sin push.

### En push a `main` (`.github/workflows/deploy.yml`)

Construye la imagen, la publica en ECR como `security-app/nmap-service:<sha>`
(y `:latest`) y despliega en el servicio ECS `nmap-service` del cluster
`security-app-cluster-v2`. Terraform (repo `infra`) es la única fuente de
verdad de la task definition (variables de entorno, secretos de SSM, roles,
logs): CI solo descarga la task definition vigente del servicio, cambia la
imagen del contenedor `nmap-service` por `<sha>`, registra la nueva revisión y
espera la estabilidad del servicio. Nada de esto se versiona en este repo.

`nmap-service` es un worker sin load balancer ni puerto expuesto, así que
"estable" significa que la tarea queda en estado `RUNNING` con
`runningCount == desiredCount`.

Requisitos en GitHub (Learner Lab no tiene OIDC; los fija
`scripts/refresh-gh-secrets.sh` del repo `infra`):

| Nombre | Tipo | Quién lo define |
|--------|------|-----------------|
| `AWS_ACCESS_KEY_ID`, `AWS_SECRET_ACCESS_KEY`, `AWS_SESSION_TOKEN` | secrets del repo | `infra` `scripts/refresh-gh-secrets.sh` |
| `AWS_REGION` | variable del repo | `infra` `scripts/refresh-gh-secrets.sh` |

Las credenciales de Learner Lab caducan: si el deploy falla al autenticarse,
ejecuta `scripts/refresh-gh-secrets.sh` en `infra` y vuelve a lanzar el workflow.

### Redeploy manual y rollback

- Redeploy: pestaña Actions, workflow **Deploy**, **Run workflow**
  (`workflow_dispatch`).
- Rollback: lanza **Run workflow** eligiendo la ref (rama o tag) de un commit
  anterior, que reconstruye y despliega esa imagen; o, sin reconstruir,
  `aws ecs update-service --cluster security-app-cluster-v2 --service nmap-service --task-definition <familia>:<revisión anterior>`.

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
excepciones son `AWS_ENDPOINT_URL` y `MS_NMAP_NVD_API_KEY` (genuinamente
opcionales) y `MS_NMAP_NVD_CACHE_TTL_SECS` (obligatoria sólo si el
enriquecimiento NVD está habilitado):

| Variable | Descripción |
|----------|-------------|
| `MS_NMAP_MONGO_URI` | URI de conexión a MongoDB (`db-nmap`), p. ej. `mongodb://host:27017` |
| `MS_NMAP_MONGO_DB` | Nombre de la base de datos donde se persisten los resultados y el trust store SSH |
| `MS_NMAP_SSH_PORT` | Puerto SSH del objetivo al que conectarse (p. ej. `22`) |
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
  -e AWS_REGION=us-east-1 \
  -e MS_NMAP_SCAN_REQUESTS_QUEUE_URL=https://sqs.us-east-1.amazonaws.com/123456789012/ms-nmap-scan-requests \
  -e MS_NMAP_SCAN_REQUESTS_DLQ_URL=https://sqs.us-east-1.amazonaws.com/123456789012/ms-nmap-scan-requests-dlq \
  -e MS_NMAP_SCAN_CANCELLATIONS_QUEUE_URL=https://sqs.us-east-1.amazonaws.com/123456789012/ms-nmap-scan-cancellations \
  -e MS_NMAP_SCAN_CANCELLATIONS_DLQ_URL=https://sqs.us-east-1.amazonaws.com/123456789012/ms-nmap-scan-cancellations-dlq \
  -e MS_NMAP_SCAN_OUTCOMES_TOPIC_ARN=arn:aws:sns:us-east-1:123456789012:scan-outcomes \
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

Las credenciales de AWS no son variables de `ms-nmap`: en ECS salen del rol de la
tarea; fuera de AWS, de la cadena por defecto del SDK (p. ej. `AWS_ACCESS_KEY_ID`
y `AWS_SECRET_ACCESS_KEY`). Contra LocalStack añade
`-e AWS_ENDPOINT_URL=http://localstack:4566` y credenciales ficticias.

### Apagado

Con `SIGTERM` (ECS) o `Ctrl-C`, `ms-nmap` deja de pedir mensajes de inmediato,
espera hasta 25 s a que terminen los escaneos en vuelo (cada uno se borra de la
cola solo tras publicar su desenlace terminal) y sale. Los que no terminen
reaparecen en la cola al vencer su `VisibilityTimeout` y se reprocesan. El
`stopTimeout` de la tarea ECS debe ser de al menos 30 s.

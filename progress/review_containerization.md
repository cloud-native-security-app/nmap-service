# Review — feature 12 (containerization)

**Veredicto:** APPROVED

Revisado por el `reviewer` el 2026-08-28 contra `docs/architecture.md`,
`docs/conventions.md`, `CHECKPOINTS.md` y el plan aprobado
`whoami-o-aguirre-abundant-raccoon.md`.

## Archivos modificados / creados (verificado con `git status --porcelain` + `git diff --stat HEAD`)

- `Dockerfile` (nuevo)
- `.dockerignore` (nuevo)
- `README.md` (nueva sección "Despliegue (Docker)", +47 líneas)
- `docs/architecture.md` (nueva sección "Despliegue", +20 líneas)
- `feature_list.json` (feature 12 `pending` → `in_progress`, 1 línea)
- `progress/current.md`, `progress/impl_containerization.md`

**`src/` y `Cargo.toml` NO se tocaron** — confirmado. La feature es puramente de
empaquetado. Sin riesgo de regresión de compilación.

## Checkpoints CHECKPOINTS.md

- C1: [x] — 4 archivos base + 4 docs presentes; `./init.sh` exit 0 (ver abajo).
- C2: [x] — solo la feature 12 en `in_progress`; features `done` con tests verdes;
  `progress/current.md` describe la sesión activa (feature 12, implementer).
- C3: [x] — `src/` sin cambios, sigue con los módulos previstos; sin dependencias
  nuevas en `Cargo.toml`; `cargo doc` sin warnings (paso de `init.sh` OK).
- C4: [x] — `cargo test` + `cargo test -- --ignored` (ssh 5, scanner 4,
  repository, scan_pipeline 3) todos verdes; `cargo clippy --all-targets -D warnings`
  limpio (paso de `init.sh` OK).
- C5: [x] — sin archivos sospechosos (`.gitignore` cubre `/target`, `*.tmp`); los
  untracked son `Dockerfile`, `.dockerignore`, `progress/impl_containerization.md`,
  legítimos. Nota para el `leader`: al cerrar la sesión falta añadir la entrada de
  la feature 12 a `progress/history.md` y pasar la feature a `done` — es tarea del
  leader, no bloquea esta review.

## Los 8 criterios de acceptance, uno a uno

### 1. Dockerfile multi-stage: builder Rust + stage final mínimo con binario + certs CA — CUMPLE
`Dockerfile` en la raíz, dos stages:
- `builder`: `FROM rust:1.98-bookworm@sha256:82150a52...` → `cargo build --release --bin ms-nmap` + `strip`.
- runtime: `FROM gcr.io/distroless/cc-debian12:nonroot@sha256:9dac0a79...` → `COPY --from=builder .../ms-nmap /usr/local/bin/ms-nmap`.
distroless/cc-debian12 aporta glibc/libgcc + `ca-certificates` (verificado en
`docker history`: capa `//common:cacerts_debian12_amd64_tar`), y
`docker inspect` muestra `SSL_CERT_FILE=/etc/ssl/certs/ca-certificates.crt`.

### 2. Imagen final sin toolchain, sin fuente, sin `nmap` — CUMPLE
Método: `cid=$(docker create ms-nmap:review); docker export "$cid" | tar -tf -`
(1791 entradas). Filtrado `grep -Ei 'cargo|rustc|nmap|\.rs$|/app|target/release|openssh|/sh$|/bash$'`:
único match = `usr/local/bin/ms-nmap` (falso positivo por la subcadena "nmap").
- No hay `cargo`, `rustc`, `/app`, ningún `*.rs`, ni `target/`.
- `bin/`, `sbin/`, `usr/bin/`, `usr/sbin/` son directorios **vacíos** (distroless, sin shell).
- `docker history --no-trunc`: solo capas de la base distroless (bazel) + LABEL +
  `COPY .../ms-nmap` (12 MB) + `USER nonroot` + `ENTRYPOINT`. Ninguna capa de build.

### 3. Contenedor corre como usuario no-root — CUMPLE
`Dockerfile`: `USER nonroot`.
`docker inspect --format '{{.Config.User}}' ms-nmap:dev` → `nonroot` (uid 65532, distroless).

### 4. Config por env vars; README/docs documentan las 7 env vars — CUMPLE
`README.md` §"Despliegue (Docker)" lista una tabla con las 7:
`MS_NMAP_MONGO_URI`, `MS_NMAP_MONGO_DB`, `MS_NMAP_SSH_PORT`,
`MS_NMAP_BROKER_ENDPOINT`, `MS_NMAP_BROKER_CREDENTIAL`,
`MS_NMAP_SSH_CONNECT_TIMEOUT_SECS`, `MS_NMAP_SSH_COMMAND_TIMEOUT_SECS`.
Coinciden exactamente con las constantes de `src/config.rs`. Incluye ejemplo de
`docker run` con las 7. Se aclara que todas son obligatorias.

### 5. `.dockerignore` correcto — CUMPLE
Excluye `target/`, `.git/`, `.gitignore`, `.claude/`, `progress/`, `docs/`,
`tests/`, `*.md`, `Dockerfile`, `.dockerignore`. Incluye los 5 exigidos.
NO excluye `Cargo.toml`, `Cargo.lock` ni `src/`. Build reproducible verificado:
`docker build` completa (ver criterio 7), luego la capa dummy-crate copia
`Cargo.toml Cargo.lock` y la capa real copia `src` — ambos presentes en el contexto.

### 6. Bases pineadas por tag concreto + digest (no `latest`) — CUMPLE
Ambos stages: `rust:1.98-bookworm@sha256:82150a52...` y
`gcr.io/distroless/cc-debian12:nonroot@sha256:9dac0a79...`. Ningún `latest`.
El build resuelve por digest sin error → digests válidos.

### 7. `docker build` OK y `docker run` arranca sin panic — CUMPLE
`docker build -t ms-nmap:review .` → completó sin error (2.5s con capas cacheadas;
informe del implementer documenta 2m47s en frío).

`docker run --rm -e MS_NMAP_MONGO_URI=mongodb://127.0.0.1:1/?serverSelectionTimeoutMS=500 -e MS_NMAP_MONGO_DB=db-nmap -e MS_NMAP_SSH_PORT=22 -e MS_NMAP_BROKER_ENDPOINT=nats://localhost:4222 -e MS_NMAP_BROKER_CREDENTIAL=x -e MS_NMAP_SSH_CONNECT_TIMEOUT_SECS=10 -e MS_NMAP_SSH_COMMAND_TIMEOUT_SECS=300 ms-nmap:review`
→ salida:
`ERROR ms_nmap: no se pudo inicializar ms-nmap error=no se pudo conectar con MongoDB: ... Connection refused (os error 111) ...`
→ `EXIT=0`. Sin `panicked at`, sin SIGSEGV (exit ≠ 139).

`docker run --rm ms-nmap:review` (sin env vars) → salida:
`ERROR ms_nmap: configuración inválida; ms-nmap no puede arrancar error=falta la variable de entorno requerida: MS_NMAP_MONGO_URI`
→ `EXIT=0`. Salida limpia, sin panic.

### 8. `docs/architecture.md` con nota de despliegue — CUMPLE
Nueva sección "## Despliegue": stages e imágenes base, qué incluye (binario +
certs CA), qué NO incluye (toolchain, fuente, `nmap`, `openssh-client`), usuario
no-root uid 65532, pin por tag+digest, `testcontainers` independiente del empaquetado.

## Verificaciones adicionales

- **`./init.sh` verde**: exit 0. `cargo fmt --check`, `clippy -D warnings`,
  `cargo test`, `cargo test -- --ignored` (tests de integración con Docker: ssh,
  scanner, repository, scan_pipeline — todos verdes), `cargo doc` OK.
- **Sin secretos horneados**: `Dockerfile` no tiene `ENV` con valores, no hace
  `COPY` de ficheros de credenciales. `docker inspect .Config.Env` → solo `PATH`
  y `SSL_CERT_FILE` (de la base distroless). `docker history` no revela nada
  sensible. `MS_NMAP_BROKER_CREDENTIAL` se pasa en runtime, nunca en la imagen.
- **Buenas prácticas**: usuario no-root ✓, `strip` del binario ✓ (imagen 54.7 MB
  disk / binario ~12 MB), capa de cache de deps (dummy crate antes de `COPY src`) ✓,
  `# syntax=docker/dockerfile:1` + LABEL OCI ✓.
- **`russh` (feature "ring") + `mongodb` 3** → TLS vía rustls/ring, sin OpenSSL del
  sistema ni `openssh-client`. La afirmación del Dockerfile/docs es correcta y el
  binario arranca en distroless/cc sin libs extra.

## Cambios requeridos

Ninguno.

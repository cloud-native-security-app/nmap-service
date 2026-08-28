# Implementación — Feature 12: containerization

## Archivos creados / modificados

- `Dockerfile` (raíz, nuevo) — multi-stage.
- `.dockerignore` (raíz, nuevo).
- `README.md` — nueva sección "Despliegue (Docker)": build, run, tabla de las 7
  env vars requeridas, aclaración de que la imagen no lleva `nmap` ni servidor HTTP.
- `docs/architecture.md` — nueva sección "Despliegue" (imagen multi-stage, qué
  incluye —binario + certs CA— y qué no —toolchain, fuente, nmap, openssh-client—,
  usuario no-root, pin por tag+digest, testcontainers es independiente).
- `feature_list.json` — feature 12 `pending` → `in_progress`.

**No se tocó `src/` ni `Cargo.toml`.** El `main.rs` existente ya arranca, loggea
con `tracing` y sale limpio sin panic tanto ante config inválida como ante Mongo
inalcanzable — no hizo falta ningún ajuste.

## Diseño del Dockerfile

- **Stage builder**: `rust:1.98-bookworm` pineado por digest
  (`sha256:82150a52ec202c1b14d7817e14516c392bb7f5cfebd88f1ed531cb37ebd39922`).
  - Capa de cacheo de dependencias: copia `Cargo.toml`/`Cargo.lock`, crea un
    `src/lib.rs`/`src/main.rs` dummy, `cargo build --release`, borra el dummy.
  - Luego `COPY src ./src`, `touch` de los entrypoints (para invalidar solo el
    crate propio, no las deps) y `cargo build --release --bin ms-nmap` + `strip`.
- **Stage runtime**: `gcr.io/distroless/cc-debian12:nonroot` pineado por digest
  (`sha256:9dac0a79194e45a7da0158a9c6da57b217585af0786db3845d1f0ec1a0dd182f`).
  Trae glibc + libgcc + `ca-certificates` + usuario `nonroot` (uid 65532). Sin
  shell ni gestor de paquetes.
  - `COPY --from=builder /app/target/release/ms-nmap /usr/local/bin/ms-nmap`
  - `LABEL org.opencontainers.image.{title,description,source}`
  - `USER nonroot`, `ENTRYPOINT ["/usr/local/bin/ms-nmap"]`
- Sin `nmap` (corre en el objetivo vía SSH) ni `openssh-client` (`russh` es Rust
  puro). El driver `mongodb` usa `rustls` → solo hacen falta los certs CA.

## `.dockerignore`

Excluye: `target/`, `.git/`, `.gitignore`, `.claude/`, `progress/`, `docs/`,
`tests/`, `*.md`, `Dockerfile`, `.dockerignore`.
NO excluye: `Cargo.toml`, `Cargo.lock`, `src/` (necesarios para el build).

## Verificación ejecutada

### 1. `docker build -t ms-nmap:dev .`
- Build limpio en frío: **2m47s** (compilación de deps 1m55s + crate 16s).
- Rebuild tras solo cambiar el pin de digest: **2.8s** (capas cacheadas).
- Imagen final: **DISK USAGE 54.7 MB / CONTENT SIZE 14.2 MB**. Binario `ms-nmap` ~12 MB.

### 2. La imagen final no tiene toolchain / fuente / nmap
`docker create` + `docker export | tar -tf -`:
- El único match de `cargo|rustc|nmap|/app|target/release|\.rs$` es
  `usr/local/bin/ms-nmap` (falso positivo por la subcadena "nmap").
- No hay `cargo`, `rustc`, `/app`, `*.rs`, ni `target/`.
- `bin/` y `usr/bin/` son directorios vacíos (distroless).
- `docker history`: solo capas de la base distroless (bazel) + LABEL + COPY del
  binario (12 MB) + USER + ENTRYPOINT.

### 3. Usuario no-root
`docker inspect --format '{{.Config.User}}'` → `nonroot`.
Ejecuta correctamente con `--user 65532:65532`.

### 4. `docker run` con las 7 env vars (Mongo inalcanzable)
```
ERROR ms_nmap: no se pudo inicializar ms-nmap error=no se pudo conectar con MongoDB: ... Connection refused (os error 111) ...
exit=0
```
Arranca, emite logs de `tracing`, falla al conectar a Mongo y **sale limpio (exit 0), sin panic ni SIGSEGV**.

### 5. `docker run` SIN env vars
```
ERROR ms_nmap: configuración inválida; ms-nmap no puede arrancar error=falta la variable de entorno requerida: MS_NMAP_MONGO_URI
exit=0
```
Error de config loggeado, salida limpia, sin panic.

### 6. `./init.sh`
**Verde (exit 0)** — `cargo fmt --check`, `clippy -D warnings`, `cargo test`,
`cargo test -- --ignored` (tests de integración con Docker), `cargo doc` todos OK.
La feature no toca `src/`, así que no había riesgo de regresión.

## Imágenes de prueba
Queda `ms-nmap:dev` en el daemon local. Se puede eliminar con
`docker rmi ms-nmap:dev` — no afecta a nada del repo.

## Cobertura de los 8 criterios de acceptance

| # | Criterio | Estado |
|---|----------|--------|
| 1 | Dockerfile multi-stage (builder Rust + final mínimo con binario + certs CA) | OK |
| 2 | Imagen final sin toolchain, sin fuente, sin `nmap` | OK (verificado por export) |
| 3 | Contenedor corre como no-root | OK (`USER nonroot`, uid 65532) |
| 4 | Config por env vars documentada para `docker run` | OK (README, tabla de 7 vars) |
| 5 | `.dockerignore` excluye target/, .git/, .claude/, progress/, docs/ | OK (y más) |
| 6 | Bases pineadas por tag concreto (no latest), ideal por digest | OK (tag + digest) |
| 7 | `docker build` OK y `docker run` arranca sin panic | OK (documentado arriba) |
| 8 | `docs/architecture.md` con nota de despliegue | OK (sección "Despliegue") |

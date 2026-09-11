# syntax=docker/dockerfile:1
#
# Imagen de producción de ms-nmap (feature 12: containerization).
#
# Multi-stage:
#   - builder: toolchain Rust completa, compila el binario `ms-nmap` en release.
#   - exploitdb: descarga `files_exploits.csv` de Exploit-DB (pineado a un commit).
#   - runtime: distroless/cc (glibc + certificados CA + usuario `nonroot`),
#     contiene el binario `ms-nmap` y el CSV `files_exploits.csv` (dato de sólo
#     lectura para el enriquecimiento offline). Sin toolchain, sin código fuente,
#     sin shell/coreutils, sin `searchsploit`, sin `nmap` (nmap se ejecuta en el
#     objetivo vía SSH, no en este contenedor — ver docs/architecture.md
#     §"SSH al objetivo, no escaneo local").
#
# Las imágenes base se fijan por tag concreto Y por digest (`@sha256:...`) para
# builds reproducibles. Al actualizar una base, refresca el digest con
# `docker buildx imagetools inspect <imagen:tag>`.

# ---------------------------------------------------------------------------
# Stage 1 — builder
# ---------------------------------------------------------------------------
FROM rust:1.98-bookworm@sha256:82150a52ec202c1b14d7817e14516c392bb7f5cfebd88f1ed531cb37ebd39922 AS builder

WORKDIR /app

# 1) Cachea la compilación de dependencias: con solo Cargo.toml/Cargo.lock y un
#    árbol de fuentes mínimo, `cargo build --release` compila todas las deps.
#    Mientras Cargo.toml/Cargo.lock no cambien, esta capa se reutiliza aunque
#    cambie `src/`. La capa se reutiliza mientras las deps no cambien.
COPY Cargo.toml Cargo.lock ./
RUN mkdir src \
    && echo '//! placeholder para cachear dependencias' > src/lib.rs \
    && echo 'fn main() {}' > src/main.rs \
    && cargo build --release \
    && rm -rf src

# 2) Copia el código real y compila el binario. Solo se recompila el crate
#    propio, no las dependencias ya cacheadas arriba.
COPY src ./src
RUN touch src/lib.rs src/main.rs \
    && cargo build --release --bin ms-nmap \
    && strip target/release/ms-nmap

# ---------------------------------------------------------------------------
# Stage 2 — exploitdb: base de datos de Exploit-DB para el enriquecimiento
#           offline de vulnerabilidades (feature 13: vuln_enrichment).
# ---------------------------------------------------------------------------
# Sólo se bundlea `files_exploits.csv` (~10 MB, un dato, no un ejecutable): el
# adaptador `ExploitDbEnricher` lo indexa en memoria y hace el lookup localmente,
# SIN egress de red (ver docs/security-scope.md). NO se instala el CLI
# `searchsploit` (script bash) para no romper la imagen distroless.
#
# Se fija a un commit CONCRETO del repo de Exploit-DB (tag `2026-09-04`) para
# builds reproducibles. Para actualizar: elegir un commit nuevo de
# https://gitlab.com/exploit-database/exploitdb/-/commits/main y cambiar el hash.
# `ADD` descarga sin necesidad de curl/wget; `--chmod=0644` deja el CSV legible
# por el usuario `nonroot` de la imagen final.
FROM rust:1.98-bookworm@sha256:82150a52ec202c1b14d7817e14516c392bb7f5cfebd88f1ed531cb37ebd39922 AS exploitdb

ADD --chmod=0644 \
    https://gitlab.com/exploit-database/exploitdb/-/raw/ef58d5f4e31fefec0e36298c0b3e718801afdeb8/files_exploits.csv \
    /opt/exploitdb/files_exploits.csv

# ---------------------------------------------------------------------------
# Stage 3 — runtime
# ---------------------------------------------------------------------------
# distroless/cc-debian12: glibc + libgcc (para el binario Rust), paquete
# ca-certificates (TLS a MongoDB/Broker vía rustls) y el usuario no-root
# `nonroot` (uid 65532). No trae shell ni gestor de paquetes.
FROM gcr.io/distroless/cc-debian12:nonroot@sha256:9dac0a79194e45a7da0158a9c6da57b217585af0786db3845d1f0ec1a0dd182f

LABEL org.opencontainers.image.title="ms-nmap" \
      org.opencontainers.image.description="Microservicio de escaneo remoto (SSH + nmap) de la plataforma blue/red team" \
      org.opencontainers.image.source="https://github.com/o-aguirre/nmap-service"

COPY --from=builder /app/target/release/ms-nmap /usr/local/bin/ms-nmap
COPY --from=exploitdb /opt/exploitdb/files_exploits.csv /opt/exploitdb/files_exploits.csv

# El CSV es un dato de sólo lectura bundleado: fija la ruta que lee `config`
# (MS_NMAP_EXPLOITDB_CSV). Es la única env var con valor en la imagen; el resto
# se inyectan en `docker run` (ver README.md).
ENV MS_NMAP_EXPLOITDB_CSV=/opt/exploitdb/files_exploits.csv

USER nonroot

ENTRYPOINT ["/usr/local/bin/ms-nmap"]

# syntax=docker/dockerfile:1
#
# Imagen de producción de ms-nmap (feature 12: containerization).
#
# Multi-stage:
#   - builder: toolchain Rust completa, compila el binario `ms-nmap` en release.
#   - runtime: distroless/cc (glibc + certificados CA + usuario `nonroot`),
#     contiene SOLO el binario. Sin toolchain, sin código fuente, sin `nmap`
#     (nmap se ejecuta en el objetivo vía SSH, no en este contenedor — ver
#     docs/architecture.md §"SSH al objetivo, no escaneo local").
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
# Stage 2 — runtime
# ---------------------------------------------------------------------------
# distroless/cc-debian12: glibc + libgcc (para el binario Rust), paquete
# ca-certificates (TLS a MongoDB/Broker vía rustls) y el usuario no-root
# `nonroot` (uid 65532). No trae shell ni gestor de paquetes.
FROM gcr.io/distroless/cc-debian12:nonroot@sha256:9dac0a79194e45a7da0158a9c6da57b217585af0786db3845d1f0ec1a0dd182f

LABEL org.opencontainers.image.title="ms-nmap" \
      org.opencontainers.image.description="Microservicio de escaneo remoto (SSH + nmap) de la plataforma blue/red team" \
      org.opencontainers.image.source="https://github.com/o-aguirre/nmap-service"

COPY --from=builder /app/target/release/ms-nmap /usr/local/bin/ms-nmap

USER nonroot

ENTRYPOINT ["/usr/local/bin/ms-nmap"]

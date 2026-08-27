# Convenciones de código

> Homogeneidad extrema. La IA predice mejor cuando el repositorio se parece
> a sí mismo en todas partes.

## Estilo Rust

- **Edition:** 2021 o superior.
- **Formato:** `cargo fmt` (configuración por defecto salvo que se documente
  lo contrario en `rustfmt.toml`).
- **Lints:** `cargo clippy --all-targets -- -D warnings` debe pasar sin
  advertencias (incluye el código de `tests/`, no solo `src/`).
- **Async:** runtime `tokio`. Ninguna llamada bloqueante (IO de archivo,
  llamadas SSH síncronas, etc.) directamente en una tarea async — usar
  `spawn_blocking` si la dependencia no es nativamente async.
- **Errores:** tipos de error propios por módulo con `thiserror` (variantes
  específicas, no `String`). `anyhow` solo se permite en `main.rs` o en el
  borde del proceso, nunca en la firma pública de una función de dominio.
- **Nada de `unwrap()`/`expect()`/`panic!()`** fuera de tests, a menos que la
  condición sea verdaderamente irrecuperable y esté documentada con un
  comentario explicando por qué.
- **Rustdoc:** todo ítem público (`pub fn`, `pub struct`, `pub enum`,
  `pub trait`) lleva un comentario `///` explicando su propósito (qué hace,
  qué puede fallar). El crate activa `#![deny(missing_docs)]` en
  `src/lib.rs` (no en `src/main.rs`: los módulos públicos —`config`,
  `domain`, `ssh`, etc.— viven en la raíz de la librería, y `lib.rs`/
  `main.rs` compilan como crates separados) — sin este lint, `cargo doc`/
  `cargo build` no fallan por falta de rustdoc, así que la regla no sería
  exigible.
- **Tests de integración con IO real:** se levantan con el crate
  `testcontainers` (contenedor MongoDB oficial para `repository`, contenedor
  con `sshd` para `ssh`/`scanner`). Nunca mocks del filesystem, de SSH ni de
  Mongo — ver `docs/verification.md`.
- **Todo test que dependa de Docker vía `testcontainers` se marca**
  `#[ignore = "requiere Docker"]`. Así `cargo test` (sin flags) corre rápido
  y sin depender de Docker, y `cargo test -- --ignored` corre específicamente
  los de integración. `init.sh` ejecuta ambos.

## Nombres

| Tipo                    | Convención        | Ejemplo               |
|-------------------------|-------------------|------------------------|
| Módulos/archivos        | `snake_case`      | `ssh.rs`, `scanner.rs` |
| Tipos/traits            | `PascalCase`      | `ScanResult`, `SshError` |
| Funciones / variables   | `snake_case`      | `run_scan`             |
| Constantes              | `UPPER_SNAKE`     | `DEFAULT_SCAN_TIMEOUT` |
| Módulos privados        | prefijo `_` en el ítem, no en el módulo | `_internal_helper` |

## Estructura de un módulo

```rust
//! Una línea describiendo el propósito del módulo.

use std::time::Duration;

use serde::{Deserialize, Serialize};

use crate::domain::ScanResult;

// tipos y lógica del módulo
```

- Imports: primero `std`, luego crates externos, luego `crate::...` — cada
  grupo separado por una línea en blanco (orden que aplica `rustfmt`
  automáticamente).

## Tests

- Tests unitarios: `#[cfg(test)] mod tests` al final del propio archivo, para
  lógica pura (`domain`, `parser`). Es el patrón idiomático en Rust (no una
  convención de otros lenguajes): el módulo de test ve las funciones privadas
  del archivo vía `use super::*`, algo que un archivo en `tests/` no puede
  hacer al compilar como crate externo. Además `#[cfg(test)]` excluye ese
  código del binario de release — costo cero en producción.
- Tests de integración: en `tests/`, un archivo por módulo que cruza un
  límite de IO real (`ssh`, `mongo`, `messaging`).
- Los tests de `ssh`/`scanner` corren contra un **servidor SSH de prueba
  local** (nunca un host real fuera de laboratorio — ver
  `docs/security-scope.md`).
- Los tests de `repository` corren contra una instancia de MongoDB de
  prueba (contenedor local), nunca contra `db-nmap` de producción.
- Nombres de test descriptivos: `parse_returns_error_on_malformed_xml`.

## Manejo de errores (ejemplo)

```rust
#[derive(Debug, thiserror::Error)]
pub enum SshError {
    #[error("autenticación SSH rechazada")]
    AuthFailed,
    #[error("host inalcanzable: {0}")]
    Unreachable(String),
    #[error("tiempo de espera agotado")]
    Timeout,
}
```

Los mensajes de error nunca incluyen credenciales, tokens ni contenido de
`ssh_credentials_ref`.

## Comentarios

Por defecto **no** se escriben. Solo se permiten cuando explican un *por qué*
no obvio (p. ej. workaround documentado, invariante sutil, restricción de
`docs/security-scope.md`). Los nombres deben hacer el resto.

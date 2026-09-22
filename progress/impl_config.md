# Informe de implementación — Feature 2 `config`

## Qué se hizo

`src/config.rs` deja de ser un stub e implementa la carga/validación de
configuración del servicio:

- **`struct Config`** con los valores del servicio, todos provenientes del
  entorno:
  - `mongo_uri: String` — URI de MongoDB (`db-nmap`).
  - `broker_endpoint: String` — endpoint del Broker.
  - `broker_credential: secrecy::SecretString` — credencial del Broker.
  - `ssh_connect_timeout: Duration` — timeout de conexión SSH.
  - `ssh_command_timeout: Duration` — timeout de comando remoto SSH.
- **`Config::from_env() -> Result<Config, ConfigError>`** (sync). Lee del
  entorno del proceso delegando en la función privada
  `Config::from_source(lookup)`, que contiene toda la lógica de validación y
  recibe un `Fn(&str) -> Option<String>` — así los tests validan la lógica sin
  mutar variables de entorno globales.
- **`ConfigError`** (`thiserror`), variantes tipadas concretas:
  - `MissingVar(&'static str)` — variable requerida ausente o vacía.
  - `InvalidValue { var: &'static str, reason: String }` — timeout presente
    pero no parseable / no positivo. `reason` nunca incluye credenciales.
  - Sin `String` genérico como error, sin `panic!`, sin `unwrap`/`expect`
    fuera de `#[cfg(test)]`.
- **Nombres de env vars** como `pub const` (`MONGO_URI_VAR`,
  `BROKER_ENDPOINT_VAR`, `BROKER_CREDENTIAL_VAR`, `SSH_CONNECT_TIMEOUT_VAR`,
  `SSH_COMMAND_TIMEOUT_VAR`), prefijadas `MS_NMAP_`. **Todas** las variables
  (URI, endpoint, credencial y ambos timeouts) son requeridas: si falta o está
  vacía → `ConfigError::MissingVar(var)`. Ningún valor tiene default en el
  código (ver ronda 2 abajo).
- Rustdoc `///` en todos los ítems públicos (`#![deny(missing_docs)]` +
  `cargo doc` en verde).

## Ronda 2 — cambios tras review (`progress/review_config.md`, CHANGES_REQUESTED)

El reviewer marcó CHANGES_REQUESTED por incumplir el criterio de `acceptance`
2 (y `docs/architecture.md` §Capas p.1: "timeouts SSH … Sin valores
hardcodeados"). Aplicado:

1. Eliminadas las consts `DEFAULT_SSH_CONNECT_TIMEOUT` y
   `DEFAULT_SSH_COMMAND_TIMEOUT` — eran valores de configuración hardcodeados.
2. `parse_timeout(var, raw)` ya no recibe fallback: si `raw` es `None` o vacío
   devuelve `ConfigError::MissingVar(var)`, igual que `required()`. Se conserva
   intacta la validación `InvalidValue` (no numérico / cero).
3. Tests: `timeouts_fall_back_to_conservative_defaults_when_unset` eliminado y
   sustituido por `missing_ssh_connect_timeout_var_yields_typed_missing_var_error`
   y `missing_ssh_command_timeout_var_yields_typed_missing_var_error`, que
   verifican `ConfigError::MissingVar(SSH_*_TIMEOUT_VAR)` tipado y concreto. El
   camino feliz mantiene las aserciones de valores concretos.
4. Nit: la credencial de test se compara contra la const local
   `TEST_BROKER_CREDENTIAL` en vez de un literal inline.

Total: 8 tests unitarios. `./init.sh` → exit 0 de nuevo (fmt, clippy, test,
doc todos `[OK]`).

## Dependencias nuevas (justificación)

- **`secrecy = "0.10"`**: la credencial del Broker no debe filtrarse por
  `Debug` (lo exige `docs/security-scope.md` §Credenciales y secretos y
  `docs/architecture.md` §Manejo de errores). `SecretString` redacta su
  contenido en `Debug`, por lo que `#[derive(Debug)]` sobre `Config` es
  seguro. Es la misma dependencia que la feature 3 (`domain_model`) ya
  requiere explícitamente para `ssh_credentials_ref`, así que se unifica el
  enfoque. No se activó la feature `serde`: la config se construye desde el
  entorno, no se deserializa.
- **`thiserror = "2"`**: `docs/conventions.md` obliga a tipos de error por
  módulo con `thiserror`. Se añade ahora al usarse por primera vez; será la
  base de `SshError`, `ScanError`, etc. en features posteriores.

No se añadió `serial_test`: al testear `from_source` con un `HashMap`
inyectado, ningún test toca `std::env`, así que no hay estado global
compartido ni necesidad de serializar la ejecución.

## Enfoque de test de variables de entorno

Los tests construyen un `HashMap<&'static str, &'static str>` con el set
completo de variables y llaman a `Config::from_source(|k| map.get(k)...)`.
Cero mutación de `std::env`, cero dependencia del orden de ejecución, corren
en paralelo sin problemas. `Config::from_env` queda como una línea trivial
(inyecta `std::env::var`) que no necesita test propio.

Casos cubiertos en `#[cfg(test)] mod tests` de `src/config.rs`:

1. `loads_valid_config_with_expected_parsed_values` — camino feliz: verifica
   los **valores concretos** parseados (strings, `Duration::from_secs(7)` /
   `from_secs(120)`, credencial expuesta), no solo `is_ok()`.
2. `missing_required_var_yields_typed_missing_var_error` — sin `MONGO_URI` →
   `matches!(err, ConfigError::MissingVar(MONGO_URI_VAR))`.
3. `empty_required_var_is_treated_as_missing` — credencial en blanco → misma
   variante tipada.
4. `missing_ssh_connect_timeout_var_yields_typed_missing_var_error` — sin
   `SSH_CONNECT_TIMEOUT_VAR` → `MissingVar(SSH_CONNECT_TIMEOUT_VAR)`.
5. `missing_ssh_command_timeout_var_yields_typed_missing_var_error` — sin
   `SSH_COMMAND_TIMEOUT_VAR` → `MissingVar(SSH_COMMAND_TIMEOUT_VAR)`.
6. `non_numeric_timeout_yields_typed_invalid_value_error` — `"diez"` →
   `ConfigError::InvalidValue { var: SSH_CONNECT_TIMEOUT_VAR, .. }`.
7. `zero_timeout_yields_typed_invalid_value_error` — `"0"` → `InvalidValue`.
8. `debug_output_does_not_leak_broker_credential` — `format!("{config:?}")`
   no contiene el valor de la credencial.

## Salida de `./init.sh`

Exit 0. Todos los bloques en `[OK]`:

```
[OK]    cargo fmt --check sin diferencias
[OK]    cargo clippy sin warnings
test result: ok. 8 passed; 0 failed; 0 ignored; 0 measured; 0 filtered out
[OK]    Tests unitarios pasan
[OK]    Tests de integración con Docker (testcontainers, #[ignore]) pasan o no hay ninguno todavía
[OK]    cargo doc genera sin errores (rustdoc de ítems públicos)
[OK]    Entorno listo. Puedes empezar a trabajar.
```

## Archivos tocados

- `src/config.rs` — implementación + tests.
- `Cargo.toml` — deps `secrecy`, `thiserror`.
- `Cargo.lock` — regenerado.
- `feature_list.json` — feature 2 → `in_progress`.
- `progress/current.md`, `progress/impl_config.md`.

## Pendiente

Revisión por `reviewer`. No se marca `done`.

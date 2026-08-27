# Review — feature 2 `config` (ronda 2)

**Veredicto:** APPROVED

Revisor: reviewer · Fecha: 2026-08-27 · Rama: feature/scaffolding
Archivos evaluados: `src/config.rs`, `Cargo.toml`, `Cargo.lock`, `feature_list.json`,
`progress/current.md`, `progress/impl_config.md`.

La ronda 1 fue CHANGES_REQUESTED por valores de timeout hardcodeados
(`DEFAULT_SSH_*`) que incumplían el criterio de `acceptance` 2 y
`docs/architecture.md` §Capas p.1. El implementer aplicó los 4 cambios pedidos.
Re-verificado punto por punto.

---

## Verificación de los cambios pedidos

1. **Sin valores de timeout hardcodeados:** CONFIRMADO.
   `grep "DEFAULT_\|from_secs" src/config.rs` → ninguna const de default; el único
   `Duration::from_secs` fuera de tests es `src/config.rs:140`
   (`Ok(Duration::from_secs(secs))`, donde `secs` viene de la env var parseada).
   Las consts `DEFAULT_SSH_CONNECT_TIMEOUT` / `DEFAULT_SSH_COMMAND_TIMEOUT` ya no
   existen.

2. **Timeouts SSH ahora requeridos:** CONFIRMADO.
   `parse_timeout(var, raw)` (`src/config.rs:120-141`) ya no recibe fallback: si
   `raw` es `None` o queda vacío tras `trim` → `Err(ConfigError::MissingVar(var))`.
   La validación `InvalidValue` se conserva intacta: no parseable →
   `InvalidValue { var, reason: "se esperaba un entero de segundos…" }`
   (`:128-131`); `secs == 0` → `InvalidValue { var, reason: "el timeout debe ser
   mayor que cero" }` (`:133-138`). `reason` nunca incluye credenciales.
   El rustdoc de `from_env` (`:77-82`) se actualizó: lista los 5 vars como
   requeridos.

3. **Tests:** CONFIRMADO.
   - `timeouts_fall_back_to_conservative_defaults_when_unset` eliminado.
   - Añadidos `missing_ssh_connect_timeout_var_yields_typed_missing_var_error`
     (`:204-215`) y `missing_ssh_command_timeout_var_yields_typed_missing_var_error`
     (`:217-228`): ambos removen la env var y afirman
     `matches!(err, ConfigError::MissingVar(SSH_*_TIMEOUT_VAR))` — tipado y concreto.
   - `loads_valid_config_with_expected_parsed_values` (`:167-179`) conserva las
     aserciones de valores concretos: strings exactos, `Duration::from_secs(7)`,
     `from_secs(120)`, `expose_secret() == TEST_BROKER_CREDENTIAL`.
   - `non_numeric_timeout_*` y `zero_timeout_*` siguen presentes.
   - Nit de ronda 1 resuelto: const local `TEST_BROKER_CREDENTIAL` (`:151`) en vez
     de literal inline en la aserción de la credencial.
   - Total: 8 tests unitarios, todos verdes.

4. **`./init.sh` y toolchain:** CONFIRMADO (ejecutado por el revisor).
   - `./init.sh` → **exit 0**, todos los bloques `[OK]`.
   - `cargo fmt --check` → sin diferencias.
   - `cargo clippy --all-targets -- -D warnings` → sin warnings.
   - `cargo test` → `running 8 tests … 8 passed; 0 failed`.
   - `cargo test -- --ignored` → 0 (correcto: `config` no cruza IO).
   - `cargo doc --no-deps`, incluso con `RUSTDOCFLAGS="-D warnings"` → limpio.

Sin regresiones: `git status` muestra que el único archivo de `src/` tocado sigue
siendo `config.rs`; `src/domain.rs`, `src/ssh.rs`, etc. permanecen como stubs de la
feature 1.

---

## Checkpoints

- C1: [x]  4 archivos base + 4 docs presentes; `./init.sh` exit 0.
- C2: [x]  Solo la feature 2 en `in_progress`; `progress/current.md` describe la
  sesión activa; feature 1 (`done`) conserva sus tests.
- C3: [x]  `src/` solo contiene los módulos previstos; toda dep (`secrecy`,
  `thiserror`) justificada; sin `println!`/`dbg!`/`unwrap`/`expect`/`panic!` fuera
  de `#[cfg(test)]` (verificado con grep); `cargo doc --no-deps` sin warnings.
  **Ya no hay valores hardcodeados** — el motivo del rechazo de ronda 1 está
  resuelto.
- C4: [x]  `config` es lógica pura → no requiere test de integración (C4 aplica a
  `ssh`/`scanner`/`repository`/`messaging`). `cargo test` > 0 y verde;
  `cargo clippy --all-targets -- -D warnings` limpio.
- C5: [x]  Sin archivos sin trackear sospechosos (`progress/impl_config.md` y
  `progress/review_config.md` son esperados; no hay `*.tmp` ni `target/` fuera del
  `.gitignore`). Feature en `in_progress`, estado correcto hasta que el leader
  cierre. Entrada en `progress/history.md` y transición a `done` las hace el leader.

---

## Criterios de `acceptance` (feature 2), uno a uno

1. **Carga Mongo URI + endpoint/credenciales broker + timeouts SSH desde env vars;
   error tipado (`thiserror`, sin panics) si falta una variable requerida:**
   CUMPLE. Las 5 variables (`MS_NMAP_MONGO_URI`, `MS_NMAP_BROKER_ENDPOINT`,
   `MS_NMAP_BROKER_CREDENTIAL`, `MS_NMAP_SSH_CONNECT_TIMEOUT_SECS`,
   `MS_NMAP_SSH_COMMAND_TIMEOUT_SECS`) son requeridas; ausencia/vacío →
   `ConfigError::MissingVar`. `ConfigError` es enum `thiserror` con variantes
   concretas (`MissingVar(&'static str)`, `InvalidValue { var, reason }`), sin
   `String` genérico. `from_env` usa `std::env::var(key).ok()`; sin
   `unwrap`/`expect`/`panic!` fuera de tests.

2. **Ningún valor de configuración hardcodeado:** CUMPLE. Solo los nombres de env
   var son `const` (permitido). No hay defaults de URI, endpoint, credencial ni
   timeouts.

3. **Tests cubren config válida con valores concretos + falta de variable requerida
   → error tipado concreto:** CUMPLE. Ver detalle en "Verificación", punto 3.

---

## Otras verificaciones

- **Credencial del broker no se filtra por `Debug`/`Display`:** CORRECTO.
  `broker_credential: secrecy::SecretString`; `Config` deriva `Debug` (seguro,
  `SecretString` redacta); no implementa `Display`. `ConfigError` no transporta la
  credencial (`InvalidValue.reason` solo formatea el valor del timeout con `{:?}`).
  Test `debug_output_does_not_leak_broker_credential` lo comprueba. La aserción del
  camino feliz compara `expose_secret()` contra una const de test ficticia — API
  prevista para aserciones; aceptable.

- **Deps nuevas justificadas (C3):** `secrecy = "0.10"` (redacción de credencial —
  `docs/security-scope.md` §Credenciales, `docs/architecture.md` §Manejo de errores;
  además la usa la feature 3; solo arrastra `zeroize`). `thiserror = "2"`
  (`docs/conventions.md` §Errores lo obliga). `serial_test` correctamente **no**
  añadido (tests inyectan `HashMap`, no tocan `std::env`).

- **Sin scope creep hacia features 3-10:** CONFIRMADO. Solo `src/config.rs`
  modificado en `src/`. No se define `ScanRequest` ni tipos de dominio.

- **Rustdoc en todo ítem público:** CORRECTO. `Config` + 5 campos, `ConfigError` +
  variantes + campos, las 5 consts de env var, `from_env`. `from_source`,
  `required`, `parse_timeout` son privadas. `#![deny(missing_docs)]` activo,
  `cargo doc` verde (también con `-D warnings`).

- **Estilo/convenciones:** correcto. Orden de imports std → externo → `super::*`.
  Consts `UPPER_SNAKE`. `//!` de módulo de una línea. Sin comentarios superfluos.

---

## Cambios requeridos

Ninguno. La feature 2 `config` cumple los 3 criterios de `acceptance`, los
checkpoints C1-C5 y las convenciones. `./init.sh` en verde. Apta para pasar a
`done` (acción del leader).

# Implementación — feature 18: configurable_scan_timing

## Resumen

Se agregó la variable de entorno opcional `MS_NMAP_SCAN_TIMING` para elegir el
`Timing` (`-T`) de `nmap` sin recompilar, siguiendo exactamente el mismo
patrón de `src/config.rs` que las variables de timeout SSH ya existentes.
`detection_flags` (`-sV --script vuln`) no se tocó: sigue hardcodeado en
`ScanOptions::default()`.

## Cambios

- `src/config.rs`:
  - Nueva constante `SCAN_TIMING_VAR = "MS_NMAP_SCAN_TIMING"` documentada.
  - Nuevo campo `Config::scan_timing: Timing` (importa `crate::scanner::Timing`).
  - Nueva función privada `parse_timing`: variable ausente/vacía ->
    `Timing::Polite` (default, sin error); `"polite"`/`"normal"`/`"aggressive"`
    -> `Timing::Polite`/`Normal`/`Aggressive`; cualquier otro valor ->
    `ConfigError::InvalidValue { var: SCAN_TIMING_VAR, .. }`.
  - `Config::from_source` llama a `parse_timing` y puebla el nuevo campo.
  - Doc de `Config::from_env` actualizado (lista de `InvalidValue`).
  - Tests nuevos en `#[cfg(test)] mod tests`: default Polite sin la variable,
    `"normal"` -> `Timing::Normal`, `"aggressive"` -> `Timing::Aggressive`,
    valores inválidos (`"T4"`, `"AGGRESSIVE"`, `"insane"`) -> `InvalidValue`
    tipado con `var == SCAN_TIMING_VAR`, y `""` tratado como ausente (default
    Polite). El test `loads_valid_config_with_expected_parsed_values` ahora
    también verifica `scan_timing == Timing::Polite` por defecto.
- `src/main.rs`: el composition root arma `ScanOptions` con
  `timing: config.scan_timing` y el resto de `ScanOptions::default()` (spread),
  en vez de `ScanOptions::default()` a secas. `build_command`/`run_scan` no
  cambiaron de firma; siguen recibiendo `ScanOptions` igual que antes.
- `docs/security-scope.md`: nueva subsección "Timing de escaneo configurable
  (feature `configurable_scan_timing`)" bajo "Límite de las capacidades de
  escaneo": documenta el propósito operativo (pruebas/demos, evitar superar
  `MS_NMAP_SSH_COMMAND_TIMEOUT_SECS`), que el default de producción sigue
  siendo `Timing::Polite` (`-T2`) sin cambio de comportamiento si no se
  configura, que un valor inválido es un error tipado (no un "mejor
  esfuerzo"), y que `detection_flags` permanece explícitamente fuera del
  alcance de esta variable.

## Fuera de alcance (no tocado)

- `ScanOptions::default()` en `src/scanner.rs`: su `timing` por defecto y
  `detection_flags` no cambiaron.
- `build_command`/`run_scan`/`run_scan_with`: firma pública intacta.
- `Timing` (enum): no se agregaron variantes nuevas ni se expusieron
  `Paranoid`/`Sneaky`/`Insane` vía la variable de entorno (fuera del
  acceptance, que solo pide `polite`/`normal`/`aggressive`).

## Verificación

`./init.sh` corrido completo en verde (incluyendo `cargo test -- --ignored`
contra Docker real):

- `cargo fmt --check`: sin diferencias.
- `cargo clippy --all-targets -- -D warnings`: sin warnings.
- `cargo test`: 147 passed (incluye los 28 de `config::tests`, con los 4
  nuevos de `scan_timing`).
- `cargo test -- --ignored`: 29 passed (tests de integración con
  testcontainers, Docker disponible en este entorno).
- `cargo doc --no-deps`: genera sin errores.

## Estado

Feature 18 implementada y verificada localmente. Queda pendiente la revisión
del `reviewer` antes de marcarla `done` (no la cierro yo mismo, por protocolo).

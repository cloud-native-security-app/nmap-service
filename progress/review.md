# Review — feature 18 (configurable_scan_timing)

**Veredicto:** APPROVED

## Verificación contra el acceptance de la feature (`feature_list.json`, id 18)

1. `MS_NMAP_SCAN_TIMING` opcional, `'polite'|'normal'|'aggressive'` ->
   `Timing::Polite/Normal/Aggressive`; cualquier otro valor ->
   `ConfigError::InvalidValue` tipado: cumplido. `src/config.rs:322-340`
   (`parse_timing`) sigue el mismo patrón que `parse_strict_bool`/
   `parse_timeout`: usa la variante `ConfigError::InvalidValue { var, reason }`
   ya existente, sin tipo de error nuevo y sin `panic!`.
2. Ausente -> default exactamente `Timing::Polite`, cero cambio de
   comportamiento: cumplido. `parse_timing` devuelve `Ok(Timing::Polite)`
   cuando `raw` es `None` o vacío tras `trim` (`src/config.rs:323-325`), y
   `ScanOptions::default()` en `src/scanner.rs` (sin diff, confirmado con
   `git diff -- src/scanner.rs`) sigue usando `Timing::Polite` como default
   propio — ambos caminos coinciden.
3. `detection_flags` (`-sV --script vuln`) NO se vuelve configurable:
   cumplido. `src/scanner.rs` no tiene ningún cambio (diff vacío); línea 82
   sigue hardcodeando `vec!["-sV", "--script", "vuln"]` en
   `ScanOptions::default()`. `src/main.rs` solo sobreescribe el campo
   `timing` vía struct-update (`ScanOptions { timing: config.scan_timing,
   ..ScanOptions::default() }`), dejando `detection_flags` intacto.
4. `Config` expone el `Timing` elegido; `build_command`/`run_scan` sin
   cambio de firma pública: cumplido. Nuevo campo público
   `Config::scan_timing: Timing` (`src/config.rs:169-171`); `build_command`
   (privada, `src/scanner.rs:212`) y `run_scan` (`src/scanner.rs:133`) no
   tienen diff alguno.
5. `docs/security-scope.md` documenta la variable: cumplido. Nueva
   subsección "Timing de escaneo configurable" bajo "Límite de las
   capacidades de escaneo" (líneas 97-122): explica el knob operativo, el
   default seguro de producción, el error tipado para valores inválidos y
   que `detection_flags` queda fuera de alcance — coincide 1:1 con lo que
   pide el acceptance.
6. Tests unitarios nuevos en `src/config.rs` (ausente/normal/aggressive/
   inválido): cumplido —
   `missing_scan_timing_var_defaults_to_polite`,
   `scan_timing_var_normal_maps_to_timing_normal`,
   `scan_timing_var_aggressive_maps_to_timing_aggressive`,
   `scan_timing_var_rejects_invalid_values` (con `"T4"`, `"AGGRESSIVE"`,
   `"insane"` como inválidos, verificando `ConfigError::InvalidValue { var,
   .. }` con `var == SCAN_TIMING_VAR`). `loads_valid_config_with_expected_parsed_values`
   se actualizó para afirmar también el default `Timing::Polite`.
   Observación menor no bloqueante: ese mismo test mete el caso `""` (vacío)
   dentro del loop de "valores inválidos" con un `continue` especial en vez
   de un test dedicado (`empty_..._is_treated_as_missing`, patrón usado para
   `BROKER_VHOST_VAR`/`EXPLOITDB_CSV_VAR` en el resto del archivo). No viola
   ninguna regla de `docs/conventions.md`, es solo una pequeña inconsistencia
   de estilo — no bloquea la aprobación.
7. `cargo fmt --check`, `cargo clippy --all-targets -- -D warnings`,
   `cargo test` e `./init.sh` en verde: cumplido, ver más abajo.

## Arquitectura y convenciones

- `src/config.rs` importa `crate::scanner::Timing` (único `use crate::...`
  del archivo hasta ahora). Evalué si esto viola el orden de capas de
  `docs/architecture.md` (config es la capa 1, scanner la 4): no es así. La
  dependencia va en la dirección correcta (la capa externa/de composición
  `config` depende de un tipo puro de una capa interna, `scanner::Timing` no
  depende de `config`, confirmado — `scanner.rs` solo importa `crate::ssh`).
  No hay ciclo, y es exactamente lo que pide el acceptance #4 ("`Config`
  expone el `Timing`"): reusar el enum existente evita duplicarlo y mantiene
  una sola fuente de verdad, coherente con "homogeneidad extrema" de
  `docs/conventions.md`.
- Orden de imports (`std` -> crates externos -> `crate::...`, separados por
  línea en blanco) respetado en `src/config.rs:9-13`.
- Ningún `unwrap()`/`expect()`/`panic!()` fuera de `#[cfg(test)] mod tests`
  (que empieza en la línea 344): verificado con `rg` sobre el archivo
  completo, todas las ocurrencias están después de esa línea.
- Ningún tipo de error nuevo: reutiliza `ConfigError::InvalidValue` ya
  existente (`src/config.rs:103-117`, sin diff en el enum).
- Rustdoc en todo ítem público nuevo (`SCAN_TIMING_VAR`, `Config::scan_timing`)
  y doc de `Config::from_env` actualizado con el nuevo caso de
  `InvalidValue`; `cargo doc` compila sin errores (con `#![deny(missing_docs)]`
  activo en `src/lib.rs`, esto habría fallado si faltara algún rustdoc).
- Sin regresión en `src/scanner.rs`, `src/ssh.rs`, `src/repository.rs`, etc.
  (diff limitado a `src/config.rs`, `src/main.rs`, `docs/security-scope.md`,
  `feature_list.json`, `progress/current.md`).
- `feature_list.json`: la feature 18 se agregó con `"status": "in_progress"`
  (correcto, el implementer/reviewer no la marcan `done`); exactamente 1
  feature en `in_progress` en todo el archivo.

## Ejecución de `./init.sh`

Corrida completa, verde de punta a punta:

- `cargo fmt --check`: sin diferencias.
- `cargo clippy --all-targets -- -D warnings`: sin warnings.
- `cargo test` (sin Docker): **147 passed; 0 failed; 0 ignored** en
  `nmap_service` (incluye los 4 tests nuevos de `scan_timing` + el test
  existente actualizado), 0 en `ms_nmap`, resto de archivos en `tests/`
  solo corren los casos sin Docker (`stub_fixture_parses_into_the_expected_scan_result`:
  ok); todos los que requieren Docker aparecen como `ignored, requiere
  Docker`, como exige `docs/conventions.md`.
- `cargo test -- --ignored` (con Docker real vía `testcontainers`): **25
  passed, 0 failed** en total (`broker_adapter` 5/5, `repository` 11/11,
  `scan_pipeline` 4/4, `scanner` 4/4, `ssh` 5/5). **No apareció el flake
  intermitente preexistente de `enrichment::nvd::tests`** documentado en la
  sesión de la feature 14 (ese módulo no tiene tests `#[ignore]` — sus tests
  corren sin Docker, vía `wiremock`, y ya pasaron en la primera tanda sin
  problema: `enrich_maps_the_mocked_nvd_response_to_a_vuln_finding`,
  `cache_hit_avoids_a_second_http_call`,
  `duplicated_cpe_across_ports_is_queried_once`,
  `unreachable_server_yields_ok_with_no_findings_never_panics`,
  `http_500_yields_backend_error_without_panicking_and_keeps_other_cpes`,
  todos `ok` en la corrida). No hubo que descartar ningún flake esta vez
  porque no se presentó.
- `cargo doc --no-deps`: genera sin errores.
- Exit code final de `./init.sh`: 0.

## Checkpoints (`CHECKPOINTS.md`)

- C1: [x] — Existen los 4 archivos base y los 4 docs; `./init.sh` termina en
  exit code 0.
- C2: [x] — Exactamente 1 feature en `in_progress` (id 18, esperado mientras
  está pendiente de este veredicto); todas las features `done` tienen tests
  que pasan (147 unitarios + 25 de integración, todos verdes);
  `progress/current.md` describe solo la sesión activa de la feature 18, sin
  basura de sesiones anteriores.
- C3: [x] — `src/` solo contiene los módulos previstos
  (`config, domain, ssh, scanner, parser, repository, messaging, enrichment,
  pipeline, wiring`, más `lib.rs`/`main.rs`); sin dependencias nuevas en
  `Cargo.toml`; sin `println!`/`dbg!`/`unwrap()`/`panic!()` fuera de tests en
  el código nuevo; `cargo doc --no-deps` sin warnings.
- C4: [x] — Tests de integración con Docker real vía `testcontainers` para
  `ssh`/`scanner`/`repository`/`messaging` (sin tocar); `cargo test` muestra
  147+25 tests, todos verdes; `cargo clippy --all-targets -- -D warnings`
  sin advertencias.
- C5: [x] — Sin archivos sospechosos de código (`target/` correctamente
  ignorado). Nota no bloqueante: `.atl/` aparece sin trackear en
  `git status`, pero es un artefacto auto-generado de tooling
  ("Auto-generated by gentle-ai skill-registry refresh"), ajeno al diff del
  implementer y no relacionado con esta feature — no es basura de código
  dejada por la sesión. `progress/history.md` conserva la entrada de la
  última sesión cerrada (feature 17); la de la feature 18 queda pendiente de
  que el leader la mueva tras este veredicto, que es exactamente el
  protocolo esperado.

## Cambios requeridos

Ninguno.

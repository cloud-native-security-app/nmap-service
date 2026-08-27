# Review — feature 5 `nmap_execution`

**Veredicto:** APPROVED

Revisor: reviewer. Fecha: 2026-08-27. Ronda 1.

## Resumen de verificación ejecutada

`export PATH="$HOME/.cargo/bin:$PATH" && ./init.sh` → **EXIT 0** (confirmado dos veces).

- `cargo fmt --check` — limpio.
- `cargo clippy --all-targets -- -D warnings` — sin warnings (cubre `tests/scanner.rs`).
- `cargo test` — 36 unit tests, 36 passed / 0 failed (14 nuevos en `src/scanner.rs`).
- `cargo test -- --ignored` — **corrió de verdad con contenedores Docker reales**:
  `tests/scanner.rs` 4/4 passed (3.69s), `tests/ssh.rs` 5/5 passed (regresión OK).
- `cargo doc --no-deps` — sin warnings (`#![deny(missing_docs)]` satisfecho).

## Checkpoints (CHECKPOINTS.md)

- C1: [x] `./init.sh` termina con exit 0; los 4 docs y 4 archivos base presentes.
- C2: [x] Sólo la feature 5 en `in_progress`. El implementer NO la marcó `done`
  (sigue `in_progress` en `feature_list.json`). `progress/current.md` describe la
  sesión activa.
- C3: [x] `src/scanner.rs` es un módulo previsto en `docs/architecture.md` (capa 4).
  Sin deps nuevas en `Cargo.toml` (`thiserror`/`tracing`/`testcontainers`/`secrecy`
  ya estaban). Sin `println!`/`dbg!`/`unwrap`/`panic!` fuera de tests (los 2
  `expect` de `src/scanner.rs` están en `#[cfg(test)] mod tests`, líneas 255 y 372).
  `cargo doc --no-deps` limpio: todo ítem público con rustdoc.
- C4: [x] `tests/scanner.rs` aporta tests de integración para la capa `scanner`
  que cruza IO SSH, contra contenedor `sshd` real vía `testcontainers`
  (`lscr.io/linuxserver/openssh-server:version-9.9_p2-r0`), nunca una IP real
  (target = `127.0.0.1` del propio contenedor). `cargo test` > 0 y verde.
  `cargo clippy --all-targets` sin warnings.
- C5: [x] Sin archivos sospechosos sin trackear (`progress/impl_nmap_execution.md`
  y `tests/scanner.rs` son entregables legítimos de la feature). El estado de la
  feature 5 refleja `in_progress` correctamente (cierre + entrada en
  `progress/history.md` los gestiona el leader tras esta aprobación).

## Criterios de `acceptance` de la feature 5 — uno a uno

### 1. `run_scan(session: &SshSession, target_ip, has_sudo: bool) -> Result<String, ScanError>` con flags de detección configurables, devuelve XML de stdout — CUMPLE

- Firma exacta del acceptance en `src/scanner.rs:130-136`
  (`pub async fn run_scan(session: &SshSession, target_ip: IpAddr, has_sudo: bool) -> Result<String, ScanError>`).
- Delega en `run_scan_with(.., &ScanOptions::default())`. El par
  `run_scan` / `run_scan_with` + `struct ScanOptions { detection_flags: Vec<String>, timing: Timing }`
  es un patrón idiomático razonable para la configurabilidad; `run_scan` conserva
  la firma del contrato. Aceptado.
- `ScanOptions::default()` = `["-sV", "--script", "vuln"]` + `-oX -` + `-T2`
  (`src/scanner.rs:79-86`, y `build_command` añade siempre `-oX -`).
- `interpret` devuelve `Ok(output.stdout)` en `exit_code == 0` (`src/scanner.rs:205-207`).
- Test unitario `build_command_always_has_detection_flags_xml_timing_and_target`
  y `custom_options_are_reflected_in_the_command`; integración
  `run_scan_without_sudo_returns_the_stub_xml` valida contenido real del XML
  (`<nmaprun`, `portid="22"`), no sólo "no es Err".

### 2. `has_sudo == true` → `sudo -n` + `-O`; `has_sudo == false` → sin sudo ni `-O` — CUMPLE

- `build_command` (`src/scanner.rs:168-189`): `if has_sudo { push "sudo"; push "-n" }`
  antes de `nmap`, y `if has_sudo { push "-O" }` tras los flags de detección.
- Tests unitarios `build_command_with_sudo_prefixes_sudo_n_and_adds_os_detection`
  (verifica `starts_with("sudo -n nmap ")` y presencia de `-O`) y
  `build_command_without_sudo_omits_sudo_and_os_detection` (ausencia de ambos).
- Integración: `run_scan_with_sudo_elevates_and_returns_xml` — el stub de `nmap`
  exige `id -u == 0` cuando ve `-O`, así que el test prueba de verdad que
  `sudo -n` elevó privilegios; `run_scan_without_sudo_returns_the_stub_xml` cubre
  el camino sin sudo.

### 3. Timing `-T` configurable, default conservador según `docs/security-scope.md` — CUMPLE

- `ScanOptions.timing: Timing`, default `Timing::Polite` → `-T2` (`src/scanner.rs:53`, `:75-84`).
- Test unitario `default_timing_is_conservative`: comprueba `flag() == "-T2"`,
  que NO es `Aggressive`/`Insane`, y que el comando construido no contiene
  `-T4`/`-T5`.
- Conforme a `docs/security-scope.md` §"Límite de las capacidades de escaneo"
  (default conservador, evitar `-T4`/`-T5`). Este default de escaneo SÍ está
  autorizado explícitamente por el doc — no se marca como hardcodeo prohibido.

### 4. nmap no instalado → `ScanError::ToolNotAvailable` distinguible — CUMPLE

- Variante propia `ScanError::ToolNotAvailable` (`src/scanner.rs:98-99`).
- `looks_like_missing_tool` (`src/scanner.rs:216-225`): `exit_code == 127`, o
  (con exit ≠ 0) `stderr` contiene `command not found` / `nmap: not found`.
- Tests unitarios `interpret_exit_127_is_tool_not_available` y
  `interpret_sudo_missing_nmap_stderr_is_tool_not_available`.
- Integración `run_scan_without_nmap_installed_is_tool_not_available` (sin stub
  instalado) → `ScanError::ToolNotAvailable`. PASSED con Docker real.

### 5. sudo pedido pero falla por privilegios → `ScanError::InsufficientPrivileges` distinguible — CUMPLE

- Variante propia `ScanError::InsufficientPrivileges` (`src/scanner.rs:103-104`).
- `interpret` la devuelve sólo si `has_sudo && exit_code != 0 && looks_like_sudo_denied(stderr)`
  (`src/scanner.rs:201-203`); patrones: `password is required`,
  `a terminal is required`, `no tty present`, `sudo: sorry`.
- La guarda `has_sudo` evita falsos positivos: test
  `interpret_sudo_like_stderr_is_ignored_when_sudo_not_requested` confirma que
  con `has_sudo == false` el mismo stderr cae en `NmapFailed`.
- Tests unitarios `interpret_sudo_password_required_is_insufficient_privileges`,
  `interpret_sudo_terminal_required_is_insufficient_privileges`.
- Integración `run_scan_with_sudo_but_denied_is_insufficient_privileges`: stub
  de `sudo` en `/usr/local/bin/sudo` que emite `sudo: a password is required` y
  exit 1 → `ScanError::InsufficientPrivileges`. PASSED con Docker real.

### 6. Tests de integración con contenedor sshd de testcontainers, `#[ignore = "requiere Docker"]`, stub de nmap, casos con y sin sudo — CUMPLE

- `tests/scanner.rs`: 4 tests `#[tokio::test]` + `#[ignore = "requiere Docker"]`.
- Stub ejecutable de `nmap` (`FAKE_NMAP`) copiado con `with_copy_to` + `chmod 0755`
  vía `container.exec`; no requiere nmap real.
- Cubre: sin sudo (XML), con sudo (elevación + XML), sin nmap (ToolNotAvailable),
  sudo denegado (InsufficientPrivileges).
- `cargo test -- --ignored` los ejecutó de verdad: 4/4 PASSED en 3.69s.

## Alcance de seguridad (`docs/security-scope.md`)

- **Sólo detección:** default nunca incluye NSE `exploit`/`intrusive`; sólo `-sV`
  y `--script vuln`. El rustdoc del módulo y de `ScanOptions` advierte
  explícitamente de mantenerse en la detección permitida al personalizar
  `detection_flags`. OK.
- **sudo sólo `-n` (no interactivo):** `build_command` sólo emite `sudo -n`,
  nunca `sudo` a secas. OK.
- **Target como `IpAddr`:** `target_ip: IpAddr` se interpola vía `to_string()`
  (dígitos, `.`, `:`); no hay interpolación de cadenas arbitrarias en el comando.
  Documentado en el rustdoc de `run_scan_with`. OK.
- **Sin credenciales en logs/errores:** `scanner` no maneja credenciales; el
  `tracing::debug!(%command, ...)` sólo contiene `nmap`, flags e IP. El
  `#[error]` de `InsufficientPrivileges` está redactado sin la palabra
  "contraseña"/"password"; test `scan_error_display_does_not_mention_credentials`
  lo fija (banned: `password`, `contraseña`, `secret`, `credential`). OK.
- **Tests contra laboratorio local:** contenedor `sshd`, target `127.0.0.1`
  interno; nunca IP de terceros. OK.

## Otros puntos revisados

- **`ScanError` no genérico:** 4 variantes distintas (`ToolNotAvailable`,
  `InsufficientPrivileges`, `Ssh(#[from] SshError)`, `NmapFailed { exit_code, stderr }`),
  `thiserror`, sin `String`/`Box<dyn Error>` como retorno. Conforme a
  `docs/architecture.md` §"Manejo de errores" y `docs/conventions.md`.
- **`stderr` truncado:** `NmapFailed.stderr` se trunca a `STDERR_MAX_BYTES = 2000`
  respetando límites UTF-8 (`truncate_utf8`, `src/scanner.rs:239-248`). Test
  `interpret_other_nonzero_exit_is_nmap_failed_with_truncated_stderr` (entrada de
  5000 bytes → ≤ 2004).
- **Centinela `exit_code == -1`:** `interpret` no lo confunde con un exit real —
  con stderr vacío no matchea `ToolNotAvailable` ni `InsufficientPrivileges`,
  cae en `NmapFailed { exit_code: -1 }`. Test
  `interpret_signal_terminated_is_nmap_failed` lo confirma.
- **Async correcto:** `russh` es async nativo; `run_scan_with` sólo hace `await`
  sobre `SshSession::run_command`. Sin llamadas bloqueantes.
- **Sin scope creep:** `git diff` muestra sólo `src/scanner.rs`,
  `feature_list.json` (status `pending` → `in_progress`), `progress/current.md`,
  y los nuevos `tests/scanner.rs` + `progress/impl_nmap_execution.md`. No se tocó
  `Cargo.toml`, `ssh`, `parser`, `repository`, `lib`, `domain`.
- **Rustdoc:** todo ítem público (`Timing` + variantes, `ScanOptions` + campos,
  `ScanError` + variantes + campos, `run_scan`, `run_scan_with`) documentado;
  `cargo doc` limpio.

## Cambios requeridos

Ninguno. Feature lista para cerrar: el leader puede pasar `feature_list.json`
feature 5 → `done` y añadir la entrada correspondiente a `progress/history.md`.

## Observaciones menores (no bloquean)

1. `progress/impl_nmap_execution.md` dice "13 tests unitarios" pero hay 14 en
   `src/scanner.rs` (y `cargo test` reporta 36 en total). Discrepancia de conteo
   en el informe, sin impacto.
2. `ScanOptions.detection_flags` es un `Vec<String>` totalmente reemplazable: un
   llamador interno podría inyectar flags agresivos. El rustdoc lo advierte y el
   default es seguro; aceptable para una API interna del servicio. Si en el
   futuro `config`/`messaging` exponen esto al exterior, conviene validar los
   flags contra una allowlist (`-sV`, `--script vuln`).

# Implementación — Feature 5 `nmap_execution`

Estado: implementada + verificada (`./init.sh` exit 0). Pendiente de review.
Feature sigue en `in_progress` en `feature_list.json` (no la marco `done` yo).

## Archivos

- `src/scanner.rs` — reemplazado el stub por la implementación completa + tests
  unitarios (`#[cfg(test)] mod tests`, sin Docker).
- `tests/scanner.rs` — nuevo, tests de integración con `testcontainers`
  (`#[ignore = "requiere Docker"]`).
- `feature_list.json` — feature 5 `pending` → `in_progress`.
- `progress/current.md` — bitácora.
- `Cargo.toml` — **sin cambios**. No hicieron falta dependencias nuevas
  (`thiserror`, `tracing`, `testcontainers`, `secrecy` ya estaban).

## API pública añadida en `src/scanner.rs`

- `async fn run_scan(session: &SshSession, target_ip: IpAddr, has_sudo: bool) -> Result<String, ScanError>`
  — delega en `run_scan_with(.., &ScanOptions::default())`.
- `async fn run_scan_with(session, target_ip, has_sudo, &ScanOptions) -> Result<String, ScanError>`
  — variante configurable. Se eligió el patrón `run_scan` + `run_scan_with`
  (en vez de un solo `run_scan` con `Option<ScanOptions>`) por ser el más
  idiomático y dejar la ruta corta sin ceremonia.
- `struct ScanOptions { detection_flags: Vec<String>, timing: Timing }` + `Default`.
- `enum Timing { Paranoid..Insane }` (`-T0`..`-T5`).
- `enum ScanError` (`thiserror`, variantes distintas, sin genérico):
  `ToolNotAvailable`, `InsufficientPrivileges`, `Ssh(#[from] SshError)`,
  `NmapFailed { exit_code: i32, stderr: String }`.

Privadas: `build_command` (construcción pura del comando) e `interpret`
(clasificación pura de `CommandOutput` → `Result<String, ScanError>`), ambas
testeadas directamente.

## Decisiones de diseño y alcance de seguridad

- **Defaults autorizados** (`docs/security-scope.md`): `ScanOptions::default()`
  = `-sV --script vuln` + `-oX -` + `-T2`. El doc de `security-scope` autoriza
  explícitamente un default conservador de timing aquí (a diferencia de los
  timeouts de config, feature 2, que no pueden tener default). Documentado en
  el rustdoc del módulo y de `ScanOptions`.
- **Timing por defecto: `-T2` (`Timing::Polite`)**. `security-scope.md`
  §"Límite de las capacidades de escaneo" pide "un valor por defecto
  conservador ... evitar `-T4`/`-T5`". Se eligió `-T2` sobre `-T3` (el default
  propio de nmap) porque `-T2` "usa menos ancho de banda y recursos del
  objetivo", alineado con el objetivo declarado de "minimizar el riesgo de
  degradar el servicio del objetivo". Test `default_timing_is_conservative` lo
  fija.
- **Sólo detección**: default nunca incluye scripts `exploit`/`intrusive`; el
  rustdoc de `ScanOptions` advierte que un `detection_flags` personalizado
  debe mantenerse dentro de `-sV`/`--script vuln`.
- **sudo** (`security-scope.md` §"Escalación de privilegios"): `has_sudo == true`
  → prefijo `sudo -n ` (no interactivo, falla rápido) + `-O`. `has_sudo == false`
  → ni `sudo` ni `-O`.
- **Target**: `target_ip: IpAddr`; se interpola vía `to_string()` (sólo
  dígitos/`.`/`:`), nunca una cadena arbitraria.
- **Clasificación de errores** (`interpret`, orden de decisión):
  1. `ToolNotAvailable` — `exit_code == 127`, o `stderr` (con exit ≠ 0) contiene
     `command not found` / `nmap: not found`.
  2. `InsufficientPrivileges` — sólo si `has_sudo`, exit ≠ 0 y `stderr` tipo
     `password is required` / `a terminal is required` / `no tty present` /
     `sudo: sorry`.
  3. `exit_code == 0` → `Ok(stdout)` (el XML).
  4. resto → `NmapFailed { exit_code, stderr }` con `stderr` truncado a
     ~2000 bytes respetando límites UTF-8 (no hay credenciales en el comando,
     pero se trunca igual). `exit_code == -1` (centinela "sin ExitStatus" de
     `CommandOutput`) cae aquí.
- Ningún `unwrap`/`expect`/`panic!` fuera de tests. Mensajes de error no
  mencionan credenciales (test `scan_error_display_does_not_mention_credentials`;
  el `#[error]` de `InsufficientPrivileges` se redactó para no incluir la
  palabra "contraseña").
- `run_scan_with` emite un `tracing::debug!(%command, ...)` — el comando sólo
  contiene `nmap`, flags e IP, sin secretos.

## Tests

### Unitarios (`src/scanner.rs`, sin Docker) — 14

- `build_command_with_sudo_prefixes_sudo_n_and_adds_os_detection`
- `build_command_without_sudo_omits_sudo_and_os_detection`
- `build_command_always_has_detection_flags_xml_timing_and_target`
- `default_timing_is_conservative` (verifica `-T2`, no `-T4`/`-T5`)
- `custom_options_are_reflected_in_the_command`
- `interpret_exit_127_is_tool_not_available`
- `interpret_sudo_missing_nmap_stderr_is_tool_not_available`
- `interpret_sudo_password_required_is_insufficient_privileges`
- `interpret_sudo_terminal_required_is_insufficient_privileges`
- `interpret_sudo_like_stderr_is_ignored_when_sudo_not_requested`
- `interpret_success_returns_stdout_xml`
- `interpret_other_nonzero_exit_is_nmap_failed_with_truncated_stderr`
- `interpret_signal_terminated_is_nmap_failed`
- `scan_error_display_does_not_mention_credentials`

### Integración (`tests/scanner.rs`, `#[ignore = "requiere Docker"]`) — 4

Patrón reusado de `tests/ssh.rs` (imagen `lscr.io/linuxserver/openssh-server`,
tag fijo `version-9.9_p2-r0`). Stub de `nmap` copiado con `with_copy_to` (bytes)
+ `chmod 0755` vía `container.exec` (con `CmdWaitFor::exit_code(0)`), porque
`with_copy_to` de bytes deja 0644 en `testcontainers` 0.24. El stub verifica que
recibió `-oX -` (si no, sale con código 2) y, si ve `-O`, exige `id -u == 0`
(así el caso con sudo comprueba que `sudo -n` elevó de verdad).

- `run_scan_without_sudo_returns_the_stub_xml` — `has_sudo=false` → XML del stub.
- `run_scan_with_sudo_elevates_and_returns_xml` — `has_sudo=true` → funciona y
  el stub confirma uid 0.
- `run_scan_without_nmap_installed_is_tool_not_available` — sin stub →
  `ScanError::ToolNotAvailable`.
- `run_scan_with_sudo_but_denied_is_insufficient_privileges` — stub de `sudo`
  falso en `/usr/local/bin/sudo` que deniega → `ScanError::InsufficientPrivileges`.

**Nota sobre la imagen**: `SUDO_ACCESS=true` en `linuxserver/openssh-server`
sólo concede `sudo` **con** contraseña cuando el usuario tiene contraseña (y
aquí la necesitamos para el auth SSH del cliente, que sólo soporta contraseña).
Su script de init hace `echo "$USER ALL=(ALL) ALL" >> /etc/sudoers` *después*
del `@includedir`, así que un fichero en `/etc/sudoers.d` no lo puede anular.
Por eso el helper `start_target(passwordless_sudo=true)` reescribe la regla vía
`exec` como root: `sed -i '/^scanuser ALL=/d' /etc/sudoers` + append
`scanuser ALL=(ALL) NOPASSWD: ALL`. Es setup de test contra un contenedor
local de laboratorio, no toca la lógica del servicio.

## Verificación

`./init.sh` → exit 0:
- `cargo fmt --check` limpio
- `cargo clippy --all-targets -- -D warnings` limpio
- `cargo test` — 36 unit + 0 fail (los 9 de integración quedan `ignored`)
- `cargo test -- --ignored` — 4 (scanner) + 5 (ssh) pasan con contenedores reales
- `cargo doc --no-deps` limpio (sin warnings de intra-doc links)

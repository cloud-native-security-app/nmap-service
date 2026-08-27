# Review — feature 4 `ssh_client`

**Veredicto:** APPROVED

Revisor: reviewer. Fecha: 2026-08-27. Rama: `feature/ssh_client`.

## Ejecución de `./init.sh` (hecha por el revisor)

`./init.sh` → exit 0, `[OK] Entorno listo`.

- `cargo fmt --check` → sin diferencias.
- `cargo clippy --all-targets -- -D warnings` → sin warnings (cubre `tests/ssh.rs`).
- `cargo test` (sin Docker) → 22 unit tests, 22 passed (8 nuevos de `ssh.rs`).
- `cargo test -- --ignored` → **5 tests de integración con Docker real, 5 passed**
  (contenedor `lscr.io/linuxserver/openssh-server:version-9.9_p2-r0` levantado
  vía `testcontainers`, ~3.3 s). No hubo "no pude probar por Docker".
- `cargo doc --no-deps` → genera sin warnings (`#![deny(missing_docs)]` activo).

## Checklist C1–C5

- **C1** [x] — 4 archivos base + 4 docs presentes; `./init.sh` exit 0.
- **C2** [x] — solo la feature 4 en `in_progress`; `progress/current.md` describe
  la sesión activa; features `done` (1–3) siguen con tests verdes.
- **C3** [x] — `src/` solo contiene los módulos previstos; `russh 0.63` y las
  features `time`/`net` de tokio están justificadas (ver abajo); sin
  `println!`/`dbg!`/`unwrap`/`panic!` fuera de tests; `cargo doc` limpio.
- **C4** [x] — `tests/ssh.rs` es el test de integración del módulo `ssh` contra
  contenedor Docker real vía `testcontainers`, nunca contra IP real; `cargo test`
  > 0 y verde; clippy limpio. (scanner/repository/messaging aún `pending` —
  deberán aportar los suyos en sus features.)
- **C5** [x] — sin archivos basura sin trackear (`tests/`, `progress/*.md` son
  legítimos). Cierre de sesión (mover a `history.md`, marcar `done`) queda para
  el leader tras esta aprobación.

## Los 7 criterios de `acceptance`

### 1. `connect(...) -> Result<SshSession, SshError>` async — CUMPLE
Firma real: `connect(host, port, user, credentials, store, timeouts)`.
Desviación (`port`, `store`, `timeouts`) documentada tanto en el rustdoc del
módulo (`src/ssh.rs` líneas 17–30) como en `progress/impl_ssh_client.md` y es
razonable: `port` (contenedores no usan 22), `store` (sin él no hay TOFU,
aprobado por el usuario), `timeouts` como `Duration` explícitos (respeta la
lección de feature 2: ningún timeout hardcodeado; `SshTimeouts` no define
defaults, vienen de `config`). NO se marca como incumplimiento.

### 2. `run_command(cmd: &str) -> Result<CommandOutput, SshError>` — CUMPLE
`CommandOutput { stdout: String, stderr: String, exit_code: i32 }`. stderr se
toma de `ExtendedData { ext: 1 }`, exit de `ExitStatus`. `exit_code` es `i32`
con centinela `-1` si el server cierra sin `exit-status` (muerte por señal),
decisión documentada. Verificado por tests de integración 1 y 2 (stdout exacto
`"hola-mundo\n"` / stderr `"fallo-remoto\n"` + exit 7).

### 3. Trait `HostKeyStore` + impl en memoria — CUMPLE
Firma literal del acceptance: `known_fingerprint(&self, host: &str) -> Option<Fingerprint>`
y `remember(&mut self, host: &str, fingerprint: Fingerprint)`. Supertrait `: Send`
añadido (necesario para `Handler + Send + 'static` de russh) — adición inocua.
`InMemoryHostKeyStore` (`HashMap`) con `new`/`Default`.

### 4. TOFU en `connect()` — CUMPLE
`verify_fingerprint` (usada por `check_server_key`): host desconocido → `remember`
+ acepta; igual → acepta; distinto → NO sobrescribe, marca `mismatch`
(`AtomicBool`) y devuelve `Ok(false)` → russh aborta el handshake → `connect`
devuelve `SshError::HostKeyMismatch { host }` **antes de intentar autenticar**
(la conexión se rechaza, no continúa). Cubierto por unit tests
`tofu_decision_*` y por el test de integración 5.

### 5. Variantes distintas de `SshError` — CUMPLE
`AuthFailed`, `Timeout`, `Unreachable(String)`, `HostKeyMismatch { host }` son
variantes separadas (+ `Protocol(String)` / `Io(String)` tipadas como catch-all,
no un `String` genérico de retorno). `from_russh` mapea sin parsear texto
(timeouts→Timeout, IO de red→Unreachable, NotAuthenticated/NoAuthMethod→AuthFailed).

### 6. Credenciales nunca en logs ni errores — CUMPLE
- `grep tracing src/ssh.rs` → **cero** ocurrencias.
- `expose()` aparece **solo** en la línea 435, el punto exacto de
  `authenticate_password`.
- Ninguna variante de `SshError` ni ningún `#[error(...)]` contiene la credencial
  (`HostKeyMismatch` solo lleva `host`; `Unreachable` solo host + motivo de red).
- `Verifier` no deriva `Debug` y no tiene campo de credencial; `SshSession` tiene
  `Debug` manual que no expone `handle` ni secreto.
- `SshCredentialsRef` (domain) ya redacta en `Debug`/`Display`/`Serialize`.
- Unit test `ssh_error_display_never_mentions_credentials` cubre las 6 variantes.

### 7. Tests de integración con `testcontainers` + los 6 comportamientos — CUMPLE
5 tests `#[tokio::test]` + `#[ignore = "requiere Docker"]` en `tests/ssh.rs`,
todos verdes contra contenedor real. Cobertura de los 6 comportamientos:

| Comportamiento del acceptance | Test |
|---|---|
| conexión exitosa | `connect_succeeds_and_runs_remote_command` |
| fallo de auth | `connect_with_wrong_password_fails_with_auth_failed` |
| comando remoto devuelve stdout esperado | `connect_succeeds_and_runs_remote_command` (assert exacto) + `run_command_captures_stderr_and_nonzero_exit_code` |
| primera conexión guarda el fingerprint | `first_connection_stores_fingerprint_and_second_is_accepted` (1ª mitad) |
| segunda conexión mismo host lo acepta | `first_connection_stores_fingerprint_and_second_is_accepted` (2ª mitad) |
| host key distinta (MITM) → `HostKeyMismatch` | `changed_host_key_is_rejected_with_host_key_mismatch` |

El test 4 cubre 2 comportamientos (guardar + aceptar) → 6 comportamientos en
5 tests. El caso MITM usa el "Enfoque A" recomendado en
`progress/explore_testcontainers_sshd.md` (sembrar un fingerprint incorrecto en
el store antes de `connect`), que ejerce exactamente el branch de rechazo del
acceptance sin depender de puertos fijos ni reinicio de sshd. Aceptable.

## Verificaciones adicionales

- **`Cargo.toml`**: `russh = { version = "0.63", default-features = false, features = ["ring"] }`
  justificado (explore doc + informe: backend `ring` evita toolchain C de
  `aws-lc-sys`). **No** se añadió `ssh-key` como dep directa (se usa el reexport
  `russh::keys::ssh_key::PublicKey`). tokio `time` (para `tokio::time::timeout`)
  y `net` justificadas. Deps mínimas. (C3)
- **`Fingerprint`** deriva `Serialize`/`Deserialize` → feature 7 (Mongo) podrá
  persistirlo. Unit test `fingerprint_json_round_trip_preserves_digest`.
- **Verificación de host key nunca deshabilitada**: `check_server_key` devuelve
  `Ok(trusted)` (nunca `Ok(true)` incondicional); `Certificate(_) => Ok(false)`.
  No hay bypass "para tests".
- **Sin scope creep**: cambios solo en `Cargo.toml`, `Cargo.lock`,
  `feature_list.json`, `progress/`, `src/ssh.rs`, `tests/ssh.rs`. `src/lib.rs`
  (`run()`) intacto; no se tocó scanner/parser/repository/messaging.
- **Rustdoc** en todo ítem público; `cargo doc --no-deps` limpio.
- **Sin `unwrap`/`expect`/`panic!`** fuera de `#[cfg(test)]` (verificado por grep
  en líneas 1–448 de `src/ssh.rs`). En `verify_fingerprint` el `Mutex`
  envenenado se recupera con `into_inner()` en vez de panicar.
- **Timeouts**: ningún valor hardcodeado; `SshTimeouts { connect, command }` se
  pasa como parámetro con `Duration` explícitos.

## Observaciones menores (NO bloqueantes)

1. `CommandOutput.exit_code: i32` con centinela `-1`: funcional y documentado.
   Una futura variante explícita (p. ej. `TerminatedBySignal`) sería más limpia
   si el scanner necesita distinguir señal de exit real — considerar en feature 5.
2. `client::Config::default()` no fija `inactivity_timeout`; hoy se cubre con
   `tokio::time::timeout` en connect y run_command. Suficiente para esta feature.
3. El caso MITM no usa dos contenedores con host keys reales distintas (Enfoque
   B); el Enfoque A empleado es el recomendado por la investigación y ejerce el
   mismo branch. Sin acción requerida.

## Cambios requeridos

Ninguno.

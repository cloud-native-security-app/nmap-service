# Implementación feature 4 — `ssh_client`

Estado: implementada y verificada (`./init.sh` verde, incl. `cargo test -- --ignored`
con Docker real). Pendiente de revisión y de marcar `done`.

## Qué se hizo

### `Cargo.toml`
- `russh = { version = "0.63", default-features = false, features = ["ring"] }`.
  Se usa el backend `ring` (no el `aws-lc-rs` por defecto) para evitar la
  toolchain C/cmake de `aws-lc-sys` y mantener el build ligero; `ring` cubre
  curve25519 + aes-gcm/ctr + ed25519, suficiente para OpenSSH moderno.
- **No** se añadió `ssh-key` como dependencia directa: el único tipo externo que
  aparece en la API pública (`russh::keys::ssh_key::PublicKey`, parámetro de
  `Fingerprint::from_host_public_key`) es accesible vía el reexport de `russh`.
- `tokio`: se añadieron las features `time` (para `tokio::time::timeout`) y `net`.

### `src/ssh.rs` (API pública, todo con rustdoc; `#![deny(missing_docs)]` activo)
- `Fingerprint` — newtype sobre `[u8; 32]` (digest SHA-256 crudo). `Clone,
  PartialEq, Eq, Debug, Serialize, Deserialize`. Constructores
  `from_host_public_key(&PublicKey)` (usa `key.fingerprint(HashAlg::Sha256)`) y
  `from_sha256_bytes([u8; 32])` (tests / rehidratar desde Mongo). `openssh_format()`
  + `Display` → `SHA256:<base64-sin-padding>` (base64 implementado a mano, sin dep
  nueva).
- `trait HostKeyStore: Send` con `known_fingerprint` / `remember` (firma literal
  del acceptance).
- `InMemoryHostKeyStore` (`HashMap<String, Fingerprint>`) + `Default` + `new`.
- `CommandOutput { stdout: String, stderr: String, exit_code: i32 }`. Se eligió
  `i32`: el `exit-status` de SSH es `u32`, pero se usa `-1` como centinela cuando
  el servidor cierra el canal sin enviar `exit-status` (p. ej. muerte por señal).
  stdout/stderr se decodifican con `from_utf8_lossy`.
- `SshTimeouts { connect: Duration, command: Duration }` — sin defaults en el
  módulo; los valores vienen de `config` (feature 2).
- `SshError` (`thiserror`): variantes **distintas** `AuthFailed`, `Timeout`,
  `Unreachable(String)`, `HostKeyMismatch { host }`, y catch-all tipado
  `Protocol(String)` / `Io(String)`. `SshError::from_russh(err, endpoint)` mapea
  `russh::Error` (timeouts → `Timeout`; `IO` con `ErrorKind` de red →
  `Unreachable("host:port: <kind>")`; `NotAuthenticated`/`NoAuthMethod` →
  `AuthFailed`; resto → `Protocol`/`Io`). Ningún mensaje contiene credenciales ni
  material de clave (test lo verifica).
- `Verifier` (interno, sin `Debug`, sin credencial): implementa
  `russh::client::Handler`. `check_server_key` recibe
  `&russh::keys::PublicKeyOrCertificate` (verificado contra el fuente de russh
  0.63.1; en la variante `PublicKey { key, .. }`); certificados → `Ok(false)`.
  Delega en `verify_fingerprint(store, host, current)`:
  desconocido → `remember` + acepta; igual → acepta; distinto → marca
  `mismatch` (`Arc<AtomicBool>` compartido con `connect`) y devuelve `Ok(false)`.
  Nunca `Ok(true)` incondicional.
- `connect(host, port, user, credentials, store, timeouts)`:
  `tokio::time::timeout(timeouts.connect, russh::client::connect(...))`; si el
  handshake falla y `mismatch` está marcado → `SshError::HostKeyMismatch { host }`
  (russh devuelve `Error::UnknownKey` cuando `check_server_key` da `Ok(false)`).
  Auth solo por password vía `credentials.expose()` en el punto exacto de
  `handle.authenticate_password`. `AuthResult::Failure` → `AuthFailed`.
- `SshSession::run_command(&self, cmd)`: `channel_open_session` → `exec(true, cmd)`
  → bucle `channel.wait()` acumulando `Data` / `ExtendedData { ext: 1 }` /
  `ExitStatus`, todo bajo `tokio::time::timeout(timeouts.command)`.
- `Debug` manual para `SshSession` (no expone handle ni credencial).

### Desviación de firma respecto al `acceptance` (documentada, como con `ip` en feat. 3)
El acceptance dice `connect(host, user, credentials)`. La firma real es
`connect(host, port, user, credentials, store, timeouts)`:
- `port`: el objetivo no siempre escucha en 22 (contenedores usan 2222 + puerto
  de host aleatorio).
- `store: &Arc<Mutex<dyn HostKeyStore>>`: obligatorio; sin él no hay TOFU.
  Se usa `std::sync::Mutex` (no `tokio::sync::Mutex`): así el supertrait `: Send`
  del acceptance basta para que `Arc<Mutex<dyn HostKeyStore>>` sea `Send + Sync`
  y `Verifier` cumpla `Handler + Send + 'static` que exige `russh::client::connect`.
  `check_server_key` no hace `.await` mientras tiene el lock.
- `timeouts: SshTimeouts`: `Duration` explícitos de connect/comando; no se
  hardcodea ningún default (regla de feature 2).

Extensión futura no implementada (fuera de acceptance): auth por clave pública
(`russh` la soporta con `authenticate_publickey` / `PrivateKeyWithHashAlg`).

## Tests

### Unitarios (`src/ssh.rs`, sin Docker) — 8, todos verdes
- `in_memory_store_remembers_and_returns_fingerprint` (remember→known; desconocido→None).
- `fingerprint_json_round_trip_preserves_digest` (serde round-trip).
- `fingerprint_openssh_format_has_expected_shape`.
- `ssh_error_display_never_mentions_credentials` (Display de las 6 variantes sin
  términos de credencial).
- `tofu_decision_{unknown_host_is_remembered_and_accepted, matching_fingerprint_is_accepted,
  changed_fingerprint_is_rejected}` — cubren `verify_fingerprint`, la función real
  que usa `check_server_key` (no una réplica).

### Integración (`tests/ssh.rs`, `#[tokio::test]` + `#[ignore = "requiere Docker"]`) — 5, todos verdes
Imagen `lscr.io/linuxserver/openssh-server:version-9.9_p2-r0` (tag fijo real,
pulleado y verificado). Wait: `WaitFor::message_on_stdout("[ls.io-init] done.")`.
`get_host()` + `get_host_port_ipv4()`. `ContainerAsync` vivo toda la duración.
1. `connect_succeeds_and_runs_remote_command` — `echo` → stdout + exit 0.
2. `run_command_captures_stderr_and_nonzero_exit_code` — `sh -c 'echo … >&2; exit 7'`.
3. `connect_with_wrong_password_fails_with_auth_failed`.
4/5. `first_connection_stores_fingerprint_and_second_is_accepted` — 1er connect
   guarda el fingerprint en el store vacío; 2º connect al mismo host lo acepta y
   el fingerprint no cambia.
6. `changed_host_key_is_rejected_with_host_key_mismatch` — Enfoque A: se siembra
   `Fingerprint::from_sha256_bytes([0x42; 32])` para ese host antes de `connect`
   → `SshError::HostKeyMismatch`.

## Verificación
`./init.sh` → todo `[OK]`: `cargo fmt --check`, `cargo clippy --all-targets -D warnings`
(incluye `tests/`), `cargo test` (22 unit), `cargo test -- --ignored` (5 de Docker),
`cargo doc --no-deps`.

## Archivos tocados
- `Cargo.toml`, `Cargo.lock` (deps)
- `src/ssh.rs` (implementación + tests unitarios)
- `tests/ssh.rs` (nuevo, tests de integración)
- `feature_list.json` (status feature 4 → `in_progress`)

# Bitácora histórica (append-only)

> Cada vez que se cierra una sesión, su resumen se añade aquí.
> No edites entradas anteriores. Solo añades al final.

---

## 2026-08-27 — Feature 1: scaffolding

- **Agente:** implementer + reviewer
- **Estado final:** `done` (reviewer aprobó, ver `progress/review_scaffolding.md`)

### Qué se hizo

- Inicializado el crate Rust `nmap-service` (edition 2021, `publish = false`):
  lib `nmap_service` (`src/lib.rs`) + bin delgado `ms-nmap` (`src/main.rs`).
- `src/lib.rs`: `#![deny(missing_docs)]`, `pub mod` para `config`, `domain`,
  `messaging`, `parser`, `repository`, `scanner`, `ssh`, y `pub async fn run()`
  stub con rustdoc.
- `src/main.rs`: `#[tokio::main]` + `tracing_subscriber::fmt::init()` + llamada a
  `nmap_service::run()`.
- Stubs de módulo (solo `//!` doc) para cada capa. `messaging` como
  `src/messaging/mod.rs` con `pub mod consumer;` / `pub mod publisher;` sin lógica.
- `Cargo.toml`: deps `tokio` (rt-multi-thread, macros), `tracing`,
  `tracing-subscriber`, `serde` (derive), `serde_json`; dev-dep `testcontainers`.

### Verificación

- `./init.sh` → EXIT 0. `cargo fmt --check`, `cargo clippy --all-targets -- -D
  warnings`, `cargo build`, `cargo test` (0 tests), `cargo doc --no-deps`: todo limpio.
- Sin tests propios: el scaffolding no introduce lógica pura testeable.

### Notas / seguimiento

- Docker no disponible en el shell de la sesión; irrelevante para esta feature
  (no hay tests `#[ignore = "requiere Docker"]` todavía). Relevante para features
  4, 5, 7, 10.
- Detalle: `progress/impl_scaffolding.md`, `progress/review_scaffolding.md`.
- Commit pendiente (lo gestiona el leader).

---

## 2026-08-27 — Feature 2: config

- **Agente:** implementer + reviewer
- **Estado final:** `done` (reviewer aprobó en ronda 2, ver `progress/review_config.md`)

### Qué se hizo

- `src/config.rs` deja de ser stub e implementa la carga/validación de config
  desde variables de entorno.
- `struct Config`: `mongo_uri: String`, `broker_endpoint: String`,
  `broker_credential: secrecy::SecretString`, `ssh_connect_timeout: Duration`,
  `ssh_command_timeout: Duration`. `#[derive(Debug)]` seguro (la credencial se
  redacta).
- `Config::from_env() -> Result<Config, ConfigError>` (sync) delega en la
  función privada `from_source(lookup: Fn(&str) -> Option<String>)` que
  contiene toda la validación.
- `ConfigError` (`thiserror`): `MissingVar(&'static str)` e
  `InvalidValue { var: &'static str, reason: String }`. Sin `String` genérico,
  sin panic/unwrap/expect fuera de tests.
- Nombres de env vars como `pub const` (`MS_NMAP_MONGO_URI`,
  `MS_NMAP_BROKER_ENDPOINT`, `MS_NMAP_BROKER_CREDENTIAL`,
  `MS_NMAP_SSH_CONNECT_TIMEOUT_SECS`, `MS_NMAP_SSH_COMMAND_TIMEOUT_SECS`).
  **Todas requeridas**; ausente/vacía → `MissingVar`. Timeout no numérico o
  cero → `InvalidValue`. Ningún valor de configuración hardcodeado.
- Deps nuevas: `secrecy = "0.10"` (redacción de la credencial del Broker en
  `Debug`; la reutiliza la feature 3) y `thiserror = "2"` (convención de
  errores por módulo). No se añadió `serial_test`: los tests inyectan un
  `HashMap` en `from_source`, no mutan `std::env`.

### Verificación

- 8 tests unitarios en `#[cfg(test)] mod tests` de `src/config.rs`: camino
  feliz con valores concretos (strings, `Duration`, credencial expuesta),
  `MissingVar` tipado para cada variable requerida (incl. ambos timeouts),
  variable vacía tratada como ausente, `InvalidValue` para timeout no numérico
  y cero, y `Debug` no filtra la credencial.
- `./init.sh` → EXIT 0: `cargo fmt --check`, `cargo clippy --all-targets -- -D
  warnings`, `cargo test` (8 passed), `cargo doc --no-deps` todo limpio.

### Notas / seguimiento

- Ronda 1 recibió CHANGES_REQUESTED: tenía defaults de timeout hardcodeados
  (`DEFAULT_SSH_*`) y trataba los timeouts como opcionales, contra
  `docs/architecture.md` §Capas p.1. Ronda 2 los eliminó y volvió requeridas
  las env vars de timeout.
- Detalle: `progress/impl_config.md`, `progress/review_config.md`.
- Commit pendiente (lo gestiona el leader).

---

## 2026-08-27 — Feature 3: domain_model

- **Agente:** implementer + reviewer
- **Estado final:** `done` (reviewer aprobó en ronda 2, ver `progress/review_domain_model.md`)

### Qué se hizo

- `src/domain.rs` deja de ser stub e implementa los tipos puros del dominio (sin IO).
- `ScanRequest { correlation_id: CorrelationId, ip: IpAddr, network_user: String,
  ssh_credentials_ref: SshCredentialsRef, has_sudo: bool, requested_by: String }`.
  El campo IP se llama `ip` (nombre Rust + clave serde), como fija el acceptance
  y esperan el mensaje del Broker (feature 8) y el documento Mongo (feature 7).
- `SshCredentialsRef`: newtype sobre `secrecy::SecretString` con `Debug`/`Display`
  redactados (`[REDACTED]`) e impls serde manuales: `Serialize` emite `[REDACTED]`,
  `Deserialize` lee el valor real (`String::deserialize` + `SecretString::from`).
  El round-trip de `ScanRequest` es intencionadamente lossy en la credencial;
  la credencial nunca se re-serializa hacia Mongo/Broker (docs/security-scope.md).
- `ScanResult { host: IpAddr, ports: Vec<PortFinding>, vulnerabilities:
  Vec<VulnFinding>, scanned_at: OffsetDateTime }` — exactamente los 4 campos del
  acceptance; `scanned_at` serializado como RFC 3339.
- `PortFinding { port: u16, protocol, state, service: Option<String>,
  version: Option<String> }`; `VulnFinding { id: Option<String>, severity,
  description: String, nse_script: String }`.
- Enums con encoding string estable: `Protocol` (Tcp/Udp), `PortState` (6 estados
  de nmap), `Severity` (Unknown..Critical). Newtype `CorrelationId` (transparent).
- Deps nuevas: `time = { version = "0.3", features = ["serde-well-known"] }` (dep
  directa nueva, justificada por `scanned_at` RFC 3339; elegida sobre `chrono`
  por menor superficie) y `time`/`macros` como dev-dependency (`datetime!` en
  tests). `secrecy` sin cambios respecto a feature 2 (`"0.10"`, sin features).

### Verificación

- 7 tests unitarios en `#[cfg(test)] mod tests` de `src/domain.rs`: round-trip
  JSON completo de `ScanResult` (3 puertos en distintos estados/protocolos + 1
  vuln con CVE, `assert_eq!` del valor completo); `scanned_at` sale como RFC 3339;
  `Debug` y JSON de `ScanRequest` no filtran la credencial; `Display`/`Debug` de
  `SshCredentialsRef` redactados y valor recuperable vía `expose()`;
  deserialización de credencial real desde mensaje del Broker; encoding estable
  de los enums.
- `./init.sh` → EXIT 0: `cargo fmt --check`, `cargo clippy --all-targets -- -D
  warnings`, `cargo test` (15 passed: 8 config + 7 domain), `cargo doc --no-deps`
  todo limpio.

### Notas / seguimiento

- Ronda 1 recibió CHANGES_REQUESTED: campo IP nombrado `target_ip` en vez de
  `ip` (contrato del acceptance); feature `serde` de `secrecy` añadida sin uso;
  justificación incorrecta de `time` en el informe ("dep transitiva previa").
  Ronda 2 corrigió los tres puntos.
- Los cambios en `docs/architecture.md` (§"Hexagonal parcial") y `feature_list.json`
  (feature id:11 `hexagonal_ports`) no los hizo el implementer; ya estaban staged
  al arrancar la sesión. Los gestiona el leader.
- Detalle: `progress/impl_domain_model.md`, `progress/review_domain_model.md`.
- Commit pendiente (lo gestiona el leader).

---

## 2026-08-27 — Feature 4: ssh_client

- **Agente:** implementer + reviewer
- **Estado final:** `done` (reviewer aprobó sin cambios, ver `progress/review_ssh_client.md`)

### Qué se hizo

- `src/ssh.rs` deja de ser stub e implementa el cliente SSH hacia el objetivo con
  verificación de host key por TOFU.
- Dep nueva: `russh = { version = "0.63", default-features = false, features = ["ring"] }`
  (backend `ring`, no `aws-lc-rs`, para evitar toolchain C/cmake). No se añadió
  `ssh-key` como dep directa (se usa el reexport `russh::keys::ssh_key`).
  `tokio` gana las features `time` y `net`.
- API pública (rustdoc en todo ítem; `#![deny(missing_docs)]`):
  - `Fingerprint` — newtype sobre `[u8; 32]` (SHA-256 crudo), `Clone/PartialEq/Eq/
    Debug/Serialize/Deserialize`; `from_host_public_key(&PublicKey)`,
    `from_sha256_bytes([u8;32])`, `openssh_format()`/`Display` → `SHA256:<base64>`.
  - `trait HostKeyStore: Send` (`known_fingerprint`/`remember`) +
    `InMemoryHostKeyStore` (`HashMap`, `Default`/`new`).
  - `CommandOutput { stdout: String, stderr: String, exit_code: i32 }` (`-1` si el
    canal se cierra sin `exit-status`).
  - `SshTimeouts { connect, command }` (Durations explícitos, sin defaults en el módulo).
  - `SshError` (`thiserror`): variantes distintas `AuthFailed`, `Timeout`,
    `Unreachable(String)`, `HostKeyMismatch { host }`, catch-all tipado
    `Protocol(String)`/`Io(String)`. Mensajes sin credenciales ni material de clave.
  - `connect(host, port, user, credentials, store, timeouts) -> Result<SshSession, SshError>`
    (async) y `SshSession::run_command(&self, cmd)`.
- TOFU: `Verifier` (interno, sin `Debug`, sin credencial) implementa
  `russh::client::Handler::check_server_key` (param `&PublicKeyOrCertificate`,
  verificado contra russh 0.63.1). Delega en `verify_fingerprint(store, host, fp)`:
  desconocido → `remember` + acepta; igual → acepta; distinto → marca
  `Arc<AtomicBool>` compartido y devuelve `Ok(false)`. `connect` traduce el error
  resultante a `HostKeyMismatch { host }`. Nunca `Ok(true)` incondicional.
- Auth solo por password vía `credentials.expose()` en el punto exacto de
  `authenticate_password`. Auth por clave pública queda como extensión futura
  (fuera de acceptance).

### Desviación de firma (documentada, como `ip` en feature 3)

- Acceptance: `connect(host, user, credentials)`. Real:
  `connect(host, port, user, credentials, store, timeouts)`.
- `port`: el objetivo no siempre escucha en 22. `store`: obligatorio para TOFU;
  se usa `std::sync::Mutex` (no `tokio`) para que el supertrait `: Send` baste
  para `Verifier: Handler + Send + 'static`. `timeouts`: `Duration` explícitos
  de `config`, sin hardcodear (regla de feature 2).

### Verificación

- 8 tests unitarios en `src/ssh.rs` (sin Docker): store remember/None, `Fingerprint`
  round-trip serde y formato OpenSSH, `SshError` Display sin términos de credencial,
  y 3 sobre `verify_fingerprint` (la fn real que usa `check_server_key`):
  unknown→remember+accept, match→accept, mismatch→reject sin sobrescribir.
- 5 tests de integración en `tests/ssh.rs` (`#[tokio::test]` + `#[ignore = "requiere Docker"]`)
  contra `lscr.io/linuxserver/openssh-server:version-9.9_p2-r0`: conexión OK +
  `echo`; stderr + exit≠0; password mala → `AuthFailed`; 1ª conexión guarda
  fingerprint y 2ª al mismo host lo acepta; host key sembrada distinta → `HostKeyMismatch`
  (Enfoque A).
- `./init.sh` → EXIT 0: `cargo fmt --check`, `cargo clippy --all-targets -- -D warnings`
  (incluye `tests/`), `cargo test` (22 passed), `cargo test -- --ignored` (5 passed
  con Docker real), `cargo doc --no-deps`.

### Notas / seguimiento

- Aprobado en ronda 1 sin cambios requeridos.
- Detalle: `progress/impl_ssh_client.md`, `progress/review_ssh_client.md`.
- `progress/explore_ssh_crate.md` y `progress/explore_testcontainers_sshd.md`
  (investigación previa del leader) quedan como referencia.
- Commit pendiente (lo gestiona el leader).

---

## 2026-08-27 — Feature 5: nmap_execution

- **Agente:** implementer + reviewer
- **Estado final:** `done` (reviewer aprobó sin cambios, ver `progress/review_nmap_execution.md`)

### Qué se hizo

- `src/scanner.rs` deja de ser stub e implementa la ejecución remota de `nmap`
  sobre una `SshSession` ya establecida, devolviendo el XML crudo de `stdout`.
- `Cargo.toml` **sin cambios**: no hicieron falta dependencias nuevas.
- API pública (rustdoc en todo ítem):
  - `async fn run_scan(session: &SshSession, target_ip: IpAddr, has_sudo: bool)
    -> Result<String, ScanError>` — delega en `run_scan_with(.., &ScanOptions::default())`.
  - `async fn run_scan_with(session, target_ip, has_sudo, &ScanOptions)` — variante
    configurable (patrón `run_scan` + `run_scan_with`, el más idiomático).
  - `struct ScanOptions { detection_flags: Vec<String>, timing: Timing }` + `Default`
    (`-sV --script vuln` + `-oX -` + `-T2`).
  - `enum Timing { Paranoid..Insane }` (`-T0`..`-T5`).
  - `enum ScanError` (`thiserror`, variantes distintas, sin genérico):
    `ToolNotAvailable`, `InsufficientPrivileges`, `Ssh(#[from] SshError)`,
    `NmapFailed { exit_code: i32, stderr: String }`.
  - Privadas testeadas directamente: `build_command` (construcción pura del
    comando) e `interpret` (clasificación pura `CommandOutput` → `Result`).
- Alcance de seguridad (`docs/security-scope.md`):
  - Defaults de escaneo autorizados explícitamente aquí (a diferencia de los
    timeouts de config, feature 2). Documentado en rustdoc.
  - Timing por defecto `-T2` (`Timing::Polite`), elegido sobre `-T3` por
    "usa menos ancho de banda y recursos del objetivo" — alineado con
    §"Límite de las capacidades de escaneo" (evitar `-T4`/`-T5`).
  - Sólo detección: default nunca incluye scripts `exploit`/`intrusive`.
  - `has_sudo == true` → prefijo `sudo -n ` + `-O`; `false` → ni `sudo` ni `-O`.
  - `target_ip: IpAddr` interpolada vía `to_string()` (sólo dígitos/`.`/`:`).
  - Sin `unwrap`/`expect`/`panic!` fuera de tests. Mensajes de error sin
    credenciales (el `#[error]` de `InsufficientPrivileges` se redactó para no
    incluir la palabra "contraseña").
- Clasificación de errores (`interpret`, orden): `ToolNotAvailable` (exit 127 /
  stderr `command not found` / `nmap: not found`) → `InsufficientPrivileges`
  (sólo si `has_sudo`, exit≠0, stderr tipo `password/terminal is required`) →
  `exit 0` → `Ok(stdout)` → resto `NmapFailed` con stderr truncado a ~2000 B
  respetando límites UTF-8. `exit_code == -1` (centinela de `CommandOutput`)
  cae en `NmapFailed`.

### Verificación

- 14 tests unitarios en `#[cfg(test)] mod tests` de `src/scanner.rs` (sin Docker):
  construcción de comando con/sin sudo, flags/timing/IP siempre presentes,
  `-T2` conservador, opciones personalizadas reflejadas, y mapeo de
  `CommandOutput` → cada variante de `ScanError` (incl. sudo-like ignorado sin
  `has_sudo`, éxito, exit genérico truncado, señal, Display sin credenciales).
- 4 tests de integración en `tests/scanner.rs` (`#[tokio::test]` +
  `#[ignore = "requiere Docker"]`) contra
  `lscr.io/linuxserver/openssh-server:version-9.9_p2-r0`, patrón de `tests/ssh.rs`.
  Stub de `nmap` copiado con `with_copy_to` (bytes) + `chmod 0755` vía
  `container.exec` (`CmdWaitFor::exit_code(0)`); el stub verifica `-oX -` y, si
  ve `-O`, exige `id -u == 0`. Casos: sin sudo → XML; con sudo → XML y uid 0;
  sin stub → `ToolNotAvailable`; stub de `sudo` que deniega → `InsufficientPrivileges`.
- `./init.sh` → EXIT 0: `cargo fmt --check`, `cargo clippy --all-targets -- -D
  warnings`, `cargo test` (36 passed: config 8 + domain 7 + ssh 7 + scanner 14),
  `cargo test -- --ignored` (scanner 4 + ssh 5, con Docker real),
  `cargo doc --no-deps` limpio.

### Notas / seguimiento

- Aprobado en ronda 1 sin cambios requeridos.
- Ajuste de test (no toca lógica del servicio): `SUDO_ACCESS=true` en la imagen
  sólo da `sudo` sin contraseña si el usuario no tiene contraseña (y aquí la
  necesitamos para el auth SSH). El helper `start_target(passwordless_sudo=true)`
  reescribe la regla vía `exec` como root
  (`sed -i '/^scanuser ALL=/d' /etc/sudoers` + append `NOPASSWD`), porque el
  init de la imagen añade la regla con contraseña *después* del `@includedir`.
- Detalle: `progress/impl_nmap_execution.md`, `progress/review_nmap_execution.md`.
- Commit pendiente (lo gestiona el leader).

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

---

## 2026-08-27 — Feature 6: xml_parser

- **Agente:** implementer + reviewer
- **Estado final:** `done` (reviewer aprobó en ronda 2, ver `progress/review_xml_parser.md`)

### Qué se hizo

- `src/parser.rs` deja de ser stub e implementa la conversión del XML de `nmap`
  (`-oX`) en `ScanResult`. Función pura y síncrona, sin IO.
- `Cargo.toml`: + `roxmltree = "0.21"` (XML DOM de solo lectura, Rust puro, sin
  `unsafe`/FFI; elegido sobre `quick-xml` porque el informe de una IP es un árbol
  pequeño que se navega mejor que con eventos). Se parsea con
  `ParsingOptions { allow_dtd: true, .. }` porque `nmap` emite `<!DOCTYPE nmaprun>`.
- API pública (rustdoc en todo ítem, incl. variantes/campos de enum):
  - `fn parse(xml: &str) -> Result<ScanResult, ParseError>`.
  - `enum ParseError` (`thiserror`): `MalformedXml(String)`,
    `UnexpectedStructure { detail }`, `InvalidValue { field, value }`,
    `MultipleHosts`. Nunca `panic!`.
  - `const MAX_DESCRIPTION_LEN: usize = 800`.
- Mapeo (documentado en el rustdoc del módulo): `host` de `<address
  addrtype="ipv4|ipv6">`; `scanned_at` de `<runstats><finished time>` (epoch s)
  con fallback a `<nmaprun start>`; los 6 `PortState` crudos de nmap; `version` =
  `product` + `version` + `(extrainfo)`; `vulnerabilities` de los `<script>` bajo
  `<port>` y `<hostscript>` (estado NSE `VULNERABLE`/`LIKELY VULNERABLE` o CVEs
  sin `NOT VULNERABLE`; un `VulnFinding` por CVE distinto; severidad de
  `risk factor:`/`severity:`, del `cvss` más alto, o `VULNERABLE (Exploitable)`
  → High; descripción recortada a 800 chars). Host down → `ScanResult` vacío;
  sin `<host>` → `UnexpectedStructure`; varios `<host>` → `MultipleHosts`.
- Sin `unwrap`/`expect`/`panic!` fuera de tests.

### Fixtures — `tests/fixtures/` (7, XML real de Nmap 7.98)

Generados con Docker (`instrumentisto/nmap`) contra contenedores propios en redes
aisladas (`openssh-server`, `httpd:2.4.49`, `metasploitable2`, IPs sin asignar).
Procedencia y comando exacto de cada uno en `tests/fixtures/README.md` (lo exige
`docs/security-scope.md`). Ninguno editado a mano. Contenedores y redes
destruidos al terminar. Archivos: `open_ports_service_version.xml`,
`no_open_ports.xml`, `filtered_ports.xml`, `host_down.xml`, `no_host_element.xml`,
`multiple_hosts.xml`, `vuln_findings.xml`.

### Verificación

- 11 tests unitarios en `#[cfg(test)] mod tests` de `src/parser.rs`: un test por
  fixture verificando contenido concreto del `ScanResult` (IP, puertos exactos
  con estado/servicio/versión, `scanned_at` como epoch, CVE + severidad + script
  de cada vuln); `filtered`/`open|filtered` de punta a punta por `parse()`;
  `parse_state` de todos los estados crudos; `MalformedXml` (cabecera real
  truncada), `UnexpectedStructure` (XML sin `<nmaprun>` y `<nmaprun>` sin
  `<host>`), `MultipleHosts`, `InvalidValue` (`portid` fuera de rango u16).
- `./init.sh` → EXIT 0: `cargo fmt --check`, `cargo clippy --all-targets -- -D
  warnings`, `cargo test` (47 passed), `cargo test -- --ignored` (ssh 5 +
  scanner 4, sin regresión), `cargo doc --no-deps` limpio.

### Notas / seguimiento

- Ronda 1 recibió CHANGES_REQUESTED: `filtered`/`open|filtered` solo se probaban
  contra la fn privada `parse_state`, nunca por `parse()` hasta un `ScanResult`.
  Ronda 2 añadió el fixture real `filtered_ports.xml` (TCP `filtered` + UDP
  `open|filtered` en un mismo `<host>`) y el test
  `parses_filtered_and_open_filtered_ports_end_to_end`.
- Detalle: `progress/impl_xml_parser.md`, `progress/review_xml_parser.md`.
- Commit pendiente (lo gestiona el leader).

---

## 2026-08-27 — Feature 7: mongo_persistence

- **Agente:** implementer + reviewer
- **Estado final:** `done` (reviewer aprobó sin cambios, ver `progress/review_mongo_persistence.md`)

### Qué se hizo

- **A. `src/ssh.rs` — `HostKeyStore` pasa a async** (decisión del usuario, dentro
  del alcance de esta feature):
  - `#[async_trait::async_trait] pub trait HostKeyStore: Send + Sync` (se añade
    `Sync`): `known_fingerprint(&self, host) -> Result<Option<Fingerprint>, HostKeyStoreError>`
    y `remember(&self, host, Fingerprint) -> Result<(), HostKeyStoreError>` (`&self`,
    ya no `&mut self`).
  - Nuevo error propio `HostKeyStoreError` (`thiserror`): `Unavailable(String)`
    (almacén de respaldo caído → la conexión SSH se aborta) y `Corrupt(String)`
    (registro con formato inesperado). Variante `SshError::HostKeyStore(#[from]
    HostKeyStoreError)`.
  - Tipo compartido pasa de `Arc<Mutex<dyn HostKeyStore>>` a `Arc<dyn HostKeyStore>`
    (sin `Mutex` externo). `Verifier`, `connect(store: &Arc<dyn HostKeyStore>)`,
    `verify_fingerprint(store: &dyn HostKeyStore, ...)` ahora `async`. `Verifier`
    comparte con `connect` un slot `Arc<Mutex<Option<HostKeyStoreError>>>` además
    del `AtomicBool` de mismatch; `check_server_key` devuelve `Ok(false)` en
    ambos casos (nunca acepta una clave sin verificar).
  - `InMemoryHostKeyStore`: `entries: std::sync::Mutex<HashMap<..>>` (guard tomado
    y soltado dentro de cada método, sin cruzar `.await`; sus `async fn` no hacen
    `.await` real y nunca devuelven `Err`).
  - Regresión features 4 y 5: `tests/ssh.rs` (5) y `tests/scanner.rs` (4) verdes
    con Docker; 3 unit tests de `ssh.rs` convertidos a `#[tokio::test]` + 2 nuevos
    (`HostKeyStoreError` en Display, hex round-trip vía `SshError`).

- **B. `src/repository.rs` — `MongoRepository`** (struct concreto, NO trait; el
  puerto `ScanResultRepository` es feature 11):
  - `async fn connect(uri, db_name) -> Result<Self, RepoError>`: crea el `Client`,
    hace `run_command({ping:1})` para fallar rápido, guarda las `Collection`. `Clone`.
  - `async fn save(&self, result: &ScanResult, correlation_id: &CorrelationId)
    -> Result<ScanId, RepoError>` — firma ampliada (documentada como desviación,
    igual que `connect` en features 4/5): `ScanResult` no lleva `correlation_id`.
  - `async fn find_by_id(&self, id: &ScanId)` y `find_by_correlation_id(&self,
    correlation_id: &CorrelationId)` → `Result<Option<ScanResult>, RepoError>`;
    id inexistente → `Ok(None)`. `find_by_correlation_id` usa `find_one().sort({timestamp:-1})`.
  - Documento `StoredScan { _id: ObjectId, correlation_id, timestamp (RFC3339
    string), result: <ScanResult anidado> }`.
  - `ScanId`: newtype `#[serde(transparent)]` sobre el hex del `ObjectId`
    (`new`/`as_str`/`Display`/`FromStr`/`From<ObjectId>`).
  - `RepoError` (`thiserror`): `ConnectionFailed` (ServerSelection/Io/DnsResolve/
    ConnectionPoolCleared), `Serialization` (BSON + `ScanId` inválido), `Backend`
    (resto). `impl From<mongodb::error::Error>` con `match *err.kind`. Sin panics.
  - `scanned_at` (y `timestamp`) se persisten como **string RFC3339** (vía el
    `#[serde(with = "time::serde::rfc3339")]` que ya tiene `ScanResult`), no
    `bson::DateTime`: consistente con el JSON al Broker, sin dep extra de `bson`.
    Trade-off documentado en el rustdoc de módulo (no se hacen rangos temporales
    sobre esos campos en este servicio).

- **C. `src/repository.rs` — `MongoHostKeyStore`** implementa el `HostKeyStore`
  async sobre `Collection<Document>` (colección `ssh_host_keys`), obtenido con
  `MongoRepository::host_key_store()`. `remember` = `update_one(...).upsert(true)`
  con `$set` del fingerprint y `$setOnInsert` de `first_seen` (idempotente).
  Documento `{ "_id": "<host>", "fingerprint_sha256_hex": "<64 hex>",
  "first_seen": "<rfc3339>" }` (hex, no el `[u8;32]` crudo; `fingerprint_from_hex`
  valida longitud 64 y dígitos → `HostKeyStoreError::Corrupt`).

- **D. `Cargo.toml`:** `+ mongodb = "3"` (driver oficial async exigido por
  `docs/architecture.md`), `+ async-trait = "0.1"` movido a `[dependencies]`
  (necesario para `Arc<dyn HostKeyStore>` con `async fn`; antes solo dev-transitiva
  vía testcontainers). **`futures-util` NO añadido** (no se iteran cursores:
  `find_one().sort()`) — desviación consciente de `progress/explore_mongo.md`.
  `tokio` **sin** `"sync"` (toda la sincronización usa `std::sync::Mutex` sin
  cruzar `.await`).

### Verificación

- 9 tests unitarios nuevos en `src/repository.rs`: `ScanId` round-trip
  (string/serde/`From<ObjectId>`/rechazo no-hex); `RepoError::from` (E/S de red →
  `ConnectionFailed`, BSON → `Serialization`) y Display sin términos de credencial;
  `fingerprint_to_hex`/`from_hex` round-trip + rechazo de longitud/dígitos;
  `connect_to_unreachable_mongo_is_connection_failed` (`#[tokio::test]` sin Docker,
  `mongodb://127.0.0.1:1/?serverSelectionTimeoutMS=500` → `ConnectionFailed`,
  cubre el `ServerSelection` real que es `#[non_exhaustive]`).
- `tests/repository.rs` nuevo — 6 tests `#[tokio::test]` + `#[ignore = "requiere
  Docker"]`, contenedor `mongo:7`, base `db-nmap-test` (nunca producción):
  save+find_by_id (asserts de contenido: puertos, CVE, severidad, `scanned_at`),
  save+find_by_correlation_id (+ desconocido → `None`), id inexistente → `Ok(None)`,
  forma del documento crudo (`correlation_id`/`timestamp`/`result.scanned_at` como
  strings, timestamp en rango), `MongoHostKeyStore` remember/known + host
  desconocido → `None` + persistencia entre instancias nuevas (`Client` nuevo) +
  `remember` idempotente.
- `./init.sh` → EXIT 0: `cargo fmt --check`, `cargo clippy --all-targets -- -D
  warnings`, `cargo test` (56 passed: config 8 + domain 7 + parser 11 + scanner 14
  + ssh 7 + repository 9), `cargo test -- --ignored` (15 passed: repository 6 +
  scanner 4 + ssh 5, con Docker real, sin regresión), `cargo doc --no-deps` limpio.
- Sin `unwrap`/`expect`/`panic!` fuera de `#[cfg(test)]` (`now_rfc3339` usa
  `unwrap_or_default()`, admisible).

### Notas / seguimiento

- Aprobado en ronda 1 sin cambios requeridos.
- Archivos tocados: `src/ssh.rs`, `src/repository.rs` (era stub), `tests/repository.rs`
  (nuevo), `tests/ssh.rs`, `tests/scanner.rs`, `Cargo.toml`/`Cargo.lock`,
  `feature_list.json`.
- Detalle: `progress/impl_mongo_persistence.md`, `progress/review_mongo_persistence.md`.
  Investigación previa: `progress/explore_mongo.md`.
- Commit pendiente (lo gestiona el leader): incluir `tests/repository.rs` y los
  `progress/*.md` nuevos.

---

## 2026-08-27 — Feature 8: broker_consumer

- **Agente:** implementer + reviewer
- **Estado final:** `done` (reviewer aprobó sin cambios, ver
  `progress/review_broker_consumer.md`; 65 unit + 15 Docker verdes, sin regresión)

### Qué se hizo

- `src/messaging/consumer.rs` reescrito (era stub `//!`):
  - `trait ScanRequestSource` (async vía `async-trait`, `Send + Sync`,
    dyn-compatible): `next_request(&self) -> Result<Option<IncomingScanRequest>, ConsumeError>`.
    Modelo pull; `Ok(None)` = stream cerrado; `Err` no fatal para mensaje
    ilegible, `Transport` para fallo del broker.
  - `IncomingScanRequest`: wrapper `#[non_exhaustive]` sobre `ScanRequest`
    (campo `pub request`), punto de extensión para un token de ack/nack cuando
    se decida la tecnología de broker. Hoy no hay ack.
  - `parse_scan_request(&[u8]) -> Result<ScanRequest, ConsumeError>` en dos
    etapas (`from_slice` a `Value` -> `MalformedPayload`; `from_value` a
    `ScanRequest` -> `InvalidSchema`). Sin `panic`/`unwrap`.
  - `ConsumeError` (`thiserror`): `MalformedPayload` / `InvalidSchema` /
    `Transport`. El payload crudo nunca entra al error; `redact_credential`
    borra el valor de `ssh_credentials_ref` de la descripción de `serde` por si
    llegó con un tipo inesperado (ver `docs/security-scope.md`).
  - `log_request_received(&ScanRequest)`: `tracing::info!` con `correlation_id`
    y campos no sensibles, nunca la credencial. `pub` para reuso por adaptadores
    reales; el stub la llama al entregar.
  - `InMemoryScanRequestSource` (stub): cola FIFO tras `Mutex`; `from_requests`
    y `from_raw_messages`. Un mensaje inválido se entrega como `Err` y no
    interrumpe los siguientes (parseo = responsabilidad de la fuente).
- 9 tests unitarios nuevos en el módulo (mensaje válido -> campos; JSON roto;
  basura no-UTF8; campo ausente; credencial no filtrada en el error x2; orden
  FIFO + `None`; error-luego-continúa; logging sin credencial).
- Sin dependencias nuevas en `Cargo.toml`.
- `./init.sh` verde (fmt + clippy `-D warnings` + unit + Docker `--ignored` +
  doc), exit 0. Sin regresión en features 1-7.
- Detalle: `progress/impl_broker_consumer.md`, `progress/review_broker_consumer.md`.
- Commit pendiente (lo gestiona el leader): incluir `src/messaging/consumer.rs`
  y los `progress/*.md` nuevos.

---

## 2026-08-27 — Feature 9: broker_publisher

- **Agente:** implementer + reviewer
- **Estado final:** `done` (reviewer aprobó; corrección de flakiness aplicada
  después, ver `progress/review_broker_publisher.md` y
  `progress/impl_broker_publisher.md`)

### Qué se hizo

- Reescrito `src/messaging/publisher.rs` (era stub `//!`), con simetría de estilo
  respecto a `consumer.rs`:
  - `trait ScanResultSink` (`#[async_trait]`, `Send + Sync`, dyn-compatible),
    método único `publish(&self, &ScanOutcome) -> Result<(), PublishError>`.
  - `ScanOutcome` (`Serialize`/`Deserialize`, `#[serde(tag = "status",
    rename_all = "snake_case")]`): `Completed { correlation_id, result }` y
    `Failed { correlation_id, reason }`. Ambas variantes llevan `correlation_id`
    aparte porque `ScanResult` no lo transporta; `ms-analisis` lo necesita para
    correlacionar éxito y fallo. Shape del mensaje documentado en el rustdoc
    (timestamp del ejemplo como `+00:00`, salida real de `time::serde::rfc3339`).
  - `PublishError` (`thiserror`): `Transport(String)` y `Serialization(String)`.
  - `encode_outcome(&ScanOutcome) -> Result<Vec<u8>, PublishError>`: cuerpo JSON
    canónico reutilizable por los adaptadores reales.
  - `log_outcome_published(&ScanOutcome)` + función pura privada
    `outcome_log_fields` (`correlation_id`, `status`, `counts`): sólo campos no
    sensibles, estructuralmente incapaz de llevar el `reason` o el `ScanResult`.
  - `InMemoryScanResultSink` stub: `Mutex<Vec<ScanOutcome>>`, `published()` para
    inspección en tests; cada `publish` serializa, traza y guarda copia.
- `src/messaging/mod.rs`: doc del módulo actualizada (ya no "stub del
  scaffolding"; enlaza los dos traits).
- Sin dependencias nuevas en `Cargo.toml`.
- 10 tests unitarios nuevos (serialización de `Completed` con shape concreto y
  puertos/vulns anidados, `Failed` con `correlation_id`+`reason`, round-trip,
  `encode_outcome`, accesor de `correlation_id`, stub registra éxito y fallo en
  orden, contrato de `reason`, campos de log para fallo/éxito, no-panic). Total
  75 unit verdes.

### Corrección post-review (flakiness)

- El test de logging original instalaba un `tracing_subscriber` global
  (`with_default` + `MakeWriter` en memoria), igual que el test análogo de
  `consumer.rs`. Al correr en paralelo, la caché global de interés de `tracing`
  tiene una carrera conocida -> el evento se descartaba de forma no determinista
  y `./init.sh` quedaba en rojo intermitente.
- Fix: se extrajo la construcción de campos de log a la función pura
  `outcome_log_fields`; los tests la verifican directamente, sin `tracing` ni
  subscriber global. Sin dependencia nueva (`serial_test` descartado).
- Verificado: `./init.sh` 5/5 verde (exit 0), `cargo test --lib` 10/10 verde.

### Verificación

- `./init.sh` verde (fmt + clippy `-D warnings` + 75 unit + Docker `--ignored`
  15 verdes + doc), exit 0, 5 ejecuciones seguidas. Sin regresión en features 1-8.
- Detalle: `progress/impl_broker_publisher.md`, `progress/review_broker_publisher.md`.
- Commit pendiente (lo gestiona el leader): incluir `src/messaging/publisher.rs`,
  `src/messaging/mod.rs` y los `progress/*.md` nuevos.

---

## 2026-08-27 — feature 10 `scan_pipeline_wiring` (implementer)

Orquestación end-to-end del pipeline `consumer -> ssh -> scanner -> parser ->
repository -> publisher`. Estado final: **done** (reviewer aprobó en ronda 2).

### Cambios

- **`src/config.rs`** (ampliación mínima del wiring): 2 env vars requeridas
  nuevas, mismo patrón que feature 2 (sin default; ausente/vacía/inválida ->
  `ConfigError`):
  - `MS_NMAP_SSH_PORT` (`SSH_PORT_VAR`) -> `Config::ssh_port: u16`, validada con
    `parse_port` (no numérico / fuera de `1..=65535` -> `InvalidValue`). El
    `ScanRequest` no trae puerto SSH; es config del despliegue.
  - `MS_NMAP_MONGO_DB` (`MONGO_DB_VAR`) -> `Config::mongo_db: String` para
    `MongoRepository::connect(uri, db_name)`. Decisión: env var explícita, no
    derivar del path del URI (consistencia con el resto de la config).
  - 5 tests nuevos + asserts en el test de config válida.
- **`src/pipeline.rs`** (nuevo, `pub mod pipeline;` en `lib.rs`):
  - `ScanPipeline { repo: MongoRepository, host_key_store: Arc<dyn HostKeyStore>,
    sink: Arc<dyn ScanResultSink>, ssh_port: u16, ssh_timeouts: SshTimeouts,
    scan_options: ScanOptions }`, deriva `Clone` (barato; `run` clona por
    solicitud para despacharla a `tokio::spawn`).
  - `process_one(&self, ScanRequest)`: `ssh::connect` -> `scanner::run_scan_with`
    -> `parser::parse` -> `repo.save` -> `sink.publish(Completed)`. Cualquier
    `Err` de etapa 1-4 -> `ScanOutcome::failed(correlation_id, err.to_string())`
    publicado. Nunca propaga error ni hace panic. Si `sink.publish` falla ->
    `tracing::error!` (con `correlation_id`, sin credenciales) y termina, sin
    reintentos. Loggea inicio y desenlace.
  - `run(&self, Arc<dyn ScanRequestSource>)`: bucle consumidor. `Ok(Some)` ->
    `tokio::spawn(process_one)` (concurrencia real). `Ok(None)` -> sale.
    `MalformedPayload|InvalidSchema` -> `warn!` y continúa. `Transport` ->
    `error!` y sale (reconexión/backoff = responsabilidad del adaptador de
    broker concreto, aún sin decidir). Al salir, `JoinSet` espera las tareas en
    vuelo.
  - Helper libre `next_valid_request` (extraído para testear el bucle sin
    Docker). 3 tests unitarios sin Docker (skip de mensajes envenenados + fin
    en `Ok(None)`; parada en `Transport`; construcción del `Failed` con
    `correlation_id` correcto y `reason` sin credencial).
- **`src/lib.rs`** — `run()` como composition root: `Config::from_env` ->
  `MongoRepository::connect(&mongo_uri, &mongo_db)` -> `Arc<dyn HostKeyStore> =
  Arc::new(repo.host_key_store())` (**el store de producción es el de Mongo**,
  no el `InMemory`) -> construye `ScanPipeline` con `SshTimeouts` de la config,
  `cfg.ssh_port` y `ScanOptions::default()`. No existe adaptador de broker real
  todavía (features 8/9 sólo tienen stubs `InMemory`) -> `run()` valida config,
  comprueba Mongo, deja el pipeline construido, emite `tracing::warn!` y retorna
  limpio. Firma `run()` sin cambios (`-> ()`), `main.rs` intacto, sin `anyhow`.
- **`src/messaging/publisher.rs`** (revisión ronda 1): 2 doc-comments (líneas
  170/174) — enlace intra-doc a ítem privado `outcome_log_fields` -> texto
  plano (0 warnings con `RUSTDOCFLAGS="-D warnings" cargo doc --no-deps`).
- **`Cargo.toml`**: sin cambios (`tokio::task::JoinSet` ya disponible vía
  `rt-multi-thread`).

### Tests

- **`tests/scan_pipeline.rs`** (nuevo, e2e `#[ignore = "requiere Docker"]`). El
  stub de `nmap` vuelca el fixture real **`tests/fixtures/vuln_findings.xml`**
  (ya documentado en `tests/fixtures/README.md`; no se añadió fixture nuevo —
  revisión ronda 1).
  - `stub_fixture_parses_into_the_expected_scan_result` (sin Docker): valida el
    parseo del fixture (host 172.18.0.4, puertos 21/6667 open, `vsftpd 2.3.4`,
    2 hallazgos `CVE-2011-2523`).
  - `valid_request_flows_through_pipeline_and_is_published_and_persisted`
    (criterios 1 y 2): sshd + stub nmap + `mongo:7`; 1 `Completed` con
    `correlation_id` y contenido correctos; `ScanResult` en Mongo
    (`find_by_correlation_id`); una segunda instancia de `MongoHostKeyStore` ve
    el fingerprint TOFU (prueba que el pipeline usó el store de Mongo).
  - `stage_failure_is_published_as_failed_outcome_without_crashing`
    (criterio 3): objetivo sin stub de nmap -> `ScanError::ToolNotAvailable` ->
    1 `Failed` con `correlation_id`, `reason` menciona nmap y no filtra la
    credencial; sin panic; nada persistido.
  - `multiple_requests_are_processed_concurrently` (criterio 4):
    `#[tokio::test(flavor = "multi_thread")]`, 3 solicitudes concurrentes al
    mismo sshd -> 3 `Completed`, cada uno con su `correlation_id`, los 3
    persistidos. Warm-up TOFU previo para que la contención sea del pipeline y
    no del upsert inicial del trust store.

### Revisión

- Ronda 1: `CHANGES_REQUESTED` — (1) fixture nuevo sin procedencia documentada
  -> eliminado `tests/fixtures/pipeline_stub_scan.xml`, el e2e reutiliza
  `vuln_findings.xml`; (2) 2 warnings de `cargo doc` en `publisher.rs` ->
  corregidos.
- Ronda 2: **APROBADO**.
- Detalle: `progress/impl_scan_pipeline_wiring.md`,
  `progress/review_scan_pipeline_wiring.md`.

### Verificación

- `./init.sh` verde y estable: 3 corridas tras implementación + 3 tras revisión
  ronda 1 + 2 al cierre (exit 0, 0 `[FAIL]`), incluye `cargo test -- --ignored`
  con contenedores reales sshd + `mongo:7`.
- `cargo clippy --all-targets -- -D warnings`, `cargo fmt --check`,
  `RUSTDOCFLAGS="-D warnings" cargo doc --no-deps` limpios.
- Sin regresión: 82 tests unitarios + integración de features 1-9 verdes. Sin
  `unwrap`/`expect`/`panic!` fuera de tests. Sin llamadas bloqueantes en async.
- Commit pendiente (lo gestiona el leader): `src/config.rs`, `src/pipeline.rs`,
  `src/lib.rs`, `src/messaging/publisher.rs`, `tests/scan_pipeline.rs`,
  `feature_list.json`, `progress/*.md`.

## 2026-08-27 — feature 11 `hexagonal_ports` (implementer)

Refactor sin cambio de comportamiento: extrae puertos (traits) para ssh,
scanner y repository e inyecta sus adaptadores en `lib::run()` vía
`ServicePorts`. Red de seguridad: 82 tests previos, todos verdes antes y
después (83 tras añadir un test unitario sin Docker).

### Cambios

- `src/ssh.rs`: puertos `RemoteExecutor` (`connect -> Box<dyn RemoteSession>`) y
  `RemoteSession` (`run_command`), dyn-compatibles vía `async-trait`.
  `impl RemoteSession for SshSession`; adaptador `RusshExecutor` (unit struct)
  que delega en la función libre `connect`. No se borró la función libre ni los
  métodos inherentes (`tests/ssh.rs` los usa sin cambios).
- `src/scanner.rs`: puerto `NmapScanner` + adaptador `NmapCliScanner`. Las
  funciones libres `run_scan`/`run_scan_with` pasan a `&dyn RemoteSession`;
  `tests/scanner.rs` sin cambios (coerción `&SshSession` -> `&dyn RemoteSession`).
- `src/repository.rs`: puerto `ScanResultRepository`
  (`save`/`find_by_id`/`find_by_correlation_id`); `impl` para `MongoRepository`
  delegando en los métodos inherentes (conservados; `tests/repository.rs` los
  usa directo). `HostKeyStore`/`MongoHostKeyStore` intactos (ya eran puerto).
- `src/pipeline.rs`: `ScanPipeline` sobre `Arc<dyn ...>` de cada puerto +
  `PipelineConfig`. `new(ports: ServicePorts, config: PipelineConfig)`. Structs
  públicos `ServicePorts` y `PipelineConfig`. `run_stages` usa los puertos;
  `process_one`/`run` sin cambio de lógica. Test nuevo sin Docker: fallo de
  etapa SSH -> `ScanOutcome::Failed` sin fuga de credencial.
- `src/wiring.rs` (nuevo, `pub mod wiring`): composition root
  `service_ports_from_config(&Config) -> Result<ServicePorts, WiringError>`.
  Construye `RusshExecutor`, `NmapCliScanner`, `MongoRepository`, el
  `HostKeyStore` **de Mongo**, y `sink` = `InMemoryScanResultSink` (no hay
  adaptador real de broker; documentado).
- `src/lib.rs`: `run(ports, config, source: Option<Arc<dyn ScanRequestSource>>)`.
  `source == None` (caso actual) -> loggea "adaptador de broker pendiente" y
  retorna limpio, sin panic (comportamiento observable = feature 10).
- `src/main.rs`: delgado — `Config::from_env` -> `wiring` -> `run(..., None)`.
  Sin `anyhow`, sin dependencias nuevas.
- `tests/scan_pipeline.rs`: único cambio, `build_pipeline` arma `ServicePorts` +
  `PipelineConfig` con los adaptadores reales; lógica de los 3 e2e intacta.
- `docs/architecture.md`: §"Hexagonal parcial" -> "Hexagonal completo" con tabla
  puerto/adaptador y composition root; §Capas: añadidas `pipeline` y `wiring`.
- `Cargo.toml`: sin cambios.

### Revisión

- Ronda 1: **APROBADO** sin cambios requeridos.
- Detalle: `progress/impl_hexagonal_ports.md`, `progress/review_hexagonal_ports.md`.

### Verificación

- `./init.sh` verde y estable: 3 corridas tras implementación + 2 al cierre
  (exit 0, 0 `[FAIL]`), incluye `cargo test -- --ignored` con contenedores
  reales sshd + `mongo:7` (18 tests).
- `cargo test`: 83 unitarios verdes. `cargo clippy --all-targets -- -D warnings`,
  `cargo fmt --check`, `RUSTDOCFLAGS="-D warnings" cargo doc --no-deps` limpios.
- Sin `unwrap`/`expect`/`panic!` fuera de tests.
- Commit pendiente (lo gestiona el leader): `src/ssh.rs`, `src/scanner.rs`,
  `src/repository.rs`, `src/pipeline.rs`, `src/lib.rs`, `src/main.rs`,
  `src/wiring.rs`, `tests/scan_pipeline.rs`, `docs/architecture.md`,
  `feature_list.json`, `progress/*.md`.

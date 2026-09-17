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

---

## 2026-08-27 — Feature 12: containerization

- **Agente:** implementer + reviewer
- **Estado final:** `done` (reviewer aprobó sin cambios requeridos, ver
  `progress/review_containerization.md`)

### Qué se hizo

- **`Dockerfile`** (raíz, nuevo) — multi-stage, sin tocar `src/` ni `Cargo.toml`:
  - **Stage builder**: `rust:1.98-bookworm` pineado por digest
    (`sha256:82150a52...39922`). Capa previa de cacheo de dependencias (copia
    `Cargo.toml`/`Cargo.lock`, `src` dummy, `cargo build --release`, borra dummy);
    luego `COPY src`, `touch` de entrypoints y
    `cargo build --release --bin ms-nmap` + `strip`.
  - **Stage runtime**: `gcr.io/distroless/cc-debian12:nonroot` pineado por digest
    (`sha256:9dac0a79...182f`). Trae glibc + libgcc + `ca-certificates` + usuario
    `nonroot` (uid 65532), sin shell ni gestor de paquetes. `COPY --from=builder`
    del binario a `/usr/local/bin/ms-nmap`, `LABEL` OCI, `USER nonroot`,
    `ENTRYPOINT ["/usr/local/bin/ms-nmap"]`.
  - Sin `nmap` (corre en el objetivo vía SSH), sin `openssh-client` (`russh` es
    Rust puro), sin toolchain ni código fuente en la imagen final.
- **`.dockerignore`** (raíz, nuevo): excluye `target/`, `.git/`, `.gitignore`,
  `.claude/`, `progress/`, `docs/`, `tests/`, `*.md`, `Dockerfile`,
  `.dockerignore`. NO excluye `Cargo.toml`, `Cargo.lock`, `src/`.
- **`README.md`**: nueva sección "Despliegue (Docker)" — build, `docker run` con
  tabla de las 7 env vars requeridas (una descripción por variable), aclaración
  de que la imagen no lleva `nmap` ni servidor/puerto HTTP.
- **`docs/architecture.md`**: nueva sección "Despliegue" (imagen multi-stage, qué
  incluye —binario + certs CA— y qué no —toolchain, fuente, `nmap`,
  `openssh-client`—, usuario no-root, pin por tag+digest, `testcontainers`
  independiente del empaquetado).

### Verificación

- `docker build -t ms-nmap:dev .`: OK. En frío 2m47s; rebuild cacheado 2.8s.
  Imagen final: DISK USAGE 54.7 MB / CONTENT SIZE 14.2 MB (binario ~12 MB).
- Imagen final sin toolchain/fuente/nmap: verificado con `docker create` +
  `docker export | tar -tf -` (único match de `cargo|rustc|nmap|/app|target|.rs`
  es `usr/local/bin/ms-nmap`; `bin/` y `usr/bin/` vacíos). `docker history`: solo
  capas de la base distroless + LABEL + COPY del binario + USER + ENTRYPOINT.
- Usuario no-root: `docker inspect` → `User=nonroot`; corre con `--user 65532:65532`.
- `docker run` con las 7 env vars (Mongo inalcanzable): arranca, emite logs de
  `tracing`, falla al conectar a Mongo y sale limpio (exit 0), sin panic.
- `docker run` sin env vars: loggea `configuración inválida ... falta la variable
  de entorno requerida: MS_NMAP_MONGO_URI`, sale limpio (exit 0), sin panic.
- `./init.sh` → EXIT 0 (fmt + clippy `-D warnings` + `cargo test` + `cargo test
  -- --ignored` con Docker real + `cargo doc`). La feature no toca `src/`.

### Notas / seguimiento

- Aprobado en ronda 1 sin cambios requeridos.
- No se tocó `src/` ni `Cargo.toml`: el `main.rs` existente ya arranca y sale
  limpio sin panic en contenedor.
- Imagen de prueba `ms-nmap:dev` eliminada del daemon local al cerrar.
- Detalle: `progress/impl_containerization.md`, `progress/review_containerization.md`.
- Commit pendiente (lo gestiona el leader): `Dockerfile`, `.dockerignore`,
  `README.md`, `docs/architecture.md`, `feature_list.json`, `progress/*.md`.
- Con esta feature, las 12 del `feature_list.json` quedan en `done`.

---

## 2026-09-10 — Feature 13: vuln_enrichment

- **Agente:** implementer + reviewer
- **Estado final:** `done` (reviewer aprobó sin cambios requeridos, ver
  `progress/review_vuln_enrichment.md`)

### Qué se hizo

- **`src/domain.rs`**: nuevo enum `VulnSource` (`NmapNse`/`ExploitDb`,
  `#[serde(rename_all = "snake_case")]`). `VulnFinding` gana `source: VulnSource`
  (`#[serde(default = ...)]` → `NmapNse` para documentos previos a la feature) y
  `references: Vec<String>` (`#[serde(default)]`). `PortFinding` gana
  `cpes: Vec<String>` (`#[serde(default)]`). `sample_result()` y tests
  actualizados; nuevo test de deserialización con defaults para documentos
  pre-`vuln_enrichment`.
- **`src/parser.rs`**: `collect_cpes()` recoge los `<cpe>` hijos de `<service>`
  en `PortFinding.cpes`. Los `VulnFinding` de scripts NSE llevan
  `source: VulnSource::NmapNse`, `references: vec![]`. Asserts nuevos de `cpes`
  en los fixtures `open_ports_service_version.xml` y `vuln_findings.xml`.
- **`src/enrichment.rs`** (nuevo módulo, `pub mod enrichment;` en `lib.rs`):
  - `trait VulnEnricher` (`#[async_trait]`, dyn-compatible):
    `enrich(&self, &[PortFinding]) -> Result<Vec<VulnFinding>, EnrichError>`.
  - `enum EnrichError` (`thiserror`): `DataSource(String)`, `Backend(String)`.
  - `struct ExploitDbEnricher`: `from_csv_path(&str)` (async, carga vía
    `tokio::task::spawn_blocking` + crate `csv`) indexa `files_exploits.csv` en
    memoria. Matcher deliberadamente conservador: sólo puertos con versión
    detectada; query = tokens de `"<service> <version>"`; match = ≥2 tokens y
    todos como substring case-insensitive del título, más comprobación de que
    el `mayor.menor` de cualquier token numérico de versión aparece en el
    título. `id` = primer CVE de `codes`, `source: ExploitDb`, referencia a
    `exploit-db.com/exploits/<edb_id>`.
  - `struct CompositeVulnEnricher`: ejecuta todos los enrichers y concatena; un
    `Err` de uno se loggea (`tracing::warn!`) y no aborta a los demás.
  - 9 unit tests (match real vsftpd 2.3.4 → `CVE-2011-2523`, sin match, versión
    menor errónea, puerto sin versión, CSV inexistente → `DataSource`,
    extracción de CVE con `;`, `version_prefix`, composite concatena, composite
    tolera `Err`).
- **`src/config.rs`**: nueva env var requerida `MS_NMAP_EXPLOITDB_CSV`
  (`EXPLOITDB_CSV_VAR`), campo `Config::exploitdb_csv: String`, mismo patrón que
  el resto (ausente/vacía → `ConfigError::MissingVar`). 2 tests nuevos.
- **`src/pipeline.rs`**: `ServicePorts.enricher: Arc<dyn VulnEnricher>`.
  `run_stages` invoca `enricher.enrich(&result.ports)` entre `parser::parse` y
  `repo.save`; un `Err` se loggea con `tracing::warn!` y se continúa con
  `Vec::new()` (**best-effort**, nunca `ScanOutcome::Failed`).
  `merge_enrichment_findings` deduplica por CVE (`id`) contra los hallazgos ya
  presentes (incluida deduplicación intra-`extra`); sin `id`, deduplica por
  `description`. 2 tests unitarios del merge + doble `StubEnricher`.
- **`src/wiring.rs`**: `WiringError::Enrichment(#[from] EnrichError)`. Construye
  `ExploitDbEnricher::from_csv_path(&config.exploitdb_csv)` envuelto en
  `CompositeVulnEnricher`; si el CSV no carga, el servicio no arranca.
- **`Cargo.toml`**: `+ csv = "1"` (parser CSV Rust puro, sin FFI/egress).
- **`Dockerfile`**: nuevo stage `exploitdb` (reusa la base `rust:1.98-bookworm`
  ya pineada) que descarga `files_exploits.csv` de un **commit fijo** de
  `gitlab.com/exploit-database/exploitdb` vía `ADD --chmod=0644` (sin
  curl/bash). `COPY --from=exploitdb` a la imagen distroless final +
  `ENV MS_NMAP_EXPLOITDB_CSV=/opt/exploitdb/files_exploits.csv`. Imagen sigue
  sin shell/coreutils/`searchsploit`/`nmap`.
- **Docs**: `README.md` (env var + nota "offline"), `docs/architecture.md`
  (nueva capa `enrichment` entre `parser` y `repository`, puerto en la tabla
  hexagonal, diagrama de flujo, sección Despliegue), `docs/security-scope.md`
  (enriquecimiento ExploitDB = lookup local sin egress, detección pasiva igual
  categoría que `--script vuln`; nota sobre adaptadores de API futuros).
- **Tests/fixtures**: `tests/fixtures/exploitdb_sample.csv` — 20 filas
  **reales** extraídas por EDB-ID de `/usr/share/exploitdb/files_exploits.csv`
  (procedencia documentada en `tests/fixtures/README.md`, incluye `vsftpd 2.3.4`
  → `CVE-2011-2523` y `UnrealIRCd 3.2.8.1` → `CVE-2010-2075`). `tests/scan_pipeline.rs`
  actualizado: `build_pipeline` recibe un `Arc<dyn VulnEnricher>` real (cargado
  del fixture); el e2e con Docker verifica que el `ScanResult` publicado incluye
  un `VulnFinding` con `source: ExploitDb` (aportado por el puerto 6667 /
  `UnrealIRCd`, cuyo CVE no coincide con el que ya trae nmap y por tanto
  sobrevive al dedup) y que `CVE-2011-2523` (que sí trae nmap) no se duplica.
  `src/messaging/publisher.rs` y `tests/repository.rs` actualizados a los campos
  nuevos de `PortFinding`/`VulnFinding`.

### Revisión

- Ronda 1: **APROBADO** sin cambios requeridos (`docker build` OK, imagen
  ~67.5 MB sin bash/nmap, matcher conservador verificado, sin egress, 3
  corridas de `./init.sh` estables).
- Detalle: `progress/impl_vuln_enrichment.md`, `progress/review_vuln_enrichment.md`.

### Verificación

- `./init.sh` verde y estable: 4 corridas del implementer + 3 del reviewer + 1
  de cierre (exit 0, 0 `[FAIL]`), incluye `cargo test -- --ignored` con
  contenedores reales sshd + `mongo:7`.
- `cargo clippy --all-targets -- -D warnings`, `cargo fmt --check`,
  `RUSTDOCFLAGS="-D warnings" cargo doc --no-deps` limpios.
- `docker build` OK; imagen final 67.5 MB, sin shell/coreutils/`nmap`/`searchsploit`.
- Sin `unwrap`/`expect`/`panic!` fuera de tests. Adaptador ExploitDB sin egress
  de red. Sin regresión en features 1-12.
- Commit pendiente (lo gestiona el leader): `Cargo.toml`, `Cargo.lock`,
  `Dockerfile`, `README.md`, `docs/architecture.md`, `docs/security-scope.md`,
  `src/{lib,domain,parser,config,pipeline,wiring,enrichment}.rs`,
  `src/messaging/publisher.rs`, `tests/{scan_pipeline,repository}.rs`,
  `tests/fixtures/{exploitdb_sample.csv,README.md}`, `feature_list.json`,
  `progress/*.md`.
- Con esta feature, las 13 del `feature_list.json` quedan en `done`.

---

## 2026-09-11 — Feature 14: nvd_enrichment

- **Agente:** implementer + reviewer
- **Estado final:** `done` (reviewer aprobó sin cambios requeridos, ver
  `progress/review_nvd_enrichment.md`)

### Qué se hizo

Segundo adaptador de `VulnEnricher` (feature 13), esta vez **online**:
`NvdApiEnricher` consulta la API NVD 2.0 por CPE, con egress de red **opt-in**
y caché persistente en Mongo con TTL.

- **Split de módulo**: `src/enrichment.rs` (>500 líneas) se dividió en
  `src/enrichment/{mod.rs, exploitdb.rs, nvd.rs}`. `mod.rs` conserva
  `EnrichError`, el trait `VulnEnricher` y `CompositeVulnEnricher`;
  `exploitdb.rs` es `ExploitDbEnricher` reubicado sin cambios; `nvd.rs` es el
  adaptador nuevo.
- **`src/domain.rs`**: `VulnSource::Nvd` + test de encoding estable.
- **`src/enrichment/nvd.rs`** (nuevo): `NvdApiEnricher { client, api_key,
  base_url, cache, min_interval, last_request }`. `new`/`with_base_url`
  (constructor de test para apuntar a `wiremock`). Conversión CPE 2.2→2.3 pura
  (`cpe22_to_cpe23`, rellena con `*` los 7 campos que `nmap` no reporta).
  `enrich`: dedup de CPEs con `HashSet`, cache-first, rate limiting propio
  (`tokio::sync::Mutex<Option<Instant>>`; 6.5s sin `apiKey`, 0.7s con ella —
  límites documentados de NVD: 5/30s y 50/30s respectivamente), `EnrichError::
  Backend` por CPE sin abortar los demás. Mapeo de severidad: v3.1 > v3.0 > v2
  por `baseSeverity`; v2 sin `baseSeverity` usa umbrales NVD sobre `baseScore`
  (<4.0/4.0-6.9/≥7.0); sin métricas → `Unknown`. Trait `NvdCache` (`get`/`put`
  async) + `InMemoryNvdCache` (para tests sin Docker). Tests con `wiremock`
  (servidor mock local, cero llamadas reales a NVD): mapeo completo,
  conversión CPE con el CPE real del fixture, severidad (3 caminos), caché
  evita segunda llamada HTTP, dedup de CPEs repetidos, HTTP 500 en un CPE no
  aborta los demás, servidor caído → `Ok(vec![])` sin panic.
- **`src/repository.rs`**: nueva colección `nvd_cache`; `MongoNvdCache`
  implementa `NvdCache` (documento `{_id: <cpe23>, findings, cached_at:
  BsonDateTime}` — **desviación documentada**: `cached_at` es una fecha BSON
  nativa, no una cadena RFC 3339 como el resto del repositorio, porque el
  índice TTL de Mongo sólo funciona sobre fechas BSON reales).
  `MongoRepository::nvd_cache_store(ttl) -> Result<MongoNvdCache, RepoError>`
  (async, a diferencia de `host_key_store()`: asegura el índice TTL de forma
  idempotente, con fallback a `collMod` si el TTL ya existía con otro valor —
  MongoDB rechaza cambiarlo vía `createIndexes`).
- **`src/config.rs`**: `NVD_ENRICHMENT_ENABLED_VAR` (requerida, `"true"`/
  `"false"` estricto), `NVD_API_KEY_VAR` (genuinamente opcional),
  `NVD_CACHE_TTL_VAR` (requerida sólo si el enriquecimiento está habilitado).
  9 tests nuevos cubriendo los 4 caminos pedidos por el acceptance.
- **`src/wiring.rs`**: si `config.nvd_enrichment_enabled`, construye
  `NvdApiEnricher` (con `repo.nvd_cache_store(ttl)` como caché) y lo añade al
  `CompositeVulnEnricher` junto a `ExploitDbEnricher`; si no, el composite sólo
  lleva ExploitDB — cero llamadas de red posibles (verificado en código, no
  sólo en tests). `WiringError::InvalidNvdConfig` defensivo (invariante de
  `Config` que no debería romperse nunca). `clone_secret` reconstruye el
  `SecretString` de la API key porque `SecretString` no es `Clone`.
- **`Cargo.toml`**: `+ reqwest` (`default-features = false` + `rustls-tls`,
  mismo TLS que `mongodb`, sin OpenSSL/`native-tls`); `+ wiremock` (sólo
  dev-dependency).
- **Docs**: `docs/security-scope.md` (nueva sección "Enriquecimiento de
  vulnerabilidades desde la API NVD": egress opt-in, único dato enviado
  —el CPE—, caché, rate limiting, contrato best-effort), `docs/architecture.md`
  (tabla de puertos/adaptadores, capa `enrichment` con submódulos, diagrama de
  flujo, sección Despliegue), `README.md` (nuevas env vars + ejemplo de
  `docker run` con NVD habilitado).
- **Tests de integración** (`tests/repository.rs`, `#[ignore = "requiere
  Docker"]`, `mongo:7` real): put/get de `MongoNvdCache`, miss de un CPE
  desconocido, creación del índice TTL con el `expireAfterSeconds` esperado
  (verificado vía `list_indexes` crudo), idempotencia al llamar dos veces con
  el mismo TTL, actualización del TTL vía `collMod` al cambiarlo. Esperar la
  expiración real (job de fondo de Mongo, ~60s) se consideró impráctico; se
  documentó la decisión en el propio test.

### Revisión

- Ronda 1: **APROBADO** sin cambios requeridos. El reviewer verificó línea por
  línea que `NvdApiEnricher` sólo se construye dentro del `if
  config.nvd_enrichment_enabled` de `wiring.rs` (cero rutas de código con
  posibilidad de egress si está deshabilitado), que sólo el CPE viaja en la
  request HTTP (`PortFinding` no expone IP/`correlation_id`/credenciales al
  enricher), y hizo `cargo tree -i native-tls`/`-i openssl-sys` sin resultados
  (confirma que `rustls-tls` no arrastra OpenSSL). Los 14 criterios de
  `acceptance` verificados con evidencia de código y test concretos.
- Detalle: `progress/impl_nvd_enrichment.md`, `progress/review_nvd_enrichment.md`.

### Verificación

- `./init.sh` verde en 3 corridas del implementer + 3 del reviewer + 1 de
  cierre (exit 0, 0 `[FAIL]`), incluye `cargo test -- --ignored` con
  contenedores reales `mongo:7` + `sshd`.
- `cargo test`: **115 unitarios** verdes (baseline 97 → +18: 9 `config`, 1
  `domain`, 8 `enrichment::nvd`). `cargo test -- --ignored`: **23** verdes
  (baseline 18 → +5, todos de `MongoNvdCache`).
- `cargo clippy --all-targets -- -D warnings`, `cargo fmt --check`,
  `RUSTDOCFLAGS="-D warnings" cargo doc --no-deps` limpios.
- Sin `unwrap`/`expect`/`panic!` fuera de tests. Sin regresión en features
  1-13. Sin llamadas reales a NVD en ningún test (`wiremock` local).
- Commit pendiente (lo gestiona el leader): `Cargo.toml`, `Cargo.lock`,
  `README.md`, `docs/architecture.md`, `docs/security-scope.md`,
  `src/domain.rs`, `src/pipeline.rs`, `src/repository.rs`, `src/config.rs`,
  `src/wiring.rs`, `src/enrichment.rs` (eliminado) →
  `src/enrichment/{mod,exploitdb,nvd}.rs` (nuevos), `tests/repository.rs`,
  `feature_list.json`, `progress/*.md`.
- Con esta feature, las 14 del `feature_list.json` quedan en `done`.

---

## 2026-09-17 — Feature 15: scan_started_event

- **Agente:** implementer + reviewer
- **Estado final:** `done` (reviewer aprobó sin cambios requeridos, ver
  `progress/review.md`)

### Qué se hizo

- **`src/messaging/publisher.rs`**: nueva variante `ScanOutcome::Started {
  correlation_id: CorrelationId }` dentro del mismo enum *internally tagged*
  (`#[serde(tag = "status", rename_all = "snake_case")]`) que `Completed`/
  `Failed`; serializa exactamente a `{"status":"started","correlation_id":"..."}`
  sin `result` ni `reason`. Constructor `ScanOutcome::started(correlation_id)`.
  `status_label()`/`correlation_id()`/`outcome_log_fields` (helper puro de
  logging) cubren la variante sin exponer más que `correlation_id`+`status`
  (mismo contrato de no-fuga que las otras dos). Doc del módulo actualizada:
  `Started` la consume sólo el Gateway (routing key `scan.outcome.started`),
  nunca `ms-analisis`.
- **`src/pipeline.rs`**: `ScanPipeline::process_one` publica
  `ScanOutcome::started(correlation_id)` a través del `ScanResultSink`
  inyectado **antes** de `run_stages` (SSH/nmap/parser/enrichment/repository).
  Publicación best-effort: si `sink.publish` falla, se loggea con
  `tracing::warn!` (correlation_id + error, sin credenciales) y el pipeline
  sigue igual — nunca se aborta el escaneo por esto. Exactamente una
  publicación `started` por invocación (sin bucles ni reintentos).
- Sin dependencias nuevas en `Cargo.toml`.

### Tests

- `src/messaging/publisher.rs`: `started_outcome_serializes_to_exact_message_shape_with_no_extra_fields`
  (JSON exacto sin campos extra); `outcome_json_round_trip_preserves_every_field`
  ampliado a las 3 variantes (regresión de `Completed`/`Failed` sigue verde);
  `correlation_id_accessor_works_for_all_variants`;
  `log_fields_for_started_expose_only_correlation_id_and_status`;
  `log_outcome_published_does_not_panic_for_any_variant`.
- `src/pipeline.rs` (unit, sin Docker): `ssh_stage_failure_is_published_as_failed_outcome_without_docker`
  actualizado — 2 desenlaces en orden Started→Failed, mismo `correlation_id`,
  sin filtrar la credencial; nuevo `started_publish_failure_is_best_effort_and_does_not_abort_the_scan`
  con un `FlakySink` que falla sólo la publicación de `started` y verifica que
  el pipeline sigue y publica igual el desenlace terminal.
- `tests/scan_pipeline.rs` (e2e, `#[ignore = "requiere Docker"]`): las 3
  pruebas existentes (éxito, fallo, concurrencia) se actualizaron sin debilitar
  ningún assert previo del resultado final, verificando que el primer
  desenlace de cada `correlation_id` es `Started` antes del terminal (éxito: 2
  eventos; fallo: 2 eventos; concurrencia con 3 solicitudes: 6 eventos = 3
  `Started` + 3 `Completed`, con `Started` precediendo a su terminal por cada
  `correlation_id`).

### Revisión

- Ronda 1: **APROBADO** sin cambios requeridos. El reviewer verificó los 9
  criterios de `acceptance` contra el diff real, corrió `./init.sh` 3 veces de
  forma independiente (fmt/clippy/118 unit/Docker/doc, todo verde), y grepeó
  `unwrap()/expect()/panic!()/println!/dbg!` en los archivos tocados
  confirmando que sólo aparecen dentro de `mod tests`.
- Detalle: `progress/impl_scan_started_event.md`, `progress/review.md`.

### Sobre el flake de `enrichment::nvd::tests`

- Durante la sesión se observó una falla intermitente de 2 tests de
  `enrichment::nvd::tests` al correr la suite completa en paralelo. Tanto el
  implementer como el reviewer confirmaron **independientemente** (con `git
  stash` contra el commit base `96f0288`, sin ningún cambio de esta feature)
  que el flake **ya existía antes** de la feature 15 y no la toca (feature 15
  no modifica ningún archivo de `enrichment/`). Aislado (`cargo test --lib
  enrichment::nvd`) pasa consistentemente; sólo aparece bajo presión de CPU con
  la suite completa, probablemente en el rate limiter de `NvdApiEnricher`
  (feature 14). No bloqueó esta revisión. **Queda pendiente como hallazgo de
  mantenimiento** para una sesión futura (no se abrió como feature nueva en
  este cierre).

### Verificación

- `./init.sh` verde y estable: 4 corridas del implementer + 3 del reviewer +
  1 de cierre (exit 0, 0 `[FAIL]`), incluye `cargo test -- --ignored` con
  contenedores reales `sshd` + `mongo:7` (los 3 e2e de `tests/scan_pipeline.rs`
  actualizados).
- `cargo test`: 118 unitarios verdes (baseline 115 → +3: 5 nuevos/renombrados
  en `publisher.rs` netos de las variantes ampliadas, 1 nuevo en `pipeline.rs`,
  compensados por tests reescritos en el mismo archivo). `cargo clippy
  --all-targets -- -D warnings`, `cargo fmt --check`, `RUSTDOCFLAGS="-D
  warnings" cargo doc --no-deps` limpios.
- Sin `unwrap`/`expect`/`panic!` fuera de tests. Sin regresión en features
  1-14. No se tocó nada de la feature 16 (`scan_cancellation`).
- Commit pendiente (lo gestiona el leader): `src/messaging/publisher.rs`,
  `src/pipeline.rs`, `tests/scan_pipeline.rs`, `feature_list.json`,
  `progress/*.md`.

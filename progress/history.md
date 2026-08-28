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

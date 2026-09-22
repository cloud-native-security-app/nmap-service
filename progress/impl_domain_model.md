# Feature 3 — domain_model — informe de implementación

Estado: implementada, pendiente de review. `./init.sh` en verde (exit 0).

## Archivo tocado

- `src/domain.rs` — tipos del dominio (antes stub).
- `Cargo.toml` — nuevas dependencias (`time`, feature `serde` de `secrecy`).

## Tipos definidos (todos `Serialize` + `Deserialize`)

| Tipo | Forma | Notas |
|------|-------|-------|
| `CorrelationId` | newtype `String`, `#[serde(transparent)]` | opaco; `new`, `as_str`, `Display`, `From<String>`, `From<&str>`. Derives `Hash`/`Eq` para poder usarse como clave más adelante. |
| `SshCredentialsRef` | newtype sobre `secrecy::SecretString` | redacta en `Debug`, `Display` y `Serialize`; ver sección credencial. `new(SecretString)`, `expose() -> &str`. |
| `ScanRequest` | `{ correlation_id, ip, network_user, ssh_credentials_ref, has_sudo, requested_by }` | `ip` es el nombre exacto del `acceptance` y la clave serde (mensaje del Broker / documento Mongo). |
| `Protocol` | enum `Tcp`/`Udp`, `#[serde(rename_all = "lowercase")]` | |
| `PortState` | enum `Open`/`Closed`/`Filtered`/`Unfiltered`/`OpenFiltered`/`ClosedFiltered`, `snake_case` | cubre los 6 estados de nmap; el `parser` mapeará las cadenas crudas. |
| `Severity` | enum `Unknown`/`Info`/`Low`/`Medium`/`High`/`Critical`, `lowercase` | `Unknown` cuando el script NSE no informa severidad. |
| `PortFinding` | `{ port: u16, protocol, state, service: Option<String>, version: Option<String> }` | |
| `VulnFinding` | `{ id: Option<String>, severity: Severity, description: String, nse_script: String }` | `id` = CVE u otro identificador si el script lo da. |
| `ScanResult` | `{ host: IpAddr, ports: Vec<PortFinding>, vulnerabilities: Vec<VulnFinding>, scanned_at: OffsetDateTime }` | exactamente los 4 campos del acceptance. |

## Decisiones de diseño

- **`ScanRequest.ip` / `ScanResult.host`: `std::net::IpAddr`** (no `String`).
  Queda validado al deserializar y serializa como cadena. `ms-nmap` escanea una
  IP concreta (architecture.md), no un hostname. El campo se llama `ip` (nombre
  Rust y clave serde) tal cual lo fija el `acceptance`; es la clave que
  consumirán el mensaje del Broker (feature 8) y el documento Mongo (feature 7).
- **`correlation_id`: newtype `CorrelationId`** en vez de `String` desnudo, para
  no confundirlo con otros campos de texto y darle `Display`/`as_str`. Transparent
  en serde ⇒ en JSON es una cadena normal.
- **`scanned_at`: `time::OffsetDateTime`** serializado como **RFC 3339**
  (`#[serde(with = "time::serde::rfc3339")]`). Se evita `std::time::SystemTime`
  (round-trip serde frágil / formato poco legible en Mongo). Se eligió `time`
  sobre `chrono` porque cubre lo necesario con menos superficie y ya estaba en el
  árbol de dependencias transitivas.
- **`ScanResult` NO lleva `correlation_id`**: el `parser` (feature 6) construye
  `ScanResult` solo a partir del XML de nmap, que no contiene ese dato. El enlace
  con la solicitud lo añade la capa de persistencia/publicación (features 7/9),
  como ya anticipa el acceptance de la feature 7 ("cada documento incluye ... el
  correlation_id").
- **`has_sudo: bool`** con rustdoc explícito: lo informa el Gateway/`ms-usuarios`,
  `ms-nmap` no lo verifica, y `scanner`/`nmap_execution` lo usa para decidir
  `nmap -O` vía `sudo -n` (security-scope.md).
- Enums con encoding string estable y explícito (no numérico) para que los
  documentos Mongo y los mensajes del Broker sean legibles y versionables. Test
  lo fija.
- `PartialEq`/`Eq` en todos los tipos (incl. `impl` manual en `SshCredentialsRef`
  comparando el secreto expuesto) para poder hacer `assert_eq!` del valor
  completo en el round-trip.

## Manejo de la credencial en serde (decisión pedida)

`secrecy::SecretString` **no** implementa `Serialize` (por diseño de la crate), y
`#[serde(skip)]` rompería `Deserialize` sin un `Default`. Solución:
`SshCredentialsRef` es un newtype con impls manuales:

- **`Deserialize`**: lee el `String` real y lo envuelve en `SecretString`. La
  credencial entra al sistema por el mensaje del Broker, así que `ScanRequest`
  SÍ debe poder deserializarla. Test lo cubre.
- **`Serialize`**: emite siempre el literal `"[REDACTED]"`, nunca el valor.
- **`Debug` / `Display`**: `[REDACTED]`.

Consecuencia intencionada y documentada en el rustdoc del tipo: un round-trip
`serialize → deserialize` de `ScanRequest` **pierde** la credencial (queda como
`[REDACTED]`). Es aceptable porque:
1. El acceptance exige round-trip completo solo de `ScanResult` (que no tiene
   credencial).
2. `ScanRequest` nunca se re-serializa hacia Mongo ni hacia el Broker en el
   flujo real; solo se deserializa al recibirlo.
3. Garantiza que la credencial no pueda filtrarse por `tracing::debug!`, un
   panic, ni un documento persistido (security-scope.md, architecture.md
   "Manejo de errores").

`secrecy` se deja **sin features** (`secrecy = "0.10"`, igual que en la feature
2). `SshCredentialsRef` implementa `Serialize`/`Deserialize` a mano: `Deserialize`
llama a `String::deserialize(...)` + `SecretString::from(raw)` (no depende de
ninguna feature de `secrecy`), y `Serialize` fuerza la redacción. Ningún tipo
deriva serde sobre un `SecretString` ni usa `#[serde(with = ...)]` de `secrecy`,
así que la feature `serde` de la crate no aporta nada aquí.

## Dependencias nuevas (`Cargo.toml`)

- `time = { version = "0.3", features = ["serde-well-known"] }` — **dep directa
  nueva**, justificada por `ScanResult::scanned_at`: serializarlo como RFC 3339
  requiere `time::serde::rfc3339`, que necesita esa feature (es la mínima
  suficiente). No era dep transitiva previa (`cargo tree -i time` la muestra solo
  como dep directa de `nmap-service`). Se eligió `time` sobre `chrono` por menor
  superficie.
- `time = { version = "0.3", features = ["macros"] }` en `[dev-dependencies]` —
  `datetime!` en los tests (feature aislada del binario de producción).
- `secrecy`: **sin cambios respecto a la feature 2** (`secrecy = "0.10"`, sin
  features). Las impls serde de `SshCredentialsRef` son manuales y no dependen de
  la feature `serde` de la crate.

## Tests unitarios (`src/domain.rs`, 7 tests, todos verdes)

- `scan_result_json_round_trip_preserves_every_field` — **criterio explícito**:
  `ScanResult` con 3 puertos (open / filtered / open_filtered, TCP y UDP, con y
  sin servicio/versión) + 1 vuln con CVE; serializa a JSON, deserializa,
  `assert_eq!` del valor completo.
- `scan_result_serializes_timestamp_as_rfc3339` — el timestamp sale como cadena
  RFC 3339.
- `scan_request_debug_does_not_leak_credentials` — `format!("{:?}", request)` no
  contiene el secreto y sí contiene `[REDACTED]`.
- `scan_request_serialization_does_not_leak_credentials` — el JSON de
  `ScanRequest` tampoco filtra el secreto.
- `ssh_credentials_ref_display_is_redacted_but_value_is_recoverable` — `Display`
  y `Debug` redactados; `expose()` devuelve el valor.
- `scan_request_deserializes_real_credential_from_broker_message` — un mensaje
  JSON del Broker sí carga la credencial real y el resto de campos.
- `enums_use_a_stable_string_encoding` — fija el encoding string de `Protocol`,
  `PortState`, `Severity`.

## Salida de `./init.sh`

```
[OK]    cargo fmt --check sin diferencias
[OK]    cargo clippy sin warnings
[OK]    Tests unitarios pasan        (15 passed; 0 failed  -> 8 config + 7 domain)
[OK]    Tests de integración con Docker (testcontainers, #[ignore]) pasan o no hay ninguno todavía
[OK]    cargo doc genera sin errores (rustdoc de ítems públicos)
[OK]    Entorno listo. Puedes empezar a trabajar.
exit 0
```

# Review — feature 3 `domain_model` (ronda 2)

**Veredicto:** APPROVED

Revisor: reviewer · Fecha: 2026-08-27 · Rama: feature/scaffolding
Archivos evaluados: `src/domain.rs`, `Cargo.toml`, `Cargo.lock`,
`progress/current.md`, `progress/impl_domain_model.md`.

La ronda 1 fue CHANGES_REQUESTED por: (1) el campo de IP se llamaba `target_ip`
en vez de `ip`, (2) `secrecy` llevaba una feature `serde` sin uso, (3)
justificaciones incorrectas en el informe (`time`/`secrecy`), (4) un nit de
rustdoc en `scanned_at`. El implementer aplicó los 4 cambios. Re-verificado
punto por punto; `./init.sh` en verde (ejecutado por el revisor).

> Nota informativa (no afecta al veredicto): el working tree tiene cambios en
> `docs/architecture.md` (sección "Hexagonal parcial") y `feature_list.json`
> (feature `id: 11` `hexagonal_ports`). El leader confirma que son de otra
> sesión activa, externos a esta feature, y **no** son scope creep del
> implementer. Se ignoran para el cierre de la feature 3.

---

## Verificación de los cambios pedidos

1. **Campo `ip` en `ScanRequest`:** CONFIRMADO.
   `src/domain.rs:139` → `pub ip: IpAddr`. `grep -rn "target_ip" src/ Cargo.toml`
   → sin coincidencias. La clave serde es `ip` (no hay `rename`), verificado en
   el test `scan_request_deserializes_real_credential_from_broker_message`
   (`src/domain.rs:373-389`), cuyo JSON de entrada usa `"ip": "198.51.100.4"` y
   afirma `request.ip == "198.51.100.4".parse::<IpAddr>()`. `ScanResult::host`
   sigue llamándose `host` (criterio 4) y su rustdoc referencia
   `[ScanRequest::ip]` (`:248`).

2. **`secrecy` sin feature `serde`:** CONFIRMADO.
   `Cargo.toml:22` → `secrecy = "0.10"` (igual que la feature 2).
   `cargo tree -e features -i secrecy` → solo `feature "default"`, ya no
   aparece `feature "serde"`. `Cargo.lock`: la entrada de `secrecy` ya no lista
   `serde` en `dependencies`. El crate compila y todos los tests pasan sin esa
   feature (las impls de `Serialize`/`Deserialize` de `SshCredentialsRef` son
   manuales: `String::deserialize` + `SecretString::from`, `src/domain.rs:119-127`).

3. **Justificaciones corregidas en `progress/impl_domain_model.md`:** CONFIRMADO.
   - §"Manejo de la credencial en serde" (`:77-82`): ahora explica que `secrecy`
     se deja sin features y por qué las impls manuales no dependen de la feature
     `serde` de la crate.
   - §"Dependencias nuevas" (`:84-96`): `time` documentado como **dep directa
     nueva** (ya no "transitiva previa"), justificada por `scanned_at` (RFC 3339
     requiere `time::serde::rfc3339` → feature `serde-well-known`, la mínima
     suficiente), con la comprobación `cargo tree -i time`. `secrecy`: "sin
     cambios respecto a la feature 2".
   - Nit menor no bloqueante: la línea 8 ("Archivo tocado") todavía dice
     "`Cargo.toml` — nuevas dependencias (`time`, feature `serde` de `secrecy`)";
     las secciones de detalle ya están correctas. Conviene alinearla, pero no
     impide el cierre.

4. **Nit de rustdoc de `scanned_at`:** RESUELTO.
   `src/domain.rs:254-255`: "Instante en que terminó el escaneo, serializado
   como RFC 3339 (incluye el offset UTC de la marca temporal)". Ya no afirma
   incorrectamente que el valor esté siempre en UTC.

5. **`./init.sh` y toolchain:** CONFIRMADO (ejecutado por el revisor).
   - `./init.sh` → **exit 0**, todos los bloques `[OK]`.
   - `cargo fmt --check` → sin diferencias.
   - `cargo clippy --all-targets -- -D warnings` → sin warnings.
   - `cargo test` → `running 15 tests … 15 passed; 0 failed` (8 config + 7 domain).
   - `cargo test -- --ignored` → 0 (correcto: `domain` no cruza IO).
   - `cargo doc --no-deps` → limpio (`#![deny(missing_docs)]` activo).
   - Sin regresiones: `git status` muestra que el único archivo de `src/` tocado
     es `domain.rs`; `config.rs` y los stubs de las demás capas intactos.
   - Round-trip: `scan_result_json_round_trip_preserves_every_field`
     (`src/domain.rs:315-322`) sigue haciendo
     `assert_eq!(restored, original)` del `ScanResult` completo (no `is_ok()`).

---

## Checkpoints

- C1: [x]  4 archivos base + 4 docs presentes; `./init.sh` exit 0.
- C2: [x]  Solo la feature 3 en `in_progress`; features 1 y 2 (`done`) conservan
  sus tests verdes; `progress/current.md` describe la sesión activa.
- C3: [x]  `src/` solo contiene los módulos previstos (`domain.rs` deja de ser
  stub); toda dependencia justificada: `time`/`serde-well-known` por
  `ScanResult::scanned_at` (feature mínima), `secrecy` sin features extra,
  `serde`/`serde_json`/`thiserror` de features previas. Sin
  `println!`/`dbg!`/`unwrap`/`expect`/`panic!` fuera de `#[cfg(test)]`
  (los `.expect(...)` están todos en `mod tests`). `cargo doc --no-deps` sin
  warnings; todo ítem público (tipos, campos, variantes de enum) con `///`.
- C4: [x]  `domain` es lógica pura → no requiere test de integración (C4 aplica
  a `ssh`/`scanner`/`repository`/`messaging`). `cargo test` > 0 y verde (7
  tests nuevos); `cargo clippy --all-targets -- -D warnings` limpio.
- C5: [x]  Sin archivos sin trackear sospechosos (`progress/impl_domain_model.md`
  y `progress/review_domain_model.md` son esperados; no hay `*.tmp` ni `target/`
  fuera del `.gitignore`). Feature en `in_progress`, estado correcto hasta que el
  leader cierre. La entrada en `progress/history.md` y la transición a `done` las
  hace el leader. Los cambios en `docs/architecture.md` / `feature_list.json`
  (feature 11) son de otra sesión, confirmado por el leader.

---

## Criterios de `acceptance` (feature 3), uno a uno

1. **`ScanRequest { ip, network_user, ssh_credentials_ref, has_sudo: bool,
   requested_by, correlation_id, ... }`:** CUMPLE.
   `src/domain.rs:134-156`: `correlation_id: CorrelationId` (`:136`),
   `ip: IpAddr` (`:139`), `network_user: String` (`:141`),
   `ssh_credentials_ref: SshCredentialsRef` (`:144`), `has_sudo: bool` (`:151`),
   `requested_by: String` (`:155`). Nombres y tipos exactos; `ip` como clave
   serde. `IpAddr` valida la dirección al deserializar y serializa como cadena.

2. **`ssh_credentials_ref` redacta en `Debug`/`Display`; test de que
   `format!("{:?}", request)` NO contiene el secreto; ningún código lo
   imprime:** CUMPLE.
   `SshCredentialsRef(SecretString)` (`:75`); `Debug` (`:90-94`) y `Display`
   (`:96-100`) emiten `[REDACTED]`; `Serialize` (`:110-117`) también.
   `scan_request_debug_does_not_leak_credentials` (`:338-347`):
   `!rendered.contains(secret)` y `rendered.contains(REDACTED)`.
   `scan_request_serialization_does_not_leak_credentials` (`:350-358`): idem
   sobre el JSON. Único acceso al valor: `expose()` (`:85-87`); sin
   `println!`/`dbg!`/logging del secreto en `src/`.

3. **`has_sudo` documentado con su semántica correcta:** CUMPLE.
   Rustdoc `src/domain.rs:145-150`: lo informa el Gateway/`ms-usuarios`,
   `ms-nmap` no lo verifica, `scanner` (`nmap_execution`) lo usa para decidir
   `nmap -O` vía `sudo -n`. Coherente con `docs/security-scope.md` §Escalación
   de privilegios.

4. **`ScanResult { host, ports: Vec<PortFinding>, vulnerabilities:
   Vec<VulnFinding>, scanned_at }`:** CUMPLE exactamente.
   `src/domain.rs:246-258`: `host: IpAddr`, `ports: Vec<PortFinding>`,
   `vulnerabilities: Vec<VulnFinding>`, `scanned_at: OffsetDateTime`
   (`#[serde(with = "time::serde::rfc3339")]`). Sin campos de más.

5. **`PortFinding` incluye puerto, protocolo, estado, servicio, versión:**
   CUMPLE. `src/domain.rs:214-226`: `port: u16`, `protocol: Protocol`,
   `state: PortState`, `service: Option<String>`, `version: Option<String>`.

6. **`VulnFinding` incluye identificador (CVE si aplica), severidad,
   descripción, script NSE de origen:** CUMPLE.
   `src/domain.rs:231-240`: `id: Option<String>`, `severity: Severity`,
   `description: String`, `nse_script: String`.

7. **Todos los tipos derivan `Serialize`/`Deserialize`:** CUMPLE.
   `CorrelationId`, `ScanRequest`, `Protocol`, `PortState`, `Severity`,
   `PortFinding`, `VulnFinding`, `ScanResult` derivan ambos. `SshCredentialsRef`
   los implementa a mano (redacción en `Serialize`; lectura real en
   `Deserialize`). Decisión coherente y documentada (`:61-73`): el round-trip de
   `ScanRequest` es lossy en la credencial a propósito, alineado con
   `docs/security-scope.md`.

8. **Test unitario de round-trip de `ScanResult` que compara el valor completo:**
   CUMPLE. `scan_result_json_round_trip_preserves_every_field` (`:315-322`):
   serializa → deserializa → `assert_eq!(restored, original)` sobre un
   `ScanResult` con 3 puertos (open/filtered/open_filtered, TCP y UDP, con y sin
   servicio/versión) y 1 `VulnFinding` con CVE. Complementado por
   `scan_result_serializes_timestamp_as_rfc3339` (`:325-335`) y
   `enums_use_a_stable_string_encoding` (`:392-405`).

---

## Otras verificaciones

- **Módulo puro, sin IO:** CONFIRMADO. `src/domain.rs` solo importa `std::fmt`,
  `std::net::IpAddr`, `secrecy`, `serde`, `time`. Nada de `mongodb`, `ssh`,
  `tokio`.
- **Sin scope creep hacia features 4-10:** CONFIRMADO — solo tipos, sin
  parser/ssh/repository. En `src/` solo se tocó `domain.rs`.
- **Decisión de (de)serialización de la credencial:** coherente y documentada
  (rustdoc del tipo + informe). Alineada con `docs/security-scope.md`
  §Credenciales y `docs/architecture.md` §Manejo de errores.
- **Estilo/convenciones:** correcto. Orden de imports std → externo → `super::*`;
  tipos `PascalCase`; enums con `#[serde(rename_all = ...)]` explícito y estable;
  `//!` de módulo; nombres de test descriptivos; sin comentarios superfluos.

---

## Cambios requeridos

Ninguno bloqueante. La feature 3 `domain_model` cumple los 8 criterios de
`acceptance`, los checkpoints C1-C5 y las convenciones. `./init.sh` en verde.
Apta para pasar a `done` (acción del leader).

Sugerencia menor (opcional, no bloquea): alinear la línea 8 de
`progress/impl_domain_model.md` ("Archivo tocado") con las secciones de detalle
ya corregidas — sigue mencionando la feature `serde` de `secrecy` como añadida.

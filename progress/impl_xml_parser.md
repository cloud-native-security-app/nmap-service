# Implementación feature 6 — `xml_parser`

**Estado:** implementada + verde en `./init.sh`. Pendiente de revisión y de que
el líder marque `done`.

## Qué se hizo

### `src/parser.rs` (reemplaza el stub)
- `pub fn parse(xml: &str) -> Result<ScanResult, ParseError>` — síncrona, sin IO,
  sin `unwrap`/`expect`/`panic!` fuera de `#[cfg(test)]`.
- `pub enum ParseError` (`thiserror`): `MalformedXml(String)`,
  `UnexpectedStructure { detail }`, `InvalidValue { field, value }`,
  `MultipleHosts`.
- `pub const MAX_DESCRIPTION_LEN: usize = 800`.
- Rustdoc `///` en todo ítem público (incluidas variantes y campos de enum);
  `cargo doc --no-deps` limpio con `#![deny(missing_docs)]`.

### Crate XML elegido: `roxmltree = "0.21"`
Rust puro, sin `unsafe` ni FFI. Frente a `quick-xml`: el XML de `nmap` para una
IP es un árbol pequeño (`nmaprun > host > ports > port > script`); un DOM de solo
lectura se navega de forma mucho más directa que una máquina de estados de
eventos, y el tamaño no justifica streaming. `serde-xml-rs` descartado por
enunciado. Nota: `nmap` emite `<!DOCTYPE nmaprun>`, así que se parsea con
`ParsingOptions { allow_dtd: true, .. }` (roxmltree rechaza DTD por defecto).

### Decisiones de mapeo (todas documentadas en el rustdoc del módulo)
- `host`: `<address addrtype="ipv4|ipv6">` del `<host>` (se ignora la MAC).
- `scanned_at`: `<runstats><finished time>` (epoch s); fallback a `<nmaprun start>`;
  si falta → `UnexpectedStructure`. Epoch/rango inválido → `InvalidValue`.
- `PortState`: mapea los 6 estados crudos (`open`, `closed`, `filtered`,
  `unfiltered`, `open|filtered`, `closed|filtered`); otro valor → `InvalidValue`.
- `version`: `product` + `version` unidos por espacio, `+ " (extrainfo)"` si hay;
  `None` si `nmap` no detectó nada. Ej.: `OpenSSH 9.9 (protocol 2.0)`.
- `vulnerabilities`: `<script>` bajo `<port>` y bajo `<hostscript>`. Es hallazgo
  si el estado NSE es `VULNERABLE`/`LIKELY VULNERABLE`, o si hay CVEs y no dice
  `NOT VULNERABLE`. Un `VulnFinding` por CVE distinto (`CVE-\d{4}-\d+` sobre el
  `output` y los `<elem>`), o uno con `id: None`. `severity` desde
  `risk factor:`/`severity:`, si no del `cvss` más alto de los `<elem>`
  (≥9 Critical, ≥7 High, ≥4 Medium, >0 Low), si no `VULNERABLE (Exploitable)` →
  High, si no `Unknown`. `description` = `output` recortado a 800 chars.
  Limitación documentada: scripts que reportan debilidad sin estado NSE ni CVE
  (p. ej. `http-trace`) no se clasifican como hallazgo.
- host `status state="down"` → `ScanResult` con `ports`/`vulns` vacíos.
- sin ningún `<host>` → `UnexpectedStructure` (sin `<host>` no hay dirección).
- varios `<host>` → `MultipleHosts`.

### Revisión 1 (CHANGES_REQUESTED → resuelto)
El reviewer pidió cubrir el estado `filtered` / multi-estado de punta a punta
(no solo contra la fn privada `parse_state`). Añadido:
- Fixture real nuevo `tests/fixtures/filtered_ports.xml`
  (`nmap -sS -sU -Pn -p T:22,80,U:53,161` contra `10.99.99.99`, IP sin asignar en
  red aislada `nmaplab2`): TCP `filtered` + UDP `open|filtered` en un mismo
  `<host>`. Entrada añadida a `tests/fixtures/README.md`.
- Test `parses_filtered_and_open_filtered_ports_end_to_end`: pasa el fixture por
  `parse()` y asere `PortState::Filtered` (tcp/22, tcp/80) y
  `PortState::OpenFiltered` (udp/53, udp/161) en el `ScanResult`, más el
  protocolo de cada puerto.
Ahora 7 fixtures y 11 tests de parser.

### Fixtures — `tests/fixtures/` (7, XML real de Nmap 7.98)
Generados con Docker contra contenedores propios en una red aislada `nmaplab`
(`instrumentisto/nmap` como escáner; objetivos `openssh-server`, `httpd:2.4.49`,
`metasploitable2`, e IPs sin asignar). Procedencia y comando exacto de cada uno
en `tests/fixtures/README.md` (lo exige `docs/security-scope.md`). Ningún fixture
editado a mano. Contenedores y red destruidos al terminar.

- `open_ports_service_version.xml`, `no_open_ports.xml`, `filtered_ports.xml`,
  `host_down.xml`, `no_host_element.xml`, `multiple_hosts.xml`,
  `vuln_findings.xml`.

### Tests unitarios en `src/parser.rs` (`#[cfg(test)] mod tests`, 10 tests)
Un test por fixture verificando **contenido concreto** (IP, puertos exactos con
estado/servicio/versión, `scanned_at` como epoch, CVE + severidad + script de
cada vuln). Más: `parse_state_maps_every_raw_nmap_state`,
`parse_returns_error_on_malformed_xml` (cabecera real truncada),
`parse_returns_error_on_unexpected_structure` (XML bien formado sin `<nmaprun>`),
`parse_returns_error_when_nmaprun_has_no_host`,
`parse_returns_error_on_multiple_hosts`,
`parse_reports_invalid_port_id_out_of_range` (fixture real con `portid` fuera de
rango u16). Los dos snippets XML mínimos restantes son para caminos de error /
mapeo de estados; el contenido de dominio se valida siempre contra fixtures
reales.

### `Cargo.toml`
`+ roxmltree = "0.21"` en `[dependencies]`.

## Verificación
`./init.sh` → `[OK] Entorno listo`. `cargo fmt --check`, `cargo clippy
--all-targets -- -D warnings`, `cargo test` (10 tests de parser verdes),
`cargo test -- --ignored` (9 tests de ssh/scanner con Docker, sin regresión),
`cargo doc --no-deps` — todo limpio.

## Fuera de alcance / no tocado
`src/domain.rs` sin cambios. Ninguna otra feature tocada.

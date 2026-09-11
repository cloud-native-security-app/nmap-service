# Implementación — feature 13 `vuln_enrichment`

Estado: implementada y verificada. **No** marcada `done` (pendiente review).

## Qué se hizo

### `src/domain.rs`
- Nuevo enum `VulnSource` (`#[serde(rename_all = "snake_case")]` → `nmap_nse`,
  `exploit_db`).
- `VulnFinding` gana `pub source: VulnSource` (`#[serde(default = ...)]` →
  `NmapNse` para documentos pre-feature) y `pub references: Vec<String>`
  (`#[serde(default)]`).
- `PortFinding` gana `pub cpes: Vec<String>` (`#[serde(default)]`).
- `sample_result()` actualizado (incluye ahora un `VulnFinding` `ExploitDb`);
  nuevo test `vuln_finding_deserializes_with_defaults_for_pre_enrichment_documents`;
  `enums_use_a_stable_string_encoding` cubre `VulnSource`.

### `src/parser.rs`
- `collect_cpes()`: recoge el texto de los `<cpe>` hijos de `<service>` →
  `PortFinding.cpes`.
- Los `VulnFinding` de scripts NSE llevan `source: VulnSource::NmapNse`,
  `references: vec![]`.
- Asserts nuevos de `cpes` en `open_ports_service_version.xml`
  (`cpe:/a:openbsd:openssh:9.9`) y `vuln_findings.xml`
  (`cpe:/a:vsftpd:vsftpd:2.3.4`), y de `source == NmapNse`.

### `src/enrichment.rs` (NUEVO) + `pub mod enrichment;` en `lib.rs`
- `trait VulnEnricher` (`#[async_trait]`, dyn-compatible): `enrich(&self, &[PortFinding])
  -> Result<Vec<VulnFinding>, EnrichError>`.
- `enum EnrichError` (`thiserror`): `DataSource(String)`, `Backend(String)`. Sin panic.
- `struct ExploitDbEnricher`:
  - `from_csv_path(&str)` async → `tokio::task::spawn_blocking` + crate `csv`;
    indexa `Vec<ExploitRow { edb_id, title, title_lower, title_tokens, cves, source_url }>`.
    Columnas por nombre de cabecera.
  - `enrich`: sólo puertos con `version.is_some()`; query = tokens de
    `"<service> <version>"` (minúsculas, split por no-alfanum salvo `.`).
    Match = ≥2 tokens **AND** todos substring del título **AND** (si hay token
    `mayor.menor(.p)`) ese `mayor.menor` aparece en el título. `VulnFinding` por
    fila: `id` = primer CVE de `codes` (o `None`), `severity: Unknown`,
    `description = "<título> (Exploit-DB <edb_id>)"`, `nse_script = ""`,
    `source: ExploitDb`, `references = [".../exploits/<edb_id>"] (+ source_url)`.
  - Rustdoc documenta que el matcher es conservador y que los falsos positivos
    son un riesgo conocido y asumido.
- `struct CompositeVulnEnricher` (`new(Vec<Arc<dyn VulnEnricher>>)`): corre todos,
  concatena; un `Err` → `tracing::warn!` y sigue.
- 9 unit tests (matcher vsftpd 2.3.4 → CVE-2011-2523; sin match; versión menor
  errónea; puerto sin versión; archivo inexistente → `DataSource`; extracción de
  CVE con `;`; `version_prefix`; composite concatena; composite tolera `Err`).

### `src/config.rs`
- `EXPLOITDB_CSV_VAR = "MS_NMAP_EXPLOITDB_CSV"`, campo `exploitdb_csv: String`,
  **requerida** (mismo patrón feature 2). `valid_vars()` actualizado; 2 tests
  nuevos (ausente / vacía → `MissingVar`).

### `src/pipeline.rs`
- `ServicePorts.enricher: Arc<dyn VulnEnricher>` + campo en `ScanPipeline`.
- `run_stages`: tras `parser::parse`, antes de `repo.save`, llama a
  `enricher.enrich(&result.ports)` con `unwrap_or_else` (warn + `Vec::new()` —
  **best-effort**, nunca `ScanOutcome::Failed`) y luego
  `merge_enrichment_findings(&mut result.vulnerabilities, extra)`.
- `merge_enrichment_findings`: dedup por CVE (`id`) contra los hallazgos
  existentes (incluye dedup intra-`extra` porque la lista crece); si `id` es
  `None`, dedup por `description`.
- Tests: `merge_enrichment_adds_new_cves_and_skips_ones_nmap_already_found`,
  `merge_enrichment_dedups_findings_without_id_by_description`; doble
  `StubEnricher`.

### `src/wiring.rs`
- `WiringError::Enrichment(#[from] EnrichError)`.
- Construye `ExploitDbEnricher::from_csv_path(&config.exploitdb_csv).await?` →
  `CompositeVulnEnricher::new(vec![...])`. CSV no carga → falla el arranque.

### `Cargo.toml`
- `csv = "1"` — parser CSV en Rust puro (sin FFI, sin egress). Es la dependencia
  mínima para leer `files_exploits.csv` (cabecera + campos entrecomillados con
  comas). Alternativa descartada: parseo manual (frágil con los títulos que
  llevan comas/comillas).

### `Dockerfile`
- Nuevo stage `exploitdb` (reusa la base `rust:1.98-bookworm` ya pineada):
  `ADD --chmod=0644 https://gitlab.com/exploit-database/exploitdb/-/raw/ef58d5f4e31fefec0e36298c0b3e718801afdeb8/files_exploits.csv /opt/exploitdb/files_exploits.csv`
  (commit `ef58d5f4…`, tag `2026-09-04`; `ADD` no necesita curl).
- `COPY --from=exploitdb` a la imagen distroless + `ENV MS_NMAP_EXPLOITDB_CSV=/opt/exploitdb/files_exploits.csv`.
- Imagen sigue distroless (sin shell/coreutils/searchsploit/nmap). `docker build`
  OK; tamaño **67.5 MB** (~55 MB previos + ~10 MB del CSV comprimido/plano);
  `docker run` sin las env vars → error de config limpio (no panic); confirmado
  que no hay `/busybox/sh`.

### Docs
- `README.md`: fila `MS_NMAP_EXPLOITDB_CSV` + nota de que el enriquecimiento es
  offline; sección Docker actualizada (stage `exploitdb`, qué NO incluye).
- `docs/architecture.md`: nueva capa `enrichment` (nº 6, renumerado 6→12),
  puerto en la tabla hexagonal, diagrama de flujo, sección Despliegue.
- `docs/security-scope.md`: enriquecimiento ExploitDB = lookup local **sin
  egress**, detección pasiva; nota sobre APIs futuras con egress.

### Tests / fixtures
- `tests/fixtures/exploitdb_sample.csv`: 20 filas **reales** extraídas por EDB-ID
  de `/usr/share/exploitdb/files_exploits.csv` (procedencia + comando en
  `tests/fixtures/README.md`).
- `tests/scan_pipeline.rs`: `build_pipeline` toma un `Arc<dyn VulnEnricher>`;
  helper `sample_enricher()` carga el CSV fixture; el e2e
  `valid_request_flows_through_pipeline...` ahora verifica: hallazgo NSE de nmap
  intacto (`source == NmapNse`), ≥1 hallazgo `source == ExploitDb`, CVE-2010-2075
  (UnrealIRCd, puerto 6667) aportado por enrichment, y que CVE-2011-2523 **no**
  se duplica desde Exploit-DB (dedup).
- `src/messaging/publisher.rs` y `tests/repository.rs`: `sample_result()`
  actualizado a los campos nuevos.

## Nota de diseño (dedup en el e2e)
`vuln_findings.xml` → nmap ya trae `CVE-2011-2523` (puertos 21). Las filas de
vsftpd 2.3.4 del CSV llevan ese mismo CVE → se deduplican y **no** sobreviven. El
hallazgo `ExploitDb` que sí sobrevive en el e2e es el del puerto 6667
(`UnrealIRCd`, sin versión en el XML → match sólo por tokens `irc`+`unrealircd`),
que aporta `CVE-2010-2075` / `CVE-2006-1214`, no presentes en la salida de nmap.

## `title_tokens` en `ExploitRow`
Se guarda (lo pedía el plan) con `#[allow(dead_code)]` + comentario: el matcher
usa substring sobre `title_lower` (semántica requerida por el acceptance), así
que hoy los tokens no se consultan; quedan disponibles para un índice invertido
futuro.

## Verificación
- `./init.sh` verde **4 corridas** consecutivas (exit 0, 0 `[FAIL]`), sin
  flakiness. 97 unit tests + 6 repo + 4 e2e/pipeline (Docker) + 4 scanner + 5 ssh.
- `cargo clippy --all-targets -- -D warnings`, `cargo fmt --check`,
  `RUSTDOCFLAGS="-D warnings" cargo doc --no-deps` → limpios.
- `docker build` OK. Sin `unwrap`/`expect`/`panic!` fuera de tests. Adaptador
  ExploitDB sin egress de red.
- Sin regresión features 1-12.

## Archivos tocados
`feature_list.json` (status→in_progress), `Cargo.toml`, `Cargo.lock`, `Dockerfile`,
`README.md`, `docs/architecture.md`, `docs/security-scope.md`,
`src/{lib,domain,parser,config,pipeline,wiring,enrichment}.rs`,
`src/messaging/publisher.rs`, `tests/{scan_pipeline,repository}.rs`,
`tests/fixtures/{exploitdb_sample.csv,README.md}`, `progress/`.

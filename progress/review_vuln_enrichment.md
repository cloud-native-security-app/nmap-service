# Review — feature 13 `vuln_enrichment`

**Veredicto:** APPROVED

## Entorno de verificación

- `export PATH="$HOME/.cargo/bin:$PATH"`, Docker disponible.
- `./init.sh` ejecutado **3 veces** consecutivas: exit 0 las tres, sin
  flakiness. Recuento estable en las tres corridas:
  - Unit (`cargo test`): **97 passed**, 0 failed (baseline feature 12: 83 → +14,
    coherente con los tests nuevos de `domain`, `config`, `enrichment`,
    `pipeline`, `parser`).
  - Docker (`cargo test -- --ignored`): `repository` 6, `scan_pipeline` 3
    ignorados + 1 no-ignorado (4 en total), `scanner` 4, `ssh` 5 → **18
    ignorados + 1 e2e = 19**, coherente con "~19" esperado. Todos verdes.
  - `cargo fmt --check`, `cargo clippy --all-targets -- -D warnings`, `cargo
    doc --no-deps`: limpios en las 3 corridas.
- `RUSTDOCFLAGS="-D warnings" cargo doc --no-deps` (aparte): **0 warnings**.
- `docker build -t ms-nmap:review .`: **completa sin error**, tamaño
  **67.5 MB** (disk usage) / 16.6 MB comprimido — coherente con el ~65-68 MB
  reportado.
  - Log del build confirma el stage `exploitdb` descargando
    `https://gitlab.com/exploit-database/exploitdb/-/raw/ef58d5f4e31fefec0e36298c0b3e718801afdeb8/files_exploits.csv`
    — commit **fijo** (`ef58d5f4e31fefec0e36298c0b3e718801afdeb8`), no
    `main`/`latest`.
  - `docker export` de un contenedor creado desde la imagen: contiene
    `opt/exploitdb/files_exploits.csv`; **no** contiene `bin/sh`, `bin/bash`,
    `nmap`, `searchsploit` ni coreutils. `docker run --entrypoint /bin/sh`
    falla con "no such file" (confirma distroless real, sin shell).
  - `docker run` sin las env vars requeridas: falla limpio con
    `configuración inválida ... falta la variable de entorno requerida:
    MS_NMAP_MONGO_URI` vía `tracing::error!`, sin panic.

## Los 11 criterios de aceptación, uno a uno

1. **Trait `VulnEnricher` async dyn-compatible.** `src/enrichment.rs:44-51`:
   `#[async_trait] pub trait VulnEnricher: Send + Sync { async fn enrich(&self,
   ports: &[PortFinding]) -> Result<Vec<VulnFinding>, EnrichError>; }`. ✅ Exacto
   a la firma pedida.

2. **`ExploitDbEnricher`.** `from_csv_path(path: &str) -> Result<Self,
   EnrichError>` (línea 115) usa `spawn_blocking` + crate `csv`; la ruta viene
   de `Config::exploitdb_csv`, poblado desde `MS_NMAP_EXPLOITDB_CSV`
   (`src/config.rs:45`, sin default hardcodeado, variable **requerida** —
   `ConfigError::MissingVar` si falta/vacía, tests en `config.rs:246-262`).
   Indexa en memoria (`Vec<ExploitRow>`), matchea por `service`+`version`
   (`query_tokens`, `row_matches`), extrae CVEs de `codes`
   (`extract_cves`, líneas 304-328). ✅

3. **`CompositeVulnEnricher`.** `enrichment.rs:208-234`: corre todos los
   enrichers, concatena (`all.append`), un `Err` de uno se loggea con
   `tracing::warn!` y **no aborta** a los demás (retorna `Ok(all)` siempre;
   verificado también por el test unitario
   `composite_keeps_going_when_one_enricher_errors`). ✅

4. **Invocación entre `parser::parse` y `repository::save`, best-effort.**
   Verificado con lupa en `src/pipeline.rs:184-201`: `parser::parse` en la
   línea 184, luego (antes de `self.repository.save` en la línea ~203) se
   llama `self.enricher.enrich(&result.ports).await.unwrap_or_else(|err| {
   tracing::warn!(...); Vec::new() })`, y el resultado se fusiona con
   `merge_enrichment_findings`. El `unwrap_or_else` garantiza que un `Err` del
   enricher **nunca** propaga como error de la etapa (no hay `?` ni `.map_err`
   que pudiera convertirlo en `ScanOutcome::Failed`); el flujo sigue con
   `Vec::new()` y el escaneo continúa normalmente. ✅

5. **Dedup por CVE.** `merge_enrichment_findings` (`pipeline.rs:275-296`):
   descarta un hallazgo de `extra` si su `id` ya está en `existing` (que se va
   actualizando en cada iteración, así también deduplica dos filas nuevas con
   el mismo CVE entre sí), o si no tiene `id` y ya hay uno sin `id` con la
   misma `description`. Cubierto por
   `merge_enrichment_adds_new_cves_and_skips_ones_nmap_already_found` y
   `merge_enrichment_dedups_findings_without_id_by_description`, y verificado
   end-to-end en `tests/scan_pipeline.rs` (assert final: `CVE-2011-2523`
   aparece exactamente 2 veces — las 2 de nmap — pese a que Exploit-DB también
   lo trae). ✅

6. **`VulnFinding.source`/`references`, `PortFinding.cpes`.**
   `domain.rs:226-266`: `VulnSource` (`NmapNse`/`ExploitDb`,
   `#[serde(rename_all="snake_case")]`), `VulnFinding.source` con
   `#[serde(default = "default_vuln_source")]` → `NmapNse` para documentos
   viejos, `references: Vec<String>` con `#[serde(default)]`. Todos los sitios
   de construcción actualizados: `parser.rs` (scripts NSE), `domain.rs`
   (`sample_result`), `messaging/publisher.rs` (test), `tests/repository.rs`
   (test), `src/pipeline.rs` (tests), `src/enrichment.rs`. Round-trip serde
   verde (97 unit tests incluye `domain::tests`), más el test específico
   `vuln_finding_deserializes_with_defaults_for_pre_enrichment_documents`
   (compatibilidad hacia atrás). ✅

7. **`PortFinding.cpes` desde `<cpe>`.** `parser.rs:282-300`: `collect_cpes`
   recoge el texto de los hijos `<cpe>` de `<service>`. Confirmado en
   `tests/fixtures/open_ports_service_version.xml:25`
   (`<cpe>cpe:/a:openbsd:openssh:9.9</cpe>`) y el assert
   `assert_eq!(ssh.cpes, vec!["cpe:/a:openbsd:openssh:9.9".to_owned()])`
   (`parser.rs` tests, pasa en `cargo test`). También cubierto para
   `vuln_findings.xml` (`cpe:/a:vsftpd:vsftpd:2.3.4`). ✅

8. **Dockerfile.** Ver sección de verificación arriba: stage `exploitdb` con
   commit fijo, `COPY --from=exploitdb` a runtime distroless, `ENV
   MS_NMAP_EXPLOITDB_CSV=/opt/exploitdb/files_exploits.csv`. Imagen sin
   bash/coreutils/shell/nmap confirmado empíricamente (`docker export` +
   intento de ejecutar `/bin/sh`). `docker build` completa, tamaño reportado y
   confirmado. ✅

9. **Docs.** `docs/architecture.md` capa 6 `enrichment` (líneas 91-102),
   entrada en la tabla hexagonal (línea 64), flujo de datos actualizado
   (líneas 141-143), sección Despliegue con el stage `exploitdb` (líneas
   167-181). `docs/security-scope.md` nueva sección "Enriquecimiento de
   vulnerabilidades" (líneas 74-91): lookup local sin egress, detección
   pasiva, matcher conservador con falsos positivos como riesgo conocido,
   nota sobre adaptadores de API futuros con egress. ✅

10. **Tests del matcher + e2e.** `tests/fixtures/exploitdb_sample.csv` (20
    filas reales, procedencia documentada con el comando `awk` exacto en
    `tests/fixtures/README.md`). Unit tests en `enrichment.rs` (9 funciones):
    `matches_vsftpd_234_backdoor_from_the_csv` (vsftpd 2.3.4 → CVE-2011-2523,
    `source: ExploitDb`), `returns_empty_for_a_service_without_known_exploit`
    (nginx sin match → `vec![]`), `wrong_minor_version_does_not_match`,
    `skips_ports_without_a_detected_version`,
    `missing_csv_file_is_a_data_source_error`,
    `extract_cves_handles_semicolon_separated_codes` (cubre `;`),
    `version_prefix_only_accepts_numeric_major_minor`,
    `composite_concatenates_every_enricher`,
    `composite_keeps_going_when_one_enricher_errors`. El e2e
    `tests/scan_pipeline.rs::valid_request_flows_through_pipeline...` verifica
    hallazgos `source == ExploitDb` no vacíos, `CVE-2010-2075` aportado por
    Exploit-DB, y el dedup de `CVE-2011-2523`. ✅ (Nota menor: el informe del
    implementer dice "12 unit tests" en `enrichment.rs`; el recuento real es 9
    funciones de test — no afecta la cobertura exigida, ver checklist abajo.)

11. **`cargo build` sin warnings, `./init.sh` verde, clippy/fmt/doc limpios,
    sin regresión 1-12.** Confirmado con 3 corridas de `./init.sh` (arriba). ✅

## Análisis del matcher (conservador vs. falsos positivos)

- Guard duro: puertos con `version.is_none()` se saltan por completo (línea
  181) — un servicio detectado solo por nombre (p. ej. `http` sin versión)
  **nunca** genera hallazgos. Cubierto por
  `skips_ports_without_a_detected_version`.
- `MIN_QUERY_TOKENS = 2`: una consulta de un solo token (típicamente el
  nombre de servicio) tampoco intenta match — evita el caso "http" o "ssh"
  solos inundando el CSV. No hay un test que ejercite explícitamente un
  puerto con `service` genérico + versión ambigua de un solo token
  post-tokenización (p. ej. `version = "2"`), pero el diseño (constante +
  guard) hace ese escenario extremadamente improbable dado que `nmap -sV`
  casi siempre reporta `product + version` con al menos 2 tokens útiles.
  `returns_empty_for_a_service_without_known_exploit` (http/nginx) sí
  demuestra ausencia de falsos positivos para un servicio común sin exploit
  en el CSV fixture.
- Coincidencia AND estricta de **todos** los tokens como substring del
  título + chequeo adicional de `mayor.menor` cuando la versión es numérica
  (`version_prefix`, `wrong_minor_version_does_not_match` lo verifica:
  `vsftpd 2.9.9` no matchea exploits de `2.3.x`).
  Verificado manualmente contra el CSV fixture completo para los dos
  servicios del e2e (`vsftpd 2.3.4` en puerto 21, `UnrealIRCd` sin versión
  numérica en puerto 6667): el conjunto de filas que matchean es exactamente
  el esperado por el diseño (2 filas vsftpd con CVE-2011-2523, 4 filas
  UnrealIRCd con CVE-2010-2075 x2 / CVE-2006-1214 / sin CVE), sin colisiones
  espurias con las filas de ruido (OpenSSH, Samba, ProFTPd, Apache, AIX,
  Windows) incluidas a propósito en el fixture.
- Riesgo conocido documentado en rustdoc (`enrichment.rs:77-97`) y en
  `docs/security-scope.md`: el matcher puede tener falsos negativos (p. ej.
  "Apache HTTP Server" vs. tokens `httpd`) pero prioriza no inundar de falsos
  positivos, consistente con la exigencia del criterio.

## Egress de red y alcance de seguridad

- `grep` en `src/enrichment.rs` por `reqwest|hyper|TcpStream|socket` no
  encuentra nada: las únicas apariciones de `http`/`url` son la URL estática
  `https://www.exploit-db.com/exploits/<id>` que se **construye como texto**
  para `VulnFinding.references` (no se contacta), y `source_url` leída del
  CSV (también solo texto). `ExploitDbEnricher` únicamente hace IO de
  fichero local vía `csv::ReaderBuilder::from_path` en `spawn_blocking`. Sin
  egress, confirmado.
- El `Dockerfile` descarga el CSV en el **stage builder `exploitdb`** (build
  time), no en el runtime; el runtime distroless no tiene red de salida
  distinta a la ya prevista para Mongo/Broker (`rustls`), y no hace ninguna
  descarga en `docker run`.
- `Cargo.toml`: única dependencia nueva es `csv = "1"` (+ `csv-core`
  transitiva en `Cargo.lock`), Rust puro, justificada en el informe para
  parsear campos entrecomillados/con comas del CSV. **No** hay `reqwest` ni
  ninguna dependencia HTTP nueva.
- Sin scope creep: no hay adaptador NVD/Vulners, ni mecanismo de
  auto-actualización del CSV. El `EnrichError::Backend` y el campo
  `title_tokens` (`#[allow(dead_code)]`, comentado) son placeholders
  explícitamente previstos por el plan aprobado para extensión futura, sin
  lógica adicional implementada.

## Diffs de features ya cerradas (extensión, no regresión de lógica)

- `src/messaging/publisher.rs`: único cambio es actualizar `sample_result()`
  (helper de test) a los campos nuevos (`cpes`, `source`, `references`). Sin
  cambios de lógica de publicación.
- `tests/repository.rs`: mismo patrón, solo `sample_result()` actualizado
  con los campos nuevos. Sin cambios de lógica de persistencia/consulta.
- `src/pipeline.rs`/`src/wiring.rs` (features 10-11): cambios son aditivos
  (`enricher: Arc<dyn VulnEnricher>` en `ServicePorts`/`ScanPipeline`, una
  llamada nueva en `run_stages`, `WiringError::Enrichment`); no se tocó la
  lógica de las etapas existentes (ssh/scanner/parser/repo/publisher), y los
  tests preexistentes de esas etapas siguen verdes sin modificación de
  aserciones salvo la inyección del nuevo `enricher` (dummy/stub) en los
  fixtures de test.
- `src/domain.rs`/`src/parser.rs` (features 3/6): cambios aditivos con
  `#[serde(default)]` para no romper documentos/serialización previa;
  confirmado con el test de deserialización de documentos "pre-enrichment".

## Checkpoints (`CHECKPOINTS.md`)

- C1: [x] — 4 archivos base + 4 docs presentes; `./init.sh` exit 0 (x3).
- C2: [x] — una sola feature `in_progress` (13); `feature_list.json` no fue
  marcada `done` por el implementer (correcto, pendiente de que el leader lo
  haga tras esta aprobación); `progress/current.md` describe la sesión activa
  sin basura de sesiones previas.
- C3: [x] — `docs/architecture.md` (fuente de verdad de capas) fue
  actualizado para incluir `enrichment` como capa prevista, y el código de
  `src/enrichment.rs` respeta el patrón hexagonal ya establecido (puerto +
  adaptadores, igual que `ssh`/`scanner`/`repository`). La lista literal de
  módulos en `CHECKPOINTS.md` (`config, domain, ssh, scanner, parser,
  repository, messaging`) está desactualizada desde las features 10-12
  (`pipeline`, `wiring`) y no se contradice con el criterio de aceptación de
  la feature, que exige explícitamente el nuevo módulo `enrichment` y su
  reflejo en `docs/architecture.md`. `Cargo.toml`: única dependencia nueva
  (`csv`) justificada por el criterio 2 de la feature 13. Sin
  `println!`/`dbg!`; `unwrap`/`expect`/`panic!` solo en `#[cfg(test)]`.
  `cargo doc --no-deps` sin warnings (rustdoc en todo ítem público nuevo).
- C4: [x] — el nuevo módulo `enrichment` no cruza IO de red (solo fichero
  local), por lo que no requiere un test de integración con Docker (no es
  ssh/scanner/repository/messaging); el e2e existente en
  `tests/scan_pipeline.rs` sí lo ejercita contra el pipeline real con
  Mongo/sshd en `testcontainers`. `cargo test` > 0 y verde (97 + 19).
  `cargo clippy --all-targets -- -D warnings` sin advertencias.
- C5: [x] — sin archivos sospechosos sin trackear (`git status` solo muestra
  los archivos declarados por el implementer); `progress/history.md` aún no
  tiene entrada de esta sesión — correcto en este punto del protocolo, esa
  entrada la añade el leader al cerrar tras esta aprobación (mismo patrón que
  las features 10-12); la feature 13 queda reflejada como pendiente de
  `done` a cargo del leader.

## Observaciones menores (no bloqueantes)

1. El informe `progress/impl_vuln_enrichment.md` dice "12 unit tests" para
   `src/enrichment.rs`; el recuento real son 9 funciones `#[test]`/
   `#[tokio::test]`. No afecta el veredicto: los 11 criterios de aceptación
   están cubiertos igual.
2. `docker run` sin variables de entorno termina con `exit 0` (loggea el
   error y retorna) en vez de un código de salida distinto de cero. Es un
   comportamiento heredado de `main.rs`/feature `containerization`
   (`scaffolding`/`containerization`), no algo introducido por esta feature,
   y el criterio 8 solo exige "arranca sin panic", que se cumple.

## Conclusión

Los 11 criterios de aceptación de la feature 13 se cumplen con evidencia
ejecutable. `./init.sh` verde y estable en 3 corridas (97 unit + 19
Docker/e2e), clippy/fmt/doc limpios, `docker build` exitoso con imagen
distroless verificada (sin shell/nmap/searchsploit, CSV pineado por commit),
sin egress de red en el enricher, matcher conservador con tests de no-falsos-
positivos, dedup por CVE correcto, y sin regresión en las features 1-12. Los
cambios a archivos de features ya cerradas (`publisher.rs`,
`tests/repository.rs`, `pipeline.rs`, `wiring.rs`, `domain.rs`, `parser.rs`)
son estrictamente aditivos/de construcción, no de lógica.

**APPROVED.**

# Review — feature 10 `scan_pipeline_wiring`

**Veredicto:** APPROVED

Revisor: reviewer · Fecha: 2026-08-28 (round 2)
Informe del implementer: `progress/impl_scan_pipeline_wiring.md`
Archivos revisados: `src/pipeline.rs` (nuevo), `src/lib.rs`, `src/config.rs`,
`src/messaging/publisher.rs`, `tests/scan_pipeline.rs` (nuevo),
`feature_list.json` (status), `progress/current.md`.

---

## Historial de revisión

- **Round 1 — CHANGES_REQUESTED.** Dos defectos: (1) `tests/fixtures/pipeline_stub_scan.xml`
  era un fixture nuevo escrito a mano y sin procedencia documentada; (2)
  `cargo doc --no-deps` emitía 2 warnings (`rustdoc::private_intra_doc_links` en
  `src/messaging/publisher.rs`).
- **Round 2 — APPROVED.** Ambos cambios aplicados y verificados (ver abajo).

## Verificación de los cambios del round 1

1. **Fixture** — `tests/fixtures/pipeline_stub_scan.xml` **eliminado**. El e2e
   ahora hace `include_str!("fixtures/vuln_findings.xml")` — fixture real ya
   documentado en `tests/fixtures/README.md`
   (`nmap -sV --script vuln -p 21,6667 -oX - tgt-msf`, Metasploitable 2 de
   laboratorio). No se añadió ningún fixture nuevo, así que `tests/fixtures/README.md`
   sigue siendo exacto ("salida `-oX` literal de Nmap 7.98, sin editar").
   Los asserts de los 2 tests afectados se reescribieron y **son coherentes**
   con el fixture y con el test unitario pre-existente
   `parser::tests::parses_vulnerability_findings_from_vuln_scripts`:
   - `stub_fixture_parses_into_the_expected_scan_result`: host `172.18.0.4`,
     2 puertos (21 y 6667) ambos `Open`, puerto 21 `version == "vsftpd 2.3.4"`,
     2 vulnerabilidades ambas `CVE-2011-2523`, scripts `ftp-vsftpd-backdoor` y
     `vulners`.
   - `valid_request_flows_through_pipeline_and_is_published_and_persisted`:
     mismos 2 puertos abiertos, 2 vulns `CVE-2011-2523`, una de
     `ftp-vsftpd-backdoor`.
   - El fixture contiene `irc-unrealircd-backdoor` (sólo error de conexión) →
     el parser no lo cuenta como hallazgo; los asserts (`len() == 2`) lo
     respetan.
   - `fake_nmap()` vuelca el fixture con un heredoc de delimitador entre
     comillas (`<<'NMAP_STUB_EOF'`): sin expansión de variables, seguro con los
     ~18 KB del XML.

2. **Rustdoc** — `src/messaging/publisher.rs:170` y `:174`: los enlaces
   intra-doc `[`outcome_log_fields`]` pasaron a texto plano `` `outcome_log_fields` ``.
   Verificado por el revisor:
   `RUSTDOCFLAGS="-D warnings" cargo doc --no-deps` → **exit 0, 0 warnings**.
   `cargo doc --no-deps` dentro de `./init.sh` → sin warnings.

---

## Checkpoints

- C1: [x]  `./init.sh` exit 0 (5 corridas acumuladas: 3 en round 1 + 2 en round 2); 4 archivos base + 4 docs presentes.
- C2: [x]  Sólo la feature 10 en `in_progress`; toda feature `done` conserva tests verdes; `progress/current.md` describe la sesión activa.
- C3: [x]  `cargo doc --no-deps` **sin warnings** (defecto del round 1 corregido). Sin `unwrap`/`expect`/`panic!`/`println!`/`dbg!` fuera de `#[cfg(test)]` en `src/pipeline.rs` ni `src/lib.rs`. `Cargo.toml` sin cambios (sin dependencias nuevas, sin `anyhow`). Nota: `src/pipeline.rs` es un módulo nuevo — autorizado explícitamente por el leader en el brief; queda una recomendación (no bloqueante) de reflejarlo en `docs/architecture.md` §Capas.
- C4: [x]  Un test de integración por módulo de IO; el e2e `tests/scan_pipeline.rs` corre sshd + mongo reales vía `testcontainers`, `#[ignore = "requiere Docker"]`, nunca contra `db-nmap` de producción; `cargo test` = 82 unit + 19 `--ignored` verdes; `cargo clippy --all-targets -- -D warnings` limpio.
- C5: [ ]  Pendiente de cierre por el leader: falta la entrada en `progress/history.md` y el paso de la feature 10 a `done` en `feature_list.json` (correcto que sigan sin hacerse hasta este APPROVED). No es un defecto del implementer.

---

## Criterios de `acceptance` — uno a uno (revalidados en round 2)

### Criterio 1 — un mensaje válido recorre todo el pipeline y publica un resultado — **CUMPLE**

- `valid_request_flows_through_pipeline_and_is_published_and_persisted`
  (`tests/scan_pipeline.rs:203`), `#[ignore]`, verde en las 2 corridas del round 2.
- sshd (`lscr.io/linuxserver/openssh-server:version-9.9_p2-r0`) + stub de `nmap`
  en `/usr/local/bin/nmap` + `mongo:7`, todo por `testcontainers`.
- 1 `ScanRequest` (`corr-e2e-ok`) por `InMemoryScanRequestSource::from_requests`
  → `pipeline.run(source)`.
- Verifica contenido: 1 desenlace `Completed`, `correlation_id == "corr-e2e-ok"`,
  2 puertos abiertos (21, 6667), 2 vulns `CVE-2011-2523` (una `ftp-vsftpd-backdoor`),
  `ScanResult` idéntico persistido en Mongo (`find_by_correlation_id`).
- Flujo completo sin saltar etapas: `ScanPipeline::run` → `next_valid_request`
  (consumer) → `run_stages`: `ssh::connect` → `scanner::run_scan_with` →
  `parser::parse` → `MongoRepository::save` → `sink.publish(completed)`
  (`src/pipeline.rs:121-146`).

### Criterio 2 — el `HostKeyStore` de producción es el de Mongo — **CUMPLE**

- `src/lib.rs:70`: `Arc::new(repo.host_key_store())` → `MongoHostKeyStore`, no
  `InMemoryHostKeyStore`.
- e2e (`tests/scan_pipeline.rs:264-277`): tras el escaneo, una segunda instancia
  `MongoRepository::connect(...).host_key_store()` ve el fingerprint TOFU del
  objetivo (`known_fingerprint(&ip).await` → `Some`).

### Criterio 3 — fallo en cualquier etapa → error publicado, sin crash — **CUMPLE**

- `process_one` (`src/pipeline.rs:83-116`): `run_stages` → `Ok` = `completed`,
  `Err(reason)` = `failed(correlation_id, reason)`; **siempre** publica; nunca
  propaga ni entra en pánico; fallo de `sink.publish` → `tracing::error!` y
  termina.
- Grep de `unwrap`/`expect`/`panic!`/`.blocking_`/`std::thread::sleep`/`std::fs::`
  fuera de `#[cfg(test)]` en `src/pipeline.rs` y `src/lib.rs`: **0**.
- `reason = err.to_string()`; los `Display` de `SshError`/`ScanError`/`ParseError`/
  `RepoError` redactan credenciales (tests pre-existentes +
  `stage_error_strings_become_failed_outcomes_without_leaking_credentials`,
  `src/pipeline.rs:283`).
- `stage_failure_is_published_as_failed_outcome_without_crashing`
  (`tests/scan_pipeline.rs:280`), verde 2/2: objetivo sin stub de `nmap` →
  `ScanError::ToolNotAvailable` → 1 `Failed` (`corr-e2e-fail`), `reason` contiene
  `"nmap"`, no contiene la contraseña; nada persistido.

### Criterio 4 — múltiples solicitudes concurrentes sin bloquear el runtime — **CUMPLE**

- `ScanPipeline::run` (`src/pipeline.rs:164-177`): `tasks.spawn(...)` por
  solicitud con el pipeline clonado (`#[derive(Clone)]`, campos `Arc`/`Copy`/
  baratos); al agotarse la fuente, drena el `JoinSet` — espera a las tareas en
  vuelo antes de retornar.
- Sin llamadas bloqueantes: `russh` y `mongodb` async nativos; los
  `std::sync::Mutex` de los stubs se toman/sueltan sin cruzar `.await`.
- `multiple_requests_are_processed_concurrently` (`tests/scan_pipeline.rs:331`),
  `#[tokio::test(flavor = "multi_thread", worker_threads = 4)]`, verde 2/2: 3
  solicitudes concurrentes → 3 `Completed` (`corr-c1/2/3`), los 3 persistidos.
  Warm-up TOFU previo para aislar la contención al pipeline.

---

## `src/config.rs` — ampliación del wiring — **CUMPLE patrón feature 2**

- `MS_NMAP_SSH_PORT` → `Config::ssh_port: u16` (`parse_port`: ausente/vacía →
  `MissingVar`; no numérica / fuera de `1..=65535` → `InvalidValue`; sin
  default, sin panic).
- `MS_NMAP_MONGO_DB` → `Config::mongo_db: String` (`required`).
- Tests nuevos: `missing_mongo_db_var_...`, `missing_ssh_port_var_...`,
  `non_numeric_ssh_port_...`, `out_of_range_ssh_port_...` (`"0"`, `"70000"`);
  `loads_valid_config_with_expected_parsed_values` ampliado.
- Autorizado en el brief; no es scope creep.

## `src/lib.rs::run()` — composition root — **Aceptable**

- `Config::from_env` → `MongoRepository::connect` → `Arc<dyn HostKeyStore>` de
  Mongo → `ScanPipeline` (timeouts + `ssh_port` + `ScanOptions::default()`).
- Sin adaptador real de broker: `tracing::warn!` + retorno limpio; fallos de
  config/Mongo → `tracing::error!` + `return` (nunca panic). Sin `anyhow`.
  `src/main.rs` sin cambios (git lo confirma).
- Observación menor (no bloqueante): `run()` construye `_pipeline` y lo descarta;
  el pipeline sólo se ejercita vía el e2e. Defendible mientras no exista el
  `source` real; conviene dejar registrada la continuación (solapa con feature 11).

---

## Verificación ejecutada por el revisor (round 2)

`./init.sh` — **2 ejecuciones, exit 0, sin flakiness**:

| Etapa | Resultado (idéntico en ambas corridas) |
|---|---|
| `cargo fmt --check` | sin diferencias |
| `cargo clippy --all-targets -- -D warnings` | sin warnings |
| `cargo test` (unit) | **82 passed, 0 failed** |
| `tests/scan_pipeline.rs` (no-Docker) | 1 passed (`stub_fixture_parses_into_the_expected_scan_result`) |
| `cargo test -- --ignored` · `tests/scan_pipeline.rs` | **3 passed** (`valid_request_flows...`, `stage_failure...`, `multiple_requests...`) |
| `cargo test -- --ignored` · `tests/repository.rs` | 6 passed |
| `cargo test -- --ignored` · `tests/scanner.rs` | 4 passed |
| `cargo test -- --ignored` · `tests/ssh.rs` | 5 passed |
| `cargo doc --no-deps` | exit 0, **0 warnings** |
| `RUSTDOCFLAGS="-D warnings" cargo doc --no-deps` | exit 0, **0 warnings** |

- Integración `--ignored` total: **18 passed, 0 failed** por corrida.
- **Sin regresión**: los 82 unit y los 15 de integración de features 1-9 siguen
  verdes.
- Untracked esperados: `src/pipeline.rs`, `tests/scan_pipeline.rs`,
  `progress/impl_scan_pipeline_wiring.md`, `progress/review_scan_pipeline_wiring.md`.
  Modificados: `feature_list.json`, `progress/current.md`, `src/config.rs`,
  `src/lib.rs`, `src/messaging/publisher.rs`. Sin `*.tmp` ni `target/` fuera de
  `.gitignore`.

---

## ¿Cubre el `tests/messaging.rs` diferido de features 8/9?

Parcialmente: el e2e ejercita `InMemoryScanRequestSource` (consumer) y
`InMemoryScanResultSink` (publisher) en un flujo real completo. No sustituye a un
`tests/messaging.rs` contra un broker concreto (que no existe hasta decidir la
tecnología). Aceptable; el archivo diferido sigue teniendo sentido para cuando
haya un adaptador.

---

## Cambios requeridos

Ninguno. Los 2 del round 1 están resueltos y verificados.

## Recomendaciones (no bloqueantes, para el leader / features futuras)

1. Actualizar `docs/architecture.md` §Capas para listar el módulo `pipeline` y
   describir que `lib::run()` delega la orquestación en `ScanPipeline` (extraído
   para poder inyectar dependencias en los tests e2e de Nivel 4). Mantiene
   coherente la lista de módulos que evalúa `CHECKPOINTS.md` C3.
2. En `src/lib.rs::run()`, dejar una referencia explícita (comentario con
   contexto o nota en `feature_list.json`) al punto donde se conectará el
   `source` real cuando exista el adaptador de broker (solapa con feature 11).

## Cierre de sesión (leader)

- Pasar `feature_list.json` id 10 → `done`.
- Añadir entrada de la sesión en `progress/history.md`.
- Commit con: `src/pipeline.rs`, `src/lib.rs`, `src/config.rs`,
  `src/messaging/publisher.rs`, `tests/scan_pipeline.rs`, `feature_list.json`,
  `progress/*.md`. (Fixture `tests/fixtures/pipeline_stub_scan.xml` eliminado —
  nunca llegó a commitearse.)

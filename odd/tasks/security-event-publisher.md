# security-event-publisher (KAP-07)

- Engram topic: `odd/security-event-publisher/tasks` (project: `nmap-service`)
- Branch: `feature/security_event_publisher` (off origin/develop c267ff8)
- Status: done (2026-11-10)
- Master plan: repo `infra`, `odd/tasks/kinesis-admin-panel.md` (task KAP-07). Mirror of the gateway work (KAP-06, `gateway/odd/tasks/security-event-publisher.md`).

## Objective

ms-nmap publishes `scan.started`, `scan.completed`, `scan.failed` and `finding.critical` security events to the Kinesis stream `security-events` through a `SecurityEventPublisher` port, without ever failing or delaying the scan pipeline or the SNS outcome publish.

## Scope

- Port `SecurityEventPublisher`, envelope `SecurityEvent` (source `nmap-service`) with typed constructors that return `Err` for schema-invalid values; partition key `scan_id`.
- Adapters: Kinesis (`aws-sdk-kinesis` 1.125.0, same as the gateway; honors `AWS_ENDPOINT_URL`), no-op, in-memory recorder.
- Config `SECURITY_EVENTS_STREAM_NAME` (optional; unset/blank = no-op + one startup info log; invalid = startup config error).
- Emission next to the SNS outcome publish, contract parity tests against `../broker/contracts`, LocalStack Kinesis test.
- Out of scope: user-service events (KAP-08), the gateway consumer (KAP-09), retries/outbox, changing the scan-outcome contract.

## Constraints

- Kinesis failures never fail or delay the pipeline or the SNS publish; logs carry the event type only.
- Events carry no credentials, raw scan output, error text or target IPs.
- Every emitted event validates against `broker/contracts/security-event.schema.json`.
- Unit tests do not mutate the process environment and have no wall-clock waits.
- Code comments in neutral Spanish, identifiers in English, this doc in English.

## Tooling

- TDD mode: on (source: user global config "Strict TDD Mode: enabled"); runner `make verify` (`cargo test -- --ignored` needs Docker).
- Route: delegated direct, single writer. Review policy: decline (stored user policy; no permission or secret touched).

## Decisions

- D1 Failure isolation: same as the gateway. `emit`/`emit_all` publish from a detached `tokio::spawn` task bounded by a 5 s timeout per event; `emit_all` publishes a batch in order and drops the rest of the batch on the first failure (no chain of timeouts when Kinesis is down). A crash before the task runs can lose events (accepted: Mongo/SNS stay the source of truth).
- D2 Emission order inside `process_one`: `scan.started` before the SNS `Started` publish; terminal events (`scan.completed` then the `finding.critical` ones, or `scan.failed`) right before `publish_terminal`. Both are non-blocking, so neither side waits for the other.
- D3 Idempotent republish of an already finished scan (redelivery) emits no events: no new scan happened. A rescan after a failed terminal SNS publish can emit a second terminal event with a different `event_id`; consumers see them as two facts (conservative: never drop a real scan result).
- D4 Rejected requests that keep a `correlation_id` also emit `scan.failed` (`rejected_request`), mirroring the SNS `Failed` they already publish; no `scan.started` is emitted for them.
- D5 `finding.critical` conservative choices: only findings with a `confidence` (the schema allows `confirmed|version_match` only; mapping `None` would invent data); findings with `patch_state: fixed` do not emit (target not vulnerable); they still count in `scan.completed`.
- D6 Port gap: `VulnFinding` has no port or protocol, and adding one changes the `scan-outcome` contract (gateway denies unknown fields; user-service/front plumbing). Conservative option: `port: 0`, `protocol: "tcp"` (the schema allows port 0). Follow-up needed to carry the real port.
- D7 Cap: at most 50 `finding.critical` events per scan (`MAX_FINDING_CRITICAL_EVENTS`), critical first, then high; the rest only count in `scan.completed`. Protects the 1-shard stream (1000 records/s).
- D8 The SNS oversize replacement (`Completed` -> `Failed` when the body exceeds 250 KiB) happens inside the SNS adapter and is not mirrored: `scan.completed` is still emitted because the scan did complete and is persisted.
- D9 Env var name is exactly `SECURITY_EVENTS_STREAM_NAME` (shared across services), without the `MS_NMAP_` prefix, like `AWS_*`.

## Mappings

Severity (`scan.completed.finding_counts`): 1:1 with `domain::Severity` (`critical`, `high`, `medium`, `low`, `info`, `unknown`); every `VulnFinding` counts once; open ports are not counted.

Failure (`scan.failed.reason_code`):

| Failure | reason_code |
|---|---|
| `SshError::AuthFailed`, `Timeout`, `Unreachable` | `ssh_auth_failed`, `ssh_timeout`, `ssh_unreachable` |
| `SshError::HostKeyMismatch`, `HostKeyStore` | `ssh_host_key_mismatch`, `ssh_host_key_store` |
| `SshError::Protocol`, `Io` | `ssh_protocol_error`, `ssh_io_error` |
| `ScanError::ToolNotAvailable`, `InsufficientPrivileges`, `NmapFailed` | `nmap_not_available`, `nmap_insufficient_privileges`, `nmap_failed` |
| `ScanError::Ssh(e)` | the `ssh_*` slug of `e` |
| `ParseError` | `parse_failed` |
| `RepoError` on save | `persistence_failed` |
| explicit cancellation | `scan_cancelled` |
| rejected request | `rejected_request` |

## Checklist

- [x] SEP-01 Feature doc (9e2ce5e).
- [x] SEP-02 `SecurityEvent` envelope, port, recorder/no-op adapters, `emit`/`emit_all`, schema parity tests (d24c533).
- [x] SEP-03 Kinesis adapter, `SECURITY_EVENTS_STREAM_NAME`, wiring, LocalStack test (98941d6).
- [x] SEP-04 Emission points in the pipeline, each with a failing-publisher test (1ee9646).
- [x] SEP-05 `docs/architecture.md`, `docs/security-scope.md`, README env table, this doc closed (docs commit on top of 1ee9646).

## Emission points

| Event | Where | Condition |
|---|---|---|
| `scan.started` | `src/pipeline.rs` `ScanPipeline::process_one` | before the SNS `Started` publish |
| `scan.completed` | `process_one` via `security_events::completion_events` | stages succeeded |
| `finding.critical` | `completion_events` | high/critical with confidence, not fixed, up to 50 |
| `scan.failed` | `process_one` | stage failure or cancellation |
| `scan.failed` | `src/pipeline.rs` `next_valid_request` | rejected request with `correlation_id` |

## Evidence

- RED SEP-02: `cargo test --lib --no-run` failed with 63 compile errors (`SecurityEvent`, `emit`, `FindingCounts`, publishers not found) after writing the unit tests first. GREEN: 16 unit tests, 4 contract tests (`tests/security_event_contract.rs`: every constructor validates against the schema, the 11 broker examples deserialize and round-trip, the 4 nmap examples equal the constructor output); clippy `-D warnings` clean.
- RED SEP-03: config tests failed to compile (`SECURITY_EVENTS_STREAM_NAME_VAR`, `security_events_stream_name` missing); the LocalStack test failed to compile (`create_stream`, `read_stream`, `kinesis` missing from the harness). GREEN: 3 new config tests; `cargo test --test kinesis_publisher_localstack -- --ignored` 2 passed (4 events read back with `scan_id` partition key and schema validation; missing stream gives `PublishFailed` without the body).
- RED SEP-04: `completion_events`, `StageFailure`, `ssh_reason_code` and the new `next_valid_request` argument did not exist (15 compile errors, then 7 more for the unit tests of `completion_events`). GREEN: 26 `security_events` tests and 7 new pipeline tests: success emits `started, completed, finding.critical`; SSH failure emits `started, failed(ssh_auth_failed)` with no error text; cancellation emits `scan_cancelled`; a failing publisher leaves `process_one` returning `true` and both SNS outcomes published (completed and failed flows); republish emits nothing; rejected request emits `rejected_request`; every mapped slug is schema-valid.
- Contract: tests read `../broker/contracts/` at run time and print SKIP and pass if absent.
- Final: `make verify` exit 0 (fmt, clippy `-D warnings`, tests, ignored Docker suites, `cargo doc`); `cargo test --lib` 248 passed on three consecutive runs.
- Review: none run (stored user policy: decline).

## Known limitations

- `port` is `0` and `protocol` `tcp` in every `finding.critical` (D6).
- Events can be lost if the process dies before the spawned task publishes; no retry or outbox.
- Findings without `confidence` produce no `finding.critical` (D5).
- Deployment: the ECS task role needs `kinesis:PutRecord` on the stream and the task needs `SECURITY_EVENTS_STREAM_NAME` (infra repo, not changed here).

## Next step

KAP-08 (user-service producer for `audit.recorded`); KAP-09 (gateway consumer of the stream). Follow-up: carry the real port in `VulnFinding` across the scan-outcome contract and use it here.

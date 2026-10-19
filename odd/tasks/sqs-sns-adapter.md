# Feature: sqs-sns-adapter (nmap-service)

Self-contained: any AI agent can start from this file with no prior context.

- Feature id: `sqs-sns-adapter` | Engram topic: `odd/sqs-sns-adapter/tasks` (project: nmap-service; mirror pending) | Branch: `v1`
- Master plan: repo `infra`, path `odd/tasks/cloud-native-deploy.md`
- Topology and contract (Proposed): repo `broker`, path `odd/tasks/sqs-sns-migration.md` (MSG-01 sign-off gates this feature)
- Counterpart: repo `gateway`, path `odd/tasks/sqs-sns-adapter.md`
- Decision date: 2026-10-17 (RabbitMQ replaced by SNS + SQS)

## Objective

Replace the `lapin` (AMQP) adapter in `nmap-service` (feature `broker_adapter`, module `src/messaging/rabbitmq.rs`) with the AWS SDK
for Rust: consume `ms-nmap-scan-requests` and `ms-nmap-scan-cancellations` from SQS, publish scan outcomes to the `scan-outcomes` SNS topic.

## Problem

`src/messaging/rabbitmq.rs` consumes queues `ms-nmap.scan-requests` and `ms-nmap.scan-cancellations` (ack, `nack(requeue=false)` on
malformed bodies) and publishes to exchange `scan.outcomes` with routing keys `scan.outcome.started|completed|failed`. Config
(`src/config.rs`) requires `MS_NMAP_BROKER_ENDPOINT`, `MS_NMAP_BROKER_CREDENTIAL` and `MS_NMAP_BROKER_VHOST`; the Dockerfile bakes a lab CA.

## Why

Amazon MQ is denied in the Learner Lab; the user chose SNS + SQS. SQS/SNS use public-CA HTTPS, so the lab CA is no longer needed.

## Scope

In:
- Config: region, two queue URLs, outcomes topic ARN, optional endpoint override for LocalStack (proposed names below). Remove `MS_NMAP_BROKER_*`.
- Consumers on SQS with long polling; **visibility timeout handling for long scans** (heartbeat `ChangeMessageVisibility` or a ceiling, broker Q1).
- Publisher on SNS with the `routing_key` String attribute.
- Remove `lapin` and companions, the `broker_adapter` AMQP code and the baked lab CA (Dockerfile stage, `SSL_CERT_FILE`).
- Tests against LocalStack (real container, no mocks); compose gains LocalStack.

Out:
- Scanning logic and `docs/security-scope.md` limits; message contracts (unchanged).
- Topology and Terraform (`broker` design, `infra` TF-10).

## Constraints

- Strict TDD: observe RED before implementing. Runner: `cargo test`; integration (`-- --ignored`, Docker) uses LocalStack.
- Credentials from the default AWS provider chain (ECS task role = shared `LabRole`); no static keys.
- At-least-once delivery: a duplicate `ScanRequest` must not start a second scan for the same `scan_id` (idempotency design in MSG-NM-02).
- `ScanRequest` bodies hold real SSH credentials: never log bodies; encryption and short retention come from the topology (broker Q4).
- Proposed env vars (confirm at MSG-NM-01): `AWS_REGION`, `AWS_ENDPOINT_URL` (LocalStack only), `MS_NMAP_SCAN_REQUESTS_QUEUE_URL`,
  `MS_NMAP_SCAN_CANCELLATIONS_QUEUE_URL`, `MS_NMAP_SCAN_OUTCOMES_TOPIC_ARN`.
- Planning heuristic about 400 authored changed lines per task; not a cap.
- Conventional Commits, no AI attribution; push/PR/merge are user decisions. Existing Spanish docs keep being edited in Spanish.

## Checklist

- [x] MSG-NM-01 Config: SQS/SNS variables with typed errors; RED: config tests first. Removing `MS_NMAP_BROKER_*` moves to MSG-NM-04 so the build stays green (same sequencing as the gateway).
- [x] MSG-NM-02 Request and cancellation consumers on `aws-sdk-sqs`: long poll, delete after success, malformed handling, fixed visibility timeout set by Terraform (SSH connect + command timeout + 60 s, broker decision Q1; no ChangeMessageVisibility heartbeat), idempotency by `scan_id`; LocalStack tests including redrive to DLQ after 3 receives.
- [x] MSG-NM-03 Outcome publisher on `aws-sdk-sns` with `routing_key` attribute; LocalStack test verifies the filters (Gateway gets `started`/`completed`/`failed`, the `ms-analisis` filter check is deferred until that queue exists, see broker sqs-sns-migration Q7).
- [ ] MSG-NM-04 Wiring and cleanup: update `src/wiring.rs`, remove `lapin` and the `broker_adapter` AMQP module, LocalStack in compose and README, `make verify` green.
- [ ] MSG-NM-05 Drop the baked lab CA (Dockerfile CA stage, `SSL_CERT_FILE`, `tls` build context); the image then builds with no cross-repo context.

## Acceptance criteria

- `nmap-service` consumes requests and cancellations and publishes outcomes through SNS + SQS on LocalStack and on AWS.
- Long scans are not redelivered while running; duplicates do not start a second scan; failures end in the DLQ after 3 receives.
- No `lapin`, AMQP configuration or lab CA remains; `make verify` passes; image builds without the `broker` repo.

## Checks

`cargo test`; `cargo test -- --ignored` (LocalStack); `make verify`; `docker build` without extra build contexts.

## Progress

Planned. Blocked on broker MSG-01 (topology sign-off, including the visibility-timeout question) and on MSG-02 for the AWS run.

## MSG-NM-01 evidence

- Route: delegated writer (single bounded writer, inline-verified by parent afterwards). Checkbox intentionally not ticked.
- RED: `cargo test --lib config::` -> compile failure (`E0425`/`E0599`/`E0609`, 32 errors: missing `AWS_REGION_VAR` etc., `ConfigError::InvalidUrl`/`InvalidArn`, new `Config` fields).
- GREEN: `cargo test --lib config::` -> `36 passed; 0 failed` (9 new tests). `cargo test` -> lib `155 passed; 0 failed`, integration suites only `ignored` (Docker).
- Change: `src/config.rs` adds `AWS_REGION`, optional `AWS_ENDPOINT_URL`, four queue URLs and `MS_NMAP_SCAN_OUTCOMES_TOPIC_ARN` (typed `MissingVar`, `InvalidUrl`, `InvalidArn` without echoing the value); `url = "2"` added to `Cargo.toml` (already in the lock). README env table lists the 7 vars. `MS_NMAP_BROKER_*` and `SSL_CERT_FILE` untouched (MSG-NM-04/05).
- Note: `Config::from_env` now requires the new vars at runtime, so local runs/compose must set them until MSG-NM-04 wires LocalStack.

## MSG-NM-02 evidence

- Route: delegated writer (single bounded writer; parent verifies afterwards). Checkbox intentionally not ticked. No commit/push.
- RED (tests first):
  - `cargo test --lib` -> compile failure `E0432` (`AckError`/`Acknowledger` unresolved; the pipeline tests for ack, in-flight skip and finished-scan republish).
  - `cargo test --test sqs_sources_localstack --no-run` -> `E0432: unresolved import nmap_service::messaging::sqs`.
  - `cargo test --test repository -- --ignored saving_twice connect_creates` -> `0 passed; 2 failed` (second `save` returned a different `ScanId`; `ns does not exist` / no unique index).
- GREEN:
  - `cargo test` -> lib `165 passed; 0 failed` (155 before: 8 pipeline tests + 2 sqs unit tests added); integration suites only `ignored`.
  - `cargo test --test sqs_sources_localstack -- --ignored` -> `8 passed; 0 failed` (~35 s, LocalStack 4.4 per test).
  - `cargo test --test repository -- --ignored` -> `13 passed; 0 failed` (2 new). `cargo test --test scan_pipeline -- --ignored` -> `4 passed; 0 failed`.
  - `cargo fmt --check`, `cargo clippy --all-targets -- -D warnings`, `cargo doc --no-deps`: clean. `tests/broker_adapter.rs` (RabbitMQ) intentionally not run.
- Design notes:
  - Ack handle: `IncomingScanRequest { request, ack: Arc<dyn Acknowledger> }` (`new` = `NoopAcknowledger`, `with_ack`); `Acknowledger::ack() -> Result<(), AckError>` where `AckError` is SDK-agnostic (queue, detail, boxed `#[source]`). `process_one` returns `bool` (terminal outcome published; `false` also for an in-flight skip); the private `handle_incoming` (spawned by `run`) acks only on `true`. An ack failure is logged, not fatal.
  - Idempotency: `CancellationRegistry::try_register` doubles as the in-flight set; a duplicate returns `false` without touching the original token. Then `find_by_correlation_id`: found -> republish `Completed` (no `Started`, no scan), unregister, ack if the publish succeeded. A lookup error falls back to scanning (the upsert prevents duplicate documents). Only successful scans are persisted, so a `Failed` outcome cannot be rebuilt: a redelivered message whose `Failed` publish had failed is rescanned (accepted, documented in `process_one`).
  - Mongo: `save` is `find_one_and_replace(..).upsert(true)` keyed by `correlation_id` (same `ScanId` on retry); `MongoRepository::connect` creates the unique index `scan_results_correlation_id_unique` idempotently. Startup fails if legacy duplicates already exist.
  - SQS adapters (`src/messaging/sqs.rs`): requests `MaxNumberOfMessages=1`, cancellations batch of 10 with a buffer; long poll 20 s; fixed visibility (no `ChangeMessageVisibility`). Malformed -> explicit `SendMessage` of the raw body with all message attributes to the DLQ, then delete (no delete if the DLQ send fails); the source returns `Err(MalformedPayload|InvalidSchema)` so the pipeline logs and continues. Receive errors back off 1 s..30 s inside the adapter and are never surfaced as `Transport` (`with_backoff` exists for fast tests). Bodies are never logged (only length).
  - Cancellation deletion: the source deletes a delivered cancellation when the pipeline asks for the next one (the loop applies, then re-polls), so "delete after applying" needs no port change.
  - Crypto provider: adding `aws-config`/`aws-sdk-sqs` (default features, aws-lc-rs TLS connector with an explicit provider) changed nothing about provider ambiguity: `Cargo.lock` already had `ring` (russh/reqwest/lapin) and `aws-lc-rs` (mongodb/testcontainers) for rustls 0.23. The new LocalStack test file reuses the defensive `rustls::crypto::ring::default_provider().install_default()` guard; LocalStack is plain HTTP. No production `main` change; revisit at MSG-NM-04 once `lapin` is gone.
- Accepted limitation (unchanged): cancellations are in-process. With more than one replica a cancellation can be consumed by a replica not running the scan and be lost; a cancellation arriving before its request is also lost. Today `desired_count = 1`.
- Wiring (`src/wiring.rs`) and the lapin adapters are unchanged; the SQS sources are not used until MSG-NM-04.

## MSG-NM-03 evidence

- Route: delegated writer (single bounded writer; parent verifies afterwards). Checkbox intentionally not ticked. No commit/push.
- RED (tests first):
  - `cargo test --lib --no-run` -> `E0433/E0425` (`ScanOutcome`, `encode_outcome`, `MAX_OUTCOME_BODY_BYTES`, `RESULT_TOO_LARGE_REASON`, `replacement_if_oversized` unresolved) with only the 7 new `sns` unit tests present.
  - `cargo test --test sns_sink_localstack --no-run` -> lib did not compile (`missing documentation for a module`, `#![deny(missing_docs)]`) before the adapter existed.
- GREEN:
  - `cargo test` -> lib `172 passed; 0 failed` (165 before: +7 sns unit tests, `routing_key_for` test moved to `publisher.rs`); integration suites only `ignored`.
  - `cargo test --test sns_sink_localstack -- --ignored` -> `3 passed; 0 failed` (~13 s): Started/Completed/Failed arrive through the Gateway filter `{"routing_key":[{"prefix":"scan.outcome."}]}` with exact JSON body and `routing_key` attribute; oversized Completed arrives as Failed with the fixed reason; missing topic -> `PublishError::Sns`.
  - `cargo test --test sqs_sources_localstack -- --ignored` -> `8 passed; 0 failed` (still green). `cargo fmt --check`, `cargo clippy --all-targets -- -D warnings`, `cargo doc --no-deps`: clean. `tests/broker_adapter.rs` not run.
- Threshold: `MAX_OUTCOME_BODY_BYTES = 250 * 1024` (256000 B). SNS caps body + attributes at 256 KiB (262144 B); the `routing_key` attribute and envelope need well under 1 KiB, leaving ~6 KiB margin. Only `Completed` is checked (the only variant that grows); body exactly at the threshold is published unchanged.
- Change summary: new `src/messaging/sns.rs` (`SnsScanResultSink::{from_client, connect}`, pure `replacement_if_oversized`, `RESULT_TOO_LARGE_REASON`, `ROUTING_KEY_ATTRIBUTE`); `routing_key_for` and the three `ROUTING_KEY_SCAN_OUTCOME_*` consts moved to `publisher.rs` (values unchanged; `rabbitmq.rs` re-exports the consts so `tests/broker_adapter.rs` imports still resolve); new `PublishError::Sns { topic, #[source] Box<dyn Error + Send + Sync> }`; `aws-sdk-sns = "1.116.0"`. On oversize a `warn` logs only `correlation_id` and byte sizes; bodies are never logged. Wiring and lapin adapters unchanged.
- Deferred: the `ms-analisis` filter check waits for its queue (broker Q7).

## Next step

MSG-NM-01 once broker MSG-01 is signed off.

## Decisions for MSG-NM-02 (2026-10-19)

- Delete after handle (same as the gateway, user decision A): a request message is deleted only after the scan finished AND its terminal outcome was published. `process_one` returns whether the terminal publish succeeded; on failure the message stays and SQS redelivers it.
- Idempotency by `correlation_id` (user decision A): before scanning, look up Mongo for a finished scan with that `correlation_id`; if found, republish its terminal outcome and delete the message without rescanning. If the same `correlation_id` is already in flight in this replica, skip the duplicate without deleting it. `MongoRepository::save` becomes an upsert keyed by `correlation_id` with a unique index, so a redelivery never creates a second document.
- Known limitation (accepted, documented): cancellations are in-process. With more than one replica a cancellation can be consumed by a replica that is not running the scan and is lost; a cancellation that arrives before its request is also lost. Today the service runs one replica (`desired_count = 1`). The same limitation existed with RabbitMQ.
